/**
 * Attachment upload/download fast-path for Warden Worker (JS)
 *
 * This module implements:
 * - Attachment upload logic (zero-copy streaming to R2)
 * - Attachment download logic (zero-copy streaming from R2)
 * - JWT validation for attachment tokens (HMAC-SHA256) using Web Crypto API
 *
 * Route matching and URL parsing should be handled by `src/entry.js`.
 */

const JWT_EXPECTED_ALG = "HS256";
const JWT_VALIDATION_LEEWAY_SECS = 60;
// JWT validation using Web Crypto API (no external dependencies)
async function verifyJwt(token, secret) {
  const encoder = new TextEncoder();
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid token format");
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  let header;
  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64)));
  } catch {
    throw new Error("Invalid token header");
  }

  if (!header || typeof header !== "object" || header.alg !== JWT_EXPECTED_ALG) {
    throw new Error("Invalid token algorithm");
  }

  // Import the secret key for HMAC-SHA256
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  // Decode the signature (base64url to Uint8Array)
  const signature = base64UrlDecode(signatureB64);

  // Verify the signature
  const data = encoder.encode(`${headerB64}.${payloadB64}`);
  const valid = await crypto.subtle.verify("HMAC", key, signature, data);

  if (!valid) {
    throw new Error("Invalid token signature");
  }

  // Decode and parse the payload
  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
  } catch {
    throw new Error("Invalid token payload");
  }

  if (!payload || typeof payload !== "object") {
    throw new Error("Invalid token payload");
  }

  if (typeof payload.exp !== "number") {
    throw new Error("Invalid token exp");
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now - JWT_VALIDATION_LEEWAY_SECS) {
    throw new Error("Token expired");
  }

  return payload;
}

export function base64UrlDecode(str) {
  // Convert base64url to base64
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding if needed
  while (base64.length % 4) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Generate ISO timestamp string
function nowString() {
  return new Date().toISOString();
}

// Helper to get env var with fallback
function getEnvVar(env, name, defaultValue = null) {
  try {
    const value = env[name];
    if (value && typeof value.toString === "function") {
      return value.toString();
    }
    return value || defaultValue;
  } catch {
    return defaultValue;
  }
}

// Storage backend constants
const KV_MAX_VALUE_BYTES = 25 * 1024 * 1024; // 25 MiB (KV hard limit)

// Detect which storage backend is available.
// Priority: R2 if bound, otherwise KV.
function getStorageBackend(env) {
  if (env.ATTACHMENTS_BUCKET) {
    return "r2";
  }
  if (env.ATTACHMENTS_KV) {
    return "kv";
  }
  return null;
}

// Check if using KV backend (for behavior differences)
function isKvBackend(env) {
  return getStorageBackend(env) === "kv";
}

// Get attachment size limits from env
function getAttachmentMaxBytes(env) {
  const value = getEnvVar(env, "ATTACHMENT_MAX_BYTES");
  if (!value) return null;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? null : parsed;
}

function getTotalLimitBytes(env) {
  const value = getEnvVar(env, "ATTACHMENT_TOTAL_LIMIT_KB");
  if (!value) return null;
  const kb = parseInt(value, 10);
  if (isNaN(kb)) return null;
  return kb * 1024;
}

// Get user's current attachment usage
async function getUserAttachmentUsage(db, userId, excludeAttachmentId) {
  const query = excludeAttachmentId
    ? `SELECT COALESCE(SUM(file_size), 0) as total FROM (
         SELECT a.file_size as file_size
         FROM attachments a
         JOIN ciphers c ON c.id = a.cipher_id
         WHERE c.user_id = ?1 AND a.id != ?2
         UNION ALL
         SELECT p.file_size as file_size
         FROM attachments_pending p
         JOIN ciphers c2 ON c2.id = p.cipher_id
         WHERE c2.user_id = ?1 AND p.id != ?2
       ) AS files`
    : `SELECT COALESCE(SUM(file_size), 0) as total FROM (
         SELECT a.file_size as file_size
         FROM attachments a
         JOIN ciphers c ON c.id = a.cipher_id
         WHERE c.user_id = ?1
         UNION ALL
         SELECT p.file_size as file_size
         FROM attachments_pending p
         JOIN ciphers c2 ON c2.id = p.cipher_id
         WHERE c2.user_id = ?1
       ) AS files`;

  const bindings = excludeAttachmentId ? [userId, excludeAttachmentId] : [userId];

  const result = await db.prepare(query).bind(...bindings).first();
  return result?.total || 0;
}

// Enforce attachment size limits
async function enforceLimits(db, env, userId, newSize, excludeAttachmentId) {
  if (newSize < 0) {
    throw new Error("Attachment size cannot be negative");
  }

  // KV has a hard 25MB limit per value
  if (isKvBackend(env) && newSize > KV_MAX_VALUE_BYTES) {
    throw new Error(`Attachment size exceeds KV limit (max ${KV_MAX_VALUE_BYTES / 1024 / 1024}MB)`);
  }

  const maxBytes = getAttachmentMaxBytes(env);
  if (maxBytes !== null && newSize > maxBytes) {
    throw new Error("Attachment size exceeds limit");
  }

  // Check total storage limit
  const limitBytes = getTotalLimitBytes(env);
  if (limitBytes !== null) {
    const used = await getUserAttachmentUsage(db, userId, excludeAttachmentId);
    const newTotal = used + newSize;
    if (newTotal > limitBytes) {
      throw new Error("Attachment storage limit reached");
    }
  }
}

// Handle azure-upload with zero-copy streaming (R2) or arrayBuffer (KV)
export async function handleAzureUpload(request, env, cipherId, attachmentId, token) {
  // Check storage backend
  const backend = getStorageBackend(env);
  if (!backend) {
    return new Response(JSON.stringify({ error: "Attachments are not enabled" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Get D1 database
  const db = env.vault1;
  if (!db) {
    return new Response(JSON.stringify({ error: "Database not available" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Validate JWT token
  let claims;
  try {
    const secret = env.JWT_SECRET?.toString?.() || env.JWT_SECRET;
    if (!secret) {
      throw new Error("JWT_SECRET not configured");
    }
    claims = await verifyJwt(token, secret);
  } catch (err) {
    return new Response(JSON.stringify({ error: `Invalid token: ${err.message}` }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Validate token claims match the request
  if (claims.cipher_id !== cipherId || claims.attachment_id !== attachmentId) {
    return new Response(JSON.stringify({ error: "Invalid download token" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  const userId = claims.sub;

  // Verify cipher belongs to user and is not deleted
  const cipher = await db
    .prepare("SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2")
    .bind(cipherId, userId)
    .first();

  if (!cipher) {
    return new Response(JSON.stringify({ error: "Cipher not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (cipher.organization_id) {
    return new Response(JSON.stringify({ error: "Organization attachments are not supported" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (cipher.deleted_at) {
    return new Response(
      JSON.stringify({ error: "Cannot modify attachments for deleted cipher" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  // Fetch pending attachment record
  const pending = await db
    .prepare("SELECT * FROM attachments_pending WHERE id = ?1")
    .bind(attachmentId)
    .first();

  if (!pending) {
    return new Response(JSON.stringify({ error: "Attachment not found or already uploaded" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (pending.cipher_id !== cipherId) {
    return new Response(JSON.stringify({ error: "Attachment does not belong to cipher" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Get Content-Length from request headers
  const contentLengthHeader = request.headers.get("Content-Length");
  if (!contentLengthHeader) {
    return new Response(JSON.stringify({ error: "Missing Content-Length header" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const contentLength = parseInt(contentLengthHeader, 10);
  if (isNaN(contentLength) || contentLength <= 0) {
    return new Response(JSON.stringify({ error: "Invalid Content-Length header" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Enforce limits before upload
  try {
    await enforceLimits(db, env, userId, contentLength, attachmentId);
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Build storage key
  const storageKey = `${cipherId}/${attachmentId}`;
  let uploadedSize;

  if (backend === "kv") {
    // KV backend: streaming upload (KV.put accepts ReadableStream)
    // Note: KV doesn't return the uploaded size, so we trust Content-Length
    const kv = env.ATTACHMENTS_KV;
    try {
      await kv.put(storageKey, request.body);
    } catch (err) {
      return new Response(JSON.stringify({ error: `Upload failed: ${err.message}` }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
    // KV doesn't return actual size, trust Content-Length
    uploadedSize = contentLength;
  } else {
    // R2 backend: streaming upload (zero-copy)
    const bucket = env.ATTACHMENTS_BUCKET;
    const putOptions = {};
    const contentType = request.headers.get("Content-Type");
    if (contentType) {
      putOptions.httpMetadata = { contentType };
    }

    let r2Object;
    try {
      r2Object = await bucket.put(storageKey, request.body, putOptions);
    } catch (err) {
      // Try to clean up on failure
      try {
        await bucket.delete(storageKey);
      } catch {
        // Ignore cleanup errors
      }
      return new Response(JSON.stringify({ error: `Upload failed: ${err.message}` }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }

    uploadedSize = r2Object.size;

    // Verify uploaded size matches Content-Length
    if (uploadedSize !== contentLength) {
      try {
        await bucket.delete(storageKey);
      } catch {
        // Ignore cleanup errors
      }
      return new Response(JSON.stringify({ error: "Content-Length does not match uploaded size" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  // Finalize upload: move pending -> attachments and touch revision timestamps
  const now = nowString();
  await db.batch([
    db
      .prepare(
        "INSERT INTO attachments (id, cipher_id, file_name, file_size, akey, created_at, updated_at, organization_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
      )
      .bind(
        attachmentId,
        cipherId,
        pending.file_name,
        uploadedSize,
        pending.akey,
        pending.created_at || now,
        now,
        pending.organization_id || null
      ),
    db.prepare("DELETE FROM attachments_pending WHERE id = ?1").bind(attachmentId),
    db.prepare("UPDATE ciphers SET updated_at = ?1 WHERE id = ?2").bind(now, cipherId),
    db.prepare("UPDATE users SET updated_at = ?1 WHERE id = ?2").bind(now, userId),
  ]);

  return new Response(null, { status: 201 });
}

// Handle download with zero-copy streaming (R2) or ArrayBuffer (KV)
export async function handleDownload(request, env, cipherId, attachmentId, token) {
  // Check storage backend
  const backend = getStorageBackend(env);
  if (!backend) {
    return new Response(JSON.stringify({ error: "Attachments are not enabled" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Get D1 database
  const db = env.vault1;
  if (!db) {
    return new Response(JSON.stringify({ error: "Database not available" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Validate JWT token
  let claims;
  try {
    const secret = env.JWT_SECRET?.toString?.() || env.JWT_SECRET;
    if (!secret) {
      throw new Error("JWT_SECRET not configured");
    }
    claims = await verifyJwt(token, secret);
  } catch (err) {
    return new Response(JSON.stringify({ error: `Invalid token: ${err.message}` }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Validate token claims match the request
  if (claims.cipher_id !== cipherId || claims.attachment_id !== attachmentId) {
    return new Response(JSON.stringify({ error: "Invalid download token" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  const userId = claims.sub;

  // Verify cipher belongs to user
  const cipher = await db
    .prepare("SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2")
    .bind(cipherId, userId)
    .first();

  if (!cipher) {
    return new Response(JSON.stringify({ error: "Cipher not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Fetch attachment record
  const attachment = await db
    .prepare("SELECT * FROM attachments WHERE id = ?1")
    .bind(attachmentId)
    .first();

  if (!attachment) {
    return new Response(JSON.stringify({ error: "Attachment not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (attachment.cipher_id !== cipherId) {
    return new Response(JSON.stringify({ error: "Attachment does not belong to cipher" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Build storage key
  const storageKey = `${cipherId}/${attachmentId}`;

  if (backend === "kv") {
    // KV backend: streaming download
    // Note: KV stream doesn't provide size info, use attachment.file_size from DB
    const kv = env.ATTACHMENTS_KV;
    const stream = await kv.get(storageKey, { type: "stream" });
    if (!stream) {
      return new Response(JSON.stringify({ error: "Attachment not found in storage" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    const headers = new Headers();
    headers.set("Content-Type", "application/octet-stream");
    headers.set("Content-Length", attachment.file_size.toString());

    return new Response(stream, { status: 200, headers });
  } else {
    // R2 backend: streaming download (zero-copy)
    const bucket = env.ATTACHMENTS_BUCKET;
    const r2Object = await bucket.get(storageKey);
    if (!r2Object) {
      return new Response(JSON.stringify({ error: "Attachment not found in storage" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Build response headers
    const headers = new Headers();
    const contentType = r2Object.httpMetadata?.contentType || "application/octet-stream";
    headers.set("Content-Type", contentType);
    headers.set("Content-Length", r2Object.size.toString());

    // Return response with R2 object body directly - zero-copy streaming
    return new Response(r2Object.body, { status: 200, headers });
  }
}
