/**
 * JS Wrapper Entry Point for Warden Worker
 *
 * This wrapper intercepts attachment upload and download requests for zero-copy streaming
 * to/from R2. Workers R2 binding can accept request.body directly for uploads,
 * and r2Object.body can be passed directly to Response for downloads.
 * See: https://blog.cloudflare.com/zh-cn/r2-ga/
 *
 * This avoids CPU time consumption that would occur if the body went through
 * the Rust/WASM layer with axum body conversion.
 *
 * Additionally, this wrapper can optionally offload CPU-heavy endpoints to a Rust Durable Object
 * (higher CPU budget) by binding `HEAVY_DO` in `wrangler.toml`.
 * This is used for operations like imports and password verification paths, keeping the main
 * Worker on a low-CPU fast path for typical requests.
 *
 * All other requests are passed through to the Rust WASM module.
 */

import RustWorker from "../build/index.js";
import { base64UrlDecode, handleAzureUpload, handleDownload } from "./attachments.js";

function getBearerToken(request) {
  const auth = request.headers.get("Authorization") || request.headers.get("authorization");
  if (!auth) return null;
  const m = auth.match(/^\s*Bearer\s+(.+?)\s*$/i);
  return m ? m[1] : null;
}

// Decode JWT payload WITHOUT verifying signature (used only for sharding DO instances).
// The Durable Object handler will perform full verification and reject invalid tokens.
function decodeJwtPayloadUnsafe(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const payloadB64 = parts[1];
    const payloadJson = new TextDecoder().decode(base64UrlDecode(payloadB64));
    return JSON.parse(payloadJson);
  } catch {
    return null;
  }
}

function normalizeUsername(username) {
  if (typeof username !== "string") return null;
  const v = username.trim().toLowerCase();
  return v ? v : null;
}

function normalizePathname(pathname) {
  if (typeof pathname !== "string") return "/";
  // Keep "/" unchanged; otherwise remove one or more trailing slashes.
  if (pathname === "/") return "/";
  return pathname.replace(/\/+$/, "");
}

async function getHeavyDoShardKey(request, url) {
  const pathname = url.pathname;

  // Registration endpoints and 2FA recovery are not JWT-authenticated; request body uses `email` as username.
  if (
    pathname === "/identity/accounts/register" ||
    pathname === "/identity/accounts/register/finish" ||
    pathname === "/api/two-factor/recover"
  ) {
    try {
      const body = await request.clone().json();
      const normalized = normalizeUsername(body?.email);
      return normalized ? normalized : null;
    } catch {
      return null;
    }
  }

  // Default: shard by user id (JWT sub).
  const token = getBearerToken(request);
  const sub = token ? decodeJwtPayloadUnsafe(token)?.sub : null;
  if (typeof sub === "string" && sub) return sub;

  return null;
}

// All routes offloaded to HEAVY_DO (centralized, aligned with src/router.rs).
// Keyed by path, with allowed methods to avoid accidental over-routing.
const HEAVY_DO_ROUTE_METHODS = new Map([
  // Import
  ["/api/ciphers/import", new Set(["POST"])],

  // Identity/Auth (password hashing / verification)
  ["/identity/accounts/register", new Set(["POST"])],
  ["/identity/accounts/register/finish", new Set(["POST"])],

  // Password/KDF changes
  ["/api/accounts/password", new Set(["POST"])],
  ["/api/accounts/kdf", new Set(["POST"])],

  // Dangerous ops requiring password verification
  ["/api/accounts/delete", new Set(["POST"])],
  ["/api/accounts", new Set(["DELETE"])],
  ["/api/ciphers/purge", new Set(["POST"])],

  // Key rotation needs verify master password and update entire vault
  ["/api/accounts/key-management/rotate-user-account-keys", new Set(["POST"])],

  // Two-factor
  ["/api/two-factor/get-authenticator", new Set(["POST"])],
  ["/api/two-factor/authenticator", new Set(["POST", "PUT", "DELETE"])],
  ["/api/two-factor/disable", new Set(["POST", "PUT"])],
  ["/api/two-factor/get-recover", new Set(["POST"])],
  ["/api/two-factor/recover", new Set(["POST"])],
]);

function shouldOffloadToHeavyDo(request, url) {
  const methods = HEAVY_DO_ROUTE_METHODS.get(url.pathname);
  if (!methods) return false;
  const method = (request.method || "GET").toUpperCase();
  return methods.has(method);
}

// Parse azure-upload route: /api/ciphers/{id}/attachment/{attachment_id}/azure-upload
function parseAzureUploadPath(path) {
  const parts = path.replace(/^\//, "").split("/");
  // Expected: ["api", "ciphers", "{cipher_id}", "attachment", "{attachment_id}", "azure-upload"]
  if (
    parts.length === 6 &&
    parts[0] === "api" &&
    parts[1] === "ciphers" &&
    parts[3] === "attachment" &&
    parts[5] === "azure-upload"
  ) {
    return { cipherId: parts[2], attachmentId: parts[4] };
  }
  return null;
}

// Parse download route: /api/ciphers/{id}/attachment/{attachment_id}/download
function parseDownloadPath(path) {
  const parts = path.replace(/^\//, "").split("/");
  // Expected: ["api", "ciphers", "{cipher_id}", "attachment", "{attachment_id}", "download"]
  if (
    parts.length === 6 &&
    parts[0] === "api" &&
    parts[1] === "ciphers" &&
    parts[3] === "attachment" &&
    parts[5] === "download"
  ) {
    return { cipherId: parts[2], attachmentId: parts[4] };
  }
  return null;
}

// Main fetch handler
export default {
  async fetch(request, env, ctx) {
    // Normalize pathname to avoid trailing slashes
    const url = new URL(request.url);
    url.pathname = normalizePathname(url.pathname);
    request = new Request(url.toString(), request);
    const method = (request.method || "GET").toUpperCase();

    // Optional: route selected CPU-heavy endpoints to Durable Objects.
    // This keeps the main Worker on a low-CPU path while allowing heavy work to complete.
    if (env.HEAVY_DO) {
      // Token endpoint:
      // - password grant is CPU-heavy (password verification) => offload
      // - refresh_token grant is lightweight (JWT HS256 verify) => keep in Worker/WASM
      if (url.pathname === "/identity/connect/token" && method === "POST") {
        const body = await request.clone().text();
        const params = new URLSearchParams(body);
        const grantType = params.get("grant_type");
        if (grantType !== "refresh_token") {
          const shardKey = normalizeUsername(params.get("username"));
          const name = shardKey ? `user:${shardKey}` : "user:default";
          const id = env.HEAVY_DO.idFromName(name);
          const stub = env.HEAVY_DO.get(id);
          return stub.fetch(request, { body });
        }
      } else if (shouldOffloadToHeavyDo(request, url)) {
        const shardKey = await getHeavyDoShardKey(request, url);
        const name = shardKey ? `user:${shardKey}` : "user:default";
        const id = env.HEAVY_DO.idFromName(name);
        const stub = env.HEAVY_DO.get(id);
        return stub.fetch(request);
      }
    }

    // Attachment upload/download fast-path (R2 zero-copy streaming + JWT validation)
    if (method === "PUT") {
      const parsed = parseAzureUploadPath(url.pathname);
      if (parsed) {
        const token = url.searchParams.get("token");
        if (!token) {
          return new Response(
            JSON.stringify({ error: "Missing upload token" }), 
            { status: 401, headers: { "Content-Type": "application/json" } }
          );
        }
        return handleAzureUpload(
          request,
          env,
          parsed.cipherId,
          parsed.attachmentId,
          token
        );
      }
    } else if (method === "GET") {
      const parsed = parseDownloadPath(url.pathname);
      if (parsed) {
        const token = url.searchParams.get("token");
        if (!token) {
          return new Response(
            JSON.stringify({ error: "Missing download token" }),
            { status: 401, headers: { "Content-Type": "application/json" } }
          );
        }
        return handleDownload(
          request,
          env,
          parsed.cipherId,
          parsed.attachmentId,
          token
        );
      }
    }

    // Pass all other requests to Rust WASM
    const worker = new RustWorker(ctx, env);
    return worker.fetch(request);
  },

  async scheduled(event, env, ctx) {
    // Pass scheduled events to Rust WASM
    const worker = new RustWorker(ctx, env);
    return worker.scheduled(event);
  },
};

// Re-export Rust Durable Object class implemented in WASM.
// wrangler.toml binds HEAVY_DO -> class_name = "HeavyDo".
export { HeavyDo } from "../build/index.js";
