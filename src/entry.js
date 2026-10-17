/**
 * JS Wrapper Entry Point for Warden Worker
 *
 * This wrapper handles WebSocket notification routing and optionally offloads CPU-heavy
 * endpoints to a Rust Durable Object (higher CPU budget).
 *
 * All other requests are passed through to the Rust WASM module.
 */

import RustWorker from "../build/index.js";

function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
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

function decodeJwtPayloadUnsafe(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return null;
    }
    return JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1])));
  } catch {
    return null;
  }
}

function getBearerToken(request) {
  const auth = request.headers.get("Authorization") || request.headers.get("authorization");
  if (!auth) return null;
  const m = auth.match(/^\s*Bearer\s+(.+?)\s*$/i);
  return m ? m[1] : null;
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

  // Registration endpoints are not JWT-authenticated; request body uses `email` as username.
  if (
    pathname === "/identity/accounts/register" ||
    pathname === "/identity/accounts/register/finish"
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

  // Security stamp rotation requires password verification
  ["/api/accounts/security-stamp", new Set(["POST"])],

  // Key rotation needs verify master password and update entire vault
  ["/api/accounts/key-management/rotate-user-account-keys", new Set(["POST"])],

  // Two-factor
  ["/api/two-factor/get-authenticator", new Set(["POST"])],
  ["/api/two-factor/authenticator", new Set(["POST", "PUT", "DELETE"])],
  ["/api/two-factor/disable", new Set(["POST", "PUT"])],
  ["/api/two-factor/get-recover", new Set(["POST"])],
]);

function shouldOffloadToHeavyDo(request, url) {
  const methods = HEAVY_DO_ROUTE_METHODS.get(url.pathname);
  if (!methods) return false;
  const method = (request.method || "GET").toUpperCase();
  return methods.has(method);
}

function escapeHtml(str) {
  return String(str).replace(/[&<>'"]/g, (tag) =>
    ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "'": "&#39;",
      '"': "&quot;",
    }[tag] || tag)
  );
}

function formatSenderAddress(email, name) {
  if (!email) return null;
  const trimmedEmail = email.trim();
  if (trimmedEmail.includes("<") && trimmedEmail.includes(">")) {
    return trimmedEmail;
  }
  const fromName = name?.trim() || "Vaultwarden";
  return `${fromName} <${trimmedEmail}>`;
}

async function handlePasswordHint(request, env, ctx) {
  const clonedRequest = request.clone();
  const worker = new RustWorker(ctx, env);
  const res = await worker.fetch(request);

  const resendApiKey = env.RESEND_API_KEY;
  const mailFrom = env.MAIL_FROM;

  // Optional: only send email if RESEND_API_KEY and MAIL_FROM are configured
  if (!resendApiKey || !mailFrom) {
    return res;
  }

  // If rate limit exceeded or server error, return original response
  if (res.status !== 400) {
    return res;
  }

  try {
    const data = await res.clone().json();
    const msg = data?.error || data?.message || "";
    const prefix = "Your password hint is: ";

    if (msg.startsWith(prefix)) {
      const hint = msg.slice(prefix.length).trim();
      let reqBody = null;
      try {
        reqBody = await clonedRequest.json();
      } catch {}
      const recipientEmail = reqBody?.email;

      if (recipientEmail && hint) {
        const sender = formatSenderAddress(mailFrom, env.MAIL_FROM_NAME);
        const emailPayload = {
          from: sender,
          to: [recipientEmail],
          subject: "Your Bitwarden Master Password Hint",
          text: `You (or someone) requested the master password hint for your account.\n\nYour master password hint is:\n${hint}\n\nIf you did not request this hint, you can safely ignore this email.`,
          html: `<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 24px; border: 1px solid #e1e4e8; border-radius: 8px;">
  <h2 style="color: #175ddc; margin-top: 0;">Master Password Hint</h2>
  <p style="color: #333; font-size: 14px; line-height: 1.5;">You (or someone) requested the master password hint for your vault account.</p>
  <div style="background-color: #f6f8fa; border: 1px solid #d1d5da; border-radius: 6px; padding: 12px 16px; margin: 18px 0; font-family: monospace; font-size: 16px; color: #24292e; word-break: break-all;">
    ${escapeHtml(hint)}
  </div>
  <p style="color: #586069; font-size: 12px; margin-top: 24px; border-top: 1px solid #eaecef; padding-top: 12px;">If you did not request this hint, you can safely ignore this email.</p>
</div>`,
        };

        const resendRes = await fetch("https://api.resend.com/emails", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${resendApiKey}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(emailPayload),
        });

        if (resendRes.ok) {
          return new Response(JSON.stringify({}), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        } else {
          const errText = await resendRes.text();
          console.error("Resend API error:", resendRes.status, errText);
          return res;
        }
      }
    } else if (msg === "Sorry, you have no password hint...") {
      return new Response(JSON.stringify({}), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
  } catch (err) {
    console.error("handlePasswordHint error:", err);
  }

  return res;
}

// Main fetch handler
export default {
  async fetch(request, env, ctx) {
    // Normalize pathname to avoid trailing slashes
    const url = new URL(request.url);
    url.pathname = normalizePathname(url.pathname);
    request = new Request(url.toString(), request);
    const method = (request.method || "GET").toUpperCase();

    if (url.pathname === "/api/accounts/password-hint" && method === "POST") {
      return handlePasswordHint(request, env, ctx);
    }

    if (
      env.NOTIFY_DO &&
      method === "GET" &&
      (url.pathname === "/notifications/hub" || url.pathname === "/notifications/anonymous-hub")
    ) {
      const id = env.NOTIFY_DO.idFromName("global");
      const stub = env.NOTIFY_DO.get(id);
      return stub.fetch(request);
    }

    // Optional: route selected CPU-heavy endpoints to Durable Objects.
    // This keeps the main Worker on a low-CPU path while allowing heavy work to complete.
    if (env.HEAVY_DO) {
      // Token endpoint:
      // - plain password grant is CPU-heavy (password verification / KDF migration) => offload
      // - authrequest password grant skips master-password verification => keep in Worker/WASM
      // - refresh_token grant is lightweight (JWT HS256 verify) => keep in Worker/WASM
      if (url.pathname === "/identity/connect/token" && method === "POST") {
        const body = await request.clone().text();
        const params = new URLSearchParams(body);
        const grantType = params.get("grant_type");
        const authRequest =
          params.get("authrequest") ||
          params.get("authRequest");

        if (grantType === "password" && !authRequest) {
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

    // Pass all other requests to Rust WASM (streaming routes are intercepted in Rust)
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
export { HeavyDo, NotifyDo } from "../build/index.js";
