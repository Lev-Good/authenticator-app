/**
 * Master Authenticator - Cloudflare Worker Backup Server
 * ======================================================
 * שומר כספות מוצפנות ב-Cloudflare KV.
 *
 * פעולות:
 *   GET  ?action=ping
 *   POST { action: "get_vault", email }
 *   POST { action: "save_vault", email, password, vault, recoveryKey?, recoveryPackage?, resetToken? }
 *   POST { action: "begin_recovery", email }
 *   POST { action: "recover_vault", email, token, recoveryKey }
 *
 * recoveryKey אינו נשמר בתוך הכספת המוצפנת. הוא נשמר ב-KV לצורך שליחתו
 * במייל האיפוס דרך Apps Script. המשתמש לעולם אינו שולח את סיסמת המאסטר הישנה.
 */

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

const MAX_VAULT_SIZE = 2 * 1024 * 1024;
const MAX_RECOVERY_PACKAGE_SIZE = 4 * 1024 * 1024;
const RESET_TOKEN_TTL_MS = 15 * 60 * 1000;
const WORKER_VERSION = "recovery-relay-get-v3";
const DEFAULT_LEGACY_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbw8HA3YCdesH9x3xDmE8ybUynTB-9yEYzJ7gCt5rShNmRBJgT29HLvszP0JE1L-5eRqGg/exec";

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return jsonResponse(null, 204);
    }

    try {
      if (!env.VAULT_KV) {
        return jsonResponse({
          success: false,
          message: "Server misconfigured: KV binding (VAULT_KV) is missing",
        }, 500);
      }

      /** @type {Record<string, any>} */
      let params = {};
      if (request.method === "POST") {
        const text = await request.text();
        try {
          params = JSON.parse(text);
        } catch {
          params = {};
        }
      } else if (request.method === "GET") {
        const url = new URL(request.url);
        for (const [key, value] of url.searchParams) params[key] = value;
      } else {
        return jsonResponse({ success: false, message: "Method not allowed" }, 405);
      }

      if (params === null || typeof params !== "object" || Array.isArray(params)) {
        return jsonResponse({ success: false, message: "Invalid JSON body" }, 400);
      }

      if (!isAuthorized(request, params, env)) {
        return jsonResponse({ success: false, message: "Unauthorized" }, 401);
      }

      const action = params.action;
      const email = params.email ? params.email.toString().trim().toLowerCase() : "";

      if (!action) {
        return jsonResponse({ success: false, message: "Missing action parameter" });
      }

      if (action === "ping") {
        return jsonResponse({
          success: true,
          message: "Connection successful! Backup server is alive.",
          version: WORKER_VERSION,
        });
      }

      if (action === "get_vault") {
        if (!isValidEmail(email)) {
          return jsonResponse({ success: false, message: "Valid email is required" });
        }

        const stored = await env.VAULT_KV.get(email, "json");
        if (!stored) return jsonResponse({ success: true, registered: false });

        const secureClient = params.clientVersion === "secure-v1";
        const suppliedAuthHash = params.password ? params.password.toString().trim() : "";
        if (secureClient && stored.secureAuthHash && !constantTimeEquals(suppliedAuthHash, stored.secureAuthHash)) {
          return jsonResponse({ success: false, message: "Unauthorized" }, 401);
        }

        return jsonResponse({
          success: true,
          registered: true,
          vault: stored.vault ? stored.vault.toString() : "",
          updatedAt: stored.updatedAt || undefined,
        });
      }

      if (action === "save_vault") {
        const password = params.password ? params.password.toString().trim() : "";
        const vault = params.vault ? params.vault.toString().trim() : "";
        const recoveryKey = params.recoveryKey ? params.recoveryKey.toString().trim() : "";
        const recoveryPackage = params.recoveryPackage || null;
        const resetToken = params.resetToken ? params.resetToken.toString().trim() : "";

        if (!isValidEmail(email) || !password || !vault) {
          return jsonResponse({
            success: false,
            message: "Email, password and vault are required",
          });
        }
        if (vault.length > MAX_VAULT_SIZE) {
          return jsonResponse({ success: false, message: "Vault too large" }, 413);
        }
        if (!isValidVault(vault)) {
          return jsonResponse({
            success: false,
            message: "Vault must be a valid JSON object",
          }, 400);
        }
        if (recoveryPackage && !isValidRecoveryPackage(recoveryPackage)) {
          return jsonResponse({
            success: false,
            message: "Recovery package is invalid",
          }, 400);
        }
        if (recoveryPackage && JSON.stringify(recoveryPackage).length > MAX_RECOVERY_PACKAGE_SIZE) {
          return jsonResponse({ success: false, message: "Recovery package too large" }, 413);
        }

        let resetRecord = null;
        if (resetToken) {
          resetRecord = await getValidResetRecord(env, email, resetToken);
          if (!resetRecord) {
            return jsonResponse({ success: false, message: "Reset link is invalid or expired" }, 401);
          }
        }

        const existing = await env.VAULT_KV.get(email, "json");
        const secureClient = params.clientVersion === "secure-v1";
        // קישור איפוס תקף מאשר את הכתיבה גם כשגיבוב הסיסמה החדש שונה
        // מהגיבוב השמור; אחרת נאכוף את גיבוב האימות.
        if (secureClient && !resetRecord && existing && existing.secureAuthHash && !constantTimeEquals(password, existing.secureAuthHash)) {
          return jsonResponse({ success: false, message: "Unauthorized" }, 401);
        }

        const now = new Date().toISOString();
        const stored = {
          password,
          vault,
          updatedAt: now,
          // Older clients do not send recovery data; preserve existing data.
          recoveryKey: recoveryKey || (existing && existing.recoveryKey) || "",
          recoveryPackage: recoveryPackage || (existing && existing.recoveryPackage) || null,
          // New clients authenticate writes with the password hash; legacy clients remain compatible.
          secureAuthHash: secureClient ? password : (existing && existing.secureAuthHash) || "",
        };

        await env.VAULT_KV.put(email, JSON.stringify(stored));
        if (resetRecord) {
          await env.VAULT_KV.delete(resetRecord.storageKey);
        }

        return jsonResponse({
          success: true,
          message: "הכספת סונכרנה בהצלחה בענן!",
          updatedAt: now,
        });
      }

      if (action === "begin_recovery") {
        if (!isValidEmail(email)) {
          return jsonResponse({ success: false, message: "Valid email is required" }, 400);
        }
        if (!env.LEGACY_SCRIPT_URL || !env.RECOVERY_RELAY_KEY) {
          return jsonResponse({
            success: false,
            message: "Recovery email relay is not configured",
          }, 503);
        }

        const stored = await env.VAULT_KV.get(email, "json");
        // Do not reveal whether an email is registered or has recovery material.
        if (!stored || !stored.recoveryKey || !stored.recoveryPackage) {
          return jsonResponse({
            success: true,
            message: "אם הכתובת קיימת, נשלח אליה קישור שחזור.",
          });
        }

        const token = randomToken();
        const storageKey = "reset:" + await sha256Hex(token);
        const expiresAt = Date.now() + RESET_TOKEN_TTL_MS;
        await env.VAULT_KV.put(storageKey, JSON.stringify({ email, expiresAt }));

        const resetBase = env.RESET_BASE_URL || "https://lev-good.github.io/authenticator-app/";
        const resetUrl = new URL(resetBase);
        resetUrl.searchParams.set("reset", token);
        resetUrl.searchParams.set("email", email);

        const relayPayload = {
          action: "send_reset_link",
          email,
          reset_url: resetUrl.toString(),
          recovery_key: stored.recoveryKey,
          relay_key: env.RECOVERY_RELAY_KEY,
        };
        const relayUrls = [...new Set([
          env.LEGACY_SCRIPT_URL,
          DEFAULT_LEGACY_SCRIPT_URL,
        ].filter(Boolean).map(String))];
        let relayResponse = null;
        let relayResult = null;
        let relayError = null;

        for (const relayTarget of relayUrls) {
          try {
            // Apps Script redirects POST requests to script.googleusercontent.com.
            // Use its GET API directly so the action survives that redirect.
            const relayUrl = new URL(relayTarget);
            const relayMethod = relayUrl.hostname === "script.google.com" ? "GET" : "POST";
            const candidateResponse = await fetchRelay(relayUrl.toString(), relayPayload, 5, relayMethod);
            let candidateResult = null;
            try {
              candidateResult = await candidateResponse.json();
            } catch {
              candidateResult = null;
            }

            relayResponse = candidateResponse;
            relayResult = candidateResult;
            relayError = null;
            if (candidateResponse.ok && candidateResult && candidateResult.success === true) break;

            // Retry only when the configured deployment is an older script that
            // does not know the relay action. Do not duplicate real mail failures.
            const unsupportedAction = candidateResult && (
              candidateResult.message === "Unknown action: send_reset_link" ||
              candidateResult.message === "Missing action parameter"
            );
            if (!unsupportedAction) break;
          } catch (error) {
            relayError = error;
          }
        }

        if (!relayResponse || !relayResponse.ok || !relayResult || relayResult.success !== true) {
          await env.VAULT_KV.delete(storageKey);
          return jsonResponse({
            success: false,
            message: relayResult && relayResult.message
              ? relayResult.message
              : relayError && relayError.message
                ? relayError.message
                : "Unable to send recovery email",
          }, 502);
        }

        return jsonResponse({
          success: true,
          message: "אם הכתובת קיימת, נשלח אליה קישור שחזור.",
        });
      }

      if (action === "recover_vault") {
        if (!isValidEmail(email) || !params.token || !params.recoveryKey) {
          return jsonResponse({ success: false, message: "Email, token and recovery key are required" }, 400);
        }

        const resetRecord = await getValidResetRecord(env, email, params.token.toString());
        if (!resetRecord) {
          return jsonResponse({ success: false, message: "Reset link is invalid or expired" }, 401);
        }

        const stored = await env.VAULT_KV.get(email, "json");
        if (!stored || !stored.recoveryKey || !constantTimeEquals(
          stored.recoveryKey,
          params.recoveryKey.toString().trim()
        )) {
          return jsonResponse({ success: false, message: "Recovery key is invalid" }, 401);
        }

        return jsonResponse({
          success: true,
          recoveryPackage: stored.recoveryPackage,
        });
      }

      return jsonResponse({ success: false, message: "Unknown action: " + action });
    } catch (error) {
      return jsonResponse({
        success: false,
        message: "Server error: " + error.toString(),
      }, 500);
    }
  },
};

async function fetchRelay(url, payload, redirectsLeft = 5, method = "POST") {
  const requestUrl = new URL(url);
  const init = {
    method,
    redirect: "manual",
  };
  if (method === "POST") {
    init.headers = { "Content-Type": "application/json" };
    init.body = JSON.stringify(payload);
  } else if (method === "GET") {
    for (const [key, value] of Object.entries(payload)) {
      requestUrl.searchParams.set(key, String(value));
    }
  }

  const response = await fetch(requestUrl, init);
  if (response.status < 300 || response.status >= 400) return response;

  const location = response.headers.get("Location");
  if (!location || redirectsLeft <= 0) {
    throw new Error("Recovery relay redirect could not be followed");
  }

  const nextUrl = new URL(location, requestUrl);
  const isAppsScriptRedirect =
    requestUrl.hostname === "script.google.com" &&
    nextUrl.hostname === "script.googleusercontent.com";

  if (isAppsScriptRedirect) {
    for (const [key, value] of Object.entries(payload)) {
      nextUrl.searchParams.set(key, String(value));
    }
    return fetchRelay(nextUrl.toString(), payload, redirectsLeft - 1, "GET");
  }

  return fetchRelay(nextUrl.toString(), payload, redirectsLeft - 1, method);
}

function isAuthorized(request, params, env) {
  const configured = env.API_TOKEN && String(env.API_TOKEN).length > 0;
  if (!configured) return true;

  const authHeader = request.headers.get("Authorization") || "";
  const headerToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  const provided = headerToken || (typeof params.token === "string" ? params.token : "");
  return constantTimeEquals(provided, String(env.API_TOKEN));
}

function isValidEmail(email) {
  return typeof email === "string" && email.length > 3 && email.length <= 254 && email.includes("@");
}

function isValidVault(vault) {
  try {
    const parsed = JSON.parse(vault);
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed);
  } catch {
    return false;
  }
}

function isValidRecoveryPackage(value) {
  return Boolean(
    value &&
    typeof value === "object" &&
    typeof value.ciphertext === "string" &&
    typeof value.iv === "string" &&
    typeof value.tag === "string"
  );
}

async function getValidResetRecord(env, email, token) {
  if (!token || typeof token !== "string" || token.length < 20) return null;
  const storageKey = "reset:" + await sha256Hex(token);
  const record = await env.VAULT_KV.get(storageKey, "json");
  if (!record || record.email !== email || !record.expiresAt || Date.now() > record.expiresAt) {
    if (record) await env.VAULT_KV.delete(storageKey);
    return null;
  }
  return { ...record, storageKey };
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToBase64Url(bytes);
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function constantTimeEquals(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function jsonResponse(data, status = 200) {
  return new Response(data === null ? null : JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "no-store",
      ...CORS_HEADERS,
    },
  });
}
