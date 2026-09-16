/**
 * Cloudflare Worker: שרת גיבוי מוצפן וכספת מרכזית (KV-backed)
 * ==============================================================
 * תואם מלא ל-API של הסקריפט הישן (Google Apps Script):
 *   - get_vault: שליפת כספת מוצפנת לפי אימייל (מאומתת ע"י גיבוב סיסמה)
 *   - save_vault: שמירת כספת מוצפנת בענן (מאומתת ע"י גיבוב סיסמה או טוקן איפוס)
 *   - ping: בדיקת תקינות
 *   - begin_recovery: שליחת קישור שחזור מאובטח במייל (מוגבל קצב)
 *   - recover_vault: שליפת חבילת שחזור מוצפנת עם טוקן ומפתח
 *
 * אבטחה:
 *   - אכיפת אימות מחמירה ללא תלות ב-clientVersion
 *   - הגבלת קצב (Rate Limiting) על שחזור סיסמה וניסיונות אימות שגויים
 *   - ביטול מיידי של קישורי איפוס קודמים
 *   - הגבלת CORS לפי Origin מורשה
 */

const MAX_VAULT_SIZE = 2 * 1024 * 1024;
const MAX_RECOVERY_PACKAGE_SIZE = 4 * 1024 * 1024;
const RESET_TOKEN_TTL_MS = 15 * 60 * 1000;
const AUTH_LOCKOUT_MS = 15 * 60 * 1000;
const MAX_AUTH_FAILURES = 5;
const MAX_RECOVERY_ATTEMPTS = 3;
const WORKER_VERSION = "recovery-relay-get-v4-hardened";
const DEFAULT_LEGACY_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbw8HA3YCdesH9x3xDmE8ybUynTB-9yEYzJ7gCt5rShNmRBJgT29HLvszP0JE1L-5eRqGg/exec";

export default {
  async fetch(request, env) {
    const respond = (data, status = 200) => jsonResponse(data, status, request);

    if (request.method === "OPTIONS") {
      return respond(null, 204);
    }

    try {
      if (!env.VAULT_KV) {
        return respond({
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
        return respond({ success: false, message: "Method not allowed" }, 405);
      }

      if (params === null || typeof params !== "object" || Array.isArray(params)) {
        return respond({ success: false, message: "Invalid JSON body" }, 400);
      }

      if (!isAuthorized(request, params, env)) {
        return respond({ success: false, message: "Unauthorized" }, 401);
      }

      const action = params.action;
      const email = params.email ? params.email.toString().trim().toLowerCase() : "";

      if (!action) {
        return respond({ success: false, message: "Missing action parameter" });
      }

      if (action === "ping") {
        return respond({
          success: true,
          message: "Connection successful! Backup server is alive.",
          version: WORKER_VERSION,
        });
      }

      if (action === "get_vault") {
        if (!isValidEmail(email)) {
          return respond({ success: false, message: "Valid email is required" });
        }

        const stored = await env.VAULT_KV.get(email, "json");
        if (!stored) return respond({ success: true, registered: false });

        // בדיקת נעילה עקב ניסיונות אימות כושלים (Rate Limiting)
        const failKey = "rl:fail:" + email;
        const failRecord = await env.VAULT_KV.get(failKey, "json");
        const now = Date.now();
        if (failRecord && failRecord.lockedUntil && failRecord.lockedUntil > now) {
          return respond({
            success: false,
            message: "יותר מדי ניסיונות אימות שגויים. החשבון נעול זמנית להגנה. אנא נסה שוב בעוד מספר דקות.",
          }, 429);
        }

        const suppliedAuthHash = params.password ? params.password.toString().trim() : "";
        const expectedAuthHash = (stored.secureAuthHash || stored.password || "").toString().trim();

        if (expectedAuthHash) {
          let authValid = constantTimeEquals(suppliedAuthHash, expectedAuthHash);
          if (!authValid && stored.password) {
            const hashedStored = await sha256Base64(stored.password);
            if (constantTimeEquals(suppliedAuthHash, hashedStored)) {
              authValid = true;
            }
          }

          if (!authValid) {
            const currentCount = (failRecord && failRecord.count ? failRecord.count : 0) + 1;
            const lockedUntil = currentCount >= MAX_AUTH_FAILURES ? now + AUTH_LOCKOUT_MS : 0;
            await env.VAULT_KV.put(failKey, JSON.stringify({ count: currentCount, lockedUntil }));
            return respond({ success: false, message: "Unauthorized" }, 401);
          }

          // אימות הצליח - איפוס מונה כישלונות
          if (failRecord) {
            await kvDelete(env.VAULT_KV, failKey);
          }
        }

        return respond({
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
          return respond({
            success: false,
            message: "Email, password and vault are required",
          });
        }
        if (vault.length > MAX_VAULT_SIZE) {
          return respond({ success: false, message: "Vault too large" }, 413);
        }
        if (!isValidVault(vault)) {
          return respond({
            success: false,
            message: "Vault must be a valid JSON object",
          }, 400);
        }
        if (recoveryPackage && !isValidRecoveryPackage(recoveryPackage)) {
          return respond({
            success: false,
            message: "Recovery package is invalid",
          }, 400);
        }
        if (recoveryPackage && JSON.stringify(recoveryPackage).length > MAX_RECOVERY_PACKAGE_SIZE) {
          return respond({ success: false, message: "Recovery package too large" }, 413);
        }

        let resetRecord = null;
        if (resetToken) {
          resetRecord = await getValidResetRecord(env, email, resetToken);
          if (!resetRecord) {
            return respond({ success: false, message: "Reset link is invalid or expired" }, 401);
          }
        }

        const existing = await env.VAULT_KV.get(email, "json");
        const existingAuthHash = existing ? (existing.secureAuthHash || existing.password || "").toString().trim() : "";

        // קישור איפוס תקף מאשר כתיבה גם כשגיבוב הסיסמה החדש שונה.
        // אחרת - אם כבר קיימת כספת עם סיסמה/גיבוב, חובה לאמת.
        if (!resetRecord && existing && existingAuthHash) {
          // פרמטר authHash (או oldPassword) מאפשר שינוי סיסמה עבור משתמש מחובר
          const suppliedAuth = (params.authHash || params.oldPassword || password).toString().trim();
          let authValid = constantTimeEquals(suppliedAuth, existingAuthHash);
          if (!authValid && existing.password) {
            const hashedExisting = await sha256Base64(existing.password);
            if (constantTimeEquals(suppliedAuth, hashedExisting)) {
              authValid = true;
            }
          }

          if (!authValid) {
            return respond({ success: false, message: "Unauthorized" }, 401);
          }
        }

        const now = new Date().toISOString();
        const stored = {
          password,
          vault,
          updatedAt: now,
          recoveryKey: recoveryKey || (existing && existing.recoveryKey) || "",
          recoveryPackage: recoveryPackage || (existing && existing.recoveryPackage) || null,
          secureAuthHash: password,
        };

        await env.VAULT_KV.put(email, JSON.stringify(stored));
        if (resetRecord) {
          await kvDelete(env.VAULT_KV, resetRecord.storageKey);
          await kvDelete(env.VAULT_KV, "last_reset:" + email);
        }

        // ניקוי מנעול שגיאות אימות אם היה קיים
        await kvDelete(env.VAULT_KV, "rl:fail:" + email);

        return respond({
          success: true,
          message: "הכספת סונכרנה בהצלחה בענן!",
          updatedAt: now,
        });
      }

      if (action === "begin_recovery") {
        if (!isValidEmail(email)) {
          return respond({ success: false, message: "Valid email is required" }, 400);
        }
        if (!env.LEGACY_SCRIPT_URL || !env.RECOVERY_RELAY_KEY) {
          return respond({
            success: false,
            message: "Recovery email relay is not configured",
          }, 503);
        }

        // הגבלת קצב: עד 3 בקשות שחזור ב-15 דקות לכתובת אימייל
        const rlKey = "rl:rec:" + email;
        const rlData = await env.VAULT_KV.get(rlKey, "json");
        const now = Date.now();
        if (rlData && rlData.resetAt > now) {
          if (rlData.count >= MAX_RECOVERY_ATTEMPTS) {
            return respond({
              success: false,
              message: "חרגת ממספר בקשות השחזור המותרות. אנא נסה שוב בעוד מספר דקות.",
            }, 429);
          }
          await env.VAULT_KV.put(rlKey, JSON.stringify({ count: rlData.count + 1, resetAt: rlData.resetAt }));
        } else {
          await env.VAULT_KV.put(rlKey, JSON.stringify({ count: 1, resetAt: now + RESET_TOKEN_TTL_MS }));
        }

        const stored = await env.VAULT_KV.get(email, "json");
        // Do not reveal whether an email is registered or has recovery material.
        if (!stored || !stored.recoveryKey || !stored.recoveryPackage) {
          return respond({
            success: true,
            message: "אם הכתובת קיימת, נשלח אליה קישור שחזור.",
          });
        }

        // ביטול קישורי שחזור פעילים קודמים לאותו אימייל
        const lastResetKey = await env.VAULT_KV.get("last_reset:" + email);
        if (lastResetKey) {
          await kvDelete(env.VAULT_KV, lastResetKey);
        }

        const token = randomToken();
        const storageKey = "reset:" + await sha256Hex(token);
        const expiresAt = now + RESET_TOKEN_TTL_MS;
        await env.VAULT_KV.put(storageKey, JSON.stringify({ email, expiresAt }));
        await env.VAULT_KV.put("last_reset:" + email, storageKey);

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
          await kvDelete(env.VAULT_KV, storageKey);
          return respond({
            success: false,
            message: relayResult && relayResult.message
              ? relayResult.message
              : relayError && relayError.message
                ? relayError.message
                : "Unable to send recovery email",
          }, 502);
        }

        return respond({
          success: true,
          message: "אם הכתובת קיימת, נשלח אליה קישור שחזור.",
        });
      }

      if (action === "recover_vault") {
        if (!isValidEmail(email) || !params.token || !params.recoveryKey) {
          return respond({ success: false, message: "Email, token and recovery key are required" }, 400);
        }

        const resetRecord = await getValidResetRecord(env, email, params.token.toString());
        if (!resetRecord) {
          return respond({ success: false, message: "Reset link is invalid or expired" }, 401);
        }

        const stored = await env.VAULT_KV.get(email, "json");
        if (!stored || !stored.recoveryKey || !constantTimeEquals(
          stored.recoveryKey,
          params.recoveryKey.toString().trim()
        )) {
          return respond({ success: false, message: "Recovery key is invalid" }, 401);
        }

        return respond({
          success: true,
          recoveryPackage: stored.recoveryPackage,
        });
      }

      return respond({ success: false, message: "Unknown action: " + action });
    } catch (error) {
      console.error("Worker error:", error);
      return respond({
        success: false,
        message: "Internal server error",
      }, 500);
    }
  },
};


async function kvDelete(kv, key) {
  if (kv && typeof kv.delete === "function") {
    try {
      await kv.delete(key);
    } catch {}
  }
}

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
    if (record) await kvDelete(env.VAULT_KV, storageKey);
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

async function sha256Base64(value) {
  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  const arr = Array.from(new Uint8Array(hash));
  let binary = "";
  for (const b of arr) binary += String.fromCharCode(b);
  return btoa(binary);
}

function constantTimeEquals(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function jsonResponse(data, status = 200, request = null) {
  const origin = request && request.headers ? request.headers.get("Origin") : null;
  const allowedOrigins = [
    "https://lev-good.github.io",
    "http://localhost",
    "http://127.0.0.1",
  ];
  let allowOrigin = "*";
  if (origin) {
    const isAllowed = allowedOrigins.some((ao) => origin === ao || origin.startsWith(ao + ":"));
    allowOrigin = isAllowed ? origin : "https://lev-good.github.io";
  }

  return new Response(data === null ? null : JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": allowOrigin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Vary": "Origin",
    },
  });
}
