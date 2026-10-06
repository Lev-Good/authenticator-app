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
          try {
            const sp = new URLSearchParams(text);
            for (const [k, v] of sp) params[k] = v;
          } catch {}
        }
      } else if (request.method === "GET") {
        const url = new URL(request.url);
        for (const [key, value] of url.searchParams) params[key] = value;
      } else {
        return jsonResponse({ success: false, message: "Method not allowed" }, 405);
      }

      const reqUrl = new URL(request.url);
      for (const [key, value] of reqUrl.searchParams) {
        if (!params[key]) params[key] = value;
      }

      const action = params.action;
      const isYemotCall = request.url.includes("/yemot") || action === "yemot" || Boolean(params.ApiPhone || params.ApiCallId);
      if (isYemotCall) {
        return handleYemotCall(params, env);
      }

      if (params === null || typeof params !== "object" || Array.isArray(params)) {
        return jsonResponse({ success: false, message: "Invalid JSON body" }, 400);
      }

      if (!isAuthorized(request, params, env)) {
        return jsonResponse({ success: false, message: "Unauthorized" }, 401);
      }

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

      if (action === "save_phone_access") {
        return handleSavePhoneAccess(params, env);
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

function yemotTextResponse(text) {
  return new Response(text, {
    status: 200,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function normalizePhone(p) {
  if (!p) return "";
  let clean = p.toString().replace(/\D/g, "");
  if (clean.startsWith("972")) clean = "0" + clean.slice(3);
  return clean;
}

// ----------------------------------------------------
// שמירת הגדרות גישה טלפונית מהאתר (save_phone_access)
// ----------------------------------------------------
async function handleSavePhoneAccess(params, env) {
  const email = params.email ? params.email.toString().trim().toLowerCase() : "";
  const password = params.password ? params.password.toString().trim() : "";
  const phoneSettings = params.phoneSettings;

  if (!isValidEmail(email) || !password || !phoneSettings) {
    return jsonResponse({ success: false, message: "נתונים חסרים לשמירת הגדרות טלפון" }, 400);
  }

  // אימות מול הכספת בענן
  const stored = await env.VAULT_KV.get(email, "json");
  if (!stored) {
    return jsonResponse({ success: false, message: "המשתמש אינו רשום" }, 404);
  }
  if (stored.secureAuthHash && !constantTimeEquals(password, stored.secureAuthHash)) {
    return jsonResponse({ success: false, message: "אימות נכשל: סיסמה שגויה" }, 401);
  }

  // ניקוי רישומי טלפון ישנים אם הוגדרו
  const oldMeta = await env.VAULT_KV.get("phone_meta:" + email, "json");
  if (oldMeta && Array.isArray(oldMeta.phones)) {
    for (const ph of oldMeta.phones) {
      await env.VAULT_KV.delete("phone:" + ph);
    }
  }

  if (phoneSettings.enabled === false) {
    await env.VAULT_KV.delete("phone_meta:" + email);
    return jsonResponse({ success: true, message: "גישה טלפונית בוטלה בהצלחה" });
  }

  const rawPhones = Array.isArray(phoneSettings.authorizedPhones) ? phoneSettings.authorizedPhones : [];
  const normalizedPhones = rawPhones.map(normalizePhone).filter(p => p.length >= 9);

  if (normalizedPhones.length === 0) {
    return jsonResponse({ success: false, message: "חובה להזין לפחות מספר טלפון מורשה אחד" }, 400);
  }

  const phoneRecord = {
    email: email,
    pinHash: phoneSettings.pinHash || "",
    pinSalt: phoneSettings.pinSalt || "",
    accounts: Array.isArray(phoneSettings.accounts) ? phoneSettings.accounts : [],
    updatedAt: new Date().toISOString(),
  };

  const recordStr = JSON.stringify(phoneRecord);
  for (const ph of normalizedPhones) {
    await env.VAULT_KV.put("phone:" + ph, recordStr);
  }

  await env.VAULT_KV.put("phone_meta:" + email, JSON.stringify({
    phones: normalizedPhones,
    updatedAt: new Date().toISOString(),
  }));

  return jsonResponse({
    success: true,
    message: "הגדרות קו טלפון נשמרו וסונכרנו בהצלחה!",
    phonesLinked: normalizedPhones.length,
  });
}

// ----------------------------------------------------
// ניהול שיחות טלפון מימות המשיח (Yemot IVR Handler)
// ----------------------------------------------------
function formatNameForTts(name) {
  if (!name) return "החשבון";
  // ניקוי תווים מיוחדים
  let cleaned = name.replace(/[^\u0590-\u05FFa-zA-Z0-9\s]/g, " ");
  // הוספת רווח בין אותיות לספרות כדי שהקריין יקריא בצורה שוטפת (למשל 'דרייב 7' ולא 'דרייב7')
  cleaned = cleaned.replace(/([\u0590-\u05FFa-zA-Z])(\d)/g, "$1 $2");
  cleaned = cleaned.replace(/(\d)([\u0590-\u05FFa-zA-Z])/g, "$1 $2");
  return cleaned.replace(/\s+/g, " ").trim() || "חשבון";
}

async function handleYemotCall(params, env) {
  try {
    const callerPhone = normalizePhone(params.ApiPhone || "");
    const unregChoice = (params.unreg_choice || "").toString().trim();
    const inputPhone = normalizePhone(params.input_phone || "");
    const pin = (params.pin || "").toString().trim();
    const accChoice = (params.acc_choice || "").toString().trim();
    const postChoice = (params.post_choice || "").toString().trim();

    // 1. קביעת מספר היעד של המשתמש:
    const targetPhone = inputPhone || callerPhone;

    // 2. אם המשתמש הגיע לתפריט חיוג לא מזוהה (unreg_choice)
    if (unregChoice) {
      if (unregChoice === "1") {
        if (!inputPhone) {
          return yemotTextResponse(
            "read=t-נא הקישו את מספר הטלפון המורשה שהגדרתם בחשבונכם ולאחריו סולמית=input_phone,,10,9,10,NO,no,no,,,,,,,,no"
          );
        }
      } else {
        return yemotTextResponse("id_list_message=t-תודה ולהתראות, הנכם מוזמנים להיכנס לאתר ולהגדיר את מספרכם בהגדרות החשבון&hangup");
      }
    }

    // 3. אם אין מספר יעד כלל (חסוי ולא הוקש מספר)
    if (!targetPhone) {
      return yemotTextResponse(
        "read=t-מספר הטלפון לא מזוהה, אנא הקישו את מספר הטלפון המורשה בחשבונכם ולאחריו סולמית=input_phone,,10,9,10,NO,no,no,,,,,,,,no"
      );
    }

    // 4. בדיקת קיום מספר היעד במאגר
    const phoneData = await env.VAULT_KV.get("phone:" + targetPhone, "json");
    if (!phoneData) {
      if (inputPhone) {
        return yemotTextResponse("id_list_message=t-לא נמצא חשבון פעיל המשויך למספר שהקשתם, אנא היכנסו לאתר ורשמו את המספר בהגדרות&hangup");
      }
      return yemotTextResponse(
        "read=t-שלום, מספר הטלפון שממנו התקשרתם טרם הוגדר במערכת, באפשרותכם להיכנס לאתר ולהגדיר את מספר הטלפון בהגדרות החשבון, אם יש לכם חשבון פעיל עם מספר מורשה, הקישו 1 כדי להקיש את המספר והקוד הסודי שלכם, לסיום נתקו את השיחה=unreg_choice,,1,1,10,NO,no,no,,,,,,,,no"
      );
    }

    // 5. בדיקת קוד סודי (PIN) אם הוגדר
    if (phoneData.pinHash) {
      if (!pin) {
        return yemotTextResponse(
          "read=t-שלום, נא הקישו את הקוד הסודי שלכם ולאחריו סולמית=pin,,6,4,10,NO,no,no,,,,,,,,no"
        );
      }

      // הגנה ממתקפת brute force
      const lockKey = "lock:" + targetPhone;
      const lockData = await env.VAULT_KV.get(lockKey, "json");
      if (lockData && lockData.lockedUntil && Date.now() < lockData.lockedUntil) {
        const minutesLeft = Math.ceil((lockData.lockedUntil - Date.now()) / 60000);
        return yemotTextResponse("id_list_message=t-החשבון ננעל עקב ריבוי ניסיונות שגויים, אנא נסו שוב בעוד " + minutesLeft + " דקות&hangup");
      }

      const inputPinHash = await sha256Hex(pin + (phoneData.pinSalt || ""));
      if (!constantTimeEquals(inputPinHash, phoneData.pinHash)) {
        let attempts = (lockData && lockData.attempts ? lockData.attempts : 0) + 1;
        if (attempts >= 3) {
          const lockedUntil = Date.now() + 15 * 60 * 1000;
          await env.VAULT_KV.put(lockKey, JSON.stringify({ lockedUntil, attempts }), { expirationTtl: 900 });
          return yemotTextResponse("id_list_message=t-הקוד הסודי שגוי, החשבון ננעל ל-15 דקות מטעמי אבטחה&hangup");
        }
        await env.VAULT_KV.put(lockKey, JSON.stringify({ attempts }), { expirationTtl: 900 });
        return yemotTextResponse(
          "read=t-הקוד הסודי שהוקש שגוי, נותרו לכם " + (3 - attempts) + " ניסיונות, אנא הקישו שוב ולאחריו סולמית=pin,,6,4,10,NO,no,no,,,,,,,,no"
        );
      }

      // PIN תקין - איפוס נעילה
      await env.VAULT_KV.delete(lockKey);
    }

    // 6. המשתמש אומת בהצלחה! טיפול בבחירת חשבון והשמעת TOTP
    const accounts = Array.isArray(phoneData.accounts) ? phoneData.accounts : [];
    if (accounts.length === 0) {
      return yemotTextResponse("id_list_message=t-לא הוגדרו חשבונות להשמעה טלפונית עבור משתמש זה&hangup");
    }

    // טיפול בבחירה לאחר השמעה (post_choice: 1 = שמיעה חוזרת, 2 = חזרה לתפריט)
    if (postChoice) {
      if (postChoice === "1") {
        const targetAcc = accChoice ? accounts.find(a => String(a.slot) === accChoice) : accounts[0];
        if (targetAcc) {
          return playOtpForAccount(targetAcc, pin, accounts.length > 1);
        }
      } else if (postChoice === "2" && accounts.length > 1) {
        return presentAccountsMenu(accounts);
      } else {
        return yemotTextResponse("id_list_message=t-תודה ולהתראות&hangup");
      }
    }

    // אם הוקשה בחירת חשבון (accChoice)
    if (accChoice) {
      const acc = accounts.find(a => String(a.slot) === accChoice);
      if (!acc) {
        return yemotTextResponse(
          "read=t-הבחירה שהוקשה אינה קיימת, אנא נסו שנית=acc_choice,,2,1,10,NO,no,no,,,,,,,,no"
        );
      }
      return playOtpForAccount(acc, pin, accounts.length > 1);
    }

    // שלב ראשוני לאחר אימות: אם יש רק חשבון 1 משמיעים מיד, אחרת מציגים תפריט
    if (accounts.length === 1) {
      return playOtpForAccount(accounts[0], pin, false);
    }

    return presentAccountsMenu(accounts);

  } catch (err) {
    return yemotTextResponse("id_list_message=t-אירעה שגיאה בעיבוד הבקשה&hangup");
  }
}

// תפריט בחירת חשבון
function presentAccountsMenu(accounts) {
  let promptText = "נא לבחור חשבון, ";
  const parts = accounts.map(a => {
    const cleanName = formatNameForTts(a.name || "חשבון");
    return "עבור " + cleanName + " הקישו " + a.slot;
  });
  promptText += parts.join(", ");
  return yemotTextResponse(
    "read=t-" + promptText + "=acc_choice,,2,1,10,NO,no,no,,,,,,,,no"
  );
}

// פענוח סוד, חישוב TOTP והשמעה
async function playOtpForAccount(acc, pin, hasMultipleAccounts) {
  try {
    let secret = acc.secret;
    if (acc.encryptedSecret && pin) {
      secret = await decryptWithPin(acc.encryptedSecret, acc.iv, acc.tag, pin, acc.salt);
    }

    if (!secret) {
      return yemotTextResponse("id_list_message=t-לא ניתן לפענח את מפתח החשבון&hangup");
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const secondsRemaining = 30 - (nowSec % 30);
    let targetEpoch = nowSec;
    let timingMsg = "";

    // אם נותרו פחות מ-8 שניות - מקריאים כבר את הקוד של החלון הבא
    if (secondsRemaining < 8) {
      targetEpoch = nowSec + 30;
      timingMsg = " לתקופה הבאה הינו, ";
    }

    const totpCode = await generateTotpCode(secret, targetEpoch);
    const accountName = formatNameForTts(acc.name || "החשבון");

    let postOptions = "t-לשמיעה חוזרת הקישו 1";
    if (hasMultipleAccounts) {
      postOptions += ", לחזרה לתפריט הקישו 2";
    }
    postOptions += ", לסיום נתקו את השיחה";

    const message = "t-קוד האימות עבור " + accountName + timingMsg + ".d-" + totpCode + ".t-שוב.d-" + totpCode + "." + postOptions;

    return yemotTextResponse(
      "read=" + message + "=post_choice,,1,1,10,NO,no,no,,,,,,,,no"
    );
  } catch (err) {
    return yemotTextResponse("id_list_message=t-שגיאה בחישוב קוד האימות&hangup");
  }
}

// פענוח AES-GCM מבוסס PIN
async function decryptWithPin(ciphertextBase64, ivBase64, tagBase64, pin, saltBase64) {
  const salt = new Uint8Array(atob(saltBase64).split("").map(c => c.charCodeAt(0)));
  const pinKey = await derivePinKey(pin, salt);

  const ciphertextBytes = new Uint8Array(atob(ciphertextBase64).split("").map(c => c.charCodeAt(0)));
  const ivBytes = new Uint8Array(atob(ivBase64).split("").map(c => c.charCodeAt(0)));
  const tagBytes = new Uint8Array(atob(tagBase64).split("").map(c => c.charCodeAt(0)));

  const combined = new Uint8Array(ciphertextBytes.length + tagBytes.length);
  combined.set(ciphertextBytes);
  combined.set(tagBytes, ciphertextBytes.length);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivBytes },
    pinKey,
    combined
  );
  return new TextDecoder().decode(decrypted);
}

async function derivePinKey(pin, salt) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(pin),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 50000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// מחולל TOTP (RFC 6238) ב-WebCrypto (HMAC-SHA1)
async function generateTotpCode(secret, epochSeconds) {
  const keyBytes = base32Decode(secret);
  const timeStep = Math.floor(epochSeconds / 30);

  const messageBytes = new Uint8Array(8);
  let temp = timeStep;
  for (let i = 7; i >= 0; i--) {
    messageBytes[i] = temp & 0xff;
    temp = Math.floor(temp / 256);
  }

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, messageBytes);
  const hmacResult = new Uint8Array(signature);
  const offset = hmacResult[hmacResult.length - 1] & 0x0f;
  const binCode = ((hmacResult[offset] & 0x7f) << 24) |
                  ((hmacResult[offset + 1] & 0xff) << 16) |
                  ((hmacResult[offset + 2] & 0xff) << 8) |
                  (hmacResult[offset + 3] & 0xff);
  const otp = binCode % 1000000;
  return otp.toString().padStart(6, "0");
}

function base32Decode(str) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  str = str.replace(/=+$/, "").toUpperCase().replace(/\s/g, "");
  let bits = 0, value = 0;
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    const val = alphabet.indexOf(str[i]);
    if (val === -1) throw new Error("תו Base32 לא חוקי: " + str[i]);
    value = (value << 5) | val;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}
