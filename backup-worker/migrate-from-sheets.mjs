#!/usr/bin/env node
/**
 * סקריפט הגירה: Google Apps Script (גיליון) → Cloudflare Worker + KV
 * =================================================================
 * מעביר את כל המשתמשים (אימייל + סיסמה + כספת מוצפנת) מהישן לחדש,
 * באותו פרוטוקול בדיוק שהלקוחות משתמשים בו (get_vault / save_vault).
 *
 * שימוש:
 *   node backup-worker/migrate-from-sheets.mjs \
 *     --from <URL-הסקריפט-הישן> --to <URL-ה-Worker> [אפשרויות]
 *
 * אפשרויות:
 *   --from <url>      כתובת הסקריפט הישן (Google Apps Script) - חובה
 *   --to <url>        כתובת ה-Worker החדש - חובה
 *   --token <v>       ה-API_TOKEN של ה-Worker (אם הוגדר בשרת) - אופציונלי
 *   --export-key <v>  ה-EXPORT_KEY של פעולת export_all בסקריפט הישן - אופציונלי
 *   --email <addr>    העברה של משתמש בודד בלבד (בדיקה ממוקדת)
 *   --dry-run         לקרוא ולדווח בלבד - בלי לכתוב דבר לשרת החדש
 *   --force           לדרוס נתונים קיימים ב-KV גם אם הם חדשים יותר מהגיליון
 *   --verbose         הדפסת שורה מפורטת לכל משתמש
 *   --json            הדפסת סיכום JSON בשורה האחרונה (לבדיקות אוטומטיות)
 *   --help            הוראות שימוש
 *
 * התנהגות:
 *   - קורא את כל השורות מהגיליון הישן (action=export_all).
 *   - מדלג על שורות פגומות (ללא אימייל / כספת שאינה JSON תקין) ומדווח עליהן
 *     - בלי להעביר אותן פגומות לשרת החדש.
 *   - עבור כל משתמש תקין: אם ב-KV קיים נתון חדש יותר מהגיליון - מדלג (לא דורס!).
 *     כך אפשר להריץ את הסקריפט שוב ושוב בתקופת המעבר הכפולה ללא סיכון.
 *   - מסיר קידומות ישנות מה-password (P_ / ') - כמו שפעולת השחזור הישנה עשתה.
 *
 * דרישה: Node.js 18 ומעלה.
 */

const args = process.argv.slice(2);

function arg(name) {
  const i = args.indexOf(name);
  return i !== -1 && args[i + 1] ? args[i + 1] : "";
}
function has(name) {
  return args.includes(name);
}

if (has("--help") || has("-h")) {
  console.log(`סקריפט הגירה: Google Sheets → Cloudflare Worker

שימוש:
  node backup-worker/migrate-from-sheets.mjs --from <URL-ישן> --to <URL-חדש> [אפשרויות]

אפשרויות:
  --from <url>      כתובת הסקריפט הישן (Google Apps Script) - חובה
  --to <url>        כתובת ה-Worker החדש - חובה
  --token <v>       ה-API_TOKEN של ה-Worker (אם הוגדר) - אופציונלי
  --export-key <v>  ה-EXPORT_KEY של export_all בסקריפט הישן - אופציונלי
  --email <addr>    העברה של משתמש בודד בלבד
  --dry-run         לקרוא ולדווח בלבד - בלי לכתוב
  --force           לדרוס נתונים קיימים גם אם הם חדשים יותר
  --verbose         פירוט לכל משתמש
  --json            סיכום JSON בשורה האחרונה
  --help            הוראות אלה`);
  process.exit(0);
}

const FROM_URL = arg("--from");
const TO_URL = arg("--to");
const TOKEN = arg("--token");
const EXPORT_KEY = arg("--export-key");
const SINGLE_EMAIL = arg("--email").trim().toLowerCase();
const DRY_RUN = has("--dry-run");
const FORCE = has("--force");
const VERBOSE = has("--verbose");
const JSON_OUT = has("--json");

if (!FROM_URL || !TO_URL) {
  console.error("❌ שגיאה: חובה לציין גם --from וגם --to (ראה --help)");
  process.exit(2);
}
if (!/^https?:\/\//.test(FROM_URL) || !/^https?:\/\//.test(TO_URL)) {
  console.error("❌ שגיאה: --from ו--to חייבים להיות כתובות HTTP/HTTPS תקינות");
  process.exit(2);
}

// ---------- עזרים ----------

import http from "node:http";
import https from "node:https";

// שליחת POST-JSON עם חיבורים שאינם נשמרים (agent: false):
//  - לא משתמש ב-fetch הגלובלי (undici) כדי למנוע קריסת teardown ידועה של Node על Windows
//  - עוקב אחרי הפניות (redirects) ידנית — חיוני כי Apps Script מחזיר 302
//    מ-script.google.com אל script.googleusercontent.com
function postJson(url, body, token, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === "https:" ? https : http;
    const payload = JSON.stringify(body);
    const headers = {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload),
      "User-Agent": "master-auth-migration-script/1.0",
    };
    if (token) headers["Authorization"] = "Bearer " + token;

    const req = lib.request(
      url,
      { method: "POST", headers, agent: false, timeout: 60000 },
      (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (text += c));
        res.on("end", () => {
          // הפניה: עקוב אחריה (עד 5 פעמים)
          if (res.statusCode >= 300 && res.statusCode < 400) {
            const loc = res.headers.location;
            if (loc && redirectsLeft > 0) {
              const nextUrl = new URL(loc, url);

              // Apps Script מפנה POST אל script.googleusercontent.com,
              // והיעד מקבל את ההמשך כ-GET. מעבירים את פרמטרי הפעולה לכתובת
              // כדי ש-doGet יוכל לטפל בהם בלי לקבל 405.
              if (
                u.hostname === "script.google.com" &&
                nextUrl.hostname === "script.googleusercontent.com"
              ) {
                for (const [key, value] of Object.entries(body)) {
                  nextUrl.searchParams.set(key, String(value));
                }
                getJson(nextUrl.toString(), "", redirectsLeft - 1).then(resolve, reject);
              } else {
                postJson(nextUrl.toString(), body, token, redirectsLeft - 1).then(resolve, reject);
              }
              return;
            }
            reject(new Error("HTTP " + res.statusCode + " (הפנייה לא נעקבה) מ-" + url));
            return;
          }

          let data = null;
          try {
            data = JSON.parse(text);
          } catch {
            data = null;
          }
          if (res.statusCode >= 200 && res.statusCode < 300 && data !== null) {
            resolve(data);
          } else {
            reject(
              new Error(
                "HTTP " + res.statusCode + " מ-" + url + ": " +
                (text.length > 200 ? text.slice(0, 200) + "..." : text || "(ריק)")
              )
            );
          }
        });
      }
    );
    req.on("timeout", () => req.destroy(new Error("התקשרות נמשכה יותר מ-60 שניות: " + url)));
    req.on("error", reject);
    req.end(payload);
  });
}

// קריאת JSON ב-GET, כולל מעקב אחרי הפניות של Apps Script.
function getJson(url, token, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === "https:" ? https : http;
    const headers = {
      "User-Agent": "master-auth-migration-script/1.0",
    };
    if (token) headers["Authorization"] = "Bearer " + token;

    const req = lib.request(
      url,
      { method: "GET", headers, agent: false, timeout: 60000 },
      (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (text += c));
        res.on("end", () => {
          if (res.statusCode >= 300 && res.statusCode < 400) {
            const loc = res.headers.location;
            if (loc && redirectsLeft > 0) {
              const sourceUrl = new URL(url);
              const nextUrl = new URL(loc, url);

              // יש הפניות נוספות אחרי script.googleusercontent.com;
              // שומרים גם בהן את action ואת export_key.
              for (const [key, value] of sourceUrl.searchParams) {
                if (!nextUrl.searchParams.has(key)) {
                  nextUrl.searchParams.set(key, value);
                }
              }

              getJson(nextUrl.toString(), token, redirectsLeft - 1).then(resolve, reject);
              return;
            }
            reject(new Error("HTTP " + res.statusCode + " (הפנייה לא נעקבה) מ-" + url));
            return;
          }

          let data = null;
          try {
            data = JSON.parse(text);
          } catch {
            data = null;
          }

          if (res.statusCode >= 200 && res.statusCode < 300 && data !== null) {
            resolve(data);
          } else {
            reject(
              new Error(
                "HTTP " + res.statusCode + " מ-" + url + ": " +
                (text.length > 200 ? text.slice(0, 200) + "..." : text || "(ריק)")
              )
            );
          }
        });
      }
    );

    req.on("timeout", () => req.destroy(new Error("התקשרות נמשכה יותר מ-60 שניות: " + url)));
    req.on("error", reject);
    req.end();
  });
}

// הסרת קידומות ישנות מה-password (כמו בפעולת השחזור הישנה)
function normalizePassword(p) {
  if (p.startsWith("P_")) return p.slice(2);
  if (p.startsWith("'")) return p.slice(1);
  return p;
}

// בדיקה שהכספת היא אובייקט JSON תקין (אותו כלל כמו ב-Worker)
function isValidVaultJson(v) {
  try {
    const parsed = JSON.parse(v);
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed);
  } catch {
    return false;
  }
}

// המרת תאריך הגיליון ("yyyy-MM-dd HH:mm:ss" באזור הזמן של הסקריפט) ל-UTC ISO
function toIsoUtc(str, tzOffset) {
  if (!str) return "";
  const s = String(str).trim();
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})$/);
  if (m) {
    const asUtc = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
    const off = tzOffset ? tzOffset.match(/^([+-])(\d{2}):?(\d{2})$/) : null;
    if (off) {
      const minutes = (+off[2] * 60 + +off[3]) * 60000;
      const sign = off[1] === "-" ? -1 : 1;
      return new Date(asUtc - sign * minutes).toISOString();
    }
    return new Date(asUtc).toISOString();
  }
  const d = new Date(s);
  return isNaN(d.getTime()) ? "" : d.toISOString();
}

// ---------- מהלך ראשי ----------

const counters = { total: 0, ok: 0, empty: 0, invalid: 0, migrated: 0, skipped: 0, failed: 0 };
const warnings = [];   // שורות שנדלגו (לא שגיאות קטלניות)
const errors = [];     // כשלונות אמיתיים (רשת / כתיבה)
const details = [];    // פירוט משתמשים (verbose)

async function main() {
  console.log("🚚 הגירה מגוגל ל-Cloudflare" + (DRY_RUN ? "  [מצב יבש — dry-run, לא נכתוב דבר]" : ""));
  console.log("   מהשרת הישן:  " + FROM_URL);
  console.log("   לשרת החדש:   " + TO_URL + (TOKEN ? "  (עם Token)" : ""));
  console.log("");

  // 1. ייצוא כל השורות מהגיליון
  console.log("1) קורא את כל המשתמשים מהגיליון הישן...");
  let exportData;
  try {
    const body = { action: "export_all" };
    if (EXPORT_KEY) body.export_key = EXPORT_KEY;
    exportData = await postJson(FROM_URL, body, ""); // לעולם לא שולחים Token לשרת הישן
  } catch (err) {
    console.error("❌ נכשל בחיבור לשרת הישן: " + err.message);
    console.error("   בדוק: (א) הכתובת נכונה (ב) הוספת את פעולת export_all לסקריפט");
    console.error("   והרצת Deploy → New version (ג) אם הגדרת EXPORT_KEY - העבר אותו עם --export-key");
    finish(1);
  }

  if (!exportData || exportData.success !== true || !Array.isArray(exportData.users)) {
    console.error("❌ תשובה לא צפויה מהשרת הישן: " + JSON.stringify(exportData).slice(0, 300));
    finish(1);
  }

  const tzOffset = exportData.tzOffset || "";
  let rows = exportData.users;
  if (SINGLE_EMAIL) {
    rows = rows.filter((r) => (r.email || "").toString().trim().toLowerCase() === SINGLE_EMAIL);
    console.log("   (מצב --email: רק משתמש אחד — " + SINGLE_EMAIL + ")");
  }
  counters.total = rows.length;
  console.log("   נמצאו " + rows.length + " שורות" + (tzOffset ? " (אזור זמן: " + tzOffset + ")" : "") + "\n");

  // 2. סיווג השורות
  const valid = [];
  for (const row of rows) {
    const email = (row.email || "").toString().trim().toLowerCase();
    const vault = (row.vault || "").toString().trim();
    const password = normalizePassword((row.password || "").toString().trim());
    const updatedAt = toIsoUtc(row.updatedAt, tzOffset);

    if (!email || email.length > 254 || !email.includes("@")) {
      counters.invalid++;
      warnings.push("⚠️ שורה ללא אימייל תקין — נדלגה: " + JSON.stringify(row).slice(0, 120));
      continue;
    }
    if (!vault) {
      counters.empty++;
      warnings.push("ℹ️ " + email + " — ללא כספת בגיליון (משתמש שנרשם אך לא סיים הגדרה) — לא מועבר");
      continue;
    }
    if (!isValidVaultJson(vault)) {
      counters.invalid++;
      warnings.push("⚠️ " + email + " — כספת פגומה (לא JSON תקין) — נדלגה, לא הועברה");
      continue;
    }
    counters.ok++;
    valid.push({ email, password, vault, updatedAt });
  }

  if (SINGLE_EMAIL && counters.ok === 0) {
    console.error("❌ האימייל '" + SINGLE_EMAIL + "' לא נמצא בגיליון (או שאין לו כספת תקינה).");
    finish(1);
  }

  // 3. בדיקה מול השרת החדש + כתיבה
  console.log("2) בודק ומסנכרן מול השרת החדש...");
  for (const u of valid) {
    let kvTime = 0;
    let kvRegistered = false;

    if (!FORCE) {
      try {
        const existing = await postJson(TO_URL, { action: "get_vault", email: u.email }, TOKEN);
        kvRegistered = existing && existing.registered === true;
        if (kvRegistered && existing.updatedAt) {
          const t = Date.parse(existing.updatedAt);
          if (!isNaN(t)) kvTime = t;
        }
      } catch (err) {
        // לא קטלני: ננסה לכתוב בכל מקרה ונסמוך על התשובה
        kvTime = 0;
      }
      const sheetMs = Date.parse(u.updatedAt) || 0;
      if (kvRegistered && kvTime >= sheetMs) {
        counters.skipped++;
        details.push("   ⏭  " + u.email + " — כבר מעודכן בשרת החדש (נדלג)");
        continue;
      }
    }

    if (DRY_RUN) {
      // מצב יבש: רק מדווחים מה ייכתב, בלי לשלוח save_vault
      counters.migrated++;
      details.push("   📋  " + u.email + " — יועבר (מצב יבש)");
      continue;
    }

    try {
      const res = await postJson(
        TO_URL,
        { action: "save_vault", email: u.email, password: u.password, vault: u.vault },
        TOKEN
      );
      if (res && res.success === true) {
        counters.migrated++;
        details.push(
          "   ✔  " + u.email +
          " — הועבר" +
          (u.updatedAt ? " (עודכן בגיליון: " + u.updatedAt + ")" : "")
        );
      } else {
        counters.failed++;
        errors.push("❌ " + u.email + " — השרת החדש דחה את הכתיבה: " + JSON.stringify(res).slice(0, 150));
      }
    } catch (err) {
      counters.failed++;
      errors.push("❌ " + u.email + " — שגיאת תקשורת: " + err.message);
    }
  }

  // 4. דוח
  console.log("");
  console.log("── סיכום ─────────────────────────────────────────");
  console.log("   סך הכל שורות בגיליון:      " + counters.total);
  console.log("   שורות תקינות (עם כספת):    " + counters.ok);
  console.log("   " + (DRY_RUN ? "יועברו לשרת החדש" : "הועברו לשרת החדש") + ":     " + counters.migrated);
  console.log("   כבר מעודכנים (נדלגו):      " + counters.skipped);
  console.log("   ללא כספת (לא רלוונטי):     " + counters.empty);
  console.log("   פגומות / לא תקינות (דולגו): " + counters.invalid);
  console.log("   שגיאות:                     " + counters.failed);

  if (VERBOSE && details.length) {
    console.log("");
    console.log("── פירוט ─────────────────────────────────────────");
    console.log(details.join("\n"));
  }
  if (warnings.length) {
    console.log("");
    console.log("── שורות שנדלגו (אין צורך לפעול — לצורך שקיפות) ──");
    console.log(warnings.join("\n"));
  }
  if (errors.length) {
    console.log("");
    console.log("── שגיאות (יש לבדוק!) ────────────────────────────");
    console.log(errors.join("\n"));
  }

  const ok = counters.failed === 0;
  console.log(ok ? "\n✅ הסתיים בהצלחה." : "\n❌ הסתיים עם שגיאות — ראה פירוט למעלה.");

  if (JSON_OUT) {
    // שורה אחרונה = JSON — נוח לבדיקות אוטומטיות ולעיבוד
    console.log(JSON.stringify({ ...counters, dryRun: DRY_RUN }));
  }

  process.exit(ok ? 0 : 1);
}

function finish(code) {
  process.exit(code);
}

main().catch((err) => {
  console.error("❌ שגיאה בלתי צפויה: " + (err && err.stack ? err.stack : err));
  process.exit(1);
});
