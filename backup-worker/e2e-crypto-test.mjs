/**
 * בדיקת קצה-לקצה (E2E) של הקריפטוגרפיה האמיתית של האתר + השרת.
 *
 * מה זה בודק:
 * 1. מחלץ את הפונקציות הקריפטוגרפיות האמיתיות מ-index.html (לא עותק!).
 * 2. בודק אותן מול וקטורים רשמיים של RFC 6238 (TOTP), RFC 2202 (HMAC) ו-SHA-1.
 * 3. בודק מחזור הצפנה מלא: יצירת כספת -> שמירה בשרת (HTTP אמיתי) -> שליפה -> פענוח.
 * 4. משווה את ה-TOTP של האתר מול יישום ייחוס עצמאי ב-Node.
 * 5. בודק את חוזה הפרוטוקול מול סמנטיקת ה-Apps Script הישן.
 *
 * הרצה:  node backup-worker/e2e-crypto-test.mjs
 */
import http from "node:http";
import crypto from "node:crypto";
import worker from "./worker.js";
import { htmlCrypto as api } from "./html-crypto.mjs";

let passed = 0;
let failed = 0;
function check(name, cond, extra = "") {
  if (cond) { passed++; console.log("  ✔ " + name); }
  else { failed++; console.log("  ✘ " + name + (extra ? "  -> " + extra : "")); }
}

console.log("1) הפונקציות הקריפטוגרפיות האמיתיות חולצו מ-index.html (מודול משותף)");

// ---------------------------------------------------------------
// 2. וקטורים רשמיים: Base32, SHA-1, HMAC-SHA1
// ---------------------------------------------------------------
console.log("\n2) וקטורים רשמיים (RFC 2202 / FIPS 180):");
{
  const bytes = api.base32ToBytes("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
  const decoded = Buffer.from(bytes).toString("ascii");
  check("base32: מפתח RFC 6238 מפוענח ל-'12345678901234567890'", decoded === "12345678901234567890", decoded);
}

{
  const sha1abc = Buffer.from(api.sha1Raw(new TextEncoder().encode("abc"))).toString("hex");
  check("SHA-1('abc') = a9993e36...", sha1abc === "a9993e364706816aba3e25717850c26c9cd0d89d", sha1abc);
  check("SHA-1 תואם ל-Node crypto", sha1abc === crypto.createHash("sha1").update("abc").digest("hex"));
}

{
  const key1 = Buffer.alloc(20, 0x0b);
  const h1 = Buffer.from(api.hmacSha1(new Uint8Array(key1), new TextEncoder().encode("Hi There"))).toString("hex");
  check("HMAC-SHA1 RFC 2202 #1 = b6173186...", h1 === "b617318655057264e28bc0b6fb378c8ef146be00", h1);
  const h2 = Buffer.from(api.hmacSha1(new TextEncoder().encode("Jefe"), new TextEncoder().encode("what do ya want for nothing?"))).toString("hex");
  check("HMAC-SHA1 RFC 2202 #2 = effcdf6a...", h2 === "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", h2);
}

// ---------------------------------------------------------------
// 3. TOTP מול וקטורי RFC 6238 (באמצעות Stub ל-Date.now)
// ---------------------------------------------------------------
console.log("\n3) TOTP מול וקטורי RFC 6238 (SHA-1):");
{
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  const vectors = [
    [59, "287082"],
    [1111111109, "081804"],
    [1111111111, "050471"],
    [1234567890, "005924"],
    [2000000000, "279037"],
    [20000000000, "353130"],
  ];
  const realNow = Date.now;
  Date.now = () => 0;
  for (const [t, expected] of vectors) {
    Date.now = () => t * 1000;
    const got = api.generateTotp(secret);
    check(`T=${t} -> ${got}`, got === expected, `got ${got}, expected ${expected}`);
  }
  Date.now = realNow;
}

// ---------------------------------------------------------------
// 4. sha256 תואם ל-Node (קריטי - זה ה-hash שנשלח לשרת)
// ---------------------------------------------------------------
console.log("\n4) sha256 (ה-hash שנשלח לשרת):");
{
  const got = await api.sha256("סיסמה-עברית-מבחן-123!");
  const expected = crypto.createHash("sha256").update("סיסמה-עברית-מבחן-123!", "utf8").digest("base64");
  check("sha256 תואם ל-Node crypto", got === expected, got);
}

// ---------------------------------------------------------------
// 5. AES-GCM: הצפנה/פענוח + אימות כשל בסיסמה שגויה
// ---------------------------------------------------------------
console.log("\n5) AES-GCM (PBKDF2 100k iterations):");
{
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const key = await api.deriveKey("master-pass", salt);
  const enc = await api.encryptText("שלום עולם 🔐", key);
  const dec = await api.decryptText(enc.ciphertext, enc.iv, enc.tag, key);
  check("round trip מלא (עברית + אמוג'י)", dec === "שלום עולם 🔐", dec);

  const wrongKey = await api.deriveKey("master-pass-WRONG", salt);
  let threw = false;
  try { await api.decryptText(enc.ciphertext, enc.iv, enc.tag, wrongKey); } catch (e) { threw = true; }
  check("סיסמה שגויה נכשלת בפענוח (אימות שלמות)", threw);
}

// ---------------------------------------------------------------
// 6. קצה-לקצה: כספת אמיתית עוברת דרך שרת HTTP אמיתי
// ---------------------------------------------------------------
console.log("\n6) קצה-לקצה: כספת מוצפנת -> שרת HTTP אמיתי -> שליפה -> פענוח:");
{
  // סימולציה נאמנה של initializeNewVault + saveAccountsToStorage מהאתר
  const password = "master-pass";
  const email = "e2e@example.com";
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const key = await api.deriveKey(password, salt);
  const tokenEnc = await api.encryptText("AUTHENTICATED", key);
  const accounts = [
    { id: "1", name: "חשבון גוגל 1", email: "a@gmail.com", secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", notes: "הערה 🔑", backupCodes: [] },
    { id: "2", name: "חשבון גוגל 2", email: "b@gmail.com", secret: "MFRGGZDFMZTWQ2LK", notes: "", backupCodes: [{ code: "12345678", used: false }] },
  ];
  const accountsEnc = await api.encryptText(JSON.stringify(accounts), key);
  const vault = {
    Salt: btoa(String.fromCharCode(...salt)),
    VerificationTokenEncrypted: tokenEnc.ciphertext,
    VerificationTokenIv: tokenEnc.iv,
    VerificationTokenTag: tokenEnc.tag,
    AccountsEncrypted: accountsEnc.ciphertext,
    AccountsIv: accountsEnc.iv,
    AccountsTag: accountsEnc.tag,
    RecoveryEmail: email,
  };
  const pHash = await api.sha256(password);

  // שרת HTTP אמיתי עם ה-Worker
  const store = new Map();
  const env = {
    API_TOKEN: "",
    VAULT_KV: {
      async get(k, t) { const v = store.get(k); if (v === undefined) return null; return t === "json" ? JSON.parse(v) : v; },
      async put(k, v) { store.set(k, v); },
    },
  };
  const server = http.createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    const request = new Request("http://127.0.0.1" + req.url, { method: req.method, headers: req.headers, body: req.method === "GET" ? undefined : body });
    const response = await worker.fetch(request, env);
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(Buffer.from(await response.arrayBuffer()));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;

  // 6א. שמירה בדיוק עם ה-payload שהאתר שולח (Content-Type: text/plain)
  const saveRes = await fetch(base + "/", {
    method: "POST",
    headers: { "Content-Type": "text/plain;charset=utf-8" },
    body: JSON.stringify({ action: "save_vault", email, password: pHash, vault: JSON.stringify(vault) }),
  });
  const saveJson = await saveRes.json();
  check("שמירה: success", saveJson.success === true, JSON.stringify(saveJson));

  // 6ב. שליפה בדיוק עם ה-payload שהאתר שולח
  const getRes = await fetch(base + "/", {
    method: "POST",
    headers: { "Content-Type": "text/plain;charset=utf-8" },
    body: JSON.stringify({ action: "get_vault", email }),
  });
  const getJson = await getRes.json();
  check("שליפה: registered=true", getJson.registered === true);
  check("שליפה: vault הוא מחרוזת JSON", typeof getJson.vault === "string" && getJson.vault.length > 0);

  // 6ג. פענוח בדיוק כמו שהאתר עושה במסך הכניסה
  const fetchedVault = JSON.parse(getJson.vault);
  const fetchedKey = await api.deriveKey(password, new Uint8Array(atob(fetchedVault.Salt).split("").map((c) => c.charCodeAt(0))));
  const decToken = await api.decryptText(fetchedVault.VerificationTokenEncrypted, fetchedVault.VerificationTokenIv, fetchedVault.VerificationTokenTag, fetchedKey);
  check("פענוח Token = AUTHENTICATED", decToken === "AUTHENTICATED", decToken);
  const decAccounts = JSON.parse(await api.decryptText(fetchedVault.AccountsEncrypted, fetchedVault.AccountsIv, fetchedVault.AccountsTag, fetchedKey));
  check("החשבונות שרדו את המסע המלא", JSON.stringify(decAccounts) === JSON.stringify(accounts), JSON.stringify(decAccounts));

  server.closeAllConnections?.();
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
  await new Promise((resolve) => setTimeout(resolve, 250)); // מתן זמן לסגירת חיבורי keep-alive
}

// ---------------------------------------------------------------
// 7. TOTP של האתר מול יישום ייחוס עצמאי (אותו רגע)
// ---------------------------------------------------------------
console.log("\n7) TOTP האתר מול יישום ייחוס עצמאי (Node crypto):");
{
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  const appCode = api.generateTotp(secret);

  const keyBytes = Buffer.from(api.base32ToBytes(secret));
  const counter = Math.floor(Date.now() / 1000 / 30);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac("sha1", keyBytes).update(msg).digest();
  const off = h[19] & 0xf;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  const refCode = String(bin % 1000000).padStart(6, "0");

  check(`קוד האתר (${appCode}) = קוד הייחוס (${refCode})`, appCode === refCode, `${appCode} != ${refCode}`);
}

// ---------------------------------------------------------------
// 8. חוזה פרוטוקול: מבנה התשובות תואם סמנטיקת Apps Script
// ---------------------------------------------------------------
console.log("\n8) חוזה פרוטוקול (מבנה תשובות כמו הסקריפט הישן):");
{
  const store = new Map();
  const env = {
    API_TOKEN: "",
    VAULT_KV: {
      async get(k, t) { const v = store.get(k); if (v === undefined) return null; return t === "json" ? JSON.parse(v) : v; },
      async put(k, v) { store.set(k, v); },
    },
  };
  const r1 = await worker.fetch(new Request("https://x/", { method: "POST", body: JSON.stringify({ action: "get_vault", email: "new@x.com" }) }), env);
  const j1 = await r1.json();
  check("לא רשום: {success, registered:false} בלבד", j1.success === true && j1.registered === false && Object.keys(j1).sort().join(",") === "registered,success", JSON.stringify(j1));

  const r2 = await worker.fetch(new Request("https://x/", { method: "POST", body: JSON.stringify({ action: "save_vault", email: "new@x.com", password: "h", vault: JSON.stringify({ a: 1 }) }) }), env);
  const j2 = await r2.json();
  check("שמירה: {success, message, updatedAt}", j2.success === true && typeof j2.message === "string" && typeof j2.updatedAt === "string" && Object.keys(j2).sort().join(",") === "message,success,updatedAt", JSON.stringify(j2));

  const r3 = await worker.fetch(new Request("https://x/", { method: "POST", body: JSON.stringify({ action: "get_vault", email: "new@x.com" }) }), env);
  const j3 = await r3.json();
  // הערה: get_vault מחזיר גם updatedAt (לצורכי סינכרון ההגירה) - הלקוחות מתעלמים ממנו,
  // לכן הבדיקה בודקת רק את השדות החיוניים ולא שוויון מדויק של כל המפתחות.
  check("רשום: {success, registered:true, vault:string}", j3.success === true && j3.registered === true && typeof j3.vault === "string" && "success" in j3 && "registered" in j3 && "vault" in j3, JSON.stringify(j3));

  const r4 = await worker.fetch(new Request("https://x/", { method: "POST", body: JSON.stringify({ action: "get_vault" }) }), env);
  const j4 = await r4.json();
  check("שגיאה: {success:false, message}", j4.success === false && typeof j4.message === "string", JSON.stringify(j4));
}

console.log("\nתוצאה: " + passed + " עברו, " + failed + " נכשלו");
process.exit(failed === 0 ? 0 : 1);
