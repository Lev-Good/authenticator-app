/**
 * בדיקת אינטרופ בין האתר (HTML/JS) לאפליקציית הדסקטופ (C#).
 *
 * משתמש בקוד הייצור האמיתי משני הצדדים:
 *  - HTML: הפונקציות הקריפטוגרפיות שחולצו מ-index.html (html-crypto.mjs)
 *  - C#: SecurityManager.cs ו-TotpGenerator.cs המקוריים (cross-test/cross-test.csproj)
 *
 * בדיקות:
 *  A. כספת שנוצרה עם הקריפטו של ה-HTML -> נטענת בהצלחה ע"י ה-C# האמיתי
 *  B. כספת שנוצרה ע"י ה-C# האמיתי -> נפענחת ע"י הקריפטו של ה-HTML
 *  C. קוד TOTP של C# == קוד TOTP של HTML (באותו רגע)
 *
 * הרצה:  node backup-worker/cross-csharp-test.mjs
 * דורש: dotnet SDK + Node.js 18
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { htmlCrypto as api } from "./html-crypto.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const projectDir = path.join(here, "cross-test");
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cross-test-"));

let passed = 0;
let failed = 0;
function check(name, cond, extra = "") {
  if (cond) { passed++; console.log("  ✔ " + name); }
  else { failed++; console.log("  ✘ " + name + (extra ? "  -> " + extra : "")); }
}

function runCross(args) {
  return execFileSync("dotnet", ["run", "--project", projectDir, "--", ...args], {
    encoding: "utf8",
    cwd: projectDir,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

console.log("בניית ה-harness של C# (מקשר את הקוד האמיתי של MasterAuthenticator)...");
runCross(["totp", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"]); // builds + sanity

// ---------------------------------------------------------------
// A. HTML יוצר כספת -> C# טוען אותה
// ---------------------------------------------------------------
console.log("\nA) כספת מ-HTML נפתחת בקוד ה-C# האמיתי:");
{
  const password = "master-pass";
  const email = "cross-a@example.com";
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const key = await api.deriveKey(password, salt);
  const tokenEnc = await api.encryptText("AUTHENTICATED", key);
  const accounts = [
    { id: "1", name: "חשבון 1", email: "a@gmail.com", secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", notes: "הערה", backupCodes: [{ code: "11112222", used: false }] },
    { id: "2", name: "חשבון 2", email: "b@gmail.com", secret: "MFRGGZDFMZTWQ2LK", notes: "", backupCodes: [] },
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
  const vaultFile = path.join(tmpDir, "vault-html.json");
  fs.writeFileSync(vaultFile, JSON.stringify(vault));

  const out = runCross(["load", vaultFile, password]);
  check("C# טוען בהצלחה (LOAD_OK)", /LOAD_OK/.test(out), out.trim());
  check("C# ראה 2 חשבונות", /accounts=2/.test(out), out.trim());
  check("C# ראה את אימייל השחזור", out.includes(email), out.trim());
  check("הקודים המוצפנים אינם דולפים לפלט", !out.includes("11112222"));
}

// ---------------------------------------------------------------
// B. C# יוצר כספת -> HTML מפענח אותה
// ---------------------------------------------------------------
console.log("\nB) כספת מה-C# האמיתי נפענחת ע\"י הקריפטו של ה-HTML:");
{
  const password = "master-pass-2";
  const email = "cross-b@example.com";
  const vaultFile = path.join(tmpDir, "vault-csharp.json");
  runCross(["create", password, email, vaultFile]);
  const vaultJson = fs.readFileSync(vaultFile, "utf8");
  const vault = JSON.parse(vaultJson);

  check("מבנה הכספת מ-C# תקין", vault.Salt && vault.VerificationTokenEncrypted && vault.AccountsEncrypted && vault.AccountsTag && vault.RecoveryEmail === email, JSON.stringify(Object.keys(vault)));

  const key = await api.deriveKey(password, new Uint8Array(atob(vault.Salt).split("").map((c) => c.charCodeAt(0))));
  const token = await api.decryptText(vault.VerificationTokenEncrypted, vault.VerificationTokenIv, vault.VerificationTokenTag, key);
  check("Token מ-C# = AUTHENTICATED", token === "AUTHENTICATED", token);
  const accounts = JSON.parse(await api.decryptText(vault.AccountsEncrypted, vault.AccountsIv, vault.AccountsTag, key));
  check("כספת חדשה מ-C# = אפס חשבונות", Array.isArray(accounts) && accounts.length === 0, JSON.stringify(accounts));

  // וסיסמה שגויה אמורה להיכשל בשני הכיוונים
  const badKey = await api.deriveKey("wrong-pass", new Uint8Array(atob(vault.Salt).split("").map((c) => c.charCodeAt(0))));
  let threw = false;
  try { await api.decryptText(vault.VerificationTokenEncrypted, vault.VerificationTokenIv, vault.VerificationTokenTag, badKey); } catch { threw = true; }
  check("סיסמה שגויה נדחית גם מצד ה-HTML", threw);
}

// ---------------------------------------------------------------
// C. TOTP: C# מול HTML באותו רגע
// ---------------------------------------------------------------
console.log("\nC) קוד TOTP של C# == קוד TOTP של HTML (אותו רגע):");
{
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  let matched = false;
  for (let attempt = 0; attempt < 3 && !matched; attempt++) {
    const htmlCode = api.generateTotp(secret);
    const out = runCross(["totp", secret]);
    const m = /TOTP=(\d{6})/.exec(out);
    if (m && m[1] === htmlCode) matched = true;
  }
  check("הקודים זהים (גם אם חל שינוי שנייה באמצע)", matched);
}

fs.rmSync(tmpDir, { recursive: true, force: true });
console.log("\nתוצאה: " + passed + " עברו, " + failed + " נכשלו");
process.exit(failed === 0 ? 0 : 1);
