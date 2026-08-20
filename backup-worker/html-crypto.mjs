/**
 * מודול עזר: מחלץ את הפונקציות הקריפטוגרפיות האמיתיות מתוך index.html
 * (קוד הייצור עצמו, לא עותק!) כדי לבדוק אותן ישירות ב-Node.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const htmlPath = path.resolve(here, "..", "index.html");
const html = fs.readFileSync(htmlPath, "utf8");

function extractFunction(source, name) {
  const re = new RegExp("(?:async\\s+)?function\\s+" + name + "\\s*\\([^)]*\\)\\s*\\{");
  const m = re.exec(source);
  if (!m) throw new Error("function not found in index.html: " + name);
  const start = source.indexOf("{", m.index);
  let depth = 0;
  let i = start;
  for (; i < source.length; i++) {
    if (source[i] === "{") depth++;
    else if (source[i] === "}") { depth--; if (depth === 0) break; }
  }
  return source.slice(m.index, i + 1);
}

const funcNames = ["base32ToBytes", "sha1Raw", "hmacSha1", "generateTotp", "deriveKey", "encryptText", "decryptText", "sha256"];
const code = funcNames.map((n) => extractFunction(html, n)).join("\n\n");

// הפונקציות של האתר משתמשות ב-window.crypto וב-btoa/atob (קיימים ב-Node)
if (!globalThis.window) globalThis.window = { crypto: globalThis.crypto };

export const htmlCrypto = new Function(
  code + "\nreturn { base32ToBytes, sha1Raw, hmacSha1, generateTotp, deriveKey, encryptText, decryptText, sha256 };"
)();
