/**
 * בדיקת הגירה מלאה: מריץ את סקריפט ההגירה האמיתי (migrate-from-sheets.mjs)
 * מול שרת "ישן" מדומה (Apps Script עם export_all) ומול ה-Worker האמיתי,
 * ובודק: dry-run, הגירה מלאה, הסרת קידומות, דילוג על שורות פגומות,
 * סינכרון חוזר בטוח (לא דורס נתונים חדשים), וסימולציית תקופת מעבר כפולה.
 *
 * הרצה:  node backup-worker/migrate-test.mjs
 * דורש: Node.js 18 ומעלה
 */
import http from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import worker from "./worker.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MIGRATE_SCRIPT = path.join(ROOT, "backup-worker", "migrate-from-sheets.mjs");

let passed = 0;
let failed = 0;

function check(name, cond, extra = "") {
  if (cond) {
    passed++;
    console.log("  ✔ " + name);
  } else {
    failed++;
    console.log("  ✘ " + name + (extra ? "  -> " + extra : ""));
  }
}

// ---------- שרת "ישן" מדומה (Apps Script) ----------
// טבלת שורות: {email, password, vault, updatedAt} + export_all עם tzOffset.
function createOldServer(initialRows) {
  let rows = initialRows.map((r) => ({ ...r }));
  const server = http.createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    let params = {};
    try { params = JSON.parse(body); } catch { /* ignore */ }
    res.setHeader("Content-Type", "application/json");
    const action = params.action;
    if (action === "export_all") {
      res.end(JSON.stringify({ success: true, count: rows.length, tzOffset: "+0000", users: rows }));
    } else if (action === "get_vault") {
      const email = (params.email || "").trim().toLowerCase();
      const r = rows.find((x) => x.email === email);
      if (r) res.end(JSON.stringify({ success: true, registered: true, vault: r.vault }));
      else res.end(JSON.stringify({ success: true, registered: false }));
    } else if (action === "save_vault") {
      const email = (params.email || "").trim().toLowerCase();
      const idx = rows.findIndex((x) => x.email === email);
      const row = { email, password: String(params.password || ""), vault: String(params.vault || ""), updatedAt: "2026-08-19 10:00:00" };
      if (idx >= 0) rows[idx] = row; else rows.push(row);
      res.end(JSON.stringify({ success: true, message: "saved to old sheet" }));
    } else {
      res.end(JSON.stringify({ success: false, message: "Unknown action: " + action }));
    }
  });
  return {
    start: () => new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve("http://127.0.0.1:" + server.address().port))),
    close: () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(resolve); }),
    mutate: (fn) => { rows = fn(rows); },
  };
}

// ---------- Worker אמיתי מאחורי שרת HTTP ----------
function createWorkerEnv(apiToken) {
  const store = new Map();
  return {
    env: {
      API_TOKEN: apiToken || "",
      VAULT_KV: {
        async get(key, type) {
          const v = store.get(key);
          if (v === undefined) return null;
          return type === "json" ? JSON.parse(v) : v;
        },
        async put(key, value) { store.set(key, value); },
      },
    },
    store,
  };
}

async function startWorkerServer(env) {
  const server = http.createServer(async (req, res) => {
    try {
      let body = "";
      for await (const chunk of req) body += chunk;
      const headers = {};
      for (const [k, v] of Object.entries(req.headers)) headers[k] = Array.isArray(v) ? v.join(", ") : v;
      const request = new Request("http://127.0.0.1" + req.url, {
        method: req.method,
        headers,
        body: req.method === "GET" || req.method === "HEAD" ? undefined : body,
      });
      const response = await worker.fetch(request, env);
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: false, message: "Harness error: " + err.message }));
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, base: "http://127.0.0.1:" + server.address().port };
}

// ---------- הרצת סקריפט ההגירה האמיתי ----------
// אסינכרוני בכוונה: ה-child רץ בזמן שהשרתים המדומים (של הבדיקה) ממשיכים לענות.
function runMigrate(oldBase, workerBase, extraArgs = []) {
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      [MIGRATE_SCRIPT, "--from", oldBase, "--to", workerBase, "--token", "tok123", "--json", ...extraArgs],
      { cwd: ROOT }
    );
    let stdout = "", stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (code) => {
      let summary = null;
      const lines = stdout.trim().split("\n");
      try { summary = JSON.parse(lines[lines.length - 1]); } catch { /* ignore */ }
      resolve({ status: code, stdout, stderr, summary });
    });
  });
}

async function postTo(base, body, token) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = "Bearer " + token;
  const res = await fetch(base, { method: "POST", headers, body: JSON.stringify(body) });
  return res.json();
}

function fmtUTC(d) {
  return d.toISOString().slice(0, 19).replace("T", " ");
}

// ---------- נתוני התחלה ----------
const OLD_INITIAL = [
  { email: "avraham@example.com", password: "P_abc123", vault: JSON.stringify({ Salt: "s1", AccountsEncrypted: "vault-avraham" }), updatedAt: "2026-08-01 10:00:00" },
  { email: "rivka@example.com", password: "'def456", vault: JSON.stringify({ Salt: "s2", AccountsEncrypted: "vault-rivka" }), updatedAt: "2026-08-02 11:30:00" },
  { email: "david@example.com", password: "ghi789", vault: "not-json-אשפה", updatedAt: "2026-08-03 12:00:00" },   // כספת פגומה
  { email: "sarah@example.com", password: "jkl000", vault: "", updatedAt: "2026-08-04 13:00:00" },                  // ללא כספת
  { email: "moshe@example.com", password: "mno111", vault: JSON.stringify({ Salt: "s5", AccountsEncrypted: "vault-moshe" }), updatedAt: "2026-08-05 14:00:00" },
];

const old = createOldServer(OLD_INITIAL);
const oldBase = await old.start();
const { env, store } = createWorkerEnv("tok123");
const { server: ws, base: workerBase } = await startWorkerServer(env);

console.log("--- בדיקת הגירה: מצב יבש (dry-run) ---");
{
  const r = await runMigrate(oldBase, workerBase, ["--dry-run"]);
  check("dry-run: exit 0", r.status === 0, "status=" + r.status + " stderr=" + (r.stderr || "").slice(0, 200));
  check("dry-run: total=5", r.summary && r.summary.total === 5, JSON.stringify(r.summary));
  check("dry-run: ok=3 (שורות תקינות)", r.summary && r.summary.ok === 3, JSON.stringify(r.summary));
  check("dry-run: empty=1 (ללא כספת)", r.summary && r.summary.empty === 1, JSON.stringify(r.summary));
  check("dry-run: invalid=1 (כספת פגומה)", r.summary && r.summary.invalid === 1, JSON.stringify(r.summary));
  check("dry-run: migrated=3 (יועברו)", r.summary && r.summary.migrated === 3, JSON.stringify(r.summary));
  check("dry-run: failed=0", r.summary && r.summary.failed === 0, JSON.stringify(r.summary));
  check("dry-run: לא נכתב שום דבר ל-KV", store.size === 0, "store.size=" + store.size);
}

console.log("--- בדיקת הגירה: הגירה מלאה ---");
{
  const r = await runMigrate(oldBase, workerBase);
  check("הגירה: exit 0", r.status === 0, "status=" + r.status);
  check("הגירה: migrated=3", r.summary && r.summary.migrated === 3, JSON.stringify(r.summary));
  check("הגירה: failed=0", r.summary && r.summary.failed === 0, JSON.stringify(r.summary));

  const a = await postTo(workerBase, { action: "get_vault", email: "avraham@example.com" }, "tok123");
  const rv = await postTo(workerBase, { action: "get_vault", email: "rivka@example.com" }, "tok123");
  const mo = await postTo(workerBase, { action: "get_vault", email: "moshe@example.com" }, "tok123");
  const da = await postTo(workerBase, { action: "get_vault", email: "david@example.com" }, "tok123");
  const sa = await postTo(workerBase, { action: "get_vault", email: "sarah@example.com" }, "tok123");

  check("avraham הועבר עם vault מלא", a.registered === true && a.vault.includes("vault-avraham"), JSON.stringify(a));
  check("קידומת P_ הוסרה (abc123)", store.has("avraham@example.com") && JSON.parse(store.get("avraham@example.com")).password === "abc123", store.get("avraham@example.com"));
  check("קידומת ' הוסרה (def456)", JSON.parse(store.get("rivka@example.com")).password === "def456", store.get("rivka@example.com"));
  check("moshe הועבר", mo.registered === true && mo.vault.includes("vault-moshe"), JSON.stringify(mo));
  check("david (פגום) לא הועבר", da.registered !== true, JSON.stringify(da));
  check("sarah (ללא כספת) לא הועבר", sa.registered !== true, JSON.stringify(sa));
  check("get_vault מחזיר updatedAt (לסינכרון)", typeof a.updatedAt === "string" && a.updatedAt.length > 0, JSON.stringify(a));
}

console.log("--- בדיקת הגירה: הרצה חוזרת (הכל כבר מעודכן) ---");
{
  const before = JSON.stringify(Object.fromEntries(store));
  const r = await runMigrate(oldBase, workerBase);
  check("חוזר: exit 0", r.status === 0, "status=" + r.status);
  check("חוזר: skipped=3", r.summary && r.summary.skipped === 3, JSON.stringify(r.summary));
  check("חוזר: migrated=0", r.summary && r.summary.migrated === 0, JSON.stringify(r.summary));
  check("חוזר: שום דבר לא נדרס", JSON.stringify(Object.fromEntries(store)) === before);
}

console.log("--- תקופת מעבר כפולה: משתמש חדש-גרסה שומר לשרת החדש ---");
{
  // משתמש שעבר לגרסה החדשה ושמר כספת מעודכנת ישירות ל-Worker (updatedAt = עכשיו)
  await postTo(workerBase, { action: "save_vault", email: "rivka@example.com", password: "def456", vault: JSON.stringify({ Salt: "s2", AccountsEncrypted: "vault-rivka-NEW" }) }, "tok123");
  const r = await runMigrate(oldBase, workerBase);
  check("סינכרון: rivka נדלגה (החדש חדש יותר)", r.summary && r.summary.skipped >= 1 && r.summary.migrated === 0, JSON.stringify(r.summary));
  const rv = await postTo(workerBase, { action: "get_vault", email: "rivka@example.com" }, "tok123");
  check("הכספת החדשה של rivka לא נדרסה", rv.vault.includes("vault-rivka-NEW"), rv.vault);
}

console.log("--- תקופת מעבר כפולה: משתמש ישן-גרסה מעדכן את הגיליון ---");
{
  // משתמש שעוד בגרסה הישנה ושמר לגיליון אחרי ההגירה האחרונה (תאריך חדש יותר)
  const future = fmtUTC(new Date(Date.now() + 60000));
  old.mutate((rows) => {
    const idx = rows.findIndex((x) => x.email === "moshe@example.com");
    if (idx >= 0) {
      rows[idx] = { email: "moshe@example.com", password: "mno111", vault: JSON.stringify({ Salt: "s5", AccountsEncrypted: "vault-moshe-V2" }), updatedAt: future };
    }
    return rows;
  });
  const r = await runMigrate(oldBase, workerBase);
  check("סינכרון: moshe הועבר (גרסת הגיליון חדשה יותר)", r.summary && r.summary.migrated === 1, JSON.stringify(r.summary));
  const mo = await postTo(workerBase, { action: "get_vault", email: "moshe@example.com" }, "tok123");
  check("הכספת המעודכנת של moshe ב-KV", mo.vault.includes("vault-moshe-V2"), mo.vault);
  const rv = await postTo(workerBase, { action: "get_vault", email: "rivka@example.com" }, "tok123");
  check("rivka עדיין לא נדרסה", rv.vault.includes("vault-rivka-NEW"), rv.vault);
}

console.log("--- בדיקת --email (משתמש בודד) ---");
{
  old.mutate((rows) => [...rows, { email: "newuser@example.com", password: "xyz789", vault: JSON.stringify({ Salt: "s9", AccountsEncrypted: "vault-newuser" }), updatedAt: "2026-08-10 09:00:00" }]);
  const r = await runMigrate(oldBase, workerBase, ["--email", "newuser@example.com"]);
  check("--email: רק המשתמש הנבחר הועבר (migrated=1)", r.summary && r.summary.migrated === 1 && r.summary.total === 1, JSON.stringify(r.summary));
  const nu = await postTo(workerBase, { action: "get_vault", email: "newuser@example.com" }, "tok123");
  check("newuser נמצא ב-KV", nu.registered === true && nu.vault.includes("vault-newuser"), JSON.stringify(nu));

  const r2 = await runMigrate(oldBase, workerBase, ["--email", "unknown@example.com"]);
  check("--email של משתמש לא קיים -> exit 1", r2.status === 1, "status=" + r2.status + " stdout=" + JSON.stringify(r2.stdout).slice(0, 150) + " stderr=" + JSON.stringify(r2.stderr).slice(0, 150));
}

console.log("--- בדיקת --force (דריסה מכוונת) ---");
{
  const r = await runMigrate(oldBase, workerBase, ["--force"]);
  check("--force: כל התקינים נדרסו מחדש (migrated=ok, skipped=0)", r.summary && r.summary.migrated === r.summary.ok && r.summary.skipped === 0, JSON.stringify(r.summary));
}

console.log("--- בדיקת כשלונות ---");
{
  const r = await runMigrate("http://127.0.0.1:1", workerBase); // פורט סגור
  check("שרת ישן לא זמין -> exit 1", r.status === 1, "status=" + r.status);
  check("הודעת שגיאה ברורה", /export_all|--export-key|השרת הישן/.test(r.stdout), r.stdout.slice(0, 300));
}

await new Promise((resolve) => setTimeout(resolve, 100));
old.close();
ws.closeAllConnections?.();
ws.close();

console.log("\nתוצאה: " + passed + " עברו, " + failed + " נכשלו");
process.exit(failed === 0 ? 0 : 1);
