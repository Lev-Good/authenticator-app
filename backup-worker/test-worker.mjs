/**
 * בדיקות אוטומטיות ללוגיקת ה-Worker (backup-worker/worker.js)
 * הרצה:  node backup-worker/test-worker.mjs
 * דורש: Node.js 18 ומעלה (כולל Request/Response גלובליים)
 */
import worker from "./worker.js";

function createEnv(apiToken) {
  const store = new Map();
  const env = {
    API_TOKEN: apiToken || "",
    VAULT_KV: {
      async get(key, type) {
        const v = store.get(key);
        if (v === undefined) return null;
        return type === "json" ? JSON.parse(v) : v;
      },
      async put(key, value) {
        store.set(key, value);
      },
    },
  };
  return { env, store };
}

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

async function call(env, path, init) {
  const req = new Request("https://example.com" + path, init);
  const res = await worker.fetch(req, env);
  let body = null;
  try { body = await res.json(); } catch { body = null; }
  return { status: res.status, headers: res.headers, body };
}

const { env } = createEnv("");

console.log("--- מצב: ללא API_TOKEN (ברירת מחדל, פתוח) ---");

console.log("1) ping דרך GET:");
{
  const r = await call(env, "/?action=ping");
  check("status 200", r.status === 200, "status=" + r.status);
  check("success=true", r.body && r.body.success === true);
  check("CORS header", r.headers.get("Access-Control-Allow-Origin") === "*");
  check("nosniff header", r.headers.get("X-Content-Type-Options") === "nosniff");
  check("no-store header", r.headers.get("Cache-Control") === "no-store");
}

console.log("2) get_vault לאימייל לא רשום:");
{
  const r = await call(env, "/", {
    method: "POST",
    headers: { "Content-Type": "text/plain;charset=utf-8" }, // כמו שהאתר שולח
    body: JSON.stringify({ action: "get_vault", email: "new@example.com" }),
  });
  check("registered=false", r.body && r.body.registered === false);
  check("success=true", r.body && r.body.success === true);
}

console.log("3) save_vault ואז get_vault:");
{
  const vault = JSON.stringify({ Salt: "abc", AccountsEncrypted: "xyz" });
  const r1 = await call(env, "/", {
    method: "POST",
    headers: { "Content-Type": "application/json" }, // כמו שהדסקטופ שולח
    body: JSON.stringify({ action: "save_vault", email: "New@Example.COM", password: "hash123", vault }),
  });
  check("save success", r1.body && r1.body.success === true, JSON.stringify(r1.body));

  const r2 = await call(env, "/", {
    method: "POST",
    headers: { "Content-Type": "text/plain;charset=utf-8" },
    body: JSON.stringify({ action: "get_vault", email: "new@example.com" }), // אימייל באותיות קטנות
  });
  check("registered=true", r2.body && r2.body.registered === true);
  check("vault תואם", r2.body && r2.body.vault === vault, JSON.stringify(r2.body));
  check("אין סיסמה חשופה בתגובה", r2.body && !("password" in r2.body));
}

console.log("4) save_vault חסר שדות:");
{
  const r = await call(env, "/", {
    method: "POST",
    body: JSON.stringify({ action: "save_vault", email: "a@b.com" }),
  });
  check("שגיאה מוחזרת", r.body && r.body.success === false);
}

console.log("5) פעולה לא ידועה, פרמטר חסר ו-body לא JSON:");
{
  const r1 = await call(env, "/", { method: "POST", body: JSON.stringify({ action: "nope" }) });
  check("unknown action", r1.body && r1.body.success === false);
  const r2 = await call(env, "/", { method: "POST", body: "not-json" });
  check("body לא JSON לא קורס", r2.body && r2.body.success === false);
  const r3 = await call(env, "/", { method: "POST", body: JSON.stringify({}) });
  check("missing action", r3.body && r3.body.success === false);
  const r4 = await call(env, "/", { method: "POST", body: "null" }); // גוף JSON null
  check("גוף null -> 400 (לא 500)", r4.status === 400, "status=" + r4.status);
  const r5 = await call(env, "/", { method: "POST", body: "[]" }); // גוף מערך
  check("גוף מערך -> 400", r5.status === 400, "status=" + r5.status);
  const r6 = await call(env, "/", { method: "POST", body: "\"טקסט\"" }); // גוף מחרוזת
  check("גוף מחרוזת -> 400", r6.status === 400, "status=" + r6.status);
  const r7 = await call(env, "/", { method: "POST", body: "123" }); // גוף מספר
  check("גוף מספר -> 400", r7.status === 400, "status=" + r7.status);
}

console.log("6) הגנה על תוכן הכספת (vault):");
{
  const bad1 = await call(env, "/", {
    method: "POST",
    body: JSON.stringify({ action: "save_vault", email: "x@y.com", password: "h", vault: "לא-json" }),
  });
  check("vault לא JSON -> 400", bad1.status === 400, "status=" + bad1.status);
  const bad2 = await call(env, "/", {
    method: "POST",
    body: JSON.stringify({ action: "save_vault", email: "x@y.com", password: "h", vault: "123" }),
  });
  check("vault פרימיטיבי -> 400", bad2.status === 400, "status=" + bad2.status);
  const ok = await call(env, "/", {
    method: "POST",
    body: JSON.stringify({ action: "save_vault", email: "x@y.com", password: "h", vault: JSON.stringify({ a: 1 }) }),
  });
  check("vault אובייקט תקין נשמר", ok.body && ok.body.success === true);
}

console.log("7) KV binding חסר:");
{
  const req = new Request("https://example.com/?action=ping");
  const res = await worker.fetch(req, {}); // env ריק - ללא VAULT_KV
  const body = await res.json();
  check("status 500", res.status === 500, "status=" + res.status);
  check("הודעת שגיאה ברורה על KV", body && body.success === false && /KV/i.test(body.message), JSON.stringify(body));
}

console.log("8) OPTIONS preflight:");
{
  const r = await call(env, "/", { method: "OPTIONS" });
  check("status 204", r.status === 204, "status=" + r.status);
  check("Access-Control-Allow-Origin", r.headers.get("Access-Control-Allow-Origin") === "*");
  check("Authorization ב-Allow-Headers", (r.headers.get("Access-Control-Allow-Headers") || "").includes("Authorization"));
}

console.log("9) עדכון כספת קיימת (overwrite):");
{
  const r = await call(env, "/", {
    method: "POST",
    body: JSON.stringify({ action: "save_vault", email: "new@example.com", password: "h2", vault: JSON.stringify({ v: 2 }) }),
  });
  const r2 = await call(env, "/", { method: "POST", body: JSON.stringify({ action: "get_vault", email: "new@example.com" }) });
  check("הכספת עודכנה", r.body && r.body.success && r2.body && r2.body.vault === JSON.stringify({ v: 2 }));
}

console.log("10) כספת גדולה מדי נדחית:");
{
  const big = "x".repeat(3 * 1024 * 1024); // 3MB - מעבר ל-MAX_VAULT_SIZE
  const r = await call(env, "/", {
    method: "POST",
    body: JSON.stringify({ action: "save_vault", email: "big@example.com", password: "h", vault: big }),
  });
  check("status 413", r.status === 413, "status=" + r.status);
  check("success=false", r.body && r.body.success === false);
}

console.log("11) GET לא חוקי (PUT):");
{
  const r = await call(env, "/", { method: "PUT" });
  check("status 405", r.status === 405, "status=" + r.status);
}

console.log("\n--- מצב: עם API_TOKEN (מוגדר) ---");

const { env: envT } = createEnv("secret123");

console.log("12) ללא Token - נדחה:");
{
  const r = await call(envT, "/", {
    method: "POST",
    body: JSON.stringify({ action: "get_vault", email: "new@example.com" }),
  });
  check("status 401", r.status === 401, "status=" + r.status);
  check("success=false", r.body && r.body.success === false);
}

console.log("13) Token נכון ב-Header Authorization:");
{
  const r = await call(envT, "/", {
    method: "POST",
    headers: { Authorization: "Bearer secret123" },
    body: JSON.stringify({ action: "get_vault", email: "new@example.com" }),
  });
  check("status 200", r.status === 200, "status=" + r.status);
}

console.log("14) Token נכון ב-Query (GET):");
{
  const r = await call(envT, "/?action=ping&token=secret123");
  check("ping מצליח", r.body && r.body.success === true);
}

console.log("15) Token לא נכון נדחה:");
{
  const r = await call(envT, "/", {
    method: "POST",
    headers: { Authorization: "Bearer wrong" },
    body: JSON.stringify({ action: "get_vault", email: "new@example.com" }),
  });
  check("status 401", r.status === 401, "status=" + r.status);
  const r2 = await call(envT, "/?action=ping&token=wrong");
  check("GET עם Token שגוי נדחה", r2.status === 401);
}

console.log("16) OPTIONS עדיין עובד עם Token מוגדר (בלי Token):");
{
  const r = await call(envT, "/", { method: "OPTIONS" });
  check("status 204", r.status === 204, "status=" + r.status);
}

console.log("\nתוצאה: " + passed + " עברו, " + failed + " נכשלו");
process.exit(failed === 0 ? 0 : 1);
