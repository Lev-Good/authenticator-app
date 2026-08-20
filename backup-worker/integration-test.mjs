/**
 * בדיקת אינטגרציה ברמת ה-Wire - מריץ את ה-Worker מאחורי שרת HTTP אמיתי
 * ובודק את הפרוטוקול המלא: סטטוסים, כותרות, UTF-8, חוסר הפניות, ו-Token.
 *
 * הרצה:  node backup-worker/integration-test.mjs
 * דורש: Node.js 18 ומעלה
 */
import http from "node:http";
import worker from "./worker.js";

function createEnv(apiToken) {
  const store = new Map();
  return {
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

// מריץ את ה-Worker מאחורי שרת HTTP אמיתי
async function startServer(env) {
  const server = http.createServer(async (req, res) => {
    try {
      let body = "";
      for await (const chunk of req) body += chunk;
      const headers = {};
      for (const [k, v] of Object.entries(req.headers)) {
        headers[k] = Array.isArray(v) ? v.join(", ") : v;
      }
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
  const port = server.address().port;
  return { server, base: `http://127.0.0.1:${port}` };
}

const noRedirectStatuses = [];

async function raw(base, path, init) {
  const res = await fetch(base + path, init);
  noRedirectStatuses.push(res.status);
  let body = null;
  try { body = await res.json(); } catch { body = null; }
  return { status: res.status, headers: res.headers, body };
}

const { server, base } = await startServer(createEnv(""));
const { server: serverT, base: baseT } = await startServer(createEnv("secret123"));

console.log("--- בדיקות Wire: ללא Token ---");

{
  const r = await raw(base, "/?action=ping");
  check("ping: status 200", r.status === 200, "status=" + r.status);
  check("ping: success=true", r.body && r.body.success === true, JSON.stringify(r.body));
  check("ping: Content-Type JSON", (r.headers.get("content-type") || "").includes("application/json"));
  check("ping: Access-Control-Allow-Origin *", r.headers.get("access-control-allow-origin") === "*");
  check("ping: Cache-Control no-store", r.headers.get("cache-control") === "no-store");
  check("ping: X-Content-Type-Options nosniff", r.headers.get("x-content-type-options") === "nosniff");
}

{
  const vault = JSON.stringify({ Salt: "abc", AccountsEncrypted: "נתונים מוצפנים בעברית 🛡️🔐" });
  const r1 = await raw(base, "/", {
    method: "POST",
    headers: { "Content-Type": "text/plain;charset=utf-8" }, // כמו שהאתר שולח
    body: JSON.stringify({ action: "save_vault", email: "user@example.com", password: "hash", vault }),
  });
  check("save: success", r1.body && r1.body.success === true, JSON.stringify(r1.body));
  check("save: הודעה בעברית", r1.body && typeof r1.body.message === "string" && r1.body.message.length > 0);

  const r2 = await raw(base, "/", {
    method: "POST",
    headers: { "Content-Type": "application/json" }, // כמו שהדסקטופ שולח
    body: JSON.stringify({ action: "get_vault", email: "user@example.com" }),
  });
  check("get: registered=true", r2.body && r2.body.registered === true);
  check("get: vault שלם עם עברית ואמוג'י", r2.body && r2.body.vault === vault, JSON.stringify(r2.body && r2.body.vault));
}

{
  const r = await raw(base, "/", { method: "OPTIONS" });
  check("OPTIONS: status 204", r.status === 204, "status=" + r.status);
  check("OPTIONS: Allow-Methods", (r.headers.get("access-control-allow-methods") || "").includes("POST"));
  check("OPTIONS: Allow-Headers כולל Authorization", (r.headers.get("access-control-allow-headers") || "").includes("Authorization"));
}

console.log("--- בדיקות הגנה על קלט ---");

{
  const r1 = await raw(base, "/", { method: "POST", body: "null" }); // JSON null
  check("גוף null -> 400 (לא 500!)", r1.status === 400, "status=" + r1.status + " " + JSON.stringify(r1.body));
  const r2 = await raw(base, "/", { method: "POST", body: "[]" }); // מערך
  check("גוף מערך -> 400", r2.status === 400, "status=" + r2.status);
  const r3 = await raw(base, "/", { method: "POST", body: '"טקסט"' }); // מחרוזת
  check("גוף מחרוזת -> 400", r3.status === 400, "status=" + r3.status);
  const r4 = await raw(base, "/", { method: "POST", body: "123" }); // מספר
  check("גוף מספר -> 400", r4.status === 400, "status=" + r4.status);
}

{
  const r1 = await raw(base, "/", {
    method: "POST",
    body: JSON.stringify({ action: "save_vault", email: "a@b.com", password: "h", vault: "לא-json" }),
  });
  check("vault לא JSON -> 400", r1.status === 400, "status=" + r1.status);
  const r2 = await raw(base, "/", {
    method: "POST",
    body: JSON.stringify({ action: "save_vault", email: "a@b.com", password: "h", vault: "123" }),
  });
  check("vault פרימיטיבי -> 400", r2.status === 400, "status=" + r2.status);
}

{
  const r = await raw(base, "/", { method: "PUT" });
  check("PUT -> 405", r.status === 405, "status=" + r.status);
  const r2 = await raw(base, "/", { method: "POST", body: "" });
  check("גוף ריק -> Missing action", r2.body && r2.body.success === false, JSON.stringify(r2.body));
}

console.log("--- בדיקות Wire: עם Token ---");

{
  const r0 = await raw(baseT, "/", {
    method: "POST",
    body: JSON.stringify({ action: "get_vault", email: "a@b.com" }),
  });
  check("ללא Token -> 401", r0.status === 401, "status=" + r0.status);

  const r1 = await raw(baseT, "/", {
    method: "POST",
    headers: { Authorization: "Bearer secret123" },
    body: JSON.stringify({ action: "get_vault", email: "a@b.com" }),
  });
  check("Token נכון ב-Header -> 200", r1.status === 200, "status=" + r1.status);

  const r2 = await raw(baseT, "/", {
    method: "POST",
    headers: { Authorization: "Bearer wrong" },
    body: JSON.stringify({ action: "get_vault", email: "a@b.com" }),
  });
  check("Token שגוי -> 401", r2.status === 401, "status=" + r2.status);
}

console.log("--- בדיקת חוסר הפניות (Redirects) ---");
{
  const redirects = noRedirectStatuses.filter((s) => s >= 300 && s < 400);
  check("אף תשובה אינה הפנייה (3xx)", redirects.length === 0, "redirects found: " + redirects.join(","));
}

// סגירה אסינכרונית מלאה + השהיית ניקוז קצרה:
// מונעת קריסת teardown ידועה של Node על Windows (libuv) עם חיבורים פתוחים.
await new Promise((resolve) => {
  server.closeAllConnections?.();
  serverT.closeAllConnections?.();
  server.close(() => serverT.close(() => resolve()));
});
await new Promise((resolve) => setTimeout(resolve, 150));

console.log("\nתוצאה: " + passed + " עברו, " + failed + " נכשלו");
process.exit(failed === 0 ? 0 : 1);
