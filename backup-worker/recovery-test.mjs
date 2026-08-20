import worker from "./worker.js";

const store = new Map();
let relayBody = null;
let relayRequestCount = 0;
let redirectedRelayMethod = "";
const originalFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  relayRequestCount++;
  redirectedRelayMethod = init.method;
  if (relayRequestCount === 1) {
    return new Response(null, {
      status: 302,
      headers: { Location: "https://script.googleusercontent.com/macros/echo" },
    });
  }

  const redirectedUrl = new URL(url);
  relayBody = Object.fromEntries(redirectedUrl.searchParams);
  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
};

const env = {
  API_TOKEN: "",
  LEGACY_SCRIPT_URL: "https://script.google.com/macros/s/test/exec",
  RECOVERY_RELAY_KEY: "relay-secret",
  RESET_BASE_URL: "https://example.test/",
  VAULT_KV: {
    async get(key, type) {
      const value = store.get(key);
      if (value === undefined) return null;
      return type === "json" ? JSON.parse(value) : value;
    },
    async put(key, value) { store.set(key, value); },
    async delete(key) { store.delete(key); },
  },
};

async function call(body) {
  const response = await worker.fetch(new Request("https://worker.test/", {
    method: "POST",
    body: JSON.stringify(body),
  }), env);
  return { status: response.status, body: await response.json() };
}

let passed = 0;
let failed = 0;
function check(name, condition, extra = "") {
  if (condition) {
    passed++;
    console.log("  ✔ " + name);
  } else {
    failed++;
    console.log("  ✘ " + name + (extra ? " -> " + extra : ""));
  }
}

console.log("--- בדיקת שחזור מאובטח ---");
const recoveryPackage = {
  ciphertext: "encrypted-accounts",
  iv: "iv",
  tag: "tag",
};
const save = await call({
  action: "save_vault",
  email: "user@example.com",
  password: "hash",
  vault: JSON.stringify({ Salt: "s", AccountsEncrypted: "a" }),
  recoveryKey: "recovery-key",
  recoveryPackage,
});
check("שמירת חבילת שחזור", save.status === 200 && save.body.success === true);

const begin = await call({ action: "begin_recovery", email: "user@example.com" });
check("בקשת שחזור מצליחה", begin.status === 200 && begin.body.success === true);
check("המתווך קיבל בקשת מייל", relayBody && relayBody.action === "send_reset_link");
check("הפניית Apps Script נשמרה כ-GET עם פרמטרים", relayRequestCount === 2 && redirectedRelayMethod === "GET" && relayBody && relayBody.email === "user@example.com");
check("נשלח מפתח שחזור למתווך", relayBody && relayBody.recovery_key === "recovery-key");
check("נשלח token בקישור", relayBody && /reset=/.test(relayBody.reset_url));

const token = new URL(relayBody.reset_url).searchParams.get("reset");
const recovered = await call({
  action: "recover_vault",
  email: "user@example.com",
  token,
  recoveryKey: "recovery-key",
});
check("שליפת חבילת שחזור עם מפתח נכון", recovered.status === 200 && recovered.body.success === true);
check("חבילת השחזור תואמת", JSON.stringify(recovered.body.recoveryPackage) === JSON.stringify(recoveryPackage));

const wrong = await call({
  action: "recover_vault",
  email: "user@example.com",
  token,
  recoveryKey: "wrong-key",
});
check("מפתח שגוי נדחה", wrong.status === 401);

const resetSave = await call({
  action: "save_vault",
  email: "user@example.com",
  password: "new-hash",
  vault: JSON.stringify({ Salt: "new", AccountsEncrypted: "new-a" }),
  recoveryKey: "recovery-key",
  recoveryPackage,
  resetToken: token,
});
check("שמירה עם resetToken מצליחה", resetSave.status === 200 && resetSave.body.success === true);
const reused = await call({
  action: "recover_vault",
  email: "user@example.com",
  token,
  recoveryKey: "recovery-key",
});
check("ה-token חד-פעמי", reused.status === 401);

// לקוח מאובטח (secure-v1): הכספת נשמרה עם גיבוב אימות, ושחזור עם סיסמה
// חדשה חייב לעבוד — קישור האיפוס הוא האישור לכתיבה, לא גיבוב הסיסמה הישנה.
const secureEmail = "secure@example.com";
const secureSave = await call({
  action: "save_vault",
  email: secureEmail,
  password: "old-hash",
  vault: JSON.stringify({ Salt: "s", AccountsEncrypted: "a" }),
  recoveryKey: "secure-recovery-key",
  recoveryPackage,
  clientVersion: "secure-v1",
});
check("שמירת כספת מאובטחת עם גיבוב אימות", secureSave.status === 200 && secureSave.body.success === true);

const secureBegin = await call({ action: "begin_recovery", email: secureEmail });
check("בקשת שחזור לחשבון מאובטח", secureBegin.status === 200 && secureBegin.body.success === true);
const secureToken = new URL(relayBody.reset_url).searchParams.get("reset");
const secureRecovered = await call({
  action: "recover_vault",
  email: secureEmail,
  token: secureToken,
  recoveryKey: "secure-recovery-key",
});
check("שליפת חבילת שחזור מאובטחת", secureRecovered.status === 200 && secureRecovered.body.success === true);

const secureResetSave = await call({
  action: "save_vault",
  email: secureEmail,
  password: "new-hash",
  vault: JSON.stringify({ Salt: "new", AccountsEncrypted: "new-a" }),
  recoveryKey: "secure-recovery-key",
  recoveryPackage,
  resetToken: secureToken,
  clientVersion: "secure-v1",
});
check("שחזור כספת מאובטחת עם סיסמה חדשה מצליח", secureResetSave.status === 200 && secureResetSave.body.success === true);

// פריסה ישנה של Apps Script אינה מכירה את send_reset_link; ה-Worker צריך
// לנסות את ה-deployment החדש הידוע במקום להחזיר 502 מיד.
const fallbackEmail = "fallback@example.com";
const fallbackSave = await call({
  action: "save_vault",
  email: fallbackEmail,
  password: "hash",
  vault: JSON.stringify({ Salt: "s", AccountsEncrypted: "a" }),
  recoveryKey: "recovery-key",
  recoveryPackage,
});
check("הכנת משתמש לבדיקת fallback", fallbackSave.status === 200 && fallbackSave.body.success === true);
relayRequestCount = 0;
globalThis.fetch = async () => {
  relayRequestCount++;
  if (relayRequestCount === 1) {
    return new Response(JSON.stringify({ success: false, message: "Unknown action: send_reset_link" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }
  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
};
const fallbackBegin = await call({ action: "begin_recovery", email: fallbackEmail });
check("fallback ל-deployment החדש מצליח", fallbackBegin.status === 200 && fallbackBegin.body.success === true && relayRequestCount === 2);

globalThis.fetch = originalFetch;
console.log("\nתוצאה: " + passed + " עברו, " + failed + " נכשלו");
process.exit(failed === 0 ? 0 : 1);
