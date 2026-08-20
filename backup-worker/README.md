# 🛡️ שרת הגיבוי החדש — Cloudflare Worker + KV

קובץ יחיד (`worker.js`) שמחליף לחלוטין את `apps_script.js` (Google Apps Script + Google Sheets).
השרת שומר את הכספות המוצפנות ב-**Cloudflare KV** — חינם לצמיתות, תמיד פעיל, ללא הפניות (redirects),
מה שהופך אותו לפתרון אידיאלי גם תחת סינון **נטפרי** המחמיר.

> הנתונים נשארים מוצפנים במלואם בצד הלקוח (AES-GCM) — השרת רואה רק טקסט מוצפן,
> בדיוק כמו בגרסת גוגל. שום דבר לא משתנה עבור המשתמשים מלבד כתובת השרת.

---

## 📖 ה-API (אותו פרוטוקול בדיוק כמו הסקריפט הישן)

| פעולה | שיטה | פרמטרים | תשובה |
|---|---|---|---|
| `get_vault` | POST | `{ action, email }` | `{ success, registered, vault, updatedAt }` |
| `save_vault` | POST | `{ action, email, password, vault }` | `{ success, message }` |
| `ping` | GET | `?action=ping` | `{ success, message }` |

- `updatedAt` בתשובת `get_vault` הוא חותמת הזמן (UTC ISO) של השמירה האחרונה ב-KV.
  הוא לא מפריע ללקוחות (מתעלמים ממנו), ומשמש את סקריפט ההגירה לסינכרון בטוח.

- כל ה-POST נשלחים כ-JSON (השרת מקבל כל `Content-Type` — גם `text/plain` שהאתר שולח).
- האימייל נשמר באותיות קטנות — זהה להתנהגות הגיליון הישן.
- מגבלות הגנה: כספת גדולה מ-2MB נדחית (413), אימייל ארוך מ-254 תווים נדחה.

## 🔐 Token אופציונלי (מומלץ לאבטחה)

כברירת מחדל השרת פתוח — כל מי שמחזיק בכתובת ה-URL יכול לקרוא/לכתוב (כמו הסקריפט הישן).
כדי למנוע מאחרים לדרוס כספות גם אם מגלים את ה-URL:

1. ב-Worker: **Settings → Variables → Add → Secret** — שם: `API_TOKEN`, ערך: מחרוזת ארוכה ואקראית.
2. בלקוחות הגדר את אותו ערך:
   - `index.html` — הקבוע `DEVELOPER_API_TOKEN = ""` ליד ה-URL.
   - `MasterAuthenticator/MainWindow.xaml.cs` — הקבוע `DeveloperApiToken = ""`.
3. מרגע זה כל בקשה ללא ה-Token תקבל `401`.
   > ה-Token מוטבע בקובץ הלקוח שמופץ למשתמשים — הוא מגן מפני זרים, לא מפני משתמשים עצמם.
   > מכיוון שהנתונים מוצפנים בצד הלקוח, גם דריסת כספת אינה חושפת מידע — רק משביתה גישה זמנית.

## 🔁 הגדרת שחזור באמצעות מייל

פעולת `begin_recovery` משתמשת ב-Apps Script הישן כמתווך לשליחת המייל. ב-Cloudflare Worker הגדר:

- `LEGACY_SCRIPT_URL` — כתובת ה-Web App של Apps Script, המסתיימת ב-`/exec`.
- `RECOVERY_RELAY_KEY` — Secret זהה לערך `RECOVERY_RELAY_KEY` ב-Apps Script תחת **Project Settings → Script properties**.
- `RESET_BASE_URL` — כתובת האתר שאליה יפנה קישור השחזור (אופציונלי; ברירת המחדל היא האתר הרשמי).

ב-Apps Script יש להדביק את הגרסה העדכנית של `apps_script.js`, לוודא שקיימת הפעולה `send_reset_link`, לאשר הרשאת `MailApp`, ולפרוס מחדש כ-Web app עם גישה **Anyone**. לאחר מכן יש לבצע Deploy מחדש גם ל-Worker.

> חשוב: Apps Script מחזיר הפניית `302` לאחר בקשת `POST`. ה-Worker משתמש ב־`GET` של Apps Script עבור relay השחזור, ומעביר את הפרמטרים גם דרך ההפניה; פריסת Worker ישנה עדיין תחזיר `502` בעת בקשת שחזור.

---

## שלב 1: חשבון Cloudflare חינמי

1. כנס אל https://dash.cloudflare.com/sign-up וצור חשבון חינמי (אימייל + סיסמה).
2. אין צורך להעביר דומיין — אפשר להתחיל עם הדומיין החינמי של Cloudflare (`*.workers.dev`).

## שלב 2: יצירת ה-Worker

1. בתפריט הצדדי לחץ על **Workers & Pages** → **Create application** → **Create Worker**.
2. תן שם ל-Worker: `master-auth-backup` (השם הזה יופיע בכתובת ה-URL).
3. לחץ **Deploy** ואז **Edit code**.

## שלב 3: הדבקת הקוד

1. בעורך שנפתח, מחק את כל הקוד הקיים (Ctrl+A ואז Delete).
2. העתק את כל התוכן של הקובץ `worker.js` מתיקייה זו והדבק אותו בעורך.
3. לחץ על **Deploy** (הכפתור הכחול למעלה).

## שלב 4: יצירת האחסון (KV) וחיבורו

1. בתפריט הצדדי: **Workers & Pages** → **KV** → **Create a namespace**.
2. תן לו שם: `VAULT_KV` → **Create**.
3. חזור ל-**Workers & Pages** → לחץ על ה-Worker שלך (`master-auth-backup`).
4. עבור לכרטיסיית **Settings** → **Variables** → גלול ל-**KV Namespace Bindings** → לחץ **Edit** → **Add binding**:
   - **Variable name:** `VAULT_KV`
   - **KV namespace:** `VAULT_KV` (בחר מהרשימה)
   - לחץ **Save**.
5. במידת הצורך לחץ שוב **Deploy** (בכרטיסיית Deployments → **Deploy**).

## שלב 5: בדיקת החיבור

1. בעמוד ה-Worker שלך תראה את כתובת ה-URL: `https://master-auth-backup.XXXXXXXX.workers.dev`
   (ה-`XXXXXXXX` הוא סאבדומיין ייחודי של החשבון שלך).
2. פתח בדפדפן: `https://master-auth-backup.XXXXXXXX.workers.dev/?action=ping`
3. אמור לחזור JSON כזה:
   ```json
   {"success":true,"message":"Connection successful! Backup server is alive."}
   ```

## שלב 6: עדכון הלקוחות (שתי שורות בלבד)

**א. האתר (`index.html`)** — בשורה ~1863 החלף את הכתובת:

```js
const DEVELOPER_SCRIPT_URL = "https://master-auth-backup.XXXXXXXX.workers.dev";
```

**ב. אפליקציית הדסקטופ (`MasterAuthenticator/MainWindow.xaml.cs`)** — בשורה ~45:

```csharp
private const string DeveloperScriptUrl = "https://master-auth-backup.XXXXXXXX.workers.dev";
```

> החלף את `XXXXXXXX` בסאבדומיין האמיתי שלך (זה שנראה בשלב 5).
> את אותו שינוי יש לעשות גם בעותק האתר שב-`verification-app-repo/index.html`.

> ⚠️ **אחרי עדכון הקוד — חייבים לבנות מחדש את קובץ ה-EXE ולהפיץ אותו למשתמשים.**
> קובצי ה-EXE הקיימים מכילים עדיין את כתובת גוגל הישנה.

**בניית ה-EXE החדש (לאחר החלפת ה-URL בשורה 45):**

```bash
dotnet publish MasterAuthenticator/MasterAuthenticator.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true
```

הקובץ המופק: `MasterAuthenticator/bin/Release/net8.0-windows/win-x64/publish/MasterAuthenticator.exe`
(מחייב התקנת .NET 8 Desktop Runtime אצל המשתמשים. לחלופין, להסיר את `--self-contained false` כדי לקבל EXE עצמאי גדול יותר שאינו דורש התקנה).

## שלב 7 (מומלץ): דומיין מותאם אישית

כתובת `workers.dev` עובדת מצוין, אבל דומיין נקי משלך (למשל `backup.levtov.uk`) עדיף לסינון נטפרי:

1. הוסף את הדומיין שלך ל-Cloudflare (Workers & Pages → Your domain → Add a custom domain).
2. Cloudflare תבקש להעביר את רשומות ה-DNS של הדומיין אליה (תהליך של כמה דקות).
3. צור רשומת DNS מסוג CNAME: `backup` → `master-auth-backup.XXXXXXXX.workers.dev`.
4. ה-URL החדש: `https://backup.levtov.uk` — עדכן אותו בשתי שורות ה-URL בלקוחות.

## שלב 8: סינון נטפרי

1. **בדיקת שטח:** בקש מחבר עם הסינון המחמיר ביותר לפתוח את כתובת השרת (`/?action=ping`) בדפדפן.
2. **אם חסום:** החבר יכול מיידית להוסיף את הדומיין לרשימה הלבנה האישית שלו (בפרופיל האישי בנטפרי).
3. **פתרון קבוע:** הגש את הדומיין לבדיקת נטפרי (אימייל: `info@netfree.link` או טלפון: `07-2277-2255`).
   מכיוון שהשרת מחזיר רק JSON טקסטואלי ללא תמונות, הסיווג הצפוי הוא "גישה מלאה" ומהיר.

---

## 🔁 העברת נתונים מהגיליון הישן (הגירה)

כל המשתמשים הקיימים מאוחסנים בגיליון Google Sheets הישן (טבלת `Credentials`).
**לפני שמפסיקים את הסקריפט הישן יש להעביר את כל השורות לאחסון החדש** —
אחרת המשתמשים יופיעו כ"לא רשומים" וייאלצו ליצור כספת חדשה ריקה.

המדריך המלא, צעד-צעד (בדיקת עותק → הגירה → תקופת מעבר כפולה → סיום):
**→ קרא את [`MIGRATION.md`](MIGRATION.md) ←**

הכלים שמעורבים בהגירה:
- `migrate-from-sheets.mjs` — סקריפט ההגירה עצמו (דורש הוספת פעולת `export_all`
  לסקריפט הישן — הקוד וההוראות ב-`MIGRATION.md`).
- `migrate-test.mjs` — בדיקות ההגירה (33 בדיקות, כולל סימולציית תקופת מעבר כפולה).

## 🧪 בדיקות (129 בדיקות אוטומטיות)

כל ערכות הבדיקות רצות מהמקור עצמו — ללא עותקים וללא צורך בפריסה:

```bash
# 1. בדיקות הגירה: מריצות את סקריפט ההגירה האמיתי מול שרת "ישן" מדומה וה-Worker
#    האמיתי, כולל סימולציית תקופת מעבר כפולה (לא דורס נתונים חדשים) - 33 בדיקות
node backup-worker/migrate-test.mjs

# 2. בדיקות יחידה על לוגיקת השרת (פרוטוקול, CORS, Token, הגנות קלט) - 38 בדיקות
node backup-worker/test-worker.mjs

# 3. בדיקות אינטגרציה ברמת ה-Wire מול שרת HTTP אמיתי (כותרות, UTF-8, חוסר הפניות) - 25 בדיקות
node backup-worker/integration-test.mjs

# 4. בדיקות E2E של הקריפטוגרפיה האמיתית של האתר: מחלץ את הפונקציות מ-index.html
#    ובודק אותן מול וקטורי RFC 6238 רשמיים + מחזור הצפנה מלא דרך שרת אמיתי - 24 בדיקות
node backup-worker/e2e-crypto-test.mjs

# 5. בדיקות אינטרופ חוצה-שפות: כספת מ-HTML נפתחת בקוד ה-C# האמיתי ולהיפך,
#    וקודי TOTP זהים בשתי השפות - 9 בדיקות (דורש dotnet SDK)
node backup-worker/cross-csharp-test.mjs
```

דורש Node.js 18 ומעלה (בדיקה 4 דורשת גם dotnet SDK). כל הבדיקות אמורות לעבור (ירוק).

## 🔧 פתרון בעיות

| סימפטום | סיבה סבירה | פתרון |
|---|---|---|
| בדפדפן נפתחת הודעת שגיאה על שרת לא מוגדר | ה-URL עדיין עם `YOUR_WORKERS_SUBDOMAIN` | החלף את ה-placeholder בכתובת האמיתית (שלב 6) |
| `fetch failed` / "שגיאת תקשורת" באתר | כתובת שגויה או שה-Worker לא חי | בדוק `/?action=ping` בדפדפן |
| CORS error בדפדפן | ה-Worker לא עודכן לקוד החדש | הדבק מחדש את `worker.js` ולחץ Deploy |
| שגיאת `401` | Token מוגדר בשרת אבל לא בלקוח (או להיפך) | ודא ש-`API_TOKEN` זהה בשני הצדדים |
| שגיאת `522` / דף לא נפתח עם דומיין מותאם | רשומת ה-CNAME לא הוגדרה או לא התפשטה | בדוק את רשומות ה-DNS ב-Cloudflare |
| "הכספת בענן ריקה או פגומה" | המשתמש קיים בגיליון הישן שעדיין לא הועבר | הרץ את ההגירה (ראה MIGRATION.md) |
| אפליקציית הדסקטופ לא מסנכרנת בשקט | ה-URL עדיין placeholder (guard פעיל) | החלף את הכתובת ובנה מחדש את ה-EXE |

## 📊 גבולות התוכנית החינמית (די והותר לשימוש זה)

| משאב | כמות חינמית |
|---|---|
| בקשות ליום | 100,000 |
| אחסון KV | 1 GB |
| קריאות KV ליום | 100,000 |
| כתיבות KV ליום | 1,000 |

> אופציונלי: Cloudflare מציעה Rate Limiting Rules (בתוכנית החינמית יש חוק אחד)
> להגנה נוספת מפני ניצול לרעה — מוגדר ברמת הדומיין.

## אבטחה

- השרת שומר רק נתונים מוצפנים — אינו יכול לקרוא את הכספות.
- מודל האבטחה זהה למודל הישן (אפס-ידע): כל מי שמחזיק בכתובת ה-URL יכול לכתוב/לקרוא לפי אימייל.
- להגנה נוספת מפני זרים: הגדר את `API_TOKEN` (ראה למעלה).
