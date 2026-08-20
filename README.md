# 🛡️ Master Authenticator

מנהל סיסמאות מאסטר ו**קודי אימות דו-שלבי (TOTP)** — חינמי, פתוח ובעיצוב מודרני.
הנתונים מוצפנים **בצד הלקוח** (AES-GCM) — השרת רואה רק טקסט מוצפן ואינו יכול לקרוא את הכספות (אפס-ידע).

| רכיב | מיקום | תיאור |
|---|---|---|
| 🌐 **אתר** | `index.html` + `sw.js` (שורש המאגר) | האתר החי: https://lev-good.github.io/authenticator-app/ |
| 🖥️ **אפליקציית דסקטופ** | `MasterAuthenticator/` | WPF (.NET 8) — ניהול חשבונות, קודי TOTP, סנכרון לענן, שחזור במייל |
| ☁️ **שרת גיבוי** | `backup-worker/` | Cloudflare Worker + KV — אחסון כספות מוצפנות, שליחת קישורי שחזור |
| 📧 **סקריפט שחזור** | `backup-worker/apps_script.js` | Google Apps Script לשליחת מייל השחזור (relay) |

## ⬇️ הורדה

המהדורות הרשמיות (עם קובץ ה-EXE): **[Releases](https://github.com/Lev-Good/authenticator-app/releases)**

האתר החי: **[https://lev-good.github.io/authenticator-app/](https://lev-good.github.io/authenticator-app/)**

> ה-EXE דורש **.NET 8 Desktop Runtime**. לחלופין אפשר לבנות EXE עצמאי ללא התקנה (ראה בנייה).

## 🔐 מודל האבטחה

- הכספת (חשבונות + קודי גיבוי) מוצפנת ב-**AES-GCM** עם מפתח שנגזר מסיסמת המאסטר (PBKDF2) — השרת שומר רק את הטקסט המוצפן.
- השרת מאמת כתיבה דרך **גיבוב סיסמה** (`secureAuthHash`) — לא נשלחת הסיסמה עצמה.
- **שחזור סיסמה**: שליחת קישור חד-פעמי (15 דק') ומפתח שחזור במייל; המשתמש בוחר סיסמה חדשה מבלי לשלוח את הישנה.
- `API_TOKEN` אופציונלי בשרת מגן מפני זרים שדורסים כספות (מוגדר כ-Secret ב-Cloudflare).

## 📴 מצב אופליין (פרטיות) — החל מגרסה 1.2.0

מי שלא סומך על השרת יכול לעבוד **באופליין מלא** — התוכנה לא יוצרת שום קשר עם השרת:

- בהפעלה הראשונה מוצג **אשף בחירת מצב**: ☁️ מסונכרן עם השרת (ברירת מחדל) או 📴 אופליין מלא.
- במצב אופליין: הכספת נשמרת מקומית בלבד (`%LOCALAPPDATA%\MasterAuthenticator`), בלי גיבוי בענן, בלי שחזור במייל ובלי סנכרון אוטומטי כשחוזרת הרשת.
- אפשר לעבור בין המצבים בכל זמן מהכרטיסייה **הגדרות ואבטחה** → **מצב סנכרון עם השרת**; ההעדפה נשמרת בקובץ `settings.json` מקומי.
- מעבר חזרה למצב מסונכרן מעלה אוטומטית כל שינוי שהמתין מקומית.

## 🖥️ בניית אפליקציית הדסקטופ

```bash
dotnet publish MasterAuthenticator/MasterAuthenticator.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true
```

הפלט: `MasterAuthenticator/bin/Release/net8.0-windows/win-x64/publish/MasterAuthenticator.exe`

## ☁️ פריסת שרת הגיבוי (Cloudflare)

1. צור Worker בשם `master-auth-backup` והדבק את `backup-worker/worker.js`.
2. צור KV namespace בשם `VAULT_KV` וקשור אותו ל-Worker.
3. הגדר Secret-ים: `API_TOKEN`, `LEGACY_SCRIPT_URL`, `RECOVERY_RELAY_KEY` (ראה `backup-worker/README.md`).
4. פרס גרסה חדשה ב-Cloudflare.

## 🧪 בדיקות

כל הבדיקות רצות מהמקור ללא פריסה (דורש Node.js 18+; בדיקת cross דורשת dotnet SDK):

```bash
node backup-worker/migrate-test.mjs      # 33 בדיקות הגירה
node backup-worker/test-worker.mjs       # 38 בדיקות שרת
node backup-worker/integration-test.mjs  # 25 בדיקות Wire
node backup-worker/e2e-crypto-test.mjs   # 24 בדיקות קריפטו E2E
node backup-worker/cross-csharp-test.mjs # 9 בדיקות C# <-> HTML
node backup-worker/recovery-test.mjs     # 17 בדיקות שחזור
```

## 📄 רישיון

[GPL-3.0](LICENSE) — כל נגזרת של הקוד חייבת להישאר קוד פתוח.
