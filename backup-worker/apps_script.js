/**
 * Google Apps Script - Master Authenticator Backend
 * 
 * סקריפט זה מיועד לפריסה כאפליקציית אינטרנט (Web App) בגוגל סקריפט המקושר לגיליון גוגל שיטס.
 * תפקיד הסקריפט:
 * 1. לשמור ולעדכן את סיסמת המאסטר עבור כתובת אימייל מסוימת בגיליון.
 * 2. לשלוח מייל מעוצב, יוקרתי ומאובטח המכיל את הסיסמה לכתובת האימייל במידה והמשתמש שכח אותה.
 */

// הגדרת כותרות לגיליון (אם הוא חדש)
const COLUMN_EMAIL = 1;
const COLUMN_PASSWORD = 2;
const COLUMN_TIMESTAMP = 3;
const COLUMN_VAULT = 4;

// [הגירה בלבד] מפתח גישה לפעולת export_all.
// הגדר כאן מחרוזת אקראית ארוכה (למשל 20+ תווים) לפני ההגירה, כדי שרק אתה תוכל לייצא.
// אם נשאיר ריק - הפעולה פתוחה לכל מי שמחזיק בכתובת הסקריפט.
const EXPORT_KEY = "";

/**
 * פונקציה ראשית לקבלת בקשות POST (כתיבה/עדכון ושחזור)
 */
function doPost(e) {
  return handleRequest(e);
}

/**
 * פונקציה ראשית לקבלת בקשות GET (כדי לאפשר בדיקת חיבור פשוטה או שחזור קל)
 */
function doGet(e) {
  return handleRequest(e);
}

/**
 * טיפול מרכזי בכל סוגי הבקשות
 */
function handleRequest(e) {
  // הגדרת כותרות תגובה לפתרון בעיות CORS בדפדפן
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type"
  };
  
  try {
    let params = {};
    
    // ניתוח פרמטרים מתוך בקשת POST (JSON או פורמט רגיל) או בקשת GET
    if (e && e.postData && e.postData.contents) {
      try {
        params = JSON.parse(e.postData.contents);
      } catch (ex) {
        params = e.parameter;
      }
    } else if (e && e.parameter) {
      params = e.parameter;
    }
    
    const action = params.action;
    const email = params.email ? params.email.trim().toLowerCase() : "";
    const password = params.password ? params.password.trim() : "";
    
    if (!action) {
      return jsonResponse({ success: false, message: "Missing action parameter" }, headers);
    }
    
    // התחברות לגיליון הנוכחי
    const sheet = getOrCreateSheet();
    
    if (action === "save") {
      if (!email || !password) {
        return jsonResponse({ success: false, message: "Email and password are required" }, headers);
      }
      
      const result = savePasswordToSheet(sheet, email, password);
      return jsonResponse(result, headers);
      
    } else if (action === "save_vault") {
      const vault = params.vault ? params.vault.toString().trim() : "";
      if (!email || !password || !vault) {
        return jsonResponse({ success: false, message: "Email, password and vault are required" }, headers);
      }
      
      const result = saveVaultToSheet(sheet, email, password, vault);
      return jsonResponse(result, headers);
      
    } else if (action === "get_vault") {
      if (!email) {
        return jsonResponse({ success: false, message: "Email is required" }, headers);
      }
      
      const result = getVaultFromSheet(sheet, email);
      return jsonResponse(result, headers);
      
    } else if (action === "recover") {
      if (!email) {
        return jsonResponse({ success: false, message: "Email is required" }, headers);
      }
      
      const result = recoverPasswordAndSendEmail(sheet, email);
      return jsonResponse(result, headers);
      
    } else if (action === "send_reset_link") {
      // [שחזור חדש] Apps Script משמש רק כמתווך לשליחת מייל.
      const relayKey = PropertiesService.getScriptProperties().getProperty("RECOVERY_RELAY_KEY") || "";
      if (!relayKey || params.relay_key !== relayKey) {
        return jsonResponse({ success: false, message: "Unauthorized" }, headers);
      }
      if (!email || !params.reset_url || !params.recovery_key) {
        return jsonResponse({ success: false, message: "Email, reset URL and recovery key are required" }, headers);
      }
      const result = sendResetLinkEmail(
        email,
        params.reset_url.toString(),
        params.recovery_key.toString()
      );
      return jsonResponse(result, headers);
      
    } else if (action === "export_all") {
      // [הגירה בלבד] ייצוא כל השורות לשרת החדש (Cloudflare Worker).
      // אם הוגדר EXPORT_KEY, רק מי שמעביר אותו נכון יקבל את הנתונים.
      if (EXPORT_KEY && params.export_key !== EXPORT_KEY) {
        return jsonResponse({ success: false, message: "Unauthorized" }, headers);
      }
      
      const result = exportAllFromSheet(sheet);
      return jsonResponse(result, headers);
      
    } else if (action === "ping") {
      return jsonResponse({ success: true, message: "Connection successful! Apps Script is alive." }, headers);
    }
    
    return jsonResponse({ success: false, message: "Unknown action: " + action }, headers);
    
  } catch (error) {
    return jsonResponse({ success: false, message: "Server error: " + error.toString() }, headers);
  }
}

/**
 * מחזיר תגובת JSON תקינה לדפדפן
 */
function jsonResponse(data, headers) {
  const output = ContentService.createTextOutput(JSON.stringify(data))
                               .setMimeType(ContentService.MimeType.JSON);
  return output;
}

/**
 * מקבל או יוצר את הגיליון הייעודי לשמירת נתונים
 */
function getOrCreateSheet() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName("Credentials");
  
  if (!sheet) {
    sheet = ss.insertSheet("Credentials");
    // כתיבת שורת כותרת בולטת ומעוצבת
    sheet.appendRow(["כתובת אימייל (Email)", "סיסמת מאסטר (Master Password)", "תאריך עדכון אחרון (Last Updated)", "נתוני כספת מוצפנים (Vault Data)"]);
    
    // עיצוב שורת כותרת
    const headerRange = sheet.getRange(1, 1, 1, 4);
    headerRange.setFontWeight("bold");
    headerRange.setBackground("#1a73e8");
    headerRange.setFontColor("#ffffff");
    headerRange.setHorizontalAlignment("center");
    sheet.setColumnWidth(1, 250);
    sheet.setColumnWidth(2, 250);
    sheet.setColumnWidth(3, 200);
    sheet.setColumnWidth(4, 400);
  }
  return sheet;
}

/**
 * שומר או מעדכן את הסיסמה בגיליון
 */
function savePasswordToSheet(sheet, email, password) {
  const data = sheet.getDataRange().getValues();
  let foundRow = -1;
  
  // חיפוש האם האימייל כבר קיים בגיליון
  for (let i = 1; i < data.length; i++) {
    if (data[i][COLUMN_EMAIL - 1].toString().toLowerCase() === email) {
      foundRow = i + 1; // 1-indexed row number
      break;
    }
  }
  
  const timestamp = new Date();
  const formattedDate = Utilities.formatDate(timestamp, Session.getScriptTimeZone(), "yyyy-MM-dd HH:mm:ss");
  
  // שמירת הסיסמה כפי שהיא (נוודא שהיא נשלחת כטקסט עם אפסים)
  const textPassword = password.toString();
  
  if (foundRow !== -1) {
    // עדכון סיסמה קיימת
    sheet.getRange(foundRow, COLUMN_PASSWORD)
         .setValue(textPassword);
    sheet.getRange(foundRow, COLUMN_TIMESTAMP).setValue(formattedDate);
    return { success: true, message: "הסיסמה עודכנה בהצלחה בגיליון גוגל!" };
  } else {
    // הוספת שורה חדשה באופן יציב ללא appendRow שעלול להרוס עיצוב
    const nextRow = sheet.getLastRow() + 1;
    sheet.getRange(nextRow, COLUMN_EMAIL).setValue(email);
    sheet.getRange(nextRow, COLUMN_PASSWORD)
         .setValue(textPassword);
    sheet.getRange(nextRow, COLUMN_TIMESTAMP).setValue(formattedDate);
    return { success: true, message: "הסיסמה נשמרה בהצלחה בגיליון גוגל!" };
  }
}

/**
 * מאתר את הסיסמה לפי אימייל ושולח מייל מעוצב בפורמט HTML יוקרתי
 */
function recoverPasswordAndSendEmail(sheet, email) {
  const data = sheet.getDataRange().getValues();
  let password = "";
  
  // חיפוש האימייל בגיליון
  for (let i = 1; i < data.length; i++) {
    if (data[i][COLUMN_EMAIL - 1].toString().toLowerCase() === email) {
      let rawPassword = data[i][COLUMN_PASSWORD - 1].toString();
      // במקרה וקיימת קידומת ישנה מגרסאות קודמות, נסיר אותה
      if (rawPassword.startsWith("P_")) {
        password = rawPassword.substring(2);
      } else if (rawPassword.startsWith("'")) {
        password = rawPassword.substring(1);
      } else {
        password = rawPassword;
      }
      break;
    }
  }
  
  if (!password) {
    return { success: false, message: "כתובת האימייל לא נמצאה במערכת. אנא ודא שהגדרת אותה בהגדרות התוכנה." };
  }
  
  // יצירת תוכן המייל בפורמט HTML יוקרתי
  const htmlBody = `
  <!DOCTYPE html>
  <html dir="rtl" lang="he">
  <head>
    <meta charset="utf-8">
    <style>
      body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background-color: #f4f6f9;
        margin: 0;
        padding: 0;
      }
      .email-container {
        max-width: 600px;
        margin: 40px auto;
        background-color: #ffffff;
        border-radius: 12px;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
        border: 1px solid #e1e8ed;
        overflow: hidden;
      }
      .email-header {
        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
        color: #ffffff;
        padding: 30px;
        text-align: center;
      }
      .email-header h1 {
        margin: 0;
        font-size: 24px;
        font-weight: 600;
        letter-spacing: 0.5px;
      }
      .email-content {
        padding: 40px 30px;
        color: #333333;
        line-height: 1.6;
        text-align: right;
      }
      .email-content p {
        margin-top: 0;
        font-size: 16px;
      }
      .password-box {
        background-color: #f0f4f9;
        border: 2px dashed #1a73e8;
        border-radius: 8px;
        padding: 20px;
        text-align: center;
        margin: 30px 0;
        letter-spacing: 2px;
      }
      .password-text {
        font-family: 'Courier New', Courier, monospace;
        font-size: 28px;
        font-weight: bold;
        color: #1e3c72;
      }
      .warning-box {
        background-color: #fff9db;
        border-right: 4px solid #fcc419;
        padding: 15px;
        margin-bottom: 25px;
        border-radius: 4px;
        font-size: 14px;
        color: #665200;
      }
      .email-footer {
        background-color: #f8f9fa;
        padding: 20px;
        text-align: center;
        font-size: 12px;
        color: #888888;
        border-top: 1px solid #eeeeee;
      }
    </style>
  </head>
  <body>
    <div class="email-container">
      <div class="email-header">
        <h1>Master Authenticator</h1>
        <div style="font-size: 14px; margin-top: 5px; opacity: 0.9;">שחזור סיסמת מאסטר מאובטח</div>
      </div>
      <div class="email-content">
        <p>שלום רב,</p>
        <p>קיבלנו בקשה לשחזור סיסמת הכניסה הראשית של אפליקציית האימות המרכזית שלך (Master Authenticator).</p>
        
        <div class="warning-box">
          <strong>שים לב:</strong> אם לא אתה ביקשת שחזור זה, מומלץ לבדוק את אבטחת החשבון שלך. אל תחשוף סיסמה זו לאף אדם אחר.
        </div>
        
        <p>להלן סיסמת המאסטר שלך לכניסה לאפליקציה:</p>
        
        <div class="password-box">
          <div class="password-text">${password}</div>
        </div>

        <div style="font-size: 13px; color: #b91c1c; margin-top: -15px; margin-bottom: 25px; text-align: center; font-weight: bold; background-color: #fef2f2; padding: 12px; border-radius: 8px; border: 1px dashed #fca5a5; line-height: 1.5;">
          ⚠️ שים לב: אם סיסמת המאסטר שלך התחילה באפס (למשל: 0611) והספרה 0 אינה מופיעה למעלה, אנא הוסף אותה ידנית בעת ההקלדה באפליקציה (זהו שינוי תצוגה אוטומטי של גוגל שיטס).
        </div>
        
        <p>המלצה קטנה: לאחר כניסה מוצלחת, תוכל לשנות את הסיסמה לסיסמה חדשה וקלה יותר לזכירה דרך מסך ההגדרות של האפליקציה.</p>
        <p>בברכה ובהצלחה,<br>צוות האבטחה של Master Authenticator</p>
      </div>
      <div class="email-footer">
        נשלח באופן אוטומטי דרך קישור Google Sheets של המשתמש.<br>
        הודעה זו מכילה מידע רגיש. נא לשמור על דיסקרטיות.
      </div>
    </div>
  </body>
  </html>
  `;
  
  try {
    MailApp.sendEmail({
      to: email,
      subject: "🔒 שחזור סיסמת המאסטר שלך - Master Authenticator",
      htmlBody: htmlBody
    });
    return { success: true, message: "סיסמת המאסטר נשלחה בהצלחה לתיבת המייל שלך!" };
  } catch (mailError) {
    return { success: false, message: "שגיאה בשליחת המייל: " + mailError.toString() };
  }
}

/**
 * פונקציית בדיקה להרצה ידנית מתוך עורך הסקריפט (Apps Script Editor)
 * הרץ פונקציה זו כדי לראות שגיאות בזמן אמת או לאשר הרשאות גישה (Authorization)
 */
function testEmailRecovery() {
  const sheet = getOrCreateSheet();
  // החלף את המייל למטה במייל שלך הרשום בגיליון כדי לבדוק
  const testEmail = "hvusvmch@gmail.com"; 
  
  Logger.log("מתחיל בדיקת שחזור עבור: " + testEmail);
  const result = recoverPasswordAndSendEmail(sheet, testEmail);
  Logger.log("תוצאה: " + JSON.stringify(result));
}

/**
 * מאחזר את נתוני הכספת המוצפנים מהגיליון
 */
function getVaultFromSheet(sheet, email) {
  const data = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (data[i][COLUMN_EMAIL - 1].toString().toLowerCase() === email) {
      return { 
        success: true, 
        registered: true,
        vault: data[i][COLUMN_VAULT - 1] ? data[i][COLUMN_VAULT - 1].toString() : "" 
      };
    }
  }
  return { success: true, registered: false };
}

/**
 * [שחזור חדש] שולח קישור חד-פעמי ומפתח שחזור במייל.
 * הסקריפט אינו מקבל ואינו שולח את סיסמת המאסטר.
 */
function sendResetLinkEmail(email, resetUrl, recoveryKey) {
  const safeUrl = escapeHtml(resetUrl);
  const safeKey = escapeHtml(recoveryKey);
  const htmlBody = `
  <!DOCTYPE html>
  <html dir="rtl" lang="he">
  <head><meta charset="utf-8"></head>
  <body style="font-family:Arial,sans-serif;direction:rtl;line-height:1.7">
    <h2>שחזור כספת Master Authenticator</h2>
    <p>נשלחה בקשה לשחזור הגישה לכספת שלך.</p>
    <p><a href="${safeUrl}">לחץ כאן לפתיחת תהליך השחזור</a></p>
    <p><strong>מפתח השחזור שלך:</strong></p>
    <p style="font-family:monospace;font-size:18px;word-break:break-all">${safeKey}</p>
    <p>הקישור חד-פעמי ותקף לזמן קצר. לאחר השחזור תבחר סיסמת מאסטר חדשה.</p>
    <p style="color:#b91c1c">אל תעביר את הקישור או את מפתח השחזור לאדם אחר.</p>
  </body>
  </html>`;

  try {
    MailApp.sendEmail({
      to: email,
      subject: "🔐 קישור שחזור לכספת Master Authenticator",
      htmlBody: htmlBody,
      body:
        "קישור שחזור: " + resetUrl +
        "\n\nמפתח שחזור: " + recoveryKey
    });
    return { success: true, message: "קישור השחזור נשלח בהצלחה." };
  } catch (error) {
    return { success: false, message: "שגיאה בשליחת מייל השחזור: " + error.toString() };
  }
}

function escapeHtml(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * [הגירה בלבד] מייצא את כל שורות הגיליון (אימייל, סיסמה, כספת, תאריך עדכון).
 * הנתונים מוצפנים במלואם - היוצא הוא אסימונים מוצפנים בלבד.
 * משמש את סקריפט ההעברה (backup-worker/migrate-from-sheets.mjs).
 */
function exportAllFromSheet(sheet) {
  const data = sheet.getDataRange().getValues();
  const users = [];
  
  for (let i = 1; i < data.length; i++) {
    const email = (data[i][COLUMN_EMAIL - 1] || "").toString().trim().toLowerCase();
    if (!email) continue; // שורת כותרת או שורות ריקות
    
    users.push({
      email: email,
      password: (data[i][COLUMN_PASSWORD - 1] || "").toString().trim(),
      vault: (data[i][COLUMN_VAULT - 1] || "").toString().trim(),
      updatedAt: (data[i][COLUMN_TIMESTAMP - 1] || "").toString().trim()
    });
  }
  
  // קיזוז אזור הזמן של הסקריפט (למשל "+0300") - כדי שסקריפט ההגירה
  // יוכל להמיר את התאריכים ל-UTC ולהשוות אותם נכון מול ה-KV החדש.
  const tz = Session.getScriptTimeZone();
  const tzOffset = Utilities.formatDate(new Date(), tz, "Z");
  
  return { success: true, count: users.length, tzOffset: tzOffset, users: users };
}

/**
 * שומר או מעדכן את נתוני הכספת המוצפנים בגיליון
 */
function saveVaultToSheet(sheet, email, password, vault) {
  const data = sheet.getDataRange().getValues();
  let foundRow = -1;
  
  for (let i = 1; i < data.length; i++) {
    if (data[i][COLUMN_EMAIL - 1].toString().toLowerCase() === email) {
      foundRow = i + 1;
      break;
    }
  }
  
  const timestamp = new Date();
  const formattedDate = Utilities.formatDate(timestamp, Session.getScriptTimeZone(), "yyyy-MM-dd HH:mm:ss");
  
  if (foundRow !== -1) {
    sheet.getRange(foundRow, COLUMN_PASSWORD).setValue(password.toString());
    sheet.getRange(foundRow, COLUMN_TIMESTAMP).setValue(formattedDate);
    sheet.getRange(foundRow, COLUMN_VAULT).setValue(vault.toString());
    return { success: true, message: "הכספת סונכרנה בהצלחה בענן!" };
  } else {
    const nextRow = sheet.getLastRow() + 1;
    sheet.getRange(nextRow, COLUMN_EMAIL).setValue(email);
    sheet.getRange(nextRow, COLUMN_PASSWORD).setValue(password.toString());
    sheet.getRange(nextRow, COLUMN_TIMESTAMP).setValue(formattedDate);
    sheet.getRange(nextRow, COLUMN_VAULT).setValue(vault.toString());
    return { success: true, message: "חשבון ענן חדש נוצר וסונכרן בהצלחה!" };
  }
}

