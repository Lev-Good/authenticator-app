using MasterAuthenticator;

// כלי בדיקת אינטרופ: משתמש בקוד האמיתי של MasterAuthenticator (SecurityManager + TotpGenerator).
//
// מצבי הרצה:
//   cross-test load <vault.json> <password> [totpSecret]   -> טוען כספת שנוצרה ב-HTML ומדפיס LOAD_OK/LOAD_FAIL
//   cross-test create <password> <email> <out.json>        -> יוצר כספת חדשה עם הקוד האמיתי ושומר לקובץ
//   cross-test totp <secret>                              -> מדפיס קוד TOTP נוכחי של ה-secret

if (args.Length < 1)
{
    Console.WriteLine("usage: cross-test <load|create|totp> ...");
    return 2;
}

var sm = new SecurityManager();

if (args[0] == "load")
{
    if (args.Length < 3) return 2;
    string vaultJson = File.ReadAllText(args[1]);
    if (sm.LoadVault(vaultJson, args[2]))
    {
        Console.WriteLine("LOAD_OK accounts=" + sm.GetAccounts().Count + " email=" + sm.GetRecoveryEmail());
    }
    else
    {
        Console.WriteLine("LOAD_FAIL");
        return 1;
    }
    if (args.Length >= 4)
    {
        Console.WriteLine("TOTP=" + TotpGenerator.GenerateTotp(args[3]));
    }
}
else if (args[0] == "create")
{
    if (args.Length < 4) return 2;
    string vaultJson = sm.InitializeNewVault(args[1], args[2]);
    File.WriteAllText(args[3], vaultJson);
    Console.WriteLine("CREATED");
}
else if (args[0] == "totp")
{
    if (args.Length < 2) return 2;
    Console.WriteLine("TOTP=" + TotpGenerator.GenerateTotp(args[1]));
}

return 0;
