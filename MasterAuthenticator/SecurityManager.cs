using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MasterAuthenticator
{
    public class BackupCode
    {
        public string code { get; set; } = "";
        public bool used { get; set; }
    }

    public class GoogleAccount
    {
        public string id { get; set; } = "";
        public string name { get; set; } = "";
        public string email { get; set; } = "";
        public string secret { get; set; } = "";
        public string notes { get; set; } = "";
        public List<BackupCode> backupCodes { get; set; } = new List<BackupCode>();
    }

    public class RecoveryPackage
    {
        public string ciphertext { get; set; } = "";
        public string iv { get; set; } = "";
        public string tag { get; set; } = "";
    }

    public class AppSettings
    {
        public bool OfflineMode { get; set; }
    }

    public class VaultData
    {
        public int Iterations { get; set; } = 100000;
        public string Salt { get; set; } = "";
        public string VerificationTokenEncrypted { get; set; } = "";
        public string VerificationTokenIv { get; set; } = "";
        public string VerificationTokenTag { get; set; } = "";
        public string AccountsEncrypted { get; set; } = "";
        public string AccountsIv { get; set; } = "";
        public string AccountsTag { get; set; } = "";
        public string RecoveryEmail { get; set; } = "";
        public string RecoveryKeyEncrypted { get; set; } = "";
        public string RecoveryKeyIv { get; set; } = "";
        public string RecoveryKeyTag { get; set; } = "";
    }

    public class SecurityManager
    {
        private sealed class LocalVaultCache
        {
            public string Email { get; set; } = "";
            public string VaultJson { get; set; } = "";
            public string ServerUpdatedAt { get; set; } = "";
            public bool PendingSync { get; set; }
        }

        public const int ModernIterations = 600000;
        public const int LegacyIterations = 100000;

        private byte[]? _cachedKey = null;
        private VaultData _currentVault = new VaultData();
        private List<GoogleAccount> _cachedAccounts = new List<GoogleAccount>();
        private bool _offlineMode = false;

        public bool IsOfflineMode => _offlineMode;

        public bool IsUnlocked()
        {
            return _cachedKey != null;
        }

        public static bool ValidatePasswordStrength(string password, out string errorMessage)
        {
            if (string.IsNullOrWhiteSpace(password) || password.Length < 12)
            {
                errorMessage = "סיסמת המאסטר חייבת להכיל לפחות 12 תווים למען אבטחה מקסימלית.";
                return false;
            }

            bool hasLetter = false;
            bool hasDigitOrSymbol = false;
            foreach (char c in password)
            {
                if (char.IsLetter(c)) hasLetter = true;
                else hasDigitOrSymbol = true;
            }

            if (!hasLetter || !hasDigitOrSymbol)
            {
                errorMessage = "הסיסמה חייבת לשלב אותיות יחד עם ספרות או סימנים מיוחדים.";
                return false;
            }

            errorMessage = "";
            return true;
        }

        public string InitializeNewVault(string password, string email)
        {
            byte[] salt = new byte[16];
            RandomNumberGenerator.Fill(salt);

            int iterations = ModernIterations;
            byte[] key = DeriveKey(password, salt, iterations);
            _cachedKey = key;

            // Encrypt verification token "AUTHENTICATED"
            var (tokenEnc, tokenIv, tokenTag) = Encrypt("AUTHENTICATED", key);

            // Encrypt empty accounts list
            var (accountsEnc, accountsIv, accountsTag) = Encrypt(JsonSerializer.Serialize(new List<GoogleAccount>()), key);

            _currentVault = new VaultData
            {
                Iterations = iterations,
                Salt = Convert.ToBase64String(salt),
                VerificationTokenEncrypted = Convert.ToBase64String(tokenEnc),
                VerificationTokenIv = Convert.ToBase64String(tokenIv),
                VerificationTokenTag = Convert.ToBase64String(tokenTag),
                AccountsEncrypted = Convert.ToBase64String(accountsEnc),
                AccountsIv = Convert.ToBase64String(accountsIv),
                AccountsTag = Convert.ToBase64String(accountsTag),
                RecoveryEmail = email,
                RecoveryKeyEncrypted = "",
                RecoveryKeyIv = "",
                RecoveryKeyTag = ""
            };

            _cachedAccounts = new List<GoogleAccount>();
            return JsonSerializer.Serialize(_currentVault);
        }

        public bool LoadVault(string vaultJson, string password)
        {
            try
            {
                var vault = JsonSerializer.Deserialize<VaultData>(vaultJson);
                if (vault == null) return false;

                byte[] salt = Convert.FromBase64String(vault.Salt);
                int iterations = vault.Iterations > 0 ? vault.Iterations : LegacyIterations;
                byte[] key = DeriveKey(password, salt, iterations);

                byte[] tokenEnc = Convert.FromBase64String(vault.VerificationTokenEncrypted);
                byte[] tokenIv = Convert.FromBase64String(vault.VerificationTokenIv);
                byte[] tokenTag = Convert.FromBase64String(vault.VerificationTokenTag);

                string decryptedToken = Decrypt(tokenEnc, key, tokenIv, tokenTag);

                if (decryptedToken == "AUTHENTICATED")
                {
                    _cachedKey = key;
                    _currentVault = vault;
                    
                    // Decrypt and cache accounts
                    byte[] accountsEnc = Convert.FromBase64String(vault.AccountsEncrypted);
                    byte[] accountsIv = Convert.FromBase64String(vault.AccountsIv);
                    byte[] accountsTag = Convert.FromBase64String(vault.AccountsTag);
                    
                    string accountsJson = Decrypt(accountsEnc, key, accountsIv, accountsTag);
                    _cachedAccounts = JsonSerializer.Deserialize<List<GoogleAccount>>(accountsJson) ?? new List<GoogleAccount>();
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        public List<GoogleAccount> GetAccounts()
        {
            return _cachedAccounts;
        }

        public void SaveAccounts(List<GoogleAccount> accounts)
        {
            if (_cachedKey == null) throw new InvalidOperationException("הכספת נעולה");

            _cachedAccounts = accounts;
            string accountsJson = JsonSerializer.Serialize(accounts);
            var (enc, iv, tag) = Encrypt(accountsJson, _cachedKey);

            _currentVault.AccountsEncrypted = Convert.ToBase64String(enc);
            _currentVault.AccountsIv = Convert.ToBase64String(iv);
            _currentVault.AccountsTag = Convert.ToBase64String(tag);
        }

        public void SetRecoveryEmail(string email)
        {
            _currentVault.RecoveryEmail = email;
        }

        public string GetRecoveryEmail()
        {
            return _currentVault.RecoveryEmail;
        }

        public bool ChangePassword(string oldPassword, string newPassword)
        {
            if (_cachedKey == null) return false;

            try
            {
                // Verify old password
                byte[] salt = Convert.FromBase64String(_currentVault.Salt);
                int oldIterations = _currentVault.Iterations > 0 ? _currentVault.Iterations : LegacyIterations;
                byte[] oldKeyCheck = DeriveKey(oldPassword, salt, oldIterations);

                if (!CryptographicOperations.FixedTimeEquals(_cachedKey, oldKeyCheck))
                {
                    return false;
                }

                // Generate new salt and key with ModernIterations (600,000)
                byte[] newSalt = new byte[16];
                RandomNumberGenerator.Fill(newSalt);
                int newIterations = ModernIterations;
                byte[] newKey = DeriveKey(newPassword, newSalt, newIterations);

                // Re-encrypt verification token
                var (tokenEnc, tokenIv, tokenTag) = Encrypt("AUTHENTICATED", newKey);

                // Re-encrypt accounts
                string accountsJson = JsonSerializer.Serialize(_cachedAccounts);
                var (accountsEnc, accountsIv, accountsTag) = Encrypt(accountsJson, newKey);

                // Update current vault
                _currentVault.Iterations = newIterations;
                _currentVault.Salt = Convert.ToBase64String(newSalt);
                _currentVault.VerificationTokenEncrypted = Convert.ToBase64String(tokenEnc);
                _currentVault.VerificationTokenIv = Convert.ToBase64String(tokenIv);
                _currentVault.VerificationTokenTag = Convert.ToBase64String(tokenTag);
                _currentVault.AccountsEncrypted = Convert.ToBase64String(accountsEnc);
                _currentVault.AccountsIv = Convert.ToBase64String(accountsIv);
                _currentVault.AccountsTag = Convert.ToBase64String(accountsTag);

                if (_cachedKey != null)
                {
                    CryptographicOperations.ZeroMemory(_cachedKey);
                }
                _cachedKey = newKey;
                return true;
            }
            catch
            {
                return false;
            }
        }

        public void Lock()
        {
            if (_cachedKey != null)
            {
                CryptographicOperations.ZeroMemory(_cachedKey);
                _cachedKey = null;
            }
            _cachedAccounts = new List<GoogleAccount>();
            _currentVault = new VaultData();
        }

        public string ExportVault()
        {
            return JsonSerializer.Serialize(_currentVault, new JsonSerializerOptions { WriteIndented = true });
        }

        public (string recoveryKey, RecoveryPackage recoveryPackage) PrepareRecoveryMaterial()
        {
            if (_cachedKey == null) throw new InvalidOperationException("הכספת נעולה");

            string recoveryKeyRaw = "";
            if (!string.IsNullOrEmpty(_currentVault.RecoveryKeyEncrypted))
            {
                recoveryKeyRaw = Decrypt(
                    Convert.FromBase64String(_currentVault.RecoveryKeyEncrypted),
                    _cachedKey,
                    Convert.FromBase64String(_currentVault.RecoveryKeyIv),
                    Convert.FromBase64String(_currentVault.RecoveryKeyTag));
            }

            if (string.IsNullOrEmpty(recoveryKeyRaw))
            {
                byte[] recoveryKeyBytes = new byte[32];
                RandomNumberGenerator.Fill(recoveryKeyBytes);
                recoveryKeyRaw = Convert.ToBase64String(recoveryKeyBytes);
                var encryptedRecoveryKey = Encrypt(recoveryKeyRaw, _cachedKey);
                _currentVault.RecoveryKeyEncrypted = Convert.ToBase64String(encryptedRecoveryKey.ciphertext);
                _currentVault.RecoveryKeyIv = Convert.ToBase64String(encryptedRecoveryKey.iv);
                _currentVault.RecoveryKeyTag = Convert.ToBase64String(encryptedRecoveryKey.tag);
            }

            byte[] recoveryKey = Convert.FromBase64String(recoveryKeyRaw);
            string payload = JsonSerializer.Serialize(new { email = _currentVault.RecoveryEmail, accounts = _cachedAccounts });
            var encryptedPackage = Encrypt(payload, recoveryKey);

            return (
                recoveryKeyRaw,
                new RecoveryPackage
                {
                    ciphertext = Convert.ToBase64String(encryptedPackage.ciphertext),
                    iv = Convert.ToBase64String(encryptedPackage.iv),
                    tag = Convert.ToBase64String(encryptedPackage.tag)
                });
        }

        public bool ResetFromRecoveryPackage(RecoveryPackage recoveryPackage, string recoveryKeyRaw, string email, string newPassword)
        {
            try
            {
                byte[] recoveryKey = Convert.FromBase64String(recoveryKeyRaw.Trim());
                string payload = Decrypt(
                    Convert.FromBase64String(recoveryPackage.ciphertext),
                    recoveryKey,
                    Convert.FromBase64String(recoveryPackage.iv),
                    Convert.FromBase64String(recoveryPackage.tag));

                using JsonDocument document = JsonDocument.Parse(payload);
                List<GoogleAccount> accounts = document.RootElement
                    .GetProperty("accounts")
                    .Deserialize<List<GoogleAccount>>() ?? new List<GoogleAccount>();

                byte[] salt = new byte[16];
                RandomNumberGenerator.Fill(salt);
                int iterations = ModernIterations;
                byte[] key = DeriveKey(newPassword, salt, iterations);
                var token = Encrypt("AUTHENTICATED", key);
                var accountsEncrypted = Encrypt(JsonSerializer.Serialize(accounts), key);
                var recoveryKeyEncrypted = Encrypt(recoveryKeyRaw.Trim(), key);

                _currentVault = new VaultData
                {
                    Iterations = iterations,
                    Salt = Convert.ToBase64String(salt),
                    VerificationTokenEncrypted = Convert.ToBase64String(token.ciphertext),
                    VerificationTokenIv = Convert.ToBase64String(token.iv),
                    VerificationTokenTag = Convert.ToBase64String(token.tag),
                    AccountsEncrypted = Convert.ToBase64String(accountsEncrypted.ciphertext),
                    AccountsIv = Convert.ToBase64String(accountsEncrypted.iv),
                    AccountsTag = Convert.ToBase64String(accountsEncrypted.tag),
                    RecoveryEmail = email,
                    RecoveryKeyEncrypted = Convert.ToBase64String(recoveryKeyEncrypted.ciphertext),
                    RecoveryKeyIv = Convert.ToBase64String(recoveryKeyEncrypted.iv),
                    RecoveryKeyTag = Convert.ToBase64String(recoveryKeyEncrypted.tag)
                };

                _cachedKey = key;
                _cachedAccounts = accounts;
                return true;
            }
            catch
            {
                return false;
            }
        }

        // ----------------------------------------------------
        // App settings (sync mode)
        // ----------------------------------------------------
        private static string GetSettingsPath()
        {
            return Path.Combine(GetLocalVaultDirectory(), "settings.json");
        }

        public bool IsFirstRun()
        {
            // אין קובץ הגדרות כלל = הפעלה ראשונה (או שאשף ההגדרה טרם הושלם)
            return !File.Exists(GetSettingsPath());
        }

        public void LoadAppSettings()
        {
            try
            {
                string path = GetSettingsPath();
                if (!File.Exists(path)) return;
                var settings = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path));
                _offlineMode = settings != null && settings.OfflineMode;
            }
            catch
            {
                // Corrupt settings must never prevent the app from running.
                _offlineMode = false;
            }
        }

        public void SetOfflineMode(bool offline)
        {
            _offlineMode = offline;
            try
            {
                string path = GetSettingsPath();
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllText(path, JsonSerializer.Serialize(new AppSettings { OfflineMode = offline }));
            }
            catch
            {
                // Persisting the preference is best-effort; the in-memory value still applies.
            }
        }

        public void DeleteLocalVault(string email)
        {
            try
            {
                string path = GetLocalVaultPath(email);
                if (File.Exists(path)) File.Delete(path);
            }
            catch
            {
                // Cleanup failures are non-critical.
            }
        }

        public void SaveLocalVault(string email, string serverUpdatedAt, bool pendingSync)
        {
            try
            {
                if (_cachedKey == null || string.IsNullOrWhiteSpace(email)) return;

                string directory = GetLocalVaultDirectory();
                Directory.CreateDirectory(directory);

                var cache = new LocalVaultCache
                {
                    Email = email.Trim().ToLowerInvariant(),
                    VaultJson = ExportVault(),
                    ServerUpdatedAt = serverUpdatedAt ?? "",
                    PendingSync = pendingSync
                };

                File.WriteAllText(GetLocalVaultPath(email), JsonSerializer.Serialize(cache));
            }
            catch
            {
                // Local caching must never prevent an online login or cloud sync.
            }
        }

        public bool TryLoadLocalVault(string email, string password, out bool pendingSync, out string serverUpdatedAt)
        {
            pendingSync = false;
            serverUpdatedAt = "";

            try
            {
                string path = GetLocalVaultPath(email);
                if (!File.Exists(path)) return false;

                var cache = JsonSerializer.Deserialize<LocalVaultCache>(File.ReadAllText(path));
                if (cache == null || !string.Equals(cache.Email, email.Trim().ToLowerInvariant(), StringComparison.OrdinalIgnoreCase))
                    return false;

                if (!LoadVault(cache.VaultJson, password)) return false;

                var cachedVault = JsonSerializer.Deserialize<VaultData>(cache.VaultJson);
                pendingSync = cache.PendingSync || cachedVault == null || string.IsNullOrEmpty(cachedVault.RecoveryKeyEncrypted);
                serverUpdatedAt = cache.ServerUpdatedAt ?? "";
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool HasPendingLocalSync(string email)
        {
            try
            {
                string path = GetLocalVaultPath(email);
                if (!File.Exists(path)) return false;
                var cache = JsonSerializer.Deserialize<LocalVaultCache>(File.ReadAllText(path));
                if (cache == null) return false;
                var cachedVault = JsonSerializer.Deserialize<VaultData>(cache.VaultJson);
                return cache.PendingSync || cachedVault == null || string.IsNullOrEmpty(cachedVault.RecoveryKeyEncrypted);
            }
            catch
            {
                return false;
            }
        }

        private static string GetLocalVaultDirectory()
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "MasterAuthenticator");
        }

        private static string GetLocalVaultPath(string email)
        {
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(email.Trim().ToLowerInvariant()));
            string fileName = Convert.ToHexString(hash).ToLowerInvariant() + ".vault.json";
            return Path.Combine(GetLocalVaultDirectory(), fileName);
        }

        public bool ImportVault(string importJson, string password)
        {
            try
            {
                var data = JsonSerializer.Deserialize<VaultData>(importJson);
                if (data == null || string.IsNullOrEmpty(data.Salt) || string.IsNullOrEmpty(data.VerificationTokenEncrypted))
                {
                    return false;
                }

                byte[] salt = Convert.FromBase64String(data.Salt);
                int iterations = data.Iterations > 0 ? data.Iterations : LegacyIterations;
                byte[] key = DeriveKey(password, salt, iterations);

                byte[] tokenEnc = Convert.FromBase64String(data.VerificationTokenEncrypted);
                byte[] tokenIv = Convert.FromBase64String(data.VerificationTokenIv);
                byte[] tokenTag = Convert.FromBase64String(data.VerificationTokenTag);

                string decryptedToken = Decrypt(tokenEnc, key, tokenIv, tokenTag);

                if (decryptedToken == "AUTHENTICATED")
                {
                    _cachedKey = key;
                    _currentVault = data;
                    
                    byte[] accountsEnc = Convert.FromBase64String(data.AccountsEncrypted);
                    byte[] accountsIv = Convert.FromBase64String(data.AccountsIv);
                    byte[] accountsTag = Convert.FromBase64String(data.AccountsTag);
                    
                    string accountsJson = Decrypt(accountsEnc, key, accountsIv, accountsTag);
                    _cachedAccounts = JsonSerializer.Deserialize<List<GoogleAccount>>(accountsJson) ?? new List<GoogleAccount>();
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }


        // Encryption Helpers
        private static byte[] DeriveKey(string password, byte[] salt, int iterations = LegacyIterations)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(32); // 256-bit key
            }
        }

        private static (byte[] ciphertext, byte[] iv, byte[] tag) Encrypt(string plaintext, byte[] key)
        {
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] iv = new byte[12];
            RandomNumberGenerator.Fill(iv);
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[plaintextBytes.Length];

            using (var aesGcm = new AesGcm(key, tag.Length))
            {
                aesGcm.Encrypt(iv, plaintextBytes, ciphertext, tag);
            }

            return (ciphertext, iv, tag);
        }

        private static string Decrypt(byte[] ciphertext, byte[] key, byte[] iv, byte[] tag)
        {
            byte[] decryptedBytes = new byte[ciphertext.Length];

            using (var aesGcm = new AesGcm(key, tag.Length))
            {
                aesGcm.Decrypt(iv, ciphertext, tag, decryptedBytes);
            }

            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}
