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

    public class VaultData
    {
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

        private byte[]? _cachedKey = null;
        private VaultData _currentVault = new VaultData();
        private List<GoogleAccount> _cachedAccounts = new List<GoogleAccount>();

        public bool IsUnlocked()
        {
            return _cachedKey != null;
        }

        public string InitializeNewVault(string password, string email)
        {
            byte[] salt = new byte[16];
            RandomNumberGenerator.Fill(salt);

            byte[] key = DeriveKey(password, salt);
            _cachedKey = key;

            // Encrypt verification token "AUTHENTICATED"
            var (tokenEnc, tokenIv, tokenTag) = Encrypt("AUTHENTICATED", key);

            // Encrypt empty accounts list
            var (accountsEnc, accountsIv, accountsTag) = Encrypt(JsonSerializer.Serialize(new List<GoogleAccount>()), key);

            _currentVault = new VaultData
            {
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
                byte[] key = DeriveKey(password, salt);

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
                byte[] oldKeyCheck = DeriveKey(oldPassword, salt);

                if (!CryptographicOperations.FixedTimeEquals(_cachedKey, oldKeyCheck))
                {
                    return false;
                }

                // Generate new salt and key
                byte[] newSalt = new byte[16];
                RandomNumberGenerator.Fill(newSalt);
                byte[] newKey = DeriveKey(newPassword, newSalt);

                // Re-encrypt verification token
                var (tokenEnc, tokenIv, tokenTag) = Encrypt("AUTHENTICATED", newKey);

                // Re-encrypt accounts
                string accountsJson = JsonSerializer.Serialize(_cachedAccounts);
                var (accountsEnc, accountsIv, accountsTag) = Encrypt(accountsJson, newKey);

                // Update current vault
                _currentVault.Salt = Convert.ToBase64String(newSalt);
                _currentVault.VerificationTokenEncrypted = Convert.ToBase64String(tokenEnc);
                _currentVault.VerificationTokenIv = Convert.ToBase64String(tokenIv);
                _currentVault.VerificationTokenTag = Convert.ToBase64String(tokenTag);
                _currentVault.AccountsEncrypted = Convert.ToBase64String(accountsEnc);
                _currentVault.AccountsIv = Convert.ToBase64String(accountsIv);
                _currentVault.AccountsTag = Convert.ToBase64String(accountsTag);

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
            _cachedKey = null;
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
                byte[] key = DeriveKey(newPassword, salt);
                var token = Encrypt("AUTHENTICATED", key);
                var accountsEncrypted = Encrypt(JsonSerializer.Serialize(accounts), key);
                var recoveryKeyEncrypted = Encrypt(recoveryKeyRaw.Trim(), key);

                _currentVault = new VaultData
                {
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
                byte[] key = DeriveKey(password, salt);

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
        private static byte[] DeriveKey(string password, byte[] salt)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256))
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
