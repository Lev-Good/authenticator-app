using System;
using System.Security.Cryptography;
using System.Text;

namespace MasterAuthenticator
{
    public static class TotpGenerator
    {
        public static string GenerateTotp(string secret)
        {
            try
            {
                byte[] key = Base32Decode(secret);
                long epoch = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                long counter = epoch / 30;
                
                byte[] counterBytes = BitConverter.GetBytes(counter);
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(counterBytes);
                }

                using (var hmac = new HMACSHA1(key))
                {
                    byte[] hash = hmac.ComputeHash(counterBytes);
                    int offset = hash[hash.Length - 1] & 0xf;
                    
                    int binary = ((hash[offset] & 0x7f) << 24) |
                                 ((hash[offset + 1] & 0xff) << 16) |
                                 ((hash[offset + 2] & 0xff) << 8) |
                                 (hash[offset + 3] & 0xff);
                                 
                    int otp = binary % 1000000;
                    return otp.ToString("D6");
                }
            }
            catch
            {
                return "שגיאה";
            }
        }

        private static byte[] Base32Decode(string input)
        {
            input = input.Trim().ToUpper().Replace(" ", "").Replace("-", "");
            if (string.IsNullOrEmpty(input))
            {
                throw new ArgumentException("מפתח ריק");
            }

            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var bits = new StringBuilder();
            
            foreach (char c in input)
            {
                int val = alphabet.IndexOf(c);
                if (val >= 0)
                {
                    bits.Append(Convert.ToString(val, 2).PadLeft(5, '0'));
                }
                else
                {
                    throw new ArgumentException($"תו לא חוקי בבסיס 32: {c}");
                }
            }

            int byteCount = bits.Length / 8;
            byte[] bytes = new byte[byteCount];
            for (int i = 0; i < byteCount; i++)
            {
                bytes[i] = Convert.ToByte(bits.ToString(i * 8, 8), 2);
            }
            
            return bytes;
        }
    }
}
