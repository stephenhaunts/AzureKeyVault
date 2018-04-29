using System.Security.Cryptography;

namespace AzureKeyVault.PasswordProtection
{
    public class Hmac
    {
        public static byte[] ComputeHmacsha256(byte[] toBeHashed, byte[] key)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(toBeHashed);
            }
        }
    }
}
