using System;
using System.Text;
using System.Threading.Tasks;

namespace AzureKeyVault.PasswordProtection
{
    class Program
    {
        static void Main(string[] args)
        {
            KeyVault().GetAwaiter().GetResult();
        }

        public static async Task KeyVault()
        {
            IKeyVault vault = new KeyVault();

            const string MY_KEY_NAME = "StephenHauntsKey";
            string keyId = await vault.CreateKeyAsync(MY_KEY_NAME);

            byte[] localKey = Random.GenerateRandomNumber(32);

            // Encrypt our local key with Key Vault and Store it in the database
            byte[] encryptedKey = await vault.EncryptAsync(keyId, localKey);


            // Get our encrypted key from the database and decrypt it with the Key Vault.
            byte[] decryptedKey = await vault.DecryptAsync(keyId, encryptedKey);

            // Hash our password with a PBKDF2
            string password = "Pa55w0rd";
            byte[] salt = Random.GenerateRandomNumber(32);
            byte[] hashedPassword = PBKDF2.HashPassword(Encoding.ASCII.GetBytes(password), salt, 20000);

            // Now do a HMAC of the password using the key that was decrypted from the Key Vault
            byte[] protectedPassword = Hmac.ComputeHmacsha256(hashedPassword, decryptedKey);

            Console.WriteLine("Hashed Password : " + Convert.ToBase64String(hashedPassword));
            Console.WriteLine("Protected Hashed Password : " + Convert.ToBase64String(protectedPassword));
           
            // Remove HSM backed key
            await vault.DeleteKeyAsync(MY_KEY_NAME);
            Console.WriteLine("Key Deleted : " + keyId);
        }
    }
}
