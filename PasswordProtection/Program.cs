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
            const string ITERATIONS_VALUE = "PBKDF2Iterations";

            string keyId = await vault.CreateKeyAsync(MY_KEY_NAME);

            // Encrypt our salt with Key Vault and Store it in the database
            byte[] salt = Random.GenerateRandomNumber(32);
            byte[] encryptedSalt = await vault.EncryptAsync(keyId, salt);
            var iterationsId = await vault.SetSecretAsync(ITERATIONS_VALUE, "20000");

            // Get our encrypted salt from the database and decrypt it with the Key Vault.
            byte[] decryptedSalt = await vault.DecryptAsync(keyId, encryptedSalt);
            int iterations = int.Parse(await vault.GetSecretAsync(ITERATIONS_VALUE));

            // Hash our password with a PBKDF2
            string password = "Pa55w0rd";

            byte[] hashedPassword = PBKDF2.HashPassword(Encoding.ASCII.GetBytes(password), decryptedSalt, iterations);
            Console.WriteLine("Hashed Password : " + Convert.ToBase64String(hashedPassword));

            // Remove HSM backed key
            await vault.DeleteKeyAsync(MY_KEY_NAME);

            Console.WriteLine("Key Deleted : " + keyId);
        }
    }
}
