using System;
using System.Text;
using System.Threading.Tasks;

namespace AzureKeyVault.SimpleEncryptDecrypt
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
            Console.WriteLine("Key Written : " + keyId);

            // Test encryption and decryption.
            string dataToEncrypt = "Mary had a little lamb";

            byte[] encrypted = await vault.EncryptAsync(keyId, Encoding.ASCII.GetBytes(dataToEncrypt));
            byte[] decrypted = await vault.DecryptAsync(keyId, encrypted);

            var encryptedText = Convert.ToBase64String(encrypted);
            var decryptedData = Encoding.UTF8.GetString(decrypted);

            // Remove HSM backed key
            await vault.DeleteKeyAsync(MY_KEY_NAME);
            Console.WriteLine("Key Deleted : " + keyId);

        }
    }
}
