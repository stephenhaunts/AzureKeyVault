using System;
using System.Text;
using System.Threading.Tasks;

namespace AzureKeyVault.DigitalSignatures
{
    class Program
    {
        static void Main(string[] args)
        {
            KeyVault().GetAwaiter().GetResult();
        }

        public static async Task KeyVault()
        {
            IKeyVault vault = new FakeKeyVault();

            const string MY_KEY_NAME = "StephenHauntsKey";
            string keyId = await vault.CreateKeyAsync(MY_KEY_NAME);


            string importantDocument = "This is a really important document that I need to digitally sign.";

            byte[] documentDigest = Hash.Sha256(Encoding.ASCII.GetBytes(importantDocument));

            byte[] signature = await vault.Sign(keyId, documentDigest);

            bool verified = await vault.Verify(keyId, documentDigest, signature);


            // Remove HSM backed key
            await vault.DeleteKeyAsync(MY_KEY_NAME);
            Console.WriteLine("Key Deleted : " + keyId);
        }
    }
}
