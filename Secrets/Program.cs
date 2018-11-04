using System;
using System.Text;
using System.Threading.Tasks;

namespace AzureKeyVault.Secrets
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

            const string MY_SECRET = "StephenHauntsSecret";

            var secretId = await vault.SetSecretAsync(MY_SECRET, "Mary had a little lamb.");
            Console.WriteLine("Secret Written");

            string secret = await vault.GetSecretAsync(MY_SECRET);
            Console.WriteLine("Secret Retrieved : " + secret);
        }
    }
}
