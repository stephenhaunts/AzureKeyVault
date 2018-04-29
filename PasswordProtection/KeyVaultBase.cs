using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace AzureKeyVault.PasswordProtection
{
    public class KeyVaultBase
    {
        protected KeyVaultClient KeyVaultClient;
        protected ClientCredential ClientCredential;
        protected string VaultAddress;

        protected string GetKeyUri(string keyName)
        {
            var retrievedKey = KeyVaultClient.GetKeyAsync(VaultAddress, keyName).GetAwaiter().GetResult();
            return retrievedKey.Key.Kid;
        }

        protected KeyBundle GetKeyBundle()
        {
            var defaultKeyBundle = new KeyBundle
            {
                Key = new JsonWebKey
                {
                    Kty = JsonWebKeyType.Rsa
                },
                Attributes = new KeyAttributes
                {
                    Enabled = true,
                    Expires = DateTime.Now.AddYears(1)
                }
            };

            return defaultKeyBundle;
        }

        protected Dictionary<string, string> GetKeyTags()
        {
            return new Dictionary<string, string> { { "purpose", "Master Key" }, { "LadderPay Core", "LadderPay" } };
        }

        protected Dictionary<string, string> GetSecretTags()
        {
            return new Dictionary<string, string> { { "purpose", "Encrypted Secret" }, { "LadderPay Core", "LadderPay" } };
        }

        protected async Task<string> GetAccessTokenAsync(string authority, string resource, string scope)
        {
            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await context.AcquireTokenAsync(resource, ClientCredential);
            Console.WriteLine(scope);
            return result.AccessToken;
        }

        protected HttpClient GetHttpClient()
        {
            return new HttpClient();
        }
    }
}
