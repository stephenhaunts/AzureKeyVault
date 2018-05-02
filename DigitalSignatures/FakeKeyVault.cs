using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace AzureKeyVault.DigitalSignatures
{
    public class FakeKeyVault : IKeyVault
    {
        Dictionary<string, RSAParameters> publicKey = new Dictionary<string, RSAParameters>();
        Dictionary<string, RSAParameters> privateKey = new Dictionary<string, RSAParameters>();
        Dictionary<string, string> secret = new Dictionary<string, string>();

        public async Task<string> CreateKeyAsync(string keyName)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                publicKey.Add(keyName, rsa.ExportParameters(false));
                privateKey.Add(keyName, rsa.ExportParameters(true));
            }

            await Task.CompletedTask;
            return keyName;
        }

        public async Task<byte[]> DecryptAsync(string keyId, byte[] dataToDecrypt)
        {
            byte[] plain;

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;

                rsa.ImportParameters(privateKey[keyId]);
                plain = rsa.Decrypt(dataToDecrypt, true);
            }

            await Task.CompletedTask;

            return plain;
        }

        public async Task DeleteKeyAsync(string keyName)
        {
            publicKey.Remove(keyName);
            privateKey.Remove(keyName);

            await Task.CompletedTask;
            return;
        }

        public async Task<byte[]> EncryptAsync(string keyId, byte[] dataToEncrypt)
        {
            byte[] cipherbytes;

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(publicKey[keyId]);

                cipherbytes = rsa.Encrypt(dataToEncrypt, true);
            }

            await Task.CompletedTask;

            return cipherbytes;
           
        }

        public async Task<string> GetSecretAsync(string secretName)
        {
            await Task.CompletedTask;

            return secret[secretName];
        }

        public async Task<string> SetSecretAsync(string secretName, string secretValue)
        {
            await Task.CompletedTask;
            secret.Add(secretName, secretValue);

            return secretName;
        }

        public async Task<byte[]> Sign(string keyId, byte[] hash)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(privateKey[keyId]);

                var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
                rsaFormatter.SetHashAlgorithm("SHA256");

                await Task.CompletedTask;

                return rsaFormatter.CreateSignature(hash);
            }
        }

        public async Task<bool> Verify(string keyId, byte[] hash, byte[] signature)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.ImportParameters(publicKey[keyId]);

                var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                rsaDeformatter.SetHashAlgorithm("SHA256");

                await Task.CompletedTask;

                return rsaDeformatter.VerifySignature(hash, signature);
            }
        }
    }
}
