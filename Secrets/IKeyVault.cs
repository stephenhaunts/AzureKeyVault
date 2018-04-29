using System.Threading.Tasks;

namespace AzureKeyVault.Secrets
{
    public interface IKeyVault
    {
        Task<string> CreateKeyAsync(string keyName);
        Task DeleteKeyAsync(string keyName);

        Task<byte[]> EncryptAsync(string keyId, byte[] dataToEncrypt);
        Task<byte[]> DecryptAsync(string keyId, byte[] dataToDecrypt);

        Task<string> SetSecretAsync(string secretName, string secretValue);
        Task<string> GetSecretAsync(string secretName);
    }
}
