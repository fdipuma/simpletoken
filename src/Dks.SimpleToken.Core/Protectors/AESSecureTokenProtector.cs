using System;
using System.Text;
using Dks.SimpleToken.Core;

namespace Dks.SimpleToken.Protectors
{
    public sealed class AESSecureTokenProtector : ISecureTokenProtector
    {
        private readonly AESMessageHandler _handler;

        public AESSecureTokenProtector(AESEncryptionConfiguration config)
        {
            _handler = new AESMessageHandler(config);
        }

        public byte[] ProtectData(byte[] unprotectedData)
        {
            var tokenString = Convert.ToBase64String(unprotectedData);

            var encryptedToken = _handler.Encrypt(tokenString);

            return Encoding.UTF8.GetBytes(encryptedToken);
        }

        public byte[] UnprotectData(byte[] protectedData)
        {
            var encryptedString = Encoding.UTF8.GetString(protectedData);

            var decrypted = _handler.Decrypt(encryptedString);

            return Convert.FromBase64String(decrypted);
        }
    }
}
