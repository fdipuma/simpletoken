using System;
using System.Collections.Generic;
using System.Security;
using Dks.SimpleToken.Core.Serializers;
using Dks.SimpleToken.Protectors;

namespace Dks.SimpleToken.Core
{
    public class DefaultSecureTokenProvider : ISecureTokenProvider
    {
        private readonly ISecureTokenSerializer _serializer;
        private readonly ISecureTokenProtector _secureTokenProtector;

        protected ISecureTokenSerializer Serializer => _serializer;
        protected ISecureTokenProtector Protector => _secureTokenProtector;

        public DefaultSecureTokenProvider(ISecureTokenSerializer serializer, ISecureTokenProtector secureTokenProtector)
        {
            _serializer = serializer;
            _secureTokenProtector = secureTokenProtector;
        }

        public virtual string GenerateToken(IDictionary<string, string> data, int ttl = 60)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (ttl <= 0) throw new ArgumentOutOfRangeException(nameof(ttl));

            var now = DateTimeOffset.UtcNow;

            var token = SecureToken.Create(now, now.AddSeconds(ttl), data);

            var serialized = _serializer.SerializeToken(token);

            var protectedData = _secureTokenProtector.ProtectData(serialized);

            if (protectedData == null)
                throw new SecurityException("Token encryption failed");

            var encoded = Convert.ToBase64String(protectedData);

            return encoded;
        }
        
        public virtual SecureToken ValidateAndGetData(string token)
        {
            if (token == null) throw new ArgumentNullException(nameof(token));

            var decoded = Convert.FromBase64String(token);

            byte[] decrypted;
            try
            {
                decrypted = _secureTokenProtector.UnprotectData(decoded);
            }
            catch (Exception ex)
            {
                throw new SecurityException("Unable to decrypt token", ex);
            }
            
            if (decrypted == null)
                throw new SecurityException("Token decryption failed");

            var deserialized = _serializer.DeserializeToken(decrypted);

            if (deserialized.IsExpired)
                throw new SecurityException("SecureToken expired");

            return deserialized;
        }

        public static DefaultSecureTokenProvider Create(AESEncryptionConfiguration encryptionConfiguration)
        {
            return new DefaultSecureTokenProvider(new SimpleJsonSecureTokenSerializer(), new AESSecureTokenProtector(encryptionConfiguration));
        }
    }
}
