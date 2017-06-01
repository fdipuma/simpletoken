// (C) 2017 Federico Dipuma - Dynacode

using System;
using System.Collections.Generic;
using System.Text;

namespace Dks.SimpleToken.Core.Serializers
{
    public class SimpleJsonSecureTokenSerializer : ISecureTokenSerializer
    {
        // we need a surrogate so SimpleJson do not serializes
        // unwanted properties (e.g. IsExpired property)
        private class SecureTokenSurrogate
        {
            public DateTimeOffset Issued { get; set; }
            public DateTimeOffset Expire { get; set; }
            public IDictionary<string, string> Data { get; set; }
        }

        public byte[] SerializeToken(SecureToken token)
        {
            var json = SimpleJson.SimpleJson.SerializeObject(new SecureTokenSurrogate
            {
                Issued = token.Issued,
                Expire = token.Expire,
                Data = token.Data
            });
            return Encoding.UTF8.GetBytes(json);
        }

        public SecureToken DeserializeToken(byte[] serialized)
        {
            var json = Encoding.UTF8.GetString(serialized);
            var surrogate = SimpleJson.SimpleJson.DeserializeObject<SecureTokenSurrogate>(json);

            return SecureToken.Create(surrogate.Issued, surrogate.Expire, surrogate.Data);
        }
    }
}
