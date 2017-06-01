using System;
using System.IO;
using Dks.SimpleToken.Core;
using ProtoBuf;

namespace Dks.SimpleToken.Serializers
{
    /// <summary>
    /// Secure token serializer that uses protobuf-net library for
    /// implementing Google Protocol Buffers serialization and deserialization
    /// </summary>
    public class ProtobufSecureTokenSerializer : ISecureTokenSerializer
    {
        public byte[] SerializeToken(SecureToken token)
        {
            var contract = new SecureTokenContract
            {
                Issued = token.Issued.UtcTicks,
                Expire = token.Expire.UtcTicks,
                Data = token.Data
            };

            using (var ms = new MemoryStream())
            {
                Serializer.Serialize(ms, contract);
                return ms.ToArray();
            }
        }

        public SecureToken DeserializeToken(byte[] serialized)
        {
            SecureTokenContract contract;
            using (var ms = new MemoryStream(serialized))
            {
                contract = Serializer.Deserialize<SecureTokenContract>(ms);
            }

            return SecureToken.Create(
                new DateTimeOffset(contract.Issued, TimeSpan.Zero),
                new DateTimeOffset(contract.Expire, TimeSpan.Zero),
                contract.Data);
        }
    }
}
