using System.Collections.Generic;
using ProtoBuf;

namespace Dks.SimpleToken.Serializers
{
    [ProtoContract]
    internal sealed class SecureTokenContract
    {
        [ProtoMember(1)]
        public long Issued { get; set; }

        [ProtoMember(2)]
        public long Expire { get; set; }

        [ProtoMember(3)]
        public IDictionary<string, string> Data { get; set; }
    }
}
