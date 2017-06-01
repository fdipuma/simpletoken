using System.Collections.Generic;
using System.Diagnostics;
using System.Security;
using System.Threading;
using Dks.SimpleToken.Core;
using Dks.SimpleToken.Protectors;
using Dks.SimpleToken.Serializers;
using Xunit;

namespace Dks.SimpleToken.Tests
{
    public class TokenValidationTest
    {
        private static readonly Dictionary<string, string> PayLoad = new Dictionary<string, string>
        {
            {"Foo", "12"},
            {"Bar", "test"}
        };

        [Fact]
        public void ShouldCorrectlySerializeAnonymousObject_AesProtobuf()
        {
            ISecureTokenProvider provider = GetAesProtobufTokenProvider();
            var saToken = provider.GenerateToken(new { Foo = 12, Bar = "test" });

            Debug.WriteLine($"SATOKEN LENGTH: {saToken.Length}");

            var saData = provider.ValidateAndGetData(saToken);

            Assert.Equal("12", saData.Data["Foo"]);
            Assert.Equal("test", saData.Data["Bar"]);
        }

        [Fact]
        public void ShouldCorrectlySerializeAnonymousObject_Default()
        {
            ISecureTokenProvider provider = DefaultSecureTokenProvider.Create(GetAESConfig());
            var saToken = provider.GenerateToken(new { Foo = 12, Bar = "test" });

            Debug.WriteLine($"DTOKEN LENGTH: {saToken.Length}");

            var saData = provider.ValidateAndGetData(saToken);

            Assert.Equal("12", saData.Data["Foo"]);
            Assert.Equal("test", saData.Data["Bar"]);
        }

        [Fact]
        public void ShouldCorrectlySerializeDictionary_AesProtobuf()
        {
            ISecureTokenProvider provider = GetAesProtobufTokenProvider();
            var saToken = provider.GenerateToken(PayLoad);

            Debug.WriteLine($"SATOKEN LENGTH: {saToken.Length}");

            var saData = provider.ValidateAndGetData(saToken);

            Assert.Equal("12", saData.Data["Foo"]);
            Assert.Equal("test", saData.Data["Bar"]);
        }

        [Fact]
        public void ShouldCorrectlySerializeDictionary_Default()
        {
            ISecureTokenProvider provider = DefaultSecureTokenProvider.Create(GetAESConfig());
            var saToken = provider.GenerateToken(PayLoad);

            Debug.WriteLine($"DTOKEN LENGTH: {saToken.Length}");

            var saData = provider.ValidateAndGetData(saToken);

            Assert.Equal("12", saData.Data["Foo"]);
            Assert.Equal("test", saData.Data["Bar"]);
        }

        [Fact]
        public void ShouldDetectExpired_AesProtobuf()
        {
            var provider = GetAesProtobufTokenProvider();

            var token = provider.GenerateToken(new Dictionary<string, string>{
                { "Test", "ok"}
            }, 1);

            Thread.Sleep(1500);

            Assert.Throws<SecurityException>(() => provider.ValidateAndGetData(token));
        }

        [Fact]
        public void ShouldDetectExpired_Default()
        {
            var provider = DefaultSecureTokenProvider.Create(GetAESConfig());

            var token = provider.GenerateToken(new Dictionary<string, string>{
                { "Test", "ok"}
            }, 1);

            Thread.Sleep(1500);

            Assert.Throws<SecurityException>(() => provider.ValidateAndGetData(token));
        }

        private static AESEncryptionConfiguration GetAESConfig()
        {
            return new AESEncryptionConfiguration
            {
                EncryptionKey = "3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8="
            };
        }

        private static ISecureTokenProvider GetAesProtobufTokenProvider()
        {
            var serializer = new ProtobufSecureTokenSerializer();
            var protector = new AESSecureTokenProtector(GetAESConfig());

            return new DefaultSecureTokenProvider(serializer, protector);
        }
    }
}
