using System;
using System.Security.Cryptography;
using System.Text;
using Dks.SimpleToken.Protectors;
using System.Linq;
using Xunit;

namespace Dks.SimpleToken.Tests
{
    public class AESTests
    {
        [Fact]
        public void ShouldGenerateValidKey()
        {
            const int keySize = 256;
            const CipherMode mode = CipherMode.CBC;
            var key = AESEncryptionConfiguration.GenerateNewKey(keySize, mode);

            new AESEncryptionConfiguration(key, keySize, mode); // should not throw

            var bytes = Convert.FromBase64String(key);

            Assert.Equal(keySize/8, bytes.Length);

            var realKeySize = bytes.Length * 8;

            using (var aes = Aes.Create())
            {
                Assert.True(aes.LegalKeySizes.Any(x => x.MinSize <= realKeySize && realKeySize <= x.MaxSize));
            }
        }
    }
}