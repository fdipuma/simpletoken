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

            var realKeySize = bytes.Length/ 8;

            Assert.Equal(keySize/8, realKeySize);

            using (var aes = Aes.Create())
            {
                Assert.False(aes.LegalKeySizes.Any(x => x.MinSize <= realKeySize && realKeySize <= x.MaxSize));
            }
        }
    }
}