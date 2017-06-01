using System;
using System.Linq;
using System.Security.Cryptography;

namespace Dks.SimpleToken.Protectors
{
    public class AESEncryptionConfiguration
    {
        public AESEncryptionConfiguration()
        {
            CipherMode = CipherMode.CBC;
            Padding = PaddingMode.PKCS7;
            KeySize = 256;
        }

        /// <summary>
        /// Gets or sets the encryption key.
        /// </summary>
        /// <remarks>
        /// The length of the key needs to be the same as the value defined within the keySize configuration
        /// </remarks>
        /// <value>
        /// The encryption key.
        /// </value>
        public string EncryptionKey { get; set; }

        /// <summary>
        /// Gets or sets the size of the key in bits. Defaults to 256;
        /// </summary>
        /// <value>
        /// The size of the key in bits.
        /// </value>
        public int KeySize { get; set; }

        /// <summary>
        /// Gets or sets the cipher mode. Defaults to CBC.
        /// </summary>
        /// <value>
        /// The cipher mode.
        /// </value>
        public CipherMode CipherMode { get; set; }

        /// <summary>
        /// Gets or sets the padding mode. Defaults to PKCS7.
        /// </summary>
        /// <value>
        /// The padding mode.
        /// </value>
        public PaddingMode Padding { get; set; }

        /// <summary>
        /// Validates the configuration and throws an <seealso cref="CryptographicException"/> if
        /// invalid
        /// </summary>
        /// <exception cref="CryptographicException"><seealso cref="EncryptionKey"/> is missing or its size does not 
        /// match with <seealso cref="KeySize"/></exception>
        public void Validate()
        {
            if (string.IsNullOrWhiteSpace(EncryptionKey))
            {
                throw new CryptographicException("Encryption key is missing.");
            }

            using (var aes = Aes.Create())
            {
                if (!aes.LegalKeySizes.Any(x => x.MinSize <= KeySize && KeySize <= x.MaxSize))
                {
                    throw new CryptographicException("Invalid Key Size specified. The recommended value is: 256");
                }
            }

            var key = Convert.FromBase64String(EncryptionKey);

            // Check that the key length is equal to config.KeySize / 8
            // e.g. 256/8 == 32 bytes expected for the key
            if (key.Length != KeySize / 8)
            {
                throw new CryptographicException($"Encryption key has wrong length. Please ensure that it is *EXACTLY* {KeySize} bits long");
            }
        }
    }
}
