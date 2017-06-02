using System;
using System.Linq;
using System.Security.Cryptography;

namespace Dks.SimpleToken.Protectors
{
    public sealed class AESEncryptionConfiguration
    {
        /// <summary>
        /// Creates a new AES configuration
        /// </summary>
        /// <param name="key">The encryption key encoded in Base64. Its size must match <see cref="KeySize"/></param>
        /// <param name="keySize">The seize in bits of the key provided. Default 256 bits.</param>
        /// <param name="cipherMode">The cipher mode to use. Default is CBC mode.</param>
        /// <param name="padding">The padding mode to use. Default is PKCS7</param>
        /// <exception cref="ArgumentException">Encryption key is null or whitespace</exception>
        /// <exception cref="CryptographicException"><seealso cref="EncryptionKey"/> size does not match provided <seealso cref="KeySize"/></exception>
        public AESEncryptionConfiguration(string key, int keySize = 256, CipherMode cipherMode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("Encryption key cannot be null or whitespace", nameof(key));

            EncryptionKey = key;
            KeySize = keySize;
            CipherMode = cipherMode;
            Padding = padding;

            Validate();
        }

        /// <summary>
        /// Gets the encryption key.
        /// </summary>
        /// <remarks>
        /// The length of the key needs to be the same as the value defined within the keySize configuration
        /// </remarks>
        /// <value>
        /// The encryption key.
        /// </value>
        public string EncryptionKey { get; }

        /// <summary>
        /// Gets the size of the key in bits. Defaults to 256;
        /// </summary>
        /// <value>
        /// The size of the key in bits.
        /// </value>
        public int KeySize { get; }

        /// <summary>
        /// Gets the cipher mode. Defaults to CBC.
        /// </summary>
        /// <value>
        /// The cipher mode.
        /// </value>
        public CipherMode CipherMode { get; }

        /// <summary>
        /// Gets the padding mode. Defaults to PKCS7.
        /// </summary>
        /// <value>
        /// The padding mode.
        /// </value>
        public PaddingMode Padding { get; }

        /// <summary>
        /// Validates the configuration and throws an <seealso cref="CryptographicException"/> if
        /// invalid
        /// </summary>
        /// <exception cref="CryptographicException"><seealso cref="EncryptionKey"/> size does not match with <seealso cref="KeySize"/></exception>
        private void Validate()
        {
            using (var aes = Aes.Create())
            {
                if (!aes.LegalKeySizes.Any(x => x.MinSize <= KeySize && KeySize <= x.MaxSize))
                {
                    throw new CryptographicException("Invalid Key Size specified. The recommended value is: 256");
                }
            }

            var key = Convert.FromBase64String(EncryptionKey);

            // Check that the key length is equal to KeySize / 8
            // e.g. 256/8 == 32 bytes expected for the key
            if (key.Length != KeySize / 8)
            {
                throw new CryptographicException($"Encryption key has wrong length. Please ensure that it is *EXACTLY* {KeySize} bits long");
            }
        }
    }
}
