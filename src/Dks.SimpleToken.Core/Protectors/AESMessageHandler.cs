// Inspired by Simple AES
// https://github.com/ArtisanCode/SimpleAesEncryption
// The MIT License (MIT)
// Copyright(c) 2014 Artisan code

using System;
using System.IO;
using System.Security.Cryptography;

namespace Dks.SimpleToken.Protectors
{
    internal sealed class AESMessageHandler
    {
        public const string CYPHER_TEXT_IV_SEPERATOR = "??";

        /// <summary>
        /// Initializes a new instance of the <see cref="AESMessageHandler"/> class.
        /// </summary>
        /// <param name="config">The configuration.</param>
        public AESMessageHandler(AESEncryptionConfiguration config)
        {
            Configuration = config ?? throw new ArgumentNullException(nameof(config));
        }

        /// <summary>
        /// Gets or sets the configuration.
        /// </summary>
        /// <value>
        /// The configuration.
        /// </value>
        public AESEncryptionConfiguration Configuration { get; set; }

        /// <summary>
        /// Configures the crypto container.
        /// </summary>
        /// <param name="cryptoContainer">The crypto container to configure.</param>
        private void ConfigureCryptoContainer(SymmetricAlgorithm cryptoContainer)
        {
            Configuration.Validate();
            
            cryptoContainer.Mode = Configuration.CipherMode;
            cryptoContainer.Padding = Configuration.Padding;
            cryptoContainer.KeySize = Configuration.KeySize;
            cryptoContainer.Key = Convert.FromBase64String(Configuration.EncryptionKey);

            // Generate a new Unique IV for this container and transaction (can be overridden later to decrypt messages where the IV is known)
            cryptoContainer.GenerateIV();
        }


        /// <summary>
        /// Encrypts the specified source.
        /// </summary>
        /// <param name="source">The source.</param>
        /// <returns></returns>
        public string Encrypt(string source)
        {
            // Short-circuit encryption for empty strings
            if (string.IsNullOrEmpty(source))
            {
                return string.Empty;
            }

            // Encrypt the string to an array of bytes.
            var output = EncryptStringToBytes(source);

            // Return the Base64 encoded cypher-text along with the (plaintext) unique IV used for this encryption
            return string.Format("{0}{1}{2}", Convert.ToBase64String(output.Item1), CYPHER_TEXT_IV_SEPERATOR, Convert.ToBase64String(output.Item2));
        }

        /// <summary>
        /// Encrypts the string to bytes.
        /// </summary>
        /// <param name="plainText">The plain text.</param>
        /// <remarks>
        /// Original version: http://msdn.microsoft.com/en-us/library/system.security.cryptography.rijndaelmanaged.aspx
        /// 20/05/2014 @ 20:05
        /// </remarks>
        /// <returns>
        /// Item 1: The cyphertext that is generated from the plaintext input
        /// Item 2: The IV used for the encryption algorithm
        /// </returns>
        public Tuple<byte[], byte[]> EncryptStringToBytes(string plainText)
        {
            Tuple<byte[], byte[]> output;

            using (var cryptoContainer = Aes.Create())
            {
                ConfigureCryptoContainer(cryptoContainer);

                // Create an encryptor to perform the stream transform.
                var encryptor = cryptoContainer.CreateEncryptor(cryptoContainer.Key, cryptoContainer.IV);

                // Create the streams used for encryption.
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }

                        output = new Tuple<byte[], byte[]>(msEncrypt.ToArray(), cryptoContainer.IV);
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return output;
        }
        
        /// <summary>
        /// Decrypts the specified cypherText.
        /// </summary>
        /// <param name="cypherText">The cypherText to decrypt.</param>
        /// <returns>The plaintext decrypted version of the cypher text</returns>
        /// <exception cref="System.ArgumentException">Invalid source string. Unable to determine the correct IV used for the encryption. Please ensure the source string is in the format 'Cypher Text' + CYPHER_TEXT_IV_SEPERATOR + 'IV';source</exception>
        public string Decrypt(string cypherText)
        {
            // Short-circuit decryption for empty strings
            if (string.IsNullOrEmpty(cypherText))
            {
                return string.Empty;
            }

            var primatives = cypherText.Split(new[] { CYPHER_TEXT_IV_SEPERATOR }, StringSplitOptions.RemoveEmptyEntries);

            if (primatives.Length != 2)
            {
                throw new ArgumentException("Invalid cypherText. Unable to determine the correct IV used for the encryption. Please ensure the source string is in the format 'Cypher Text'" + CYPHER_TEXT_IV_SEPERATOR + "'IV'", "source");
            }

            var cypherTextPrimitave = Convert.FromBase64String(primatives[0]);
            var iv = Convert.FromBase64String(primatives[1]);

            return DecryptStringFromBytes(cypherTextPrimitave, iv);
        }

        /// <summary>
        /// Decrypts the string from bytes.
        /// </summary>
        /// <param name="cipherText">The cipher text.</param>
        /// <param name="Key">The key.</param>
        /// <param name="IV">The iv.</param>
        /// <returns></returns>
        /// <remarks>
        /// Original version: http://msdn.microsoft.com/en-us/library/system.security.cryptography.rijndaelmanaged.aspx
        /// 20/05/2014 @ 20:05
        /// </remarks>
        /// <exception cref="System.ArgumentNullException">
        /// cipherText
        /// or
        /// IV
        /// </exception>
        public string DecryptStringFromBytes(byte[] cipherText, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
            {
                throw new ArgumentNullException("cipherText");
            }

            if (IV == null || IV.Length <= 0)
            {
                throw new ArgumentNullException("IV");
            }

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an RijndaelManaged object
            // with the specified key and IV.
            using (var cryptoContainer = Aes.Create())
            {
                ConfigureCryptoContainer(cryptoContainer);

                // Remember to set the IV to the correct value for decryption
                cryptoContainer.IV = IV;

                // Create a decrytor to perform the stream transform.
                var decryptor = cryptoContainer.CreateDecryptor(cryptoContainer.Key, cryptoContainer.IV);

                // Create the streams used for decryption.
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}
