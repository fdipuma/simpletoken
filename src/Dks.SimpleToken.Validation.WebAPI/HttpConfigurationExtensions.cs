using System;
using System.Web.Http;
using Dks.SimpleToken.Core;
using Dks.SimpleToken.Protectors;

namespace Dks.SimpleToken.Validation.WebAPI
{
    public static class HttpConfigurationExtensions
    {
        /// <summary>
        /// Adds the Default Secure Token Provider implementation into Web Api configuration
        /// so <seealso cref="Dks.SimpleToken.Validation.WebAPI.ValidateToken"/> can
        /// be used.
        /// </summary>
        /// <param name="config">The <seealso cref="HttpConfiguration"/> instance to use</param>
        /// <param name="encryptionConfig">The <seealso cref="AESEncryptionConfiguration"/> instance used to configure
        /// the default implementation and encryption</param>
        /// <param name="options">Validate Token Filter options such as custom Header or Query String Parameter</param>
        /// <returns>Chainable <seealso cref="HttpConfiguration"/> object</returns>
        /// <exception cref="System.Security.Cryptography.CryptographicException">The AES configuration options are not valid</exception>
        public static HttpConfiguration AddDefaultSecureTokenProvider(this HttpConfiguration config, AESEncryptionConfiguration encryptionConfig, ValidateFilterOptions options = null)
        {
            if (encryptionConfig == null) throw new ArgumentNullException(nameof(encryptionConfig));
            if (encryptionConfig.EncryptionKey == null) throw new InvalidOperationException("The EncryptionKey cannot be null");

            encryptionConfig.Validate(); // this throws CryptographicException when invalid

            var defaultProvider = DefaultSecureTokenProvider.Create(encryptionConfig);

            config.Properties.TryAdd(typeof(ISecureTokenProvider), defaultProvider);
            config.Properties.TryAdd(typeof(ValidateFilterOptions), options ?? new ValidateFilterOptions());

            return config;
        }

        /// <summary>
        /// Adds the Default Secure Token Provider implementation into Web Api configuration
        /// using the provided instances of <seealso cref="ISecureTokenProtector"/> for token
        /// encryption and <seealso cref="ISecureTokenSerializer"/> for token serialization.
        /// This way <seealso cref="Dks.SimpleToken.Validation.WebAPI.ValidateToken"/> can
        /// be used.
        /// </summary>
        /// <param name="config">The <seealso cref="HttpConfiguration"/> instance to use</param>
        /// <param name="protector">The custom <seealso cref="ISecureTokenProtector"/> instance to use</param>
        /// <param name="serializer">The custom <seealso cref="ISecureTokenSerializer"/> to use</param>
        /// <param name="options">The <seealso cref="ValidateFilterOptions"/> instance used to configure
        /// the validation filter</param>
        /// <returns>Chainable <seealso cref="HttpConfiguration"/> object</returns>
        public static HttpConfiguration AddDefaultSecureTokenProvider(this HttpConfiguration config,
            ISecureTokenProtector protector, ISecureTokenSerializer serializer,
            ValidateFilterOptions options = null)
        {
            var provider = new DefaultSecureTokenProvider(serializer, protector);
            config.Properties.TryAdd(typeof(ISecureTokenProvider), provider);

            if (options != null)
                config.Properties.TryAdd(typeof(ValidateFilterOptions), options);

            return config;
        }

        /// <summary>
        /// Adds the provided custom <seealso cref="ISecureTokenProvider"/> implementation into Web Api
        /// configuration
        /// </summary>
        /// <param name="config">The <seealso cref="HttpConfiguration"/> instance to use</param>
        /// <param name="customProvider">The custom <seealso cref="ISecureTokenProvider"/> instance to use</param>
        /// <param name="options">The <seealso cref="ValidateFilterOptions"/> instance used to configure
        /// the validation filter</param>
        /// <returns>Chainable <seealso cref="HttpConfiguration"/> object</returns>
        public static HttpConfiguration AddCustomSecureTokenProvider(this HttpConfiguration config,
            ISecureTokenProvider customProvider, ValidateFilterOptions options = null)
        {
            config.Properties.TryAdd(typeof(ISecureTokenProvider), customProvider);
            
            if (options != null)
                config.Properties.TryAdd(typeof(ValidateFilterOptions), options);

            return config;
        }
    }
}
