using System;
using Dks.SimpleToken.Core;
using Dks.SimpleToken.Protectors;

namespace Dks.SimpleToken.Validation.MVC5
{
    /// <summary>
    /// Helper for configuring <see cref="ValidateTokenAttribute"/> in ASP.NET MVC 5
    /// </summary>
    public static class MvcSimpleTokenValidator
    {
        /// <summary>
        /// Gets the configured <see cref="ISecureTokenProvider"/> instance used by <see cref="ValidateTokenAttribute"/>
        /// </summary>
        public static ISecureTokenProvider SecureTokenProvider { get; private set; }

        /// <summary>
        /// Gets the assigned <see cref="MVC5.ValidateFilterOptions"/> instance used to customize <see cref="ValidateTokenAttribute"/>
        /// </summary>
        public static ValidateFilterOptions ValidateFilterOptions { get; private set; }

        /// <summary>
        /// Configures <see cref="ValidateTokenAttribute"/> using the provided <see cref="ISecureTokenProvider"/> instance and
        /// an optional <see cref="MVC5.ValidateFilterOptions"/> object to customize filter parameters
        /// </summary>
        /// <param name="secureTokenProvider">The Secure Token provider to use to validate tokens</param>
        /// <param name="options">Optional object used to customize the action filter parameters</param>
        public static void ConfigureFilter(ISecureTokenProvider secureTokenProvider, ValidateFilterOptions options = null)
        {
            if (secureTokenProvider == null) throw new ArgumentNullException(nameof(secureTokenProvider));
            SecureTokenProvider = secureTokenProvider;
            ValidateFilterOptions = options ?? new ValidateFilterOptions();
        }

        /// <summary>
        /// Configures <see cref="ValidateTokenAttribute"/> using the provided <see cref="ISecureTokenProtector"/> and <see cref="ISecureTokenSerializer"/>
        /// instances and an optional <see cref="MVC5.ValidateFilterOptions"/> object to customize filter parameters
        /// </summary>
        /// <param name="secureTokenProtector">The Secure Token protector used to decrypt tokens</param>
        /// <param name="secureTokenSerializer">The Secure Token serializer used to deserialize tokens</param>
        /// <param name="options">Optional object used to customize the action filter parameters</param>
        public static void ConfigureFilter(ISecureTokenProtector secureTokenProtector, ISecureTokenSerializer secureTokenSerializer,
            ValidateFilterOptions options = null)
        {
            if (secureTokenProtector == null) throw new ArgumentNullException(nameof(secureTokenProtector));
            if (secureTokenSerializer == null) throw new ArgumentNullException(nameof(secureTokenSerializer));

            ConfigureFilter(new DefaultSecureTokenProvider(secureTokenSerializer, secureTokenProtector), options);
        }

        /// <summary>
        /// Configures <see cref="ValidateTokenAttribute"/> using the the default implementation of Secure Token provider
        /// from the provided <see cref="AESEncryptionConfiguration"/> instance and an optional
        /// <see cref="MVC5.ValidateFilterOptions"/> object to customize filter parameters
        /// </summary>
        /// <param name="encryptionConfiguration">The object used to configure AES encryption and decryption</param>
        /// <param name="options">Optional object used to customize the action filter parameters</param>
        public static void ConfigureFilter(AESEncryptionConfiguration encryptionConfiguration, ValidateFilterOptions options = null)
        {
            if (encryptionConfiguration == null) throw new ArgumentNullException(nameof(encryptionConfiguration));

            var provider = DefaultSecureTokenProvider.Create(encryptionConfiguration);
            ConfigureFilter(provider, options);
        }
    }
}
