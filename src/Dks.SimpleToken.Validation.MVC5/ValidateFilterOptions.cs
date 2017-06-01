namespace Dks.SimpleToken.Validation.MVC5
{
    /// <summary>
    /// Options to customize <see cref="ValidateTokenAttribute"/>
    /// </summary>
    public sealed class ValidateFilterOptions
    {
        /// <summary>
        /// Default HTTP Header for reading tokens
        /// </summary>
        public const string DefaultSecureTokenHeader = "X-Secure-Token";

        /// <summary>
        /// Default Query string parameter name for reading tokens
        /// </summary>
        public const string DefaultSecureTokenQueryParameter = "token";

        /// <summary>
        /// Constructs an new instance
        /// </summary>
        /// <param name="secureTokenHeader">The custom HTTP header to look when searching for a Secure Token. Defaults to <see cref="DefaultSecureTokenHeader"/> if null.</param>
        /// <param name="secureTokenQueryParameter">The custom query string parameter name to look when searching for a Secure Token. Defaults to <see cref="DefaultSecureTokenQueryParameter"/> if null.</param>
        public ValidateFilterOptions(string secureTokenHeader = null, string secureTokenQueryParameter = null)
        {
            SecureTokenHeader = secureTokenHeader ?? DefaultSecureTokenHeader;
            SecureTokenQueryParameter = secureTokenQueryParameter ?? DefaultSecureTokenQueryParameter;
        }

        public string SecureTokenHeader { get; }

        public string SecureTokenQueryParameter { get; }
    }
}
