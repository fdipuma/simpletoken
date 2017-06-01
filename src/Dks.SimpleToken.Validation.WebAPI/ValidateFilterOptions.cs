namespace Dks.SimpleToken.Validation.WebAPI
{
    public class ValidateFilterOptions
    {
        public const string DefaultSecureTokenHeader = "X-Secure-Token";

        public const string DefaultSecureTokenQueryParameter = "token";

        public ValidateFilterOptions(string secureTokenHeader = null, string secureTokenQueryParameter = null)
        {
            SecureTokenHeader = secureTokenHeader ?? DefaultSecureTokenHeader;
            SecureTokenQueryParameter = secureTokenQueryParameter ?? DefaultSecureTokenQueryParameter;
        }

        public string SecureTokenHeader { get; }

        public string SecureTokenQueryParameter { get; }
    }
}
