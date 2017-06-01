namespace Dks.SimpleToken.Validation.MVC6
{
    public sealed class ValidateTokenOptions
    {
        private const string DefaultSecureTokenHeader = "X-Secure-Token";
        private const string DefaultSecureTokenQueryParameter = "token";

        public ValidateTokenOptions(string secureTokenHeader = null, string secureTokenQueryParameter = null)
        {
            SecureTokenHeader = secureTokenHeader ?? DefaultSecureTokenHeader;
            SecureTokenQueryParameter = secureTokenQueryParameter ?? DefaultSecureTokenQueryParameter;
        }

        public string SecureTokenHeader { get; }

        public string SecureTokenQueryParameter { get; }
    }
}
