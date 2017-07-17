using System.Collections.Generic;

namespace Dks.SimpleToken.Core
{
    /// <summary>
    /// Generic interface for a secure Token provider, provides methods for token generation and
    /// validation
    /// </summary>
    public interface ISecureTokenProvider
    {
        /// <summary>
        /// Generates a secure token
        /// </summary>
        /// <param name="data">Additional data to attach</param>
        /// <param name="ttl">Time To Live (before expiration) in seconds</param>
        /// <returns>An encrypted string representing the token</returns>
        string GenerateToken(IDictionary<string, string> data, int? ttl = 60);

        /// <summary>
        /// Validates a token and deserializes its data inside a SecureToken object
        /// </summary>
        /// <param name="token">Encrypted token string</param>
        /// <returns>Secure token with attached data</returns>
        SecureToken ValidateAndGetData(string token);
    }
}
