using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Web;
using System.Web.Security;
using Dks.SimpleToken.Core;
using Dks.SimpleToken.SystemWeb;

namespace Dks.SimpleToken.Providers
{
    /// <summary>
    /// Secure Token provider which uses ASP.NET <seealso cref="FormsAuthenticationTicket"/> for encryption and serialization.
    /// </summary>
    public sealed class FormsAuthSecureTokenProvider : ISecureTokenProvider
    {
        private const string DefaultTicketName = "Secure.Token";

        public string TicketName { get; }

        /// <summary>
        /// Constructs an instance using the default FormsAuthentication ticket name.
        /// </summary>
        public FormsAuthSecureTokenProvider()
            : this(DefaultTicketName)
        { }

        /// <summary>
        /// Constructs an instance using the provided FormsAuthentication ticket name.
        /// </summary>
        public FormsAuthSecureTokenProvider(string ticketName)
        {
            TicketName = ticketName;
        }

        /// <inheritdoc />
        public string GenerateToken(IDictionary<string, string> data, int ttl = 60)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (ttl <= 0) throw new ArgumentOutOfRangeException(nameof(ttl));

            var kvps = HttpUtility.ParseQueryString(string.Empty); // this will return an empty HttpValueCollection

            foreach (var kvp in data)
            {
                kvps.Add(kvp.Key, kvp.Value);
            }

            return Generate(TicketName, kvps.ToString(), ttl);
        }

        private static string Generate(string ticketName, string serializedData, int ttl = 60)
        {
            if (ticketName == null) throw new ArgumentNullException(nameof(ticketName));
            if (serializedData == null) throw new ArgumentNullException(nameof(serializedData));
            if (ttl <= 0) throw new ArgumentOutOfRangeException(nameof(ttl));

            var utcNow = DateTime.UtcNow;

            var formsTicket = new FormsAuthenticationTicket(
                1, // version
                ticketName, // ticket name
                utcNow, // issue date
                utcNow.AddSeconds(ttl), // expiration date
                true, // is persistent
                serializedData // user additional data
                );

            var encryptedTicket = FormsAuthentication.Encrypt(formsTicket);

            var compressed = CompressionUtility.Zip(encryptedTicket);

            var encoded = Convert.ToBase64String(compressed);

            return encoded;
        }

        /// <inheritdoc />
        public SecureToken ValidateAndGetData(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                throw new ArgumentException("Argument is null or whitespace", nameof(token));

            FormsAuthenticationTicket decryptedTicket;

            var compressed = Convert.FromBase64String(token);

            var encryptedTicket = CompressionUtility.Unzip(compressed);

            try
            {
                decryptedTicket = FormsAuthentication.Decrypt(encryptedTicket);
            }
            catch (Exception ex)
            {
                throw new SecurityException("Unable to decrypt token", ex);
            }

            if (decryptedTicket == null)
                throw new SecurityException("SecureToken decryption failed");

            if (decryptedTicket.Expired)
                throw new SecurityException("SecureToken is expired");

            IDictionary<string, string> data = null;

            if (decryptedTicket.UserData != null)
            {
                var nameValueCollection = HttpUtility.ParseQueryString(decryptedTicket.UserData);

                data = nameValueCollection.AllKeys
                    .ToDictionary(k => k, k => nameValueCollection[k],
                    StringComparer.OrdinalIgnoreCase);
            }

            return SecureToken.Create(decryptedTicket.IssueDate, decryptedTicket.Expiration, data ?? new Dictionary<string, string>());
        }
    }
}
