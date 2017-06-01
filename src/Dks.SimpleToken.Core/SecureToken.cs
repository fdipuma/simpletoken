using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Dks.SimpleToken.Core
{
    /// <summary>
    /// Deserialized Token information
    /// </summary>
    public sealed class SecureToken
    {
        private SecureToken()
        { }

        public static SecureToken Create(DateTimeOffset issueDate, DateTimeOffset expiration, IDictionary<string, string> data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (issueDate > expiration) throw new ArgumentException($"{nameof(issueDate)} cannot be after {nameof(expiration)}");

            return new SecureToken
            {
                Issued = issueDate,
                Expire = expiration,
                Data = new ReadOnlyDictionary<string, string>(data)
            };
        }

        /// <summary>
        /// Instant in time when the token was issued
        /// </summary>
        public DateTimeOffset Issued { get; internal set; }

        /// <summary>
        /// Instant in time when the token expires
        /// </summary>
        public DateTimeOffset Expire { get; internal set; }

        /// <summary>
        /// Indicates if the token is expired
        /// </summary>
        public bool IsExpired => DateTimeOffset.UtcNow > Expire;

        /// <summary>
        /// Additional data serialized inside the token
        /// </summary>        
        public IDictionary<string, string> Data { get; internal set; }
    }
}
