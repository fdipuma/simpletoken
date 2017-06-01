using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;

namespace Dks.SimpleToken.Core
{
    public static class SecureTokenExtensions
    {
        /// <summary>
        /// Generates a secure token
        /// </summary>
        /// <param name="provider">The token provider instance</param>
        /// <param name="data">Additional data to attach</param>
        /// <param name="ttl">Time To Live (before expiration) in seconds</param>
        /// <returns>An encrypted string representing the token</returns>
        public static string GenerateToken<T>(this ISecureTokenProvider provider, T data, int? ttl = null) where T : class
        {
            if (provider == null) throw new ArgumentNullException(nameof(provider));
            if (data == null) throw new ArgumentNullException(nameof(data));

            var dictData = ObjectToDictionary(data);

            return ttl.HasValue ? provider.GenerateToken(dictData, ttl.Value) : provider.GenerateToken(dictData);
        }

        /// <summary>
        /// Turns an object into a <see cref="Dictionary{TKey,TValue}"/>
        /// </summary>
        /// <typeparam name="T">The object type</typeparam>
        /// <param name="source"></param>
        /// <returns>A dictionary</returns>
        private static IDictionary<string, string> ObjectToDictionary<T>(T source)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));

            var dict = source as Dictionary<string, string>;
            if (dict != null) return dict;

            return typeof(T).GetTypeInfo().DeclaredProperties.Where(p => p.GetMethod.IsPublic && !p.GetMethod.IsStatic)
                .ToDictionary(p => p.Name, p => p.GetInvariantFormattedValue(source));
        }

        /// <summary>
        /// Gets the current value of a property and formats it with the InvariantCulture
        /// </summary>
        private static string GetInvariantFormattedValue(this PropertyInfo property, object component)
        {
            if (property == null) throw new ArgumentNullException(nameof(property));
            if (component == null) throw new ArgumentNullException(nameof(component));

            var value = property.GetValue(component);

            if (value == null)
                return null;
            
            var formattable = value as IFormattable;
            if(formattable != null)
                return formattable.ToString(null, CultureInfo.InvariantCulture);

            return value.ToString();
        }
    }
}
