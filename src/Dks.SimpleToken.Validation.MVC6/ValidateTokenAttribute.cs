using System;
using System.Linq;
using System.Security;
using Dks.SimpleToken.Core;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace Dks.SimpleToken.Validation.MVC6
{
    public class ValidateTokenAttribute : TypeFilterAttribute
    {
        public ValidateTokenAttribute() : base(typeof(ValidateTokenAttributeImplementation))
        { }

        private class ValidateTokenAttributeImplementation : IAuthorizationFilter
        {
            private readonly ISecureTokenProvider _secureTokenProvider;

            private readonly ValidateTokenOptions _options;

            private readonly ILogger _logger;

            public ValidateTokenAttributeImplementation(ILoggerFactory loggerFactory, ISecureTokenProvider secureTokenProvider, ValidateTokenOptions options)
            {
                _secureTokenProvider = secureTokenProvider ?? throw new ArgumentNullException(nameof(secureTokenProvider));
                _options = options ?? new ValidateTokenOptions();
                _logger = loggerFactory.CreateLogger<ValidateTokenAttribute>();
            }

            public void OnAuthorization(AuthorizationFilterContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }
                
                string token = null;
                StringValues values;

                if (context.HttpContext.Request.Headers.TryGetValue(_options.SecureTokenHeader, out values))
                {
                    token = values.FirstOrDefault();

                    if (token != null)
                        _logger.LogDebug("Security token found inside header");
                }

                if (token == null && context.HttpContext.Request.Query.TryGetValue(_options.SecureTokenQueryParameter, out values))
                {
                    token = values.FirstOrDefault();

                    if(token != null)
                        _logger.LogDebug("Security token found inside query string");
                }

                if (string.IsNullOrWhiteSpace(token))
                {
                    context.Result = new UnauthorizedResult();
                    _logger.LogWarning("No security token found for the request. Access is denied.");
                    return;
                }

                SecureToken validated;

                try
                {
                    validated = _secureTokenProvider.ValidateAndGetData(token);
                }
                catch (SecurityException)
                {
                    context.Result = new UnauthorizedResult();
                    _logger.LogWarning("Invalid or expired token for the request. Access is denied.");
                    return;
                }

                context.HttpContext.SetSecureToken(validated);
            }
        }
    }
}
