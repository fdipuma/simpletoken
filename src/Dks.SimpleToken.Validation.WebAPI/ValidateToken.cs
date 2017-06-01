using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security;
using System.Web.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using Dks.SimpleToken.Core;

namespace Dks.SimpleToken.Validation.WebAPI
{
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, Inherited = true, AllowMultiple = true)]
    public class ValidateToken : ActionFilterAttribute
    {
        // it's an ActionFilter (and not an AuthorizationFilter) because we need ModelBinding
        // for token parameters matching

        private readonly string[] _matchingParameters;
        
        public ValidateToken(params string[] matchingParameters)
        {
            _matchingParameters = matchingParameters;
        }

        /// <summary>
        /// Valida il token nell'URI (query string), e confronta i valori contenuti in esso con gli stessi forniti come parametri
        /// in base alle chiavi contenute in matchingParameters
        /// </summary>
        /// <param name="actionContext"></param>
        public override void OnActionExecuting(HttpActionContext actionContext)
        {
            if (actionContext == null)
            {
                throw new ArgumentNullException(nameof(actionContext));
            }

            var provider = GetSecureTokenProvider(actionContext);

            if (provider == null)
                throw new InvalidOperationException("No token provider could be found for this request. Please ensure " +
                                                    "you have configured the `ISecureTokenProvider` instance used with " +
                                                    "`AddSecureTokenProvider` extension methods on `HttpConfiguration`");

            var options = GetSecureTokenOptions(actionContext);

            string token = null;

            IEnumerable<string> values;
            if (actionContext.Request.Headers.TryGetValues(
                options?.SecureTokenHeader ?? ValidateFilterOptions.DefaultSecureTokenHeader, out values))
            {
                token = values.FirstOrDefault();
            }

            if (token == null)
            {
                token = actionContext
                    .Request
                    .GetQueryNameValuePairs()
                    .FirstOrDefault(i => i.Key.Equals(
                        options?.SecureTokenQueryParameter ??
                        ValidateFilterOptions.DefaultSecureTokenQueryParameter,
                        StringComparison.OrdinalIgnoreCase))
                    .Value;
            }

            if (string.IsNullOrWhiteSpace(token))
            {
                throw new HttpResponseException(actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized, "Token not found"));
            }

            SecureToken validated;

            try
            {
                validated = provider.ValidateAndGetData(token);
            }
            catch (SecurityException)
            {
                throw new HttpResponseException(actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized, "Invalid or expired token"));
            }

            foreach (var matchingParameter in _matchingParameters)
            {
                if (!actionContext.ActionArguments.ContainsKey(matchingParameter) || !validated.Data.ContainsKey(matchingParameter))
                {
                    throw new HttpResponseException(actionContext.Request.CreateResponse(
                        HttpStatusCode.Forbidden,
                        $"Parameter {matchingParameter} not found"));
                }

                var argument = actionContext.ActionArguments[matchingParameter]?.ToString();

                if (!validated.Data[matchingParameter].Equals(argument, StringComparison.InvariantCulture))
                {
                    throw new HttpResponseException(actionContext.Request.CreateResponse(
                        HttpStatusCode.Forbidden,
                        $"Parameter {matchingParameter} does not match the token"));
                }
            }
        }
        
        private static ValidateFilterOptions GetSecureTokenOptions(HttpActionContext actionContext)
        {
            object options = null;
            actionContext?.ControllerContext?.Configuration?.Properties?.TryGetValue(typeof(ValidateFilterOptions), out options);
            return options as ValidateFilterOptions;
        }

        private static ISecureTokenProvider GetSecureTokenProvider(HttpActionContext actionContext)
        {
            object provider = null;
            actionContext?.ControllerContext?.Configuration?.Properties?.TryGetValue(typeof(ISecureTokenProvider), out provider);
            return provider as ISecureTokenProvider;
        }
    }
}
