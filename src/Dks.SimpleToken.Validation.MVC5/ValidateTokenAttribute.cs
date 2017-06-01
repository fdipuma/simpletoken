using System;
using System.Net;
using System.Security;
using System.Web.Mvc;
using Dks.SimpleToken.Core;

namespace Dks.SimpleToken.Validation.MVC5
{
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, Inherited = true, AllowMultiple = false)]
    public class ValidateTokenAttribute : ActionFilterAttribute
    {
        private string[] MatchingParameters { get; }

        public ValidateTokenAttribute(params string[] matchingParameters)
        {
            MatchingParameters = matchingParameters;
        }

        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            if (filterContext == null)
            {
                throw new ArgumentNullException(nameof(filterContext));
            }

            var provider = MvcSimpleTokenValidator.SecureTokenProvider;

            if (provider == null)
                throw new InvalidOperationException("No token provider could be found for this request. Please ensure " +
                                                    "you have configured the `ISecureTokenProvider` instance by calling " +
                                                    "`MvcSimpleTokenValidator.ConfigureValidateTokenFilter` method on startup");

            var options = MvcSimpleTokenValidator.ValidateFilterOptions;

            var token = filterContext.HttpContext.Request.Headers[options.SecureTokenHeader] ??
                        filterContext.HttpContext.Request.QueryString[options.SecureTokenQueryParameter];

            if (string.IsNullOrWhiteSpace(token))
            {
                filterContext.Result = new HttpUnauthorizedResult("Token not found");
                return;
            }

            SecureToken validated;

            try
            {
                validated = provider.ValidateAndGetData(token);
            }
            catch (SecurityException)
            {
                filterContext.Result = new HttpUnauthorizedResult("Invalid or expired token");
                return;
            }

            foreach (var matchingParameter in MatchingParameters)
            {
                if (!filterContext.ActionParameters.ContainsKey(matchingParameter) || !validated.Data.ContainsKey(matchingParameter))
                {
                    filterContext.Result = new HttpStatusCodeResult(
                        HttpStatusCode.Forbidden,
                        $"Parameter {matchingParameter} not found");
                    return;
                }

                var param = filterContext.ActionParameters[matchingParameter]?.ToString();

                if (!validated.Data[matchingParameter].Equals(param, StringComparison.InvariantCulture))
                {
                    filterContext.Result = new HttpStatusCodeResult(
                        HttpStatusCode.Forbidden,
                        $"Parameter {matchingParameter} does not match");
                    return;
                }
            }
        }
    }
}
