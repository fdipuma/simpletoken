using System;
using System.Globalization;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Dks.SimpleToken.Validation.MVC6
{
    public class MatchTokenDataAttribute : ActionFilterAttribute
    {
        private readonly string[] _matchingParameters;

        public MatchTokenDataAttribute(params string[] matchingParameters)
        {
            _matchingParameters = matchingParameters;
        }

        public override void OnActionExecuting(ActionExecutingContext context)
        {
            if (context.Filters.OfType<ValidateTokenAttribute>().Any())
            {
                // main Filter not added, throw exception
                throw new InvalidOperationException($"{nameof(MatchTokenDataAttribute)} must be used in conjunction with {nameof(ValidateTokenAttribute)}");
            }

            var token = context.HttpContext.GetSecureToken();

            if (token == null)
            {
                context.Result = new ForbidResult("No token found");
                return;
            }
            
            foreach (var matchingParameter in _matchingParameters)
            {
                if (!context.ActionArguments.ContainsKey(matchingParameter) ||
                    !token.Data.ContainsKey(matchingParameter))
                {
                    context.Result = new ForbidResult($"Parameter {matchingParameter} not found");
                    return;
                }
                var argument = ToInvariantString(context.ActionArguments[matchingParameter]);

                if (!token.Data[matchingParameter].Equals(argument, StringComparison.Ordinal))
                {
                    context.Result = new ForbidResult($"Parameter {matchingParameter} mismatched");
                    return;
                }
            }

            base.OnActionExecuting(context);
        }

        private static string ToInvariantString(object obj)
        {
            if (obj == null)
                return null;
            if (obj is IConvertible convertible)
                return convertible.ToString(CultureInfo.InvariantCulture);
            if (obj is IFormattable formattable)
                return formattable.ToString(null, CultureInfo.InvariantCulture);
            return obj.ToString();
        }
    }
}
