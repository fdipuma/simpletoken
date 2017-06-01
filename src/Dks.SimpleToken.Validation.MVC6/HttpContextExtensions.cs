using System;
using Dks.SimpleToken.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dks.SimpleToken.Validation.MVC6
{
    public static class HttpContextExtensions
    {
        private const string SecurityTokenHttpContextItemKey = "Dks.SimpleToken.SecureToken";

        public static SecureToken GetSecureToken(this ControllerBase controller)
        {
            if (controller == null) throw new ArgumentNullException(nameof(controller));
            return controller.HttpContext.GetSecureToken();
        }

        public static SecureToken GetSecureToken(this HttpContext httpContext)
        {
            if (httpContext == null) throw new ArgumentNullException(nameof(httpContext));
            httpContext.Items.TryGetValue(SecurityTokenHttpContextItemKey, out object obj);
            return obj as SecureToken;
        }

        internal static void SetSecureToken(this HttpContext httpContext, SecureToken token)
        {
            if (httpContext == null) throw new ArgumentNullException(nameof(httpContext));
            httpContext.Items[SecurityTokenHttpContextItemKey] = token;
        }
    }
}
