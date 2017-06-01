using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using Dks.SimpleToken.Core;
using Dks.SimpleToken.Validation.MVC6;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Dks.SimpleToken.MVC6.Tests
{
    public class MVC6ValidationFilterTest
    {
        private const string MatchingParameter = "testParam";

        [Fact]
        public void ShouldDetectValidToken_FromQuery()
        {
            //Token generation
            var tokenProvider = new DummyTokenProvider();

            var token = tokenProvider.GenerateToken(new Dictionary<string, string> { { MatchingParameter, "value" } }, 60);

            //Filter creation
            var typeFilter = new ValidateTokenAttribute();

            var sp = CreateServiceProvider();
            var authFilter = typeFilter.CreateInstance(sp) as IAuthorizationFilter;

            var matchFilter = new MatchTokenDataAttribute(MatchingParameter);

            //Filter context initialization
            var actionContext = CraftFakeActionContext();
            actionContext.HttpContext.Request.QueryString = QueryString.Create("token", token);
            var authContext = CraftFakeAuthorizationFilterContext(actionContext);
            var executingContext = CraftFakeActionExecutingContext(actionContext);
            executingContext.ActionArguments.Add(MatchingParameter, "value");

            //Executing filter action
            authFilter.OnAuthorization(authContext);
            Assert.Null(authContext.Result);
            
            matchFilter.OnActionExecuting(executingContext);
            Assert.Null(executingContext.Result);
        }

        [Fact]
        public void ShouldDetectValidToken_FromHeader()
        {
            //Token generation
            var tokenProvider = new DummyTokenProvider();

            var token = tokenProvider.GenerateToken(new Dictionary<string, string> { { MatchingParameter, "value" } }, 60);

            //Filter creation
            var typeFilter = new ValidateTokenAttribute();

            var sp = CreateServiceProvider();
            var authFilter = typeFilter.CreateInstance(sp) as IAuthorizationFilter;

            var matchFilter = new MatchTokenDataAttribute(MatchingParameter);

            //Filter context initialization
            var actionContext = CraftFakeActionContext();
            actionContext.HttpContext.Request.Headers.Add("X-Secure-Token", token);
            var authContext = CraftFakeAuthorizationFilterContext(actionContext);
            var executingContext = CraftFakeActionExecutingContext(actionContext);
            executingContext.ActionArguments.Add(MatchingParameter, "value");

            //Executing filter action
            authFilter.OnAuthorization(authContext);
            Assert.Null(authContext.Result);

            matchFilter.OnActionExecuting(executingContext);
            Assert.Null(executingContext.Result);
        }

        [Fact]
        public void ShouldDetectMissingToken()
        {
            //Filter creation
            var typeFilter = new ValidateTokenAttribute();

            var sp = CreateServiceProvider();
            var authFilter = typeFilter.CreateInstance(sp) as IAuthorizationFilter;

            //Filter context initialization
            var actionContext = CraftFakeActionContext();
            var authContext = CraftFakeAuthorizationFilterContext(actionContext);
            
            //Executing filter action
            authFilter.OnAuthorization(authContext);
            Assert.NotNull(authContext.Result);
            Assert.IsType<UnauthorizedResult>(authContext.Result);
        }

        [Fact]
        public void ShouldDetectEmptyToken()
        {
            //Filter creation
            var typeFilter = new ValidateTokenAttribute();

            var sp = CreateServiceProvider();
            var authFilter = typeFilter.CreateInstance(sp) as IAuthorizationFilter;

            //Filter context initialization
            var actionContext = CraftFakeActionContext();
            actionContext.HttpContext.Request.QueryString = QueryString.Create("token", " ");
            var authContext = CraftFakeAuthorizationFilterContext(actionContext);

            //Executing filter action
            authFilter.OnAuthorization(authContext);
            Assert.NotNull(authContext.Result);
            Assert.IsType<UnauthorizedResult>(authContext.Result);
        }

        [Fact]
        public void ShouldDetectInvalidToken()
        {
            //Filter creation
            var typeFilter = new ValidateTokenAttribute();

            var sp = CreateServiceProvider();
            var authFilter = typeFilter.CreateInstance(sp) as IAuthorizationFilter;

            //Filter context initialization
            var actionContext = CraftFakeActionContext();
            actionContext.HttpContext.Request.QueryString = QueryString.Create("token", "RANDOMSTRING");
            var authContext = CraftFakeAuthorizationFilterContext(actionContext);

            //Executing filter action
            authFilter.OnAuthorization(authContext);
            Assert.NotNull(authContext.Result);
            Assert.IsType<UnauthorizedResult>(authContext.Result);
        }

        [Fact]
        public void ShouldDetectExpiredToken()
        {
            //Token generation
            var tokenProvider = new DummyTokenProvider();

            var token = tokenProvider.GenerateToken(new Dictionary<string, string> { { MatchingParameter, "value" } }, 1);

            //Waiting for token to expire
            Thread.Sleep(1500);

            //Filter creation
            var typeFilter = new ValidateTokenAttribute();

            var sp = CreateServiceProvider();
            var authFilter = typeFilter.CreateInstance(sp) as IAuthorizationFilter;

            //Filter context initialization
            var actionContext = CraftFakeActionContext();
            actionContext.HttpContext.Request.QueryString = QueryString.Create("token", token);
            var authContext = CraftFakeAuthorizationFilterContext(actionContext);

            //Executing filter action
            authFilter.OnAuthorization(authContext);
            Assert.NotNull(authContext.Result);
            Assert.IsType<UnauthorizedResult>(authContext.Result);
        }

        [Fact]
        public void ShouldDetectMismatchingParametersToken()
        {
            //Token generation
            var tokenProvider = new DummyTokenProvider();

            var token = tokenProvider.GenerateToken(new Dictionary<string, string> { { MatchingParameter, "value" } }, 60);

            //Filter creation
            var typeFilter = new ValidateTokenAttribute();

            var sp = CreateServiceProvider();
            var authFilter = typeFilter.CreateInstance(sp) as IAuthorizationFilter;

            var matchFilter = new MatchTokenDataAttribute(MatchingParameter);

            //Filter context initialization
            var actionContext = CraftFakeActionContext();
            actionContext.HttpContext.Request.QueryString = QueryString.Create("token", token);
            var authContext = CraftFakeAuthorizationFilterContext(actionContext);
            var executingContext = CraftFakeActionExecutingContext(actionContext);
            executingContext.ActionArguments.Add(MatchingParameter, "anothervalue");

            //Executing filter action
            authFilter.OnAuthorization(authContext);
            Assert.Null(authContext.Result);

            matchFilter.OnActionExecuting(executingContext);
            Assert.NotNull(executingContext.Result);
            Assert.IsType<ForbidResult>(executingContext.Result);
        }

        private static AuthorizationFilterContext CraftFakeAuthorizationFilterContext(ActionContext actionContext)
        {
            var ctx = new AuthorizationFilterContext(actionContext, new List<IFilterMetadata>());
            return ctx;
        }

        private static ActionExecutingContext CraftFakeActionExecutingContext(ActionContext actionContext)
        {
            var ctx = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), new Dictionary<string, object>(), null);
            return ctx;
        }

        private static ActionContext CraftFakeActionContext()
        {
            var httpContext = new DefaultHttpContext();
            var routeData = new RouteData();
            var actionDescriptor = new ActionDescriptor();
            var ctx = new ActionContext(httpContext, routeData, actionDescriptor);
            return ctx;
        }

        private static IServiceProvider CreateServiceProvider()
        {
            var sp = new DummyServiceProvider();
            sp.AddType(typeof(ISecureTokenProvider), new DummyTokenProvider());
            sp.AddType(typeof(ILoggerFactory), new DummyLoggerFactory());
            sp.AddType(typeof(ValidateTokenOptions), new ValidateTokenOptions());
            return sp;
        }

        private class DummyServiceProvider : IServiceProvider
        {
            private Dictionary<Type, object> TypeDictionary = new Dictionary<Type, object>();

            public void AddType(Type type, object obj)
            {
                TypeDictionary.Add(type, obj);
            }

            public object GetService(Type serviceType)
            {
                TypeDictionary.TryGetValue(serviceType, out object obj);
                return obj;
            }
        }

        private class DummyLoggerFactory : ILoggerFactory
        {
            public void Dispose()
            {
                // noop
            }

            public ILogger CreateLogger(string categoryName)
            {
                return new DummyLogger();
            }

            public void AddProvider(ILoggerProvider provider)
            {
                // noop
            }

            private class DummyLogger : ILogger
            {
                public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
                {
                    // noop
                }

                public bool IsEnabled(LogLevel logLevel)
                {
                    return true;
                }

                public IDisposable BeginScope<TState>(TState state)
                {
                    return new DummyDisposable();
                }

                private class DummyDisposable : IDisposable
                {
                    public void Dispose()
                    { }
                }
            }
        }
        
        private class DummyTokenProvider : DefaultSecureTokenProvider
        {
            public DummyTokenProvider() : base(new DummyTokenSerializer(), new DummyTokenProtector())
            { }

            private class DummyTokenProtector : ISecureTokenProtector
            {
                private static readonly byte[] DummyPreamble = Encoding.UTF8.GetBytes("DUMMY::__");

                public byte[] ProtectData(byte[] unprotectedData)
                {
                    return DummyPreamble.Concat(unprotectedData).ToArray();
                }

                public byte[] UnprotectData(byte[] protectedData)
                {
                    if (protectedData.Length >= DummyPreamble.Length)
                    {
                        if (protectedData.Take(DummyPreamble.Length).SequenceEqual(DummyPreamble))
                        {
                            return protectedData.Skip(DummyPreamble.Length).ToArray();
                        }
                    }

                    throw new Exception();
                }
            }

            private class DummyTokenSerializer : ISecureTokenSerializer
            {
                public byte[] SerializeToken(SecureToken token)
                {
                    return
                        Encoding.UTF8.GetBytes(
                            $"{token.Issued:O}:::{token.Expire:O}:::{string.Join("&&&", token.Data.Select(kvp => $"{kvp.Key}==={kvp.Value}"))}"
                        );
                }

                public SecureToken DeserializeToken(byte[] serialized)
                {
                    var str = Encoding.UTF8.GetString(serialized).Split(new[] { ":::" }, StringSplitOptions.None);

                    var issued = DateTimeOffset.Parse(str[0]);
                    var expire = DateTimeOffset.Parse(str[1]);
                    var dict = str[2]
                        .Split(new[] { "&&&" }, StringSplitOptions.None)
                        .Select(p => p.Split(new[] { "===" }, StringSplitOptions.None))
                        .ToDictionary(pa => pa[0], pa => pa[1]);

                    return SecureToken.Create(issued, expire, dict);
                }
            }
        }
    }
}
