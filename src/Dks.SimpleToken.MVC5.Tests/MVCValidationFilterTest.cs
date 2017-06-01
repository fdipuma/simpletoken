using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.Mvc;
using Dks.SimpleToken.Core;
using Dks.SimpleToken.Validation.MVC5;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Dks.SimpleToken.MVC5.Tests
{
    [TestClass]
    public class MVCValidationFilterTest
    {
        private const string MatchingParameter = "testParam";

        private ISecureTokenProvider _secureTokenProvider;

        [TestInitialize]
        public void Initialize()
        {
            _secureTokenProvider = new DummyTokenProvider();
            MvcSimpleTokenValidator.ConfigureFilter(_secureTokenProvider);
        }

        [TestMethod]
        public void ShouldDetectValidToken_InMVC5Filter()
        {
            //Token generation
            var token = _secureTokenProvider.GenerateToken(new Dictionary<string, string> { { MatchingParameter, "value" } }, 60);

            //Filter creation
            var filter = new ValidateTokenAttribute(MatchingParameter);

            //Filter context initialization
            var filterContext = CraftFakeFilterContext(token);

            filterContext.ActionParameters.Add(MatchingParameter, "value");

            //Executing filter action
            filter.OnActionExecuting(filterContext);

            Assert.IsNull(filterContext.Result);
        }

        [TestMethod]
        public void ShouldDetectMissingToken_InMVC5Filter()
        {
            //Filter creation
            var filter = new ValidateTokenAttribute(MatchingParameter);

            //Filter context initialization
            var filterContext = CraftFakeFilterContext();

            filterContext.ActionParameters.Add(MatchingParameter, "value");

            //Executing filter action
            filter.OnActionExecuting(filterContext);

            Assert.IsInstanceOfType(filterContext.Result, typeof(HttpUnauthorizedResult));
        }

        [TestMethod]
        public void ShouldDetectEmptyToken_InMVC5Filter()
        {
            //Filter creation
            var filter = new ValidateTokenAttribute(MatchingParameter);

            //Filter context initialization
            var filterContext = CraftFakeFilterContext(" ");

            filterContext.ActionParameters.Add(MatchingParameter, "value");

            //Executing filter action
            filter.OnActionExecuting(filterContext);

            Assert.IsInstanceOfType(filterContext.Result, typeof(HttpUnauthorizedResult));
        }

        [TestMethod]
        public void ShouldDetectInvalidToken_InMVC5Filter()
        {
            //Filter creation
            var filter = new ValidateTokenAttribute(MatchingParameter);

            //Filter context initialization
            var filterContext = CraftFakeFilterContext("RANDOMSTRING");

            filterContext.ActionParameters.Add(MatchingParameter, "value");

            //Executing filter action
            filter.OnActionExecuting(filterContext);

            Assert.IsInstanceOfType(filterContext.Result, typeof(HttpUnauthorizedResult));
        }

        [TestMethod]
        public void ShouldDetectExpiredToken_InMVC5Filter()
        {
            //Token generation
            var token = _secureTokenProvider.GenerateToken(new Dictionary<string, string> { { MatchingParameter, "value" } }, 1);

            //Waiting for token to expire
            Thread.Sleep(1500);

            //Filter creation
            var filter = new ValidateTokenAttribute(MatchingParameter);

            //Filter context initialization
            var filterContext = CraftFakeFilterContext(token);

            filterContext.ActionParameters.Add(MatchingParameter, "value");

            //Executing filter action
            filter.OnActionExecuting(filterContext);

            Assert.IsInstanceOfType(filterContext.Result, typeof(HttpUnauthorizedResult));
        }

        [TestMethod]
        public void ShouldDetectMismatchingParametersToken_InMVC5Filter()
        {
            //Token generation
            var token = _secureTokenProvider.GenerateToken(new Dictionary<string, string> { { MatchingParameter, "value" } }, 60);

            //Filter creation
            var filter = new ValidateTokenAttribute(MatchingParameter);

            //Filter context initialization
            var filterContext = CraftFakeFilterContext(token);

            filterContext.ActionParameters.Add(MatchingParameter, "anothervalue");

            //Executing filter action
            filter.OnActionExecuting(filterContext);

            Assert.IsInstanceOfType(filterContext.Result, typeof(HttpStatusCodeResult));
            Assert.AreEqual((int)HttpStatusCode.Forbidden, (filterContext.Result as HttpStatusCodeResult).StatusCode);
        }

        private static ActionExecutingContext CraftFakeFilterContext(string token = null)
        {
            return new ActionExecutingContext
            {
                ActionParameters = new Dictionary<string, object>(),
                HttpContext = new HttpContextWrapper(
                    new HttpContext(
                        new HttpRequest(
                            "test",
                            "http://test",
                            token == null ? null : "token=" + token),
                        new HttpResponse(null)))
            };
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

                    throw new ApplicationException();
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
