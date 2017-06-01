using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Web.Http;
using System.Web.Http.Controllers;
using Dks.SimpleToken.Core;
using Dks.SimpleToken.Validation.WebAPI;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Dks.SimpleToken.WebAPI.Tests
{
    [TestClass]
    public class WebApiValidationFilterTest
    {
        private const string MatchingParameter = "testParam";

        private ISecureTokenProvider _securityTokenProvider;

        [TestInitialize]
        public void Initialize()
        {
            _securityTokenProvider = new DummyTokenProvider();
        }

        [TestMethod]
        public void ShouldDetectValidToken_InWebApiFilter()
        {
            //Token generation
            var token = _securityTokenProvider.GenerateToken(new Dictionary<string, string> { { MatchingParameter, "value" } }, 60);

            //Filter creation
            var filter = new ValidateToken(MatchingParameter);

            //Filter context initialization
            var actionContext = CraftFakeActionContext(token);

            actionContext.ActionArguments.Add(MatchingParameter, "value");

            //Executing filter action
            filter.OnActionExecuting(actionContext);
        }

        [TestMethod]
        public void ShouldDetectMissingToken_InWebApiFilter()
        {
            //Filter creation
            var filter = new ValidateToken(MatchingParameter);

            //Filter context initialization
            var actionContext = CraftFakeActionContext();

            actionContext.ActionArguments.Add(MatchingParameter, "value");

            try
            {
                //Executing filter action
                filter.OnActionExecuting(actionContext);
            }
            catch (HttpResponseException ex)
            {
                Assert.AreEqual(HttpStatusCode.Unauthorized, ex.Response.StatusCode);
                return;
            }

            Assert.Fail();
        }

        [TestMethod]
        public void ShouldDetectEmptyToken_InWebApiFilter()
        {
            //Filter creation
            var filter = new ValidateToken(MatchingParameter);

            //Filter context initialization
            var actionContext = CraftFakeActionContext(" ");

            actionContext.ActionArguments.Add(MatchingParameter, "value");

            try
            {
                //Executing filter action
                filter.OnActionExecuting(actionContext);
            }
            catch (HttpResponseException ex)
            {
                Assert.AreEqual(HttpStatusCode.Unauthorized, ex.Response.StatusCode);
                return;
            }

            Assert.Fail();
        }

        [TestMethod]
        public void ShouldDetectInvalidToken_InWebApiFilter()
        {
            //Filter creation
            var filter = new ValidateToken(MatchingParameter);

            //Filter context initialization
            var actionContext = CraftFakeActionContext("RANDOMSTRING");

            actionContext.ActionArguments.Add(MatchingParameter, "value");
            
            try
            {
                //Executing filter action
                filter.OnActionExecuting(actionContext);
            }
            catch (HttpResponseException ex)
            {
                Assert.AreEqual(HttpStatusCode.Unauthorized, ex.Response.StatusCode);
                return;
            }

            Assert.Fail();
        }

        [TestMethod]
        public void ShouldDetectExpiredToken_InWebApiFilter()
        {
            //Token generation
            var token = _securityTokenProvider.GenerateToken(new Dictionary<string, string> { { MatchingParameter, "value" } }, 1);

            //Waiting for token to expire
            Thread.Sleep(1500);

            //Filter creation
            var filter = new ValidateToken(MatchingParameter);

            //Filter context initialization
            var actionContext = CraftFakeActionContext(token);

            actionContext.ActionArguments.Add(MatchingParameter, "value");

            try
            {
                //Executing filter action
                filter.OnActionExecuting(actionContext);
            }
            catch (HttpResponseException ex)
            {
                Assert.AreEqual(HttpStatusCode.Unauthorized, ex.Response.StatusCode);
                return;
            }

            Assert.Fail();
        }

        [TestMethod]
        public void ShouldDetectMismatchingParametersToken_InWebApiFilter()
        {
            //Token generation
            var token = _securityTokenProvider.GenerateToken(new Dictionary<string, string> { { MatchingParameter, "value" } }, 60);

            //Filter creation
            var filter = new ValidateToken(MatchingParameter);

            //Filter context initialization
            var actionContext = CraftFakeActionContext(token);

            actionContext.ActionArguments.Add(MatchingParameter, "anothervalue");

            try
            {
                //Executing filter action
                filter.OnActionExecuting(actionContext);
            }
            catch (HttpResponseException ex)
            {
                Assert.AreEqual(HttpStatusCode.Forbidden, ex.Response.StatusCode);
                return;
            }

            Assert.Fail();
        }

        private HttpActionContext CraftFakeActionContext(string token = null)
        {
            var config = new HttpConfiguration();
            
            var ctx = new HttpControllerContext
            {
                Request = new HttpRequestMessage(
                    HttpMethod.Get,
                    "http://test" + (token == null ? null : "?token=" + token)
                    ),
                Configuration = config
            };

            ctx.Request.SetConfiguration(config);

            config.AddCustomSecureTokenProvider(_securityTokenProvider);

            return new HttpActionContext(ctx, new ReflectedHttpActionDescriptor());
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
