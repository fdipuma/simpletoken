using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading;
using Dks.SimpleToken.Core;
using Dks.SimpleToken.Protectors;
using Dks.SimpleToken.Providers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Dks.SimpleToken.System.Web.Tests
{
    [TestClass]
    public class SystemWebTests
    {
        private static readonly Dictionary<string, string> PayLoad = new Dictionary<string, string>
        {
            {"Foo", "12"},
            {"Bar", "test"}
        };
        
        [TestMethod]
        public void ShouldCorrectlySerialize_FormsAuthTicket()
        {
            ISecureTokenProvider provider = new FormsAuthSecureTokenProvider();
            var faToken = provider.GenerateToken(PayLoad);

            Debug.WriteLine($"FATOKEN LENGTH: {faToken.Length}");

            var faData = provider.ValidateAndGetData(faToken);

            Assert.AreEqual("12", faData.Data["Foo"]);
            Assert.AreEqual("test", faData.Data["Bar"]);
        }

        [TestMethod]
        public void ShouldCorrectlySerialize_MachineKeyProtector()
        {
            ISecureTokenProvider provider = new DefaultSecureTokenProvider(new DummyTokenSerializer(), new MachineKeySecureTokenProtector());
            var mkToken = provider.GenerateToken(PayLoad);

            Debug.WriteLine($"MKTOKEN LENGTH: {mkToken.Length}");

            var mkData = provider.ValidateAndGetData(mkToken);

            Assert.AreEqual("12", mkData.Data["Foo"]);
            Assert.AreEqual("test", mkData.Data["Bar"]);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException))]
        public void ShouldDetectExpired_FormsAuthTicket()
        {
            var provider = new FormsAuthSecureTokenProvider();

            var token = provider.GenerateToken(new Dictionary<string, string>{
                { "Test", "ok"}
            }, 1);
            
            Thread.Sleep(1500);

            provider.ValidateAndGetData(token);
            Assert.Fail();
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException))]
        public void ShouldDetectExpired_MachineKeyProtector()
        {
            var provider = new DefaultSecureTokenProvider(new DummyTokenSerializer(), new MachineKeySecureTokenProtector());

            var token = provider.GenerateToken(new Dictionary<string, string>{
                { "Test", "ok"}
            }, 1);


            Thread.Sleep(1500);

            provider.ValidateAndGetData(token);
            Assert.Fail();
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
