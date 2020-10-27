using System.Collections.Generic;
using AuthenticationSdk.core;
using AuthenticationSdk.util;
using NUnit.Framework;

namespace AuthenticationSdkTests.NetCore.util
{
    [TestFixture]
    public class EnumerationsTests
    {
        private string resourceFolderPath =
            "..\\Resource";


        private MerchantConfig MerchantConfigObj(string authType, string requestType)
        {
            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", "testrest"},
                {"merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE="},
                {"merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda"},
                {"authenticationType", authType},
                {"keysDirectory", resourceFolderPath},
                {"keyFilename", ""},
                {"runEnvironment", "apitest.cybersource.com"},
                {"keyAlias", ""},
                {"keyPass", ""},
                {"enableLog", ""},
                {"logDirectory", ""},
                {"logFileName",""},
                {"logFileMaxSize", ""},
                {"timeout", ""},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };

            var obj = new MerchantConfig(configurationDictionary) { RequestType = requestType };

            return obj;
        }

        [Test]
        public void SetRequestType_Put()
        {
            var merchantConfig = MerchantConfigObj("JWT", "PUT");
            Enumerations.SetRequestType(merchantConfig);
            Assert.AreEqual(true, merchantConfig.IsPutRequest);
        }

        [Test]
        public void SetRequestType_Delete()
        {
            var merchantConfig = MerchantConfigObj("JWT", "DELETE");
            Enumerations.SetRequestType(merchantConfig);
            Assert.AreEqual(true, merchantConfig.IsDeleteRequest);
        }
    }
}
