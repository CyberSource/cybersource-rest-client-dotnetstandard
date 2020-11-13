using System.Net.Http;
using ApiSdk.util;
using NUnit.Framework;

namespace ApiSdkTests.util
{
    [TestFixture]
    public class HttpConnUtilityTests
    {     
        [Test]   
        public void GetHttpClient_Test()
        {
            var proxyAddress = "userproxy.visa.com";
            var proxyPort = "443";
                        
            var httpConnUtilityObj = new HttpConnUtility(proxyAddress, proxyPort, "");
            
            var httpClientObj = httpConnUtilityObj.GetHttpClient();

            Assert.IsInstanceOf(typeof(HttpClient), httpClientObj);
        }

    }
}
