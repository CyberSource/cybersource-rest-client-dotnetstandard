using System.Net.Http;
using System.Net.Http.Headers;
using ApiSdk.util;
using AuthenticationSdk.core;

namespace ApiSdk.connection
{
    public class HTTPConnection : IConnection
    {
        public HttpClient GetConnectionForGet(MerchantConfig merchantConfig)
        {
            var signature = AuthenticationHelper.GetSignature(merchantConfig);
            var httpConnUtility = new HttpConnUtility(merchantConfig.ProxyAddress, merchantConfig.ProxyPort, merchantConfig.TimeOut);
            var client = httpConnUtility.GetHttpClient();

            client.DefaultRequestHeaders
                        .Accept
                        .Add(new MediaTypeWithQualityHeaderValue(Constants.MediaTypeHalAndJson));

            client.DefaultRequestHeaders.Add("v-c-merchant-id", signature.MerchantId);

            client.DefaultRequestHeaders.Add("Date", signature.GmtDateTime);

            client.DefaultRequestHeaders.Add("Host", signature.HostName);

            client.DefaultRequestHeaders.Add("Signature", signature.SignatureParam);

            return client;
        }

        public HttpClient GetConnectionForPost(MerchantConfig merchantConfig)
        {
            var signature = AuthenticationHelper.GetSignature(merchantConfig);
            var httpConnUtility = new HttpConnUtility(merchantConfig.ProxyAddress, merchantConfig.ProxyPort, merchantConfig.TimeOut);
            var client = httpConnUtility.GetHttpClient();

            client.DefaultRequestHeaders.Add("v-c-merchant-id", signature.MerchantId);

            client.DefaultRequestHeaders.Add("Date", signature.GmtDateTime);

            client.DefaultRequestHeaders.Add("Host", signature.HostName);

            client.DefaultRequestHeaders.Add("Digest", signature.Digest);

            client.DefaultRequestHeaders.Add("Signature", signature.SignatureParam);

            return client;
        }

        public HttpClient GetConnectionForPut(MerchantConfig merchantConfig)
        {
            var signature = AuthenticationHelper.GetSignature(merchantConfig);
            var httpConnUtility = new HttpConnUtility(merchantConfig.ProxyAddress, merchantConfig.ProxyPort, merchantConfig.TimeOut);
            var client = httpConnUtility.GetHttpClient();

            client.DefaultRequestHeaders.Add("v-c-merchant-id", signature.MerchantId);

            client.DefaultRequestHeaders.Add("Date", signature.GmtDateTime);

            client.DefaultRequestHeaders.Add("Host", signature.HostName);

            client.DefaultRequestHeaders.Add("Digest", signature.Digest);

            client.DefaultRequestHeaders.Add("Signature", signature.SignatureParam);

            return client;
        }

        public HttpClient GetConnectionForDelete(MerchantConfig merchantConfig)
        {
            var signature = AuthenticationHelper.GetSignature(merchantConfig);
            var httpConnUtility = new HttpConnUtility(merchantConfig.ProxyAddress, merchantConfig.ProxyPort, merchantConfig.TimeOut);
            var client = httpConnUtility.GetHttpClient();

            client.DefaultRequestHeaders
                        .Accept
                        .Add(new MediaTypeWithQualityHeaderValue(Constants.MediaTypeHalAndJson));

            client.DefaultRequestHeaders.Add("v-c-merchant-id", signature.MerchantId);

            client.DefaultRequestHeaders.Add("Date", signature.GmtDateTime);

            client.DefaultRequestHeaders.Add("Host", signature.HostName);

            client.DefaultRequestHeaders.Add("Signature", signature.SignatureParam);

            return client;
        }
    }
}
