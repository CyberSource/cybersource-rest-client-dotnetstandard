using System.Net.Http;
using System.Net.Http.Headers;
using ApiSdk.util;
using AuthenticationSdk.core;

namespace ApiSdk.connection
{
    public class JWTConnection : IConnection
    {
        public HttpClient GetConnectionForGet(MerchantConfig merchantConfig)
        {
            var token = AuthenticationHelper.GetToken(merchantConfig);
            var httpConnUtility = new HttpConnUtility(merchantConfig.ProxyAddress, merchantConfig.ProxyPort, merchantConfig.TimeOut);
            var client = httpConnUtility.GetHttpClient();

            client.DefaultRequestHeaders
                .Accept
                .Add(new MediaTypeWithQualityHeaderValue(Constants.MediaTypeHalAndJson));

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(Constants.Bearer, token.BearerToken);

            return client;
        }

        public HttpClient GetConnectionForPost(MerchantConfig merchantConfig)
        {
            var token = AuthenticationHelper.GetToken(merchantConfig);
            var httpConnUtility = new HttpConnUtility(merchantConfig.ProxyAddress, merchantConfig.ProxyPort, merchantConfig.TimeOut);
            var client = httpConnUtility.GetHttpClient();

            var content = new StringContent(merchantConfig.RequestJsonData);
            content.Headers.ContentType = new MediaTypeHeaderValue(Constants.MediaTypeJson);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(Constants.Bearer, token.BearerToken);

            return client;
        }

        public HttpClient GetConnectionForPut(MerchantConfig merchantConfig)
        {
            var token = AuthenticationHelper.GetToken(merchantConfig);
            var httpConnUtility = new HttpConnUtility(merchantConfig.ProxyAddress, merchantConfig.ProxyPort, merchantConfig.TimeOut);
            var client = httpConnUtility.GetHttpClient();

            var content = new StringContent(merchantConfig.RequestJsonData);
            content.Headers.ContentType = new MediaTypeHeaderValue(Constants.MediaTypeJson);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(Constants.Bearer, token.BearerToken);

            return client;
        }

        public HttpClient GetConnectionForDelete(MerchantConfig merchantConfig)
        {
            var token = AuthenticationHelper.GetToken(merchantConfig);
            var httpConnUtility = new HttpConnUtility(merchantConfig.ProxyAddress, merchantConfig.ProxyPort, merchantConfig.TimeOut);
            var client = httpConnUtility.GetHttpClient();

            client.DefaultRequestHeaders
                .Accept
                .Add(new MediaTypeWithQualityHeaderValue(Constants.MediaTypeHalAndJson));

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(Constants.Bearer, token.BearerToken);

            return client;
        }
    }
}
