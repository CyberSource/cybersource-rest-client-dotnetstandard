using System.Net.Http;
using AuthenticationSdk.core;

namespace ApiSdk.connection
{
    public interface IConnection
    {
        HttpClient GetConnectionForGet(MerchantConfig merchantConfig);

        HttpClient GetConnectionForPost(MerchantConfig merchantConfig);

        HttpClient GetConnectionForPut(MerchantConfig merchantConfig);

        HttpClient GetConnectionForDelete(MerchantConfig merchantConfig);
    }
}
