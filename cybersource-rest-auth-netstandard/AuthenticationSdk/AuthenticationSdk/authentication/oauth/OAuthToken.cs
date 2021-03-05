using System;
using AuthenticationSdk.core;
using AuthenticationSdk.util;

namespace AuthenticationSdk.authentication.oauth
{
    public class OAuthToken : Token
    {
        public OAuthToken(MerchantConfig merchantConfig)
        {
            AccessToken = merchantConfig.AccessToken;
            RefreshToken = merchantConfig.RefreshToken;
        }

        public string AccessToken { get; set; }

        public string RefreshToken { get; set; }
    }
}
