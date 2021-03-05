using System;
using System.Collections.Generic;
using System.Text;
using AuthenticationSdk.core;

namespace AuthenticationSdk.authentication.oauth
{
    public class OAuthTokenGenerator : ITokenGenerator
    {
        private readonly MerchantConfig _merchantConfig;
        private readonly OAuthToken _oauthtoken;

        public OAuthTokenGenerator(MerchantConfig merchantConfig)
        {
            _merchantConfig = merchantConfig;
            _oauthtoken = new OAuthToken(_merchantConfig);
        }

        public Token GetToken()
        {
            return _oauthtoken;
        }
    }
}
