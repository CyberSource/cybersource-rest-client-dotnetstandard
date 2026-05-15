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

        #region NEW CONSTRUCTOR
        public OAuthToken(IMerchantCredentialSettings merchantCredentialSettings)
        {
            AccessToken = merchantCredentialSettings.AccessToken;
            RefreshToken = merchantCredentialSettings.RefreshToken;
        }
        #endregion

        public string AccessToken { get; set; }

        public string RefreshToken { get; set; }
    }
}
