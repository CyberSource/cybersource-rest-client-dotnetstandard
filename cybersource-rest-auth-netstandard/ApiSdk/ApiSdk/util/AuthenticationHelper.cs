using System;
using AuthenticationSdk.authentication.http;
using AuthenticationSdk.authentication.jwt;
using AuthenticationSdk.core;

namespace ApiSdk.util
{
    public class AuthenticationHelper
    {
        public static HttpToken GetSignature(MerchantConfig merchantConfig)
        {
            var authorizeObj = new Authorize(merchantConfig);
            var signature = authorizeObj.GetSignature();

            if (signature == null)
            {
                throw new Exception($"{Constants.ErrorPrefix} Null Signature Returned by the AuthSdk");
            }

            return signature;
        }

        public static JwtToken GetToken(MerchantConfig merchantConfig)
        {
            var authorizeObj = new Authorize(merchantConfig);
            var token = authorizeObj.GetToken();

            if (token == null)
            {
                throw new Exception($"{Constants.ErrorPrefix} Null Token Returned by the AuthSdk");
            }

            return token;
        }
    }
}
