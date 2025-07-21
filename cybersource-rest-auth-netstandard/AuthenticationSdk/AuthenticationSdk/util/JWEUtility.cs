using Jose;
using System.Security.Cryptography;
using AuthenticationSdk.core;
using System;

namespace AuthenticationSdk.util
{
    public static class JWEUtilty
    {
        [Obsolete("This method has been marked as Deprecated and will be removed in coming releases. Use DecryptUsingRSAParameters(RSAParameters, string) instead.", false)]
        public static string DecryptUsingPEM(MerchantConfig merchantConfig, string encodedData)
        {
            RSAParameters rsaParams = Cache.FetchCachedRSAParameters(merchantConfig);
            var rsa = RSA.Create();
            rsa.ImportParameters(rsaParams);
            return JWT.Decode(encodedData, rsa, JweAlgorithm.RSA_OAEP_256, JweEncryption.A256GCM);
        }

        public static string DecryptUsingRSAParameters(RSAParameters rsaParameters, string encodedData)
        {
            var rsa = RSA.Create();
            rsa.ImportParameters(rsaParameters);
            return JWT.Decode(encodedData, rsa, JweAlgorithm.RSA_OAEP_256, JweEncryption.A256GCM);
        }
    }
}
