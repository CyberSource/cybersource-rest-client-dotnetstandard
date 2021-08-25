using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AuthenticationSdk.core;

namespace AuthenticationSdk.authentication.jwt
{
    public class JwtTokenGenerator : ITokenGenerator
    {
        private readonly MerchantConfig _merchantConfig;
        private readonly JwtToken _jwtToken;

        public JwtTokenGenerator(MerchantConfig merchantConfig)
        {
            _merchantConfig = merchantConfig;
            _jwtToken = new JwtToken(_merchantConfig);
        }

        public Token GetToken()
        {
            _jwtToken.BearerToken = SetToken();
            return _jwtToken;
        }

        private static string GenerateDigest(string requestJsonData)
        {
            using (var sha256Hash = SHA256.Create())
            {
                var payloadBytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(requestJsonData));
                var digest = Convert.ToBase64String(payloadBytes);
                return digest;
            }
        }

        private string SetToken()
        {
            var token = string.Empty;

            if (_merchantConfig.IsGetRequest || _merchantConfig.IsDeleteRequest)
            {
                // Category 1 : GET / DELETE
                token = TokenForCategory1();
            }
            else if (_merchantConfig.IsPostRequest || _merchantConfig.IsPutRequest ||_merchantConfig.IsPatchRequest)
            {
                // Category 2 : POST / PUT / PATCH 
                token = TokenForCategory2();
            }

            return token;
        }

        private string TokenForCategory1()
        {
            var jwtBody = $"{{ \"iat\":\"{DateTime.Now.ToUniversalTime().ToString("r")}\"}}";

            var x5Cert = _jwtToken.Certificate;

            var publicKey = Convert.ToBase64String(x5Cert.RawData);

            var privateKey = x5Cert.GetRSAPrivateKey();

            var x5CList = new List<string>()
            {
                publicKey
            };

            var cybsHeaders = new Dictionary<string, object>()
            {
                { "v-c-merchant-id", _jwtToken.KeyAlias },
                { "x5c", x5CList }
            };

            var token = Jose.JWT.Encode(jwtBody, privateKey, Jose.JwsAlgorithm.RS256, cybsHeaders);

            return token;
        }

        private string TokenForCategory2()
        {
            var digest = GenerateDigest(_jwtToken.RequestJsonData);

            var jwtBody = $"{{\n            \"digest\":\"{digest}\", \"digestAlgorithm\":\"SHA-256\", \"iat\":\"{DateTime.Now.ToUniversalTime().ToString("r")}\"}}";

            var x5Cert = _jwtToken.Certificate;

            var publicKey = Convert.ToBase64String(x5Cert.RawData);

            var privateKey = x5Cert.GetRSAPrivateKey();

            var x5CList = new List<string>()
            {
                publicKey
            };
            var cybsHeaders = new Dictionary<string, object>()
            {
                { "v-c-merchant-id", _jwtToken.KeyAlias },
                { "x5c", x5CList }
            };

            var token = Jose.JWT.Encode(jwtBody, privateKey, Jose.JwsAlgorithm.RS256, cybsHeaders);

            return token;
        }
    }
}
