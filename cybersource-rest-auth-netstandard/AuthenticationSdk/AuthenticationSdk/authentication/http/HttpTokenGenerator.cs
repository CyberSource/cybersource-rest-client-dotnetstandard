using System;
using System.Security.Cryptography;
using System.Text;
using AuthenticationSdk.core;

namespace AuthenticationSdk.authentication.http
{
    public class HttpTokenGenerator : ITokenGenerator
    {
        private readonly MerchantConfig _merchantConfig;
        private readonly HttpToken _httpToken;

        public HttpTokenGenerator(MerchantConfig merchantConfig)
        {
            _merchantConfig = merchantConfig;
            _httpToken = new HttpToken(_merchantConfig);
        }

        public Token GetToken()
        {
            _httpToken.SignatureParam = SetSignatureParam();
            return _httpToken;
        }

        private string SetSignatureParam()
        {
            var signature = string.Empty;

            if (_merchantConfig.IsGetRequest || _merchantConfig.IsDeleteRequest)
            {
                // Category 1 : GET / DELETE
                signature = SignatureForCategory1();
            }
            else if (_merchantConfig.IsPostRequest || _merchantConfig.IsPutRequest || _merchantConfig.IsPatchRequest)
            {
                // Category 2 : POST / PUT / PATCH 
                signature = SignatureForCategory2();
            }

            return signature;
        }

        private string SignatureForCategory1()
        {
            var signatureString = new StringBuilder();
            var signatureHeaderValue = new StringBuilder();
            const string getOrDeleteHeaders = "host date (request-target) v-c-merchant-id";

            signatureString.Append($"\nhost: {_httpToken.HostName}")
                           .Append($"\ndate: {_httpToken.GmtDateTime}")
                           .Append($"\n(request-target): {_httpToken.HttpSignRequestTarget}")
                           .Append($"\nv-c-merchant-id: ");

            if (_httpToken.UseMetaKey == true)
            {
                signatureString.Append(_httpToken.PortfolioId);
            }
            else
            {
                signatureString.Append(_httpToken.MerchantId);
            }

            signatureString.Remove(0, 1);

            var signatureByteString = Encoding.UTF8.GetBytes(signatureString.ToString());
            var decodedKey = Convert.FromBase64String(_httpToken.MerchantSecretKey);
            var aKeyId = new HMACSHA256(decodedKey);
            var hashmessage = aKeyId.ComputeHash(signatureByteString);
            var base64EncodedSignature = Convert.ToBase64String(hashmessage);

            signatureHeaderValue.Append($"keyid=\"{_httpToken.MerchantKeyId}\"")
                                .Append($", algorithm=\"{_httpToken.SignatureAlgorithm}\"")
                                .Append($", headers=\"{getOrDeleteHeaders}\"")
                                .Append($", signature=\"{base64EncodedSignature}\"");

            return signatureHeaderValue.ToString();
        }

        private string SignatureForCategory2()
        {
            var signatureString = new StringBuilder();
            var signatureHeaderValue = new StringBuilder();
            _httpToken.Digest = GenerateDigest();
            const string postOrPutHeaders = "host date (request-target) digest v-c-merchant-id";

            signatureString.Append($"\nhost: {_httpToken.HostName}")
                           .Append($"\ndate: {_httpToken.GmtDateTime}")
                           .Append($"\n(request-target): {_httpToken.HttpSignRequestTarget}")
                           .Append($"\ndigest: {_httpToken.Digest}")
                           .Append($"\nv-c-merchant-id: ");

            if (_httpToken.UseMetaKey == true)
            {
                signatureString.Append(_httpToken.PortfolioId);
            }
            else
            {
                signatureString.Append(_httpToken.MerchantId);
            }

            signatureString.Remove(0, 1);

            var signatureByteString = Encoding.UTF8.GetBytes(signatureString.ToString());
            var decodedKey = Convert.FromBase64String(_httpToken.MerchantSecretKey);
            var aKeyId = new HMACSHA256(decodedKey);
            var hashmessage = aKeyId.ComputeHash(signatureByteString);
            var base64EncodedSignature = Convert.ToBase64String(hashmessage);

            signatureHeaderValue.Append($"keyid=\"{_httpToken.MerchantKeyId}\"")
                                .Append($", algorithm=\"{_httpToken.SignatureAlgorithm}\"")
                                .Append($", headers=\"{postOrPutHeaders}\"")
                                .Append($", signature=\"{base64EncodedSignature}\"");

            return signatureHeaderValue.ToString();
        }

        private string GenerateDigest()
        {
            string digest;

            using (var sha256Hash = SHA256.Create())
            {
                var payloadBytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(_httpToken.RequestJsonData));
                digest = Convert.ToBase64String(payloadBytes);
                digest = "SHA-256=" + digest;
            }

            return digest;
        }
    }
}
