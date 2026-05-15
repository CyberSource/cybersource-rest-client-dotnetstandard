using System;
using System.Security.Cryptography;
using System.Text;
using AuthenticationSdk.core;

namespace AuthenticationSdk.authentication.http
{
    public class HttpTokenGenerator : ITokenGenerator
    {
        private string SignatureForCategory1(HttpToken httpTokenValue)
        {
            var signatureString = new StringBuilder();
            var signatureHeaderValue = new StringBuilder();
            const string getOrDeleteHeaders = "host date request-target v-c-merchant-id";

            signatureString.Append($"\nhost: {httpTokenValue.HostName}")
                           .Append($"\ndate: {httpTokenValue.GmtDateTime}")
                           .Append($"\nrequest-target: {httpTokenValue.HttpSignRequestTarget}")
                           .Append($"\nv-c-merchant-id: ");

            if (httpTokenValue.UseMetaKey == true)
            {
                signatureString.Append(httpTokenValue.PortfolioId);
            }
            else
            {
                signatureString.Append(httpTokenValue.MerchantId);
            }

            signatureString.Remove(0, 1);

            var signatureByteString = Encoding.UTF8.GetBytes(signatureString.ToString());
            var decodedKey = Convert.FromBase64String(httpTokenValue.MerchantSecretKey);
            var aKeyId = new HMACSHA256(decodedKey);
            var hashmessage = aKeyId.ComputeHash(signatureByteString);
            var base64EncodedSignature = Convert.ToBase64String(hashmessage);

            signatureHeaderValue.Append($"keyid=\"{httpTokenValue.MerchantKeyId}\"")
                                .Append($", algorithm=\"{httpTokenValue.SignatureAlgorithm}\"")
                                .Append($", headers=\"{getOrDeleteHeaders}\"")
                                .Append($", signature=\"{base64EncodedSignature}\"");

            return signatureHeaderValue.ToString();
        }

        private string SignatureForCategory2(HttpToken httpTokenValue)
        {
            var signatureString = new StringBuilder();
            var signatureHeaderValue = new StringBuilder();
            httpTokenValue.Digest = GenerateDigest(httpTokenValue);
            const string postOrPutHeaders = "host date request-target digest v-c-merchant-id";

            signatureString.Append($"\nhost: {httpTokenValue.HostName}")
                           .Append($"\ndate: {httpTokenValue.GmtDateTime}")
                           .Append($"\nrequest-target: {httpTokenValue.HttpSignRequestTarget}")
                           .Append($"\ndigest: {httpTokenValue.Digest}")
                           .Append($"\nv-c-merchant-id: ");

            if (httpTokenValue.UseMetaKey == true)
            {
                signatureString.Append(httpTokenValue.PortfolioId);
            }
            else
            {
                signatureString.Append(httpTokenValue.MerchantId);
            }

            signatureString.Remove(0, 1);

            var signatureByteString = Encoding.UTF8.GetBytes(signatureString.ToString());
            var decodedKey = Convert.FromBase64String(httpTokenValue.MerchantSecretKey);
            var aKeyId = new HMACSHA256(decodedKey);
            var hashmessage = aKeyId.ComputeHash(signatureByteString);
            var base64EncodedSignature = Convert.ToBase64String(hashmessage);

            signatureHeaderValue.Append($"keyid=\"{httpTokenValue.MerchantKeyId}\"")
                                .Append($", algorithm=\"{httpTokenValue.SignatureAlgorithm}\"")
                                .Append($", headers=\"{postOrPutHeaders}\"")
                                .Append($", signature=\"{base64EncodedSignature}\"");

            return signatureHeaderValue.ToString();
        }

        private string GenerateDigest(HttpToken httpTokenValue)
        {
            string digest;

            using (var sha256Hash = SHA256.Create())
            {
                var payloadBytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(httpTokenValue.RequestJsonData));
                digest = Convert.ToBase64String(payloadBytes);
                digest = "SHA-256=" + digest;
            }

            return digest;
        }

        #region NEW PROPERTIES
        private readonly IMerchantCredentialSettings _merchantCredentialSettings;
        private readonly IMerchantRequestSettings _merchantRequestSettings;
        private readonly HttpToken _httpToken;
        #endregion

        #region NEW CONSTRUCTOR
        public HttpTokenGenerator(IMerchantCredentialSettings merchantCredentialSettings, IMerchantRequestSettings merchantRequestSettings)
        {
            _merchantCredentialSettings = merchantCredentialSettings;
            _merchantRequestSettings = merchantRequestSettings;
            _httpToken = new HttpToken(_merchantCredentialSettings, _merchantRequestSettings);
        }
        #endregion

        #region NEW METHODS
        public Token GetToken()
        {
            _httpToken.SignatureParam = SetSignatureParam(_httpToken);
            return _httpToken;
        }

        private string SetSignatureParam(HttpToken httpToken)
        {
            var signature = string.Empty;

            if (_merchantRequestSettings.RequestType.Equals("GET", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("DELETE", StringComparison.InvariantCultureIgnoreCase))
            {
                // Category 1 : GET / DELETE
                signature = SignatureForCategory1(httpToken);
            }
            else if (_merchantRequestSettings.RequestType.Equals("POST", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("PUT", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("PATCH", StringComparison.InvariantCultureIgnoreCase))
            {
                // Category 2 : POST / PUT / PATCH 
                signature = SignatureForCategory2(httpToken);
            }

            return signature;
        }
        #endregion
    }
}
