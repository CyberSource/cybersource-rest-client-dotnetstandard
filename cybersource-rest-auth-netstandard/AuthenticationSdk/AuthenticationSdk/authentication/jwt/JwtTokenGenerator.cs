using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AuthenticationSdk.core;
using AuthenticationSdk.util;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace AuthenticationSdk.authentication.jwt
{
    public class JwtTokenGenerator : ITokenGenerator
    {
        private readonly MerchantConfig _merchantConfig;
        private readonly JwtToken _jwtToken;
        private readonly bool _isResponseMLEForApi;


        public JwtTokenGenerator(MerchantConfig merchantConfig, bool isResponseMLEForApi)
        {
            _isResponseMLEForApi = isResponseMLEForApi;
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
            var payloadClaimSet = GetPayloadClaimSet();
            var headerClaimSet = GetHeaderClaimSet();

            var x5Cert = _jwtToken.Certificate;
            if (x5Cert == null)
            {
                throw new CryptographicException(
                    "Certificate is null or not loaded properly. " +
                    "Ensure the P12/PFX file exists and the password is correct.");
            }

            var privateKey = x5Cert.GetRSAPrivateKey();
            if (privateKey == null)
            {
                throw new CryptographicException(
                    "Unable to obtain the RSA private key from the certificate. " +
                    "Ensure the certificate contains a private key and that the current platform/certificate store grants access to it.");
            }

            var jwtBody = payloadClaimSet.ToString(Newtonsoft.Json.Formatting.None);

            string headerJson = headerClaimSet.ToString(Newtonsoft.Json.Formatting.None);

            // JWS compact serialization: Base64Url(header) + "." + Base64Url(payload)
            string headerEncoded  = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(headerJson));
            string payloadEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(jwtBody));
            string signingInput   = headerEncoded + "." + payloadEncoded;

            // Sign with RS256
            byte[] signingInputBytes = Encoding.ASCII.GetBytes(signingInput);
            byte[] signatureBytes;

            try
            {
                // Preferred: BouncyCastle signing (identical output to jose-jwt RS256)
                RsaPrivateCrtKeyParameters bcPrivateKey = DotNetUtilities.GetRsaKeyPair(privateKey).Private as RsaPrivateCrtKeyParameters;
                var signer = new RsaDigestSigner(new Sha256Digest());
                signer.Init(true, bcPrivateKey);
                signer.BlockUpdate(signingInputBytes, 0, signingInputBytes.Length);
                signatureBytes = signer.GenerateSignature();
            }
            catch (CryptographicException)
            {
                // Fallback: use .NET built-in RSA signing when the private key
                // cannot be exported (e.g., non-exportable CNG keys, HSM-backed keys).
                // RSA PKCS#1 v1.5 with SHA-256 is equivalent to RS256.
                signatureBytes = privateKey.SignData(signingInputBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }

            string token = signingInput + "." + Base64UrlEncoder.Encode(signatureBytes);
            return token;
        }

        private JObject GetPayloadClaimSet()
        {
            var jwtPayload = new JObject();

            // Setting the JWT digest and digest Algorithm when a POST, PUT, or PATCH request is made
            if (_merchantConfig.IsPostRequest || _merchantConfig.IsPutRequest || _merchantConfig.IsPatchRequest)
            {
                var digest = GenerateDigest(_jwtToken.RequestJsonData);
                jwtPayload["digest"] = digest;
                jwtPayload["digestAlgorithm"] = "SHA-256";
            }

            // Set the iat and exp claims using Unix timestamps
            var currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            jwtPayload["iat"] = currentTime;
            jwtPayload["exp"] = currentTime + 120; // The exp claim is set to 2 mins more than the iat claim

            // Set the request method, host and resource path in the JWT body as per the specification for all request types
            jwtPayload["request-method"] = _merchantConfig.RequestType?.ToUpper();
            jwtPayload["request-host"] = _merchantConfig.RunEnvironment;
            jwtPayload["request-resource-path"] = ExtractResourcePath(_merchantConfig.RequestTarget);

            // Choose issuer claim in the JWT body as per the use_metakey flag in the config file
            string issuer;
            if (!string.IsNullOrEmpty(_merchantConfig.UseMetaKey) && 
                bool.TryParse(_merchantConfig.UseMetaKey, out bool useMetaKey) && useMetaKey)
            {
                issuer = _merchantConfig.PortfolioId;
            }
            else
            {
                issuer = _merchantConfig.MerchantId;
            }

            jwtPayload["iss"] = issuer;
            jwtPayload["jti"] = Guid.NewGuid().ToString();
            jwtPayload["v-c-jwt-version"] = "2";
            jwtPayload["v-c-merchant-id"] = _merchantConfig.MerchantId;

            if (_isResponseMLEForApi)
            {
                // Validate and auto-extract Response MLE KID if needed
                string validatedKid = util.MLEUtility.ValidateAndAutoExtractResponseMleKid(_merchantConfig);
                jwtPayload["v-c-response-mle-kid"] = validatedKid;
            }

            return jwtPayload;
        }

        private JObject GetHeaderClaimSet()
        {
            var x5Cert = _jwtToken.Certificate;
            var serialNumber = CertificateUtility.ExtractSerialNumber(x5Cert);

            return new JObject
            {
                ["alg"] = "RS256",
                ["kid"] = serialNumber,
                ["typ"] = "JWT"
            };
        }

        private string ExtractResourcePath(string requestTarget)
        {
            if (string.IsNullOrEmpty(requestTarget))
            {
                return string.Empty;
            }

            // Split the string to remove the query params
            var parts = requestTarget.Split('?');
            return parts[0];
        }
    }
}
