using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AuthenticationSdk.core;
using AuthenticationSdk.util;
using Microsoft.IdentityModel.Tokens;
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
        private static string GenerateDigest(string requestJsonData)
        {
            using (var sha256Hash = SHA256.Create())
            {
                var payloadBytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(requestJsonData));
                var digest = Convert.ToBase64String(payloadBytes);
                return digest;
            }
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

        #region NEW PROPERTIES
        private readonly IMerchantCredentialSettings _merchantCredentialSettings;
        private readonly IMerchantRequestSettings _merchantRequestSettings;
        private readonly IMerchantMLESettings _merchantMLESettings;
        private readonly JwtToken _jwtToken;
        private readonly bool _isResponseMLEForApi;
        private readonly bool _isSharedSecret;
        #endregion

        #region NEW CONSTRUCTOR
        public JwtTokenGenerator(IMerchantCredentialSettings merchantCredentialSettings, IMerchantRequestSettings merchantRequestSettings, IMerchantMLESettings merchantMLESettings, bool isResponseMLEForApi)
        {
            _isResponseMLEForApi = isResponseMLEForApi;
            _merchantCredentialSettings = merchantCredentialSettings;
            _merchantRequestSettings = merchantRequestSettings;
            _merchantMLESettings = merchantMLESettings;
            _isSharedSecret = merchantCredentialSettings.IsSharedSecretKeyType();

            _jwtToken = new JwtToken(_merchantCredentialSettings, _merchantRequestSettings, _isSharedSecret);
        }
        #endregion

        #region NEW METHODS
        public Token GetToken()
        {
            if (_isSharedSecret)
            {
                _jwtToken.BearerToken = SetTokenWithSharedSecret(_jwtToken);
            }
            else
            {
                _jwtToken.BearerToken = SetToken(_jwtToken);
            }
            return _jwtToken;
        }

        /// <summary>
        /// Generates a JWT token signed with RS256 using the P12 certificate's private key.
        /// </summary>
        private string SetToken(JwtToken jwtTokenValue)
        {
            var payloadClaimSet = GetPayloadClaimSet(jwtTokenValue);
            var headerClaimSet = GetHeaderClaimSet(jwtTokenValue);

            var x5Cert = jwtTokenValue.Certificate;

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
            string headerEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(headerJson));
            string payloadEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(jwtBody));
            string signingInput = headerEncoded + "." + payloadEncoded;

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

        /// <summary>
        /// Generates a JWT token signed with HS256 (HMAC-SHA256) using the merchant's shared secret key.
        /// </summary>
        private string SetTokenWithSharedSecret(JwtToken jwtTokenValue)
        {
            var payloadClaimSet = GetPayloadClaimSet(jwtTokenValue);
            var headerClaimSet = GetSharedSecretHeaderClaimSet(jwtTokenValue);

            var jwtBody = payloadClaimSet.ToString(Newtonsoft.Json.Formatting.None);
            string headerJson = headerClaimSet.ToString(Newtonsoft.Json.Formatting.None);

            // JWS compact serialization: Base64Url(header) + "." + Base64Url(payload)
            string headerEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(headerJson));
            string payloadEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(jwtBody));
            string signingInput = headerEncoded + "." + payloadEncoded;

            // Sign with HMAC-SHA256
            byte[] signingInputBytes = Encoding.ASCII.GetBytes(signingInput);
            byte[] secretKeyBytes = Convert.FromBase64String(jwtTokenValue.MerchantSecretKey);

            byte[] signatureBytes;
            using (var hmac = new HMACSHA256(secretKeyBytes))
            {
                signatureBytes = hmac.ComputeHash(signingInputBytes);
            }

            string token = signingInput + "." + Base64UrlEncoder.Encode(signatureBytes);
            return token;
        }

        private JObject GetPayloadClaimSet(JwtToken jwtTokenValue)
        {
            var jwtPayload = new JObject();

            // Setting the JWT digest and digest Algorithm when a POST, PUT, or PATCH request is made
            if (_merchantRequestSettings.RequestType.Equals("POST", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("PUT", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("PATCH", StringComparison.InvariantCultureIgnoreCase))
            {
                var digest = GenerateDigest(jwtTokenValue.RequestJsonData);
                jwtPayload["digest"] = digest;
                jwtPayload["digestAlgorithm"] = "SHA-256";
            }

            // Set the iat and exp claims using Unix timestamps
            var currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            jwtPayload["iat"] = currentTime;
            jwtPayload["exp"] = currentTime + 120; // The exp claim is set to 2 mins more than the iat claim

            // Set the request method, host and resource path in the JWT body as per the specification for all request types
            jwtPayload["request-method"] = _merchantRequestSettings.RequestType?.ToUpper();
            jwtPayload["request-host"] = _merchantCredentialSettings.RunEnvironment;
            jwtPayload["request-resource-path"] = ExtractResourcePath(_merchantRequestSettings.RequestTarget);

            // Choose issuer claim in the JWT body as per the use_metakey flag in the config file
            string issuer;
            if (!string.IsNullOrEmpty(_merchantCredentialSettings.UseMetaKey) &&
                bool.TryParse(_merchantCredentialSettings.UseMetaKey, out bool useMetaKey) && useMetaKey)
            {
                issuer = _merchantCredentialSettings.PortfolioId;
            }
            else
            {
                issuer = _merchantCredentialSettings.MerchantId;
            }

            jwtPayload["iss"] = issuer;
            jwtPayload["jti"] = Guid.NewGuid().ToString();
            jwtPayload["v-c-jwt-version"] = "2";
            jwtPayload["v-c-merchant-id"] = _merchantCredentialSettings.MerchantId;

            if (_isResponseMLEForApi)
            {
                // Validate and auto-extract Response MLE KID if needed
                string validatedKid = MLEUtility.ValidateAndAutoExtractResponseMleKid(issuer, _merchantMLESettings);
                jwtPayload["v-c-response-mle-kid"] = validatedKid;
            }

            return jwtPayload;
        }

        /// <summary>
        /// RS256 header for JWT with P12 certificate.
        /// </summary>
        private JObject GetHeaderClaimSet(JwtToken jwtTokenValue)
        {
            var x5Cert = jwtTokenValue.Certificate;
            var serialNumber = CertificateUtility.ExtractSerialNumber(x5Cert);

            return new JObject
            {
                ["alg"] = "RS256",
                ["kid"] = serialNumber,
                ["typ"] = "JWT"
            };
        }

        /// <summary>
        /// HS256 header for JWT with SHARED_SECRET.
        /// </summary>
        private JObject GetSharedSecretHeaderClaimSet(JwtToken jwtTokenValue)
        {
            return new JObject
            {
                ["alg"] = "HS256",
                ["kid"] = jwtTokenValue.MerchantKeyId,
                ["typ"] = "JWT"
            };
        }
        #endregion
    }
}
