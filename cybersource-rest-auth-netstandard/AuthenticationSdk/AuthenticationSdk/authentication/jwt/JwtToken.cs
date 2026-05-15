using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using AuthenticationSdk.core;
using AuthenticationSdk.util;

namespace AuthenticationSdk.authentication.jwt
{
    public class JwtToken : Token
    {
        public JwtToken(MerchantConfig merchantConfig)
        {
            RequestJsonData = merchantConfig.RequestJsonData;
            HostName = merchantConfig.HostName;
            P12FilePath = merchantConfig.P12Keyfilepath;

            if (!File.Exists(P12FilePath))
            {
                throw new Exception($"{Constants.ErrorPrefix} File not found at the given path: {Path.GetFullPath(P12FilePath)}");
            }

            KeyAlias = merchantConfig.KeyAlias;
            KeyPass = merchantConfig.KeyPass;
            X509Certificate2Collection certs = Cache.FetchCachedCertificate(P12FilePath, KeyPass);
            Certificate = Cache.GetCertBasedOnKeyAlias(certs, merchantConfig.KeyAlias);
        }

        #region NEW CONSTRUCTOR
        /// <summary>
        /// Constructor for JWT with SHARED_SECRET (HS256).
        /// Does not load P12 or certificates — uses merchantKeyId and merchantsecretKey for HMAC signing.
        /// </summary>
        public JwtToken(IMerchantCredentialSettings merchantCredentialSettings, IMerchantRequestSettings merchantRequestSettings, bool isSharedSecret)
        {
            RequestJsonData = merchantRequestSettings.RequestJsonData;
            HostName = merchantCredentialSettings.HostName;

            if (isSharedSecret)
            {
                MerchantKeyId = merchantCredentialSettings.MerchantKeyId;
                MerchantSecretKey = merchantCredentialSettings.MerchantSecretKey;
            }
            else
            {
                P12FilePath = merchantCredentialSettings.P12Keyfilepath;

                KeyAlias = merchantCredentialSettings.KeyAlias;
                KeyPass = merchantCredentialSettings.KeyPass;
                X509Certificate2Collection certs = Cache.FetchCachedCertificate(P12FilePath, KeyPass);
                Certificate = Cache.GetCertBasedOnKeyAlias(certs, merchantCredentialSettings.KeyAlias);
            }
        }
        #endregion

        public string BearerToken { get; set; }

        public string RequestJsonData { get; set; }

        public string HostName { get; set; }

        public string P12FilePath { get; set; }

        public string KeyAlias { get; set; }

        public string KeyPass { get; }

        public X509Certificate2 Certificate { get; }

        /// <summary>
        /// The merchant key ID used as the 'kid' in the JWS header for HMAC-SHA256 (HS256) JWT signing.
        /// Only populated when jwtKeyType is SHARED_SECRET.
        /// </summary>
        public string MerchantKeyId { get; set; }

        /// <summary>
        /// The Base64-encoded shared secret key used for HMAC-SHA256 (HS256) JWT signing.
        /// Only populated when jwtKeyType is SHARED_SECRET.
        /// </summary>
        public string MerchantSecretKey { get; set; }
    }
}