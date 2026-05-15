using System;
using AuthenticationSdk.core;
using AuthenticationSdk.util;

namespace AuthenticationSdk.authentication.http
{
    public class HttpToken : Token
    {
        public HttpToken(MerchantConfig merchantConfig)
        {
            // Properties that are not dependent on merchant configuration
            SignatureAlgorithm = Constants.SignatureAlgorithm;
            GmtDateTime = DateTime.Now.ToUniversalTime().ToString("r");

            // Properties that are dependent on merchant configuration
            RequestJsonData = merchantConfig.RequestJsonData;
            HostName = merchantConfig.HostName;
            MerchantId = merchantConfig.MerchantId;
            MerchantSecretKey = merchantConfig.MerchantSecretKey;
            MerchantKeyId = merchantConfig.MerchantKeyId;
            HttpSignRequestTarget = merchantConfig.RequestType.ToLower() + " " + merchantConfig.RequestTarget;

            bool.TryParse(merchantConfig.UseMetaKey, out bool tempUseMetaKey);

            UseMetaKey = tempUseMetaKey;

            if (UseMetaKey)
            {
                PortfolioId = merchantConfig.PortfolioId;
            }
        }

        #region NEW METHODS
        public HttpToken(IMerchantCredentialSettings merchantCredentialSettings, IMerchantRequestSettings merchantRequestSettings)
        {
            // Properties that are not dependent on merchant configuration
            SignatureAlgorithm = Constants.SignatureAlgorithm;
            GmtDateTime = DateTime.Now.ToUniversalTime().ToString("r");

            // Properties that are dependent on merchant configuration
            RequestJsonData = merchantRequestSettings.RequestJsonData; // NEED TO CHECK
            HostName = merchantCredentialSettings.HostName;
            MerchantId = merchantCredentialSettings.MerchantId;
            MerchantSecretKey = merchantCredentialSettings.MerchantSecretKey;
            MerchantKeyId = merchantCredentialSettings.MerchantKeyId;
            HttpSignRequestTarget = merchantRequestSettings.RequestType.ToLower() + " " + merchantRequestSettings.RequestTarget;

            bool.TryParse(merchantCredentialSettings.UseMetaKey, out bool tempUseMetaKey);

            UseMetaKey = tempUseMetaKey;

            if (UseMetaKey)
            {
                PortfolioId = merchantCredentialSettings.PortfolioId;
            }
        }
        #endregion

        public string SignatureAlgorithm { get; set; }

        public string GmtDateTime { get; set; }

        public string MerchantId { get; set; }

        public string PortfolioId { get; set; }

        public bool UseMetaKey { get; set; }

        public string MerchantSecretKey { get; set; }

        public string RequestJsonData { get; }

        public string HostName { get; }

        public string HttpSignRequestTarget { get; set; }

        public string MerchantKeyId { get; set; }

        public string Digest { get; set; }

        public string SignatureParam { get; set; }
    }
}