using System;
using AuthenticationSdk.core;
using AuthenticationSdk.util;

namespace AuthenticationSdk.authentication.http
{
    public class HttpToken : Token
    {
        public HttpToken(MerchantConfig merchantConfig)
        {
            // props that don't use merchant config object
            SignatureAlgorithm = Constants.SignatureAlgorithm;
            GmtDateTime = DateTime.Now.ToUniversalTime().ToString("r");            

            // props that use merchant config object for their values to be set
            RequestJsonData = merchantConfig.RequestJsonData;
            HostName = merchantConfig.HostName;
            MerchantId = merchantConfig.MerchantId;
            MerchantSecretKey = merchantConfig.MerchantSecretKey;
            MerchantKeyId = merchantConfig.MerchantKeyId;
            HttpSignRequestTarget = merchantConfig.RequestType.ToLower() + " " + merchantConfig.RequestTarget;
        }

        public string SignatureAlgorithm { get; set; }

        public string GmtDateTime { get; set; }

        public string MerchantId { get; set; }

        public string MerchantSecretKey { get; set; }

        public string RequestJsonData { get; }

        public string HostName { get; }

        public string HttpSignRequestTarget { get; set; }

        public string MerchantKeyId { get; set; }

        public string Digest { get; set; }

        public string SignatureParam { get; set; }
    }
}