using System.Collections.Generic;

namespace AuthenticationSdk.util
{
    public static class Constants
    {
        public static readonly string GetUpperCase = "GET";

        public static readonly string PostUpperCase = "POST";

        public static readonly string PutUpperCase = "PUT";

        public static readonly string SignatureAlgorithm = "HmacSHA256";

        public static readonly string HostName = "apitest.cybersource.com";

        public static readonly string HideMerchantConfigProps = "MerchantSecretKey, MerchantKeyId, KeyAlias, KeyPassword, KeyPass, RequestJsonData, ClientCertPassword ";

        public static readonly List<string> OldRunEnvironmentConstants = new List<string> { "CYBERSOURCE.ENVIRONMENT.SANDBOX", "CYBERSOURCE.ENVIRONMENT.PRODUCTION", "CYBERSOURCE.ENVIRONMENT.MUTUALAUTH.SANDBOX", "CYBERSOURCE.ENVIRONMENT.MUTUALAUTH.PRODUCTION", "BANKOFAMERICA.ENVIRONMENT.SANDBOX", "BANKOFAMERICA.ENVIRONMENT.PRODUCTION", "CYBERSOURCE.IN.ENVIRONMENT.SANDBOX", "CYBESOURCE.IN.ENVIRONMENT.PRODUCTION", "CYBESOURCE.ENVIRONMENT.MUTUALAUTH.SIT" };

        public static readonly string AuthMechanismHttp = "http_signature";

        public static readonly string AuthMechanismJwt = "jwt";

        public static readonly string AuthMechanismMutualAuth = "mutual_auth";

        public static readonly string AuthMechanismOAuth = "oauth";

        public static readonly string ErrorPrefix = "Error: ";

        public static readonly string WarningPrefix = "Warning: ";

        public static readonly string DeprecationPrefix = "Deprecated: ";

        public static readonly string P12FileDirectory = "..\\..\\Resource";

        public static readonly string DefaultMleAliasForCert = "CyberSource_SJC_US";

        public static readonly int CertificateExpiryDateWarningDays = 90;

        public static readonly string LOG_REQUEST_BEFORE_MLE = "LOG_REQUEST_BEFORE_MLE: ";

        public static readonly string LOG_REQUEST_AFTER_MLE = "LOG_REQUEST_AFTER_MLE: ";

        public static readonly string DEFAULT_TIME_OUT = "100000"; // Time in milliseconds

        public static readonly string DefaultMaxConnectionPoolSize = $"{int.MaxValue}";

        // https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclient.timeout?view=net-9.0
        public static readonly string DefaultKeepAliveTime = "300000"; // Time in milliseconds
        public static readonly string MLE_CACHE_IDENTIFIER_FOR_CONFIG_CERT = "mleCertFromMerchantConfig";

        public static readonly string MLE_CACHE_IDENTIFIER_FOR_P12_CERT = "mleCertFromP12";

        public static readonly string MLE_CACHE_KEY_IDENTIFIER_FOR_RESPONSE_PRIVATE_KEY = "mleResponsePrivateKeyFromFile";
    }
}
