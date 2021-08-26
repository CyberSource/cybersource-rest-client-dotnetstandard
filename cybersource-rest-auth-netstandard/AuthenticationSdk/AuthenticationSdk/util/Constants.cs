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

        public static readonly string HideMerchantConfigProps = "MerchantSecretKey, MerchantKeyId, KeyAlias, KeyPassword, RequestJsonData, ";

        public static readonly List<string> OldRunEnvironmentConstants = new List<string> { "CYBERSOURCE.ENVIRONMENT.SANDBOX", "CYBERSOURCE.ENVIRONMENT.PRODUCTION", "CYBERSOURCE.ENVIRONMENT.MUTUALAUTH.SANDBOX", "CYBERSOURCE.ENVIRONMENT.MUTUALAUTH.PRODUCTION", "BANKOFAMERICA.ENVIRONMENT.SANDBOX", "BANKOFAMERICA.ENVIRONMENT.PRODUCTION", "CYBERSOURCE.IN.ENVIRONMENT.SANDBOX", "CYBESOURCE.IN.ENVIRONMENT.PRODUCTION", "CYBESOURCE.ENVIRONMENT.MUTUALAUTH.SIT" };

        public static readonly string AuthMechanismHttp = "http_signature";

        public static readonly string AuthMechanismJwt = "jwt";

        public static readonly string AuthMechanismMutualAuth = "mutual_auth";

        public static readonly string AuthMechanismOAuth = "oauth";

        public static readonly string ErrorPrefix = "Error: ";

        public static readonly string WarningPrefix = "Warning: ";

        public static readonly string DeprecationPrefix = "Deprecated: ";

        public static readonly string P12FileDirectory = "..\\..\\Resource";
    }
}
