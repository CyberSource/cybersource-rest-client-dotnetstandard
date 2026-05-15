using System;
using System.Collections.Generic;
using System.Text;

namespace AuthenticationSdk.core
{
    /// <summary>
    /// Provides centralized access to all configuration key constants used throughout the CyberSource authentication and client SDKs.
    /// This class is extended via partial classes in different projects to organize configuration keys by their related settings.
    /// </summary>
    public static partial class MerchantConfigurationKeys
    {
        #region Merchant Credential Settings
        /// <summary>
        /// Defines the configuration keys used when constructing a <see cref="MerchantCredentialSettings"/> instance
        /// via the dictionary-based constructor. These constants should be used as keys in the configuration dictionary
        /// to ensure type safety and avoid spelling errors.
        /// </summary>
        /// <remarks>
        /// Usage example:
        /// <code>
        /// var config = new Dictionary&lt;string, string&gt;
        /// {
        ///     { MerchantCredentialSettingsKeys.MerchantId, "my_merchant_id" },
        ///     { MerchantCredentialSettingsKeys.AuthenticationType, "JWT" },
        ///     { MerchantCredentialSettingsKeys.RunEnvironment, "apitest" },
        ///     { MerchantCredentialSettingsKeys.KeysDirectory, "/path/to/keys" },
        ///     { MerchantCredentialSettingsKeys.KeyFilename, "my_key" },
        ///     { MerchantCredentialSettingsKeys.KeyPassword, "my_password" },
        ///     { MerchantCredentialSettingsKeys.KeyAlias, "my_alias" }
        /// };
        /// var settings = new MerchantCredentialSettings(config);
        /// </code>
        /// </remarks>
        public static class MerchantCredentialSettingsKeys
        {
            /// <summary>
            /// Mandatory configuration key for the merchant identifier.
            /// Value: "merchantID"
            /// </summary>
            public const string MerchantId = "merchantID";

            /// <summary>
            /// Mandatory configuration key for the authentication type.
            /// Supported values: HTTP_SIGNATURE, JWT, OAUTH, MUTUAL_AUTH
            /// Value: "authenticationType"
            /// </summary>
            public const string AuthenticationType = "authenticationType";

            /// <summary>
            /// Mandatory configuration key for the CyberSource environment.
            /// Supported values: sbctest, apitest, production, and other environment names
            /// Value: "runEnvironment"
            /// </summary>
            public const string RunEnvironment = "runEnvironment";

            /// <summary>
            /// Optional configuration key for the directory path containing PEM-formatted certificates.
            /// Value: "pemFileDirectory"
            /// </summary>
            public const string PemFileDirectory = "pemFileDirectory";

            /// <summary>
            /// Optional configuration key indicating whether to use a meta key (portfolio-level key) for authentication.
            /// Supported values: "true" or "false"
            /// Value: "useMetaKey"
            /// </summary>
            public const string UseMetaKey = "useMetaKey";

            /// <summary>
            /// Optional configuration key for the portfolio identifier.
            /// Required when <see cref="UseMetaKey"/> is set to "true".
            /// Value: "portfolioId"
            /// </summary>
            public const string PortfolioId = "portfolioID";

            /// <summary>
            /// Optional configuration key for an intermediate host or proxy server for routing requests.
            /// Value: "intermediateHost"
            /// </summary>
            public const string IntermediateHost = "intermediateHost";

            /// <summary>
            /// Optional configuration key indicating whether to enable client certificate authentication.
            /// Supported values: "true" or "false"
            /// Value: "enableClientCert"
            /// </summary>
            public const string EnableClientCert = "enableClientCert";

            /// <summary>
            /// Optional configuration key for the directory path containing the client certificate file.
            /// Required when <see cref="EnableClientCert"/> is set to "true".
            /// Value: "clientCertDirectory"
            /// </summary>
            public const string ClientCertDirectory = "clientCertDirectory";

            /// <summary>
            /// Optional configuration key for the filename of the client certificate file.
            /// Required when <see cref="EnableClientCert"/> is set to "true".
            /// Value: "clientCertFile"
            /// </summary>
            public const string ClientCertFile = "clientCertFile";

            /// <summary>
            /// Optional configuration key for the password to access the client certificate file.
            /// Required when <see cref="EnableClientCert"/> is set to "true".
            /// Value: "clientCertPassword"
            /// </summary>
            public const string ClientCertPassword = "clientCertPassword";

            /// <summary>
            /// Configuration key for HTTP Signature authentication - the shared secret key.
            /// Required when <see cref="AuthenticationType"/> is "HTTP_SIGNATURE".
            /// Value: "merchantsecretKey"
            /// </summary>
            public const string MerchantSecretKey = "merchantsecretKey";

            /// <summary>
            /// Configuration key for HTTP Signature authentication - the merchant key identifier.
            /// Required when <see cref="AuthenticationType"/> is "HTTP_SIGNATURE".
            /// Value: "merchantKeyId"
            /// </summary>
            public const string MerchantKeyId = "merchantKeyId";

            /// <summary>
            /// Configuration key for JWT authentication - the directory containing the PKCS#12 key file.
            /// Required when <see cref="AuthenticationType"/> is "JWT".
            /// Value: "keysDirectory"
            /// </summary>
            public const string KeysDirectory = "keysDirectory";

            /// <summary>
            /// Configuration key for JWT authentication - the PKCS#12 key filename without the .p12 extension.
            /// Required when <see cref="AuthenticationType"/> is "JWT".
            /// Value: "keyFilename"
            /// </summary>
            public const string KeyFilename = "keyFilename";

            /// <summary>
            /// Configuration key for JWT authentication - the password to access the PKCS#12 key file.
            /// Required when <see cref="AuthenticationType"/> is "JWT".
            /// Value: "keyPass"
            /// </summary>
            public const string KeyPassword = "keyPass";

            /// <summary>
            /// Configuration key for JWT authentication - the alias name of the key within the PKCS#12 file.
            /// Required when <see cref="AuthenticationType"/> is "JWT" and jwtKeyType is "P12".
            /// Value: "keyAlias"
            /// </summary>
            public const string KeyAlias = "keyAlias";

            /// <summary>
            /// Configuration key for JWT authentication - specifies the JWT key type.
            /// Supported values: "P12" (default, certificate-based RS256) or "SHARED_SECRET" (HMAC-based HS256).
            /// When set to "SHARED_SECRET", merchantKeyId and merchantsecretKey are required instead of P12 certificate fields.
            /// Value: "jwtKeyType"
            /// </summary>
            public const string JwtKeyType = "jwtKeyType";

            /// <summary>
            /// Configuration key for OAuth authentication - the OAuth 2.0 access token.
            /// Required when <see cref="AuthenticationType"/> is "OAUTH".
            /// Value: "accessToken"
            /// </summary>
            public const string AccessToken = "accessToken";

            /// <summary>
            /// Configuration key for OAuth authentication - the OAuth 2.0 refresh token.
            /// Required when <see cref="AuthenticationType"/> is "OAUTH".
            /// Value: "refreshToken"
            /// </summary>
            public const string RefreshToken = "refreshToken";

            /// <summary>
            /// Configuration key for Mutual Auth and OAuth authentication - the client identifier.
            /// Required when <see cref="AuthenticationType"/> is "MUTUAL_AUTH" or "OAUTH".
            /// Value: "clientId"
            /// </summary>
            public const string ClientId = "clientId";

            /// <summary>
            /// Configuration key for Mutual Auth and OAuth authentication - the client secret.
            /// Required when <see cref="AuthenticationType"/> is "MUTUAL_AUTH" or "OAUTH".
            /// Value: "clientSecret"
            /// </summary>
            public const string ClientSecret = "clientSecret";
        }
        #endregion Merchant Credential Settings

        #region Merchant MLE Settings
        /// <summary>
        /// Defines the configuration keys used when constructing a <see cref="MerchantMLESettings"/> instance
        /// via the dictionary-based constructor. These constants should be used as keys in the configuration dictionary
        /// to ensure type safety and avoid spelling errors.
        /// </summary>
        /// <remarks>
        /// Usage example:
        /// <code>
        /// var mleConfig = new Dictionary&lt;string, string&gt;
        /// {
        ///     { MerchantMLESettingsKeys.EnableRequestMLEForOptionalApisGlobally, "true" },
        ///     { MerchantMLESettingsKeys.RequestMleKeyAlias, "CyberSource_SJC_US" },
        ///     { MerchantMLESettingsKeys.EnableResponseMleGlobally, "true" },
        ///     { MerchantMLESettingsKeys.ResponseMleKID, "your-kid-value" },
        ///     { MerchantMLESettingsKeys.ResponseMlePrivateKeyFilePath, "/path/to/private/key" },
        ///     { MerchantMLESettingsKeys.ResponseMlePrivateKeyFilePassword, "your-password" }
        /// };
        /// var mleSettings = new MerchantMLESettings(mleConfig);
        /// </code>
        /// </remarks>
        public static class MerchantMLESettingsKeys
        {
            /// <summary>
            /// Optional configuration key indicating whether to enable Message Level Encryption (MLE) globally for all requests for optional APIs.
            /// When enabled, request payloads will be encrypted using the specified certificate.
            /// Supported values: "true" or "false"
            /// Default value: "false"
            /// Value: "enableRequestMLEForOptionalApisGlobally"
            /// </summary>
            public const string EnableRequestMLEForOptionalApisGlobally = "enableRequestMLEForOptionalApisGlobally";

            /// <summary>
            /// Deprecated. Use <see cref="EnableRequestMLEForOptionalApisGlobally"/> instead.
            /// Optional configuration key indicating whether to use MLE globally for all APIs.
            /// Supported values: "true" or "false"
            /// Value: "useMLEGlobally"
            /// </summary>
            public const string UseMLEGlobally = "useMLEGlobally";

            /// <summary>
            /// Optional configuration key indicating whether to disable MLE globally for all requests for mandatory APIs.
            /// When enabled, MLE will not be applied to mandatory API operations even if globally enabled.
            /// Supported values: "true" or "false"
            /// Default value: "false"
            /// Value: "disableRequestMLEForMandatoryApisGlobally"
            /// </summary>
            public const string DisableRequestMLEForMandatoryApisGlobally = "disableRequestMLEForMandatoryApisGlobally";

            /// <summary>
            /// Optional configuration key for the alias name of the key used for MLE in the current request.
            /// This is the alias of the certificate within the PKCS#12 key file used for request encryption.
            /// Default value: <see cref="AuthenticationSdk.util.Constants.DefaultMleAliasForCert"/> ("CyberSource_SJC_US")
            /// Value: "requestMleKeyAlias"
            /// </summary>
            public const string RequestMleKeyAlias = "requestMleKeyAlias";

            /// <summary>
            /// Deprecated. Use <see cref="RequestMleKeyAlias"/> instead.
            /// Optional configuration key for the alias of the key used for MLE.
            /// Value: "mleKeyAlias"
            /// </summary>
            public const string MleKeyAlias = "mleKeyAlias";

            /// <summary>
            /// Optional configuration key for the file system path to the public certificate used for MLE requests.
            /// This certificate is used to encrypt request payloads when request MLE is enabled.
            /// Value: "mleForRequestPublicCertPath"
            /// </summary>
            public const string MleForRequestPublicCertPath = "mleForRequestPublicCertPath";

            /// <summary>
            /// Optional configuration key indicating whether to enable Message Level Encryption (MLE) globally for all API responses.
            /// When enabled, response payloads are expected to be encrypted and will be decrypted using the specified private key.
            /// Supported values: "true" or "false"
            /// Default value: "false"
            /// Value: "enableResponseMleGlobally"
            /// </summary>
            public const string EnableResponseMleGlobally = "enableResponseMleGlobally";

            /// <summary>
            /// Optional configuration key for the Key ID (KID) of the private key used to decrypt MLE responses.
            /// This identifier is used to locate the correct private key for response decryption.
            /// Required when <see cref="EnableResponseMleGlobally"/> is set to "true" (unless using P12/PFX files with auto-extraction).
            /// Value: "responseMleKID"
            /// </summary>
            public const string ResponseMleKID = "responseMleKID";

            /// <summary>
            /// Optional configuration key for the file system path to the private key used for decrypting MLE responses.
            /// This can be a PEM, KEY, P8, P12, or PFX file. If provided, this takes precedence over the ResponseMlePrivateKey object.
            /// Required when response MLE is enabled and no ResponseMlePrivateKey object is provided.
            /// Value: "responseMlePrivateKeyFilePath"
            /// </summary>
            public const string ResponseMlePrivateKeyFilePath = "responseMlePrivateKeyFilePath";

            /// <summary>
            /// Optional configuration key for the password used to access the MLE private key file for response decryption.
            /// This password is required if the private key file (P12, PFX, or encrypted PEM) is password-protected.
            /// Value: "responseMlePrivateKeyFilePassword"
            /// </summary>
            public const string ResponseMlePrivateKeyFilePassword = "responseMlePrivateKeyFilePassword";
        }
        #endregion Merchant MLE Settings

        #region Merchant Network Settings
        /// <summary>
        /// Defines the configuration keys used for network-related merchant settings.
        /// These constants should be used as keys when configuring network settings such as proxy, timeout, and client identification.
        /// </summary>
        /// <remarks>
        /// Usage example:
        /// <code>
        /// var networkConfig = new Dictionary&lt;string, string&gt;
        /// {
        ///     { MerchantConfigurationKeys.MerchantNetworkSettingsKeys.TimeOut, "100000" },
        ///     { MerchantConfigurationKeys.MerchantNetworkSettingsKeys.UseProxy, "false" }
        /// };
        /// </code>
        /// </remarks>
        public static class MerchantNetworkSettingsKeys
        {
            /// <summary>
            /// Optional configuration key for the HTTP timeout in milliseconds.
            /// Default value: 100000 (100 seconds)
            /// Value: "timeout"
            /// </summary>
            public const string TimeOut = "timeout";

            /// <summary>
            /// Optional configuration key indicating whether to use a proxy server.
            /// Supported values: "true" or "false"
            /// Default value: "false"
            /// Value: "useProxy"
            /// </summary>
            public const string UseProxy = "useProxy";

            /// <summary>
            /// Optional configuration key for the proxy server address or hostname.
            /// Required when <see cref="UseProxy"/> is set to "true".
            /// Value: "proxyAddress"
            /// </summary>
            public const string ProxyAddress = "proxyAddress";

            /// <summary>
            /// Optional configuration key for the proxy server port number.
            /// Required when <see cref="UseProxy"/> is set to "true".
            /// Value: "proxyPort"
            /// </summary>
            public const string ProxyPort = "proxyPort";

            /// <summary>
            /// Optional configuration key for the proxy server username (if authentication is required).
            /// Value: "proxyUsername"
            /// </summary>
            public const string ProxyUsername = "proxyUsername";

            /// <summary>
            /// Optional configuration key for the proxy server password (if authentication is required).
            /// Value: "proxyPassword"
            /// </summary>
            public const string ProxyPassword = "proxyPassword";

            /// <summary>
            /// Optional configuration key for the SDK client identifier for auditing and reporting purposes.
            /// Value: "sdkClientId"
            /// </summary>
            public const string SdkClientId = "sdkClientId";

            /// <summary>
            /// Optional configuration key indicating whether the code was generated by MCP.
            /// When set to "true" (case-insensitive, whitespace-trimmed), SDK telemetry headers will be sent with API requests.
            /// Supported values: "true" or "false"
            /// Default value: "false"
            /// Value: "isSDK"
            /// </summary>
            public const string IsSDK = "isSDK";

            /// <summary>
            /// Optional configuration key for the developer identifier for auditing and reporting purposes.
            /// Value: "defaultDeveloperId"
            /// </summary>
            public const string DefaultDeveloperId = "defaultDeveloperId";

            /// <summary>
            /// Optional configuration key for the maximum connection pool size for HTTP connections.
            /// Value: "maxConnectionPoolSize"
            /// </summary>
            public const string MaxConnectionPoolSize = "maxConnectionPoolSize";

            /// <summary>
            /// Optional configuration key for the keep-alive time (in milliseconds) for HTTP connections.
            /// Value: "keepAliveTime"
            /// </summary>
            public const string KeepAliveTime = "keepAliveTime";
        }
        #endregion Merchant Network Settings

        #region Merchant Legacy Settings
        /// <summary>
        /// Defines the configuration keys for legacy merchant settings for backward compatibility.
        /// These constants should be used when configuring legacy settings such as user agent and solution ID.
        /// </summary>
        /// <remarks>
        /// Usage example:
        /// <code>
        /// var legacyConfig = new Dictionary&lt;string, string&gt;
        /// {
        ///     { MerchantConfigurationKeys.MerchantLegacySettingsKeys.UserAgent, "My-Custom-Agent/1.0" },
        ///     { MerchantConfigurationKeys.MerchantLegacySettingsKeys.SolutionId, "my-solution-id" }
        /// };
        /// </code>
        /// </remarks>
        public static class MerchantLegacySettingsKeys
        {
            /// <summary>
            /// Optional configuration key for the HTTP user agent string.
            /// Default value: Auto-generated based on SDK version and runtime information
            /// Value: "userAgent"
            /// </summary>
            public const string UserAgent = "userAgent";

            /// <summary>
            /// Optional configuration key for the solution identifier used for SDK auditing and reporting.
            /// Value: "solutionId"
            /// </summary>
            public const string SolutionId = "solutionId";

            /// <summary>
            /// Optional configuration key for the temporary folder path to store downloaded files.
            /// Default value: System temporary directory (Path.GetTempPath())
            /// Value: "tempFolderPath"
            /// </summary>
            public const string TempFolderPath = "tempFolderPath";

            /// <summary>
            /// Optional configuration key for the DateTime format used in serialization.
            /// Default value: ISO 8601 format ("o")
            /// Value: "dateTimeFormat"
            /// </summary>
            public const string DateTimeFormat = "dateTimeFormat";
        }
        #endregion Merchant Legacy Settings
    }
}
