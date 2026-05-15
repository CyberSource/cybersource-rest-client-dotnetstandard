using AuthenticationSdk.util;
using NLog;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security;
using CredentialKeys = AuthenticationSdk.core.MerchantConfigurationKeys.MerchantCredentialSettingsKeys;

namespace AuthenticationSdk.core
{
    /// <summary>
    /// Provides configuration settings for merchant credentials and authentication in the CyberSource authentication SDK.
    /// Handles initialization and validation of credentials for various authentication types including JWT, HTTP Signature, OAuth, and Mutual Auth.
    /// </summary>
    public class MerchantCredentialSettings : IMutableMerchantCredentialSettings
    {
        #region Constructors
        /// <summary>
        /// Initializes a new instance of the <see cref="MerchantCredentialSettings"/> class.
        /// </summary>
        /// <param name="merchantCredentialsDictionary">Dictionary containing merchant credentials configuration values from App.Config or custom source. If null, configuration is loaded from the MerchantConfig section in App.Config.<br/>Refer to <see cref="MerchantConfigurationKeys.MerchantCredentialSettingsKeys"/> for the list of possible keys</param>
        /// <exception cref="Exception">Thrown when configuration is invalid or required credentials are missing for the specified authentication type.</exception>
        public MerchantCredentialSettings(IReadOnlyDictionary<string, string> merchantCredentialsDictionary = null) : this(merchantCredentialsDictionary, false)
        {
            var _validator = new MerchantCredentialSettingsValidator();
            if (!string.IsNullOrEmpty(AuthenticationType))
            {
                switch (AuthenticationType.ToUpper())
                {
                    case "HTTP_SIGNATURE":
                        _validator.ValidateHttpSignatureSettings(merchantCredentialsDictionary);
                        this.AddHttpSignatureCredentials(merchantCredentialsDictionary);
                        break;
                    case "JWT":
                        _validator.ValidateJwtSettings(merchantCredentialsDictionary);
                        this.AddJwtCredentials(merchantCredentialsDictionary);
                        break;
                    case "OAUTH":
                        _validator.ValidateOAuthSettings(merchantCredentialsDictionary);
                        this.AddOAuthCredentials(merchantCredentialsDictionary);
                        break;
                    case "MUTUAL_AUTH":
                        _validator.ValidateMutualAuthSettings(merchantCredentialsDictionary);
                        this.AddMutualAuthCredentials(merchantCredentialsDictionary);
                        break;
                    default:
                        //Logger.Error("Invalid or unsupported authentication type specified in configuration.");
                        //throw new Exception($"{Constants.ErrorPrefix} Invalid or unsupported authentication type specified in configuration.");
                        break;
                }
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MerchantCredentialSettings"/> class.
        /// </summary>
        /// <param name="merchantCredentialsDictionary">Dictionary containing merchant credentials configuration values from App.Config or custom source. If null, configuration is loaded from the MerchantConfig section in App.Config.<br/>Refer to <see cref="MerchantConfigurationKeys.MerchantCredentialSettingsKeys"/> for the list of possible keys</param>
        /// <param name="isValidated">Indicates whether the provided merchant credentials have already been validated. If true, validation will be skipped.</param>
        /// <exception cref="Exception">Thrown when configuration is invalid or required credentials are missing for the specified authentication type.</exception>
        internal MerchantCredentialSettings(IReadOnlyDictionary<string, string> merchantCredentialsDictionary = null, bool isValidated = false)
        {
            if (Logger == null)
            {
                Logger = LogManager.GetCurrentClassLogger();
            }

            if (merchantCredentialsDictionary == null)
            {
                IReadOnlyDictionary<string, string> merchantConfigSection = null;
                try
                {
                    var appSettingsSection = ConfigurationManager.GetSection("MerchantConfig") as NameValueCollection;
                    merchantConfigSection = appSettingsSection.AllKeys.ToDictionary(k => k, k => appSettingsSection[k]);

                    if (!isValidated)
                    {
                        var _validator = new MerchantCredentialSettingsValidator();
                        _validator.ValidateMandatorySettings(merchantConfigSection);
                    }

                    SetValuesFromDictionary(merchantConfigSection);
                }
                catch (ConfigurationErrorsException ex)
                {
                    Logger.Error($"Error accessing MerchantConfig section in App.Config: {ex.Message}");
                    throw new Exception($"{Constants.ErrorPrefix} Error accessing MerchantConfig section in App.Config: {ex.Message}", ex);
                }
                catch (Exception ex)
                {
                    Logger.Error($"Unexpected error accessing MerchantConfig section in App.Config: {ex.Message}");
                    throw new Exception($"{Constants.ErrorPrefix} Unexpected error accessing MerchantConfig section in App.Config: {ex.Message}", ex);
                }
            }
            else if (merchantCredentialsDictionary != null)
            {
                if (!isValidated)
                {
                    var _validator = new MerchantCredentialSettingsValidator();
                    _validator.ValidateMandatorySettings(merchantCredentialsDictionary);
                }

                SetValuesFromDictionary(merchantCredentialsDictionary);
            }
        }
        #endregion Constructors

        /// <summary>
        /// Populates merchant credential properties from the provided configuration dictionary.
        /// Handles different authentication types (JWT, HTTP Signature, OAuth, Mutual Auth) and their respective required fields.
        /// </summary>
        /// <param name="merchantCredentialsDict">A dictionary containing merchant configuration key-value pairs.</param>
        /// <exception cref="KeyNotFoundException">Thrown when a required configuration key is not found for the specified authentication type.</exception>
        private void SetValuesFromDictionary(IReadOnlyDictionary<string, string> merchantCredentialsDict)
        {
            try
            {
                if (merchantCredentialsDict != null)
                {
                    var merchantId = merchantCredentialsDict.GetValueOrDefault(CredentialKeys.MerchantId, null);

                    var runEnvironment = merchantCredentialsDict.GetValueOrDefault(CredentialKeys.RunEnvironment, null);
                    var hostName = runEnvironment.ToLower();

                    var authenticationType = merchantCredentialsDict.GetValueOrDefault(CredentialKeys.AuthenticationType, null);

                    var pemFileDirectory =  merchantCredentialsDict.GetValueOrDefault(CredentialKeys.PemFileDirectory, null);

                    var useMetaKey =  merchantCredentialsDict.GetValueOrDefault(CredentialKeys.UseMetaKey, null);
                    var portfolioId = string.Empty;

                    if (!string.IsNullOrEmpty(useMetaKey) && bool.Parse(useMetaKey))
                    {
                        portfolioId = merchantCredentialsDict.GetValueOrDefault(CredentialKeys.PortfolioId, null);
                    }

                    var intermediateHost = merchantCredentialsDict.GetValueOrDefault(CredentialKeys.IntermediateHost, null);

                    var enableClientCert =  merchantCredentialsDict.GetValueOrDefault(CredentialKeys.EnableClientCert, null);
                    var clientCertDirectory = string.Empty;
                    var clientCertFile = string.Empty;
                    SecureString clientCertPassword = null;

                    if (!string.IsNullOrEmpty(enableClientCert))
                    {
                        if (bool.Parse(enableClientCert))
                        {
                            clientCertDirectory =  merchantCredentialsDict.GetValueOrDefault(CredentialKeys.ClientCertDirectory, null);
                            clientCertFile =  merchantCredentialsDict.GetValueOrDefault(CredentialKeys.ClientCertFile, null);
                            clientCertPassword =  ConvertToSecureString(merchantCredentialsDict.GetValueOrDefault(CredentialKeys.ClientCertPassword, null));
                        }
                        else
                        {
                            enableClientCert = "false";
                        }
                    }
                    else
                    {
                        enableClientCert = "false";
                    }

                    MerchantId = merchantId;
                    RunEnvironment = runEnvironment;
                    HostName = hostName;
                    AuthenticationType = authenticationType;
                    PemFileDirectory = pemFileDirectory;
                    UseMetaKey = useMetaKey;
                    PortfolioId = portfolioId;
                    IntermediateHost = intermediateHost;
                    EnableClientCert = enableClientCert;
                    ClientCertDirectory = clientCertDirectory;
                    ClientCertFile = clientCertFile;
                    ClientCertPassword = ConvertFromSecureString(clientCertPassword);
                }
                else
                {
                    Logger.Error("Merchant credentials configuration is missing or invalid.");
                    throw new KeyNotFoundException("KeyNotFoundException : Merchant credentials configuration is missing or invalid.");
                }
            }
            catch (KeyNotFoundException err)
            {
                Logger.Error($"Configuration error: {err.Message}");
                throw new Exception($"{Constants.ErrorPrefix} {err.Message}", err);
            }
        }

        #region Properties
        /// <summary>
        /// Gets or sets the merchant ID for authenticating requests to CyberSource.
        /// </summary>
        public string MerchantId { get; internal set; }

        /// <summary>
        /// Gets or sets the portfolio ID used when useMetaKey is enabled.
        /// Required when the UseMetaKey property is set to true.
        /// </summary>
        public string PortfolioId { get; internal set; }

        /// <summary>
        /// Gets or sets the merchant secret key used for HTTP Signature authentication.
        /// </summary>
        public string MerchantSecretKey { get; internal set; }

        /// <summary>
        /// Gets or sets the merchant key ID used for HTTP Signature authentication.
        /// </summary>
        public string MerchantKeyId { get; internal set; }

        /// <summary>
        /// Gets or sets a value indicating whether to use a meta key (portfolio-level key) for authentication.
        /// When true, the PortfolioId must be provided.
        /// </summary>
        public string UseMetaKey { get; internal set; }

        /// <summary>
        /// Gets or sets a value indicating whether to enable client certificate authentication.
        /// When true, the ClientCertFile, ClientCertPassword, and ClientCertDirectory must be provided.
        /// </summary>
        public string EnableClientCert { get; internal set; }

        /// <summary>
        /// Gets or sets the directory path containing the client certificate file.
        /// Required when EnableClientCert is set to true.
        /// </summary>
        public string ClientCertDirectory { get; internal set; }

        /// <summary>
        /// Gets or sets the filename of the client certificate file.
        /// Required when EnableClientCert is set to true.
        /// </summary>
        public string ClientCertFile { get; internal set; }

        /// <summary>
        /// Gets or sets the password for accessing the client certificate file.
        /// Required when EnableClientCert is set to true.
        /// </summary>
        public string ClientCertPassword { get; internal set; }

        /// <summary>
        /// Gets or sets the client ID used for Mutual Auth and OAuth authentication types.
        /// </summary>
        public string ClientId { get; internal set; }

        /// <summary>
        /// Gets or sets the client secret used for Mutual Auth and OAuth authentication types.
        /// </summary>
        public string ClientSecret { get; internal set; }

        /// <summary>
        /// Gets or sets the OAuth access token used for OAuth authentication.
        /// </summary>
        public string AccessToken { get; internal set; }

        /// <summary>
        /// Gets or sets the OAuth refresh token used for OAuth authentication.
        /// </summary>
        public string RefreshToken { get; internal set; }

        /// <summary>
        /// Gets or sets the authentication type (JWT, HTTP_SIGNATURE, OAUTH, or MUTUAL_AUTH).
        /// </summary>
        public string AuthenticationType { get; internal set; }

        /// <summary>
        /// Gets or sets the directory path containing the key file used for JWT authentication.
        /// </summary>
        public string KeyDirectory { get; internal set; }

        /// <summary>
        /// Gets or sets the filename of the key file (without extension) used for JWT authentication.
        /// The .p12 extension is appended when resolving the file path.
        /// </summary>
        public string KeyfileName { get; internal set; }

        /// <summary>
        /// Gets or sets the alias of the key within the key file used for JWT authentication.
        /// </summary>
        public string KeyAlias { get; internal set; }

        /// <summary>
        /// Gets or sets the password for accessing the key file used for JWT authentication.
        /// </summary>
        public string KeyPass { get; internal set; }

        /// <summary>
        /// Gets or sets the run environment (e.g., sbctest, apitest, production) for CyberSource API endpoints.
        /// </summary>
        public string RunEnvironment { get; internal set; }

        /// <summary>
        /// Gets or sets the hostname derived from the RunEnvironment property.
        /// Used for resolving the API endpoint.
        /// </summary>
        public string HostName { get; internal set; }

        /// <summary>
        /// Gets or sets the optional intermediate host or proxy server for routing requests.
        /// </summary>
        public string IntermediateHost { get; internal set; }

        /// <summary>
        /// Gets or sets the directory path containing PEM-formatted certificates.
        /// </summary>
        public string PemFileDirectory { get; internal set; }

        /// <summary>
        /// Gets or sets the full file path to the P12 key file used for JWT authentication.
        /// This is populated during validation of JWT authentication configuration.
        /// </summary>
        public string P12Keyfilepath { get; internal set; }

        /// <summary>
        /// Gets or sets the JWT key type. Supported values: "P12" (default, certificate-based RS256) or "SHARED_SECRET" (HMAC-based HS256).
        /// When set to "SHARED_SECRET", MerchantKeyId and MerchantSecretKey are used for JWT token signing.
        /// </summary>
        public string JwtKeyType { get; internal set; }

        /// <summary>
        /// Gets or sets the NLog logger instance for logging credential configuration and validation messages.
        /// </summary>
        public static Logger Logger { get; internal set; }
        #endregion Properties

        #region Mutable Setters
        /// <summary>
        /// Sets the merchant ID for authenticating requests to CyberSource.
        /// </summary>
        /// <param name="value">The merchant ID to set.</param>
        public void SetMerchantId(string value)
        {
            MerchantId = value;
        }

        /// <summary>
        /// Sets the portfolio ID used when useMetaKey is enabled.
        /// </summary>
        /// <param name="value">The portfolio ID to set.</param>
        public void SetPortfolioId(string value)
        {
            PortfolioId = value;
        }

        /// <summary>
        /// Sets the merchant secret key used for HTTP Signature authentication.
        /// </summary>
        /// <param name="value">The merchant secret key to set.</param>
        public void SetMerchantSecretKey(string value)
        {
            MerchantSecretKey = value;
        }

        /// <summary>
        /// Sets the merchant key ID used for HTTP Signature authentication.
        /// </summary>
        /// <param name="value">The merchant key ID to set.</param>
        public void SetMerchantKeyId(string value)
        {
            MerchantKeyId = value;
        }

        /// <summary>
        /// Sets a value indicating whether to use a meta key (portfolio-level key) for authentication.
        /// </summary>
        /// <param name="value">A string value of "true" or "false" indicating whether to use meta key.</param>
        public void SetUseMetaKey(string value)
        {
            UseMetaKey = value;
        }

        /// <summary>
        /// Sets a value indicating whether to enable client certificate authentication.
        /// </summary>
        /// <param name="value">A string value of "true" or "false" indicating whether to enable client certificate authentication.</param>
        public void SetEnableClientCert(string value)
        {
            EnableClientCert = value;
        }

        /// <summary>
        /// Sets the directory path containing the client certificate file.
        /// </summary>
        /// <param name="value">The directory path to set.</param>
        public void SetClientCertDirectory(string value)
        {
            ClientCertDirectory = value;
        }

        /// <summary>
        /// Sets the filename of the client certificate file.
        /// </summary>
        /// <param name="value">The client certificate filename to set.</param>
        public void SetClientCertFile(string value)
        {
            ClientCertFile = value;
        }

        /// <summary>
        /// Sets the password for accessing the client certificate file.
        /// </summary>
        /// <param name="value">The client certificate password to set.</param>
        public void SetClientCertPassword(string value)
        {
            ClientCertPassword = value;
        }

        /// <summary>
        /// Sets the client ID used for Mutual Auth and OAuth authentication types.
        /// </summary>
        /// <param name="value">The client ID to set.</param>
        public void SetClientId(string value)
        {
            ClientId = value;
        }

        /// <summary>
        /// Sets the OAuth access token used for OAuth authentication.
        /// </summary>
        /// <param name="value">The OAuth access token to set.</param>
        public void SetAccessToken(string value)
        {
            AccessToken = value;
        }

        /// <summary>
        /// Sets the OAuth refresh token used for OAuth authentication.
        /// </summary>
        /// <param name="value">The OAuth refresh token to set.</param>
        public void SetRefreshToken(string value)
        {
            RefreshToken = value;
        }

        /// <summary>
        /// Sets the client secret used for Mutual Auth and OAuth authentication types.
        /// </summary>
        /// <param name="value">The client secret to set.</param>
        public void SetClientSecret(string value)
        {
            ClientSecret = value;
        }

        /// <summary>
        /// Sets the authentication type (JWT, HTTP_SIGNATURE, OAUTH, or MUTUAL_AUTH).
        /// </summary>
        /// <param name="value">The authentication type to set.</param>
        public void SetAuthenticationType(string value)
        {
            AuthenticationType = value;
        }

        /// <summary>
        /// Sets the directory path containing the key file used for JWT authentication.
        /// </summary>
        /// <param name="value">The key directory path to set.</param>
        public void SetKeyDirectory(string value)
        {
            KeyDirectory = value;
        }

        /// <summary>
        /// Sets the filename of the key file (without extension) used for JWT authentication.
        /// </summary>
        /// <param name="value">The key filename to set.</param>
        public void SetKeyfileName(string value)
        {
            KeyfileName = value;
        }

        /// <summary>
        /// Sets the alias of the key within the key file used for JWT authentication.
        /// </summary>
        /// <param name="value">The key alias to set.</param>
        public void SetKeyAlias(string value)
        {
            KeyAlias = value;
        }

        /// <summary>
        /// Sets the password for accessing the key file used for JWT authentication.
        /// </summary>
        /// <param name="value">The key file password to set.</param>
        public void SetKeyPass(string value)
        {
            KeyPass = value;
        }

        /// <summary>
        /// Sets the full file path to the P12 key file used for JWT authentication.
        /// </summary>
        /// <param name="value">The P12 key file path to set.</param>
        public void SetP12Keyfilepath(string value)
        {
            P12Keyfilepath = value;
        }

        /// <summary>
        /// Sets the JWT key type. Supported values: "P12" (default) or "SHARED_SECRET".
        /// </summary>
        /// <param name="value">The JWT key type to set.</param>
        public void SetJwtKeyType(string value)
        {
            JwtKeyType = value;
        }

        /// <summary>
        /// Sets the run environment (e.g., sbctest, apitest, production) for CyberSource API endpoints.
        /// </summary>
        /// <param name="value">The run environment to set.</param>
        public void SetRunEnvironment(string value)
        {
            RunEnvironment = value;
        }

        /// <summary>
        /// Sets the hostname derived from the RunEnvironment property.
        /// </summary>
        /// <param name="value">The hostname to set.</param>
        public void SetHostName(string value)
        {
            HostName = value;
        }

        /// <summary>
        /// Sets the optional intermediate host or proxy server for routing requests.
        /// </summary>
        /// <param name="value">The intermediate host to set.</param>
        public void SetIntermediateHost(string value)
        {
            IntermediateHost = value;
        }

        /// <summary>
        /// Sets the directory path containing PEM-formatted certificates.
        /// </summary>
        /// <param name="value">The PEM file directory path to set.</param>
        public void SetPemFileDirectory(string value)
        {
            PemFileDirectory = value;
        }
        #endregion Mutable Setters

        #region Helper Methods
        private static string ConvertFromSecureString(SecureString secureString)
        {
            if (secureString == null) { return null; }

            IntPtr ptr = System.Runtime.InteropServices.Marshal.SecureStringToGlobalAllocUnicode(secureString);
            try
            {
                return System.Runtime.InteropServices.Marshal.PtrToStringUni(ptr);
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }

        private static SecureString ConvertToSecureString(string value)
        {
            if (string.IsNullOrEmpty(value)) { return null; }

            var secureString = new SecureString();
            foreach (char c in value)
            {
                secureString.AppendChar(c);
            }
            secureString.MakeReadOnly();
            return secureString;
        }
        #endregion Helper Methods
    }
}
