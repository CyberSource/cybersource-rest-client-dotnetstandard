using AuthenticationSdk.util;
using NLog;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.IO;
using System.Linq;

namespace AuthenticationSdk.core
{
    /*===========================================================================================
    * Provides all the properties required for the generation of HTTP Authentication Headers.
    * Properties can either be set via App.Config or by passing any class object which Implements
    * IReadOnlyDictionary Interface.
    * If no dictionary object is passed, that means by default use <MerchantConfig> in App.Config
    * However if App.Config does not contain <MerchantConfig> an exception is thrown.
    *============================================================================================*/
    public class MerchantConfig
    {
        public MerchantConfig(IReadOnlyDictionary<string, string> merchantConfigDictionary = null, Dictionary<string, string> mapToControlMLEonAPI = null, System.Security.Cryptography.AsymmetricAlgorithm responseMlePrivateKey = null)
        {
            var _propertiesSetUsing = string.Empty;

            if (Logger == null)
            {
                Logger = LogManager.GetCurrentClassLogger();
            }

            /*
             * Set the properties of Merchant Config
             * If a dictionary object has been passed use that object
             * If no dictionary object is passed, that means use app.config
             * However, if App.Config does not contain Merchan Config, throw an exception
             */
            if (merchantConfigDictionary != null)
            {
                _propertiesSetUsing = "Dictionary Object";

                SetValuesUsingDictObj(merchantConfigDictionary, mapToControlMLEonAPI);
            }
            else
            {
                // MerchantConfig section inside App.Config File
                var merchantConfigSection = (NameValueCollection)ConfigurationManager.GetSection("MerchantConfig");

                if (merchantConfigSection != null)
                {
                    _propertiesSetUsing = "App.Config File";

                    SetValuesFromAppConfig(merchantConfigSection, mapToControlMLEonAPI);
                }
                else
                {
                    Logger.Error($"Merchant Configuration Missing in App.Config File");
                    throw new Exception($"{Constants.ErrorPrefix} Merchant Configuration Missing in App.Config File");
                }
            }

            if(responseMlePrivateKey != null)
            {
                ResponseMlePrivateKey = responseMlePrivateKey;
            }

            Logger.Debug("APPLICATION LOGGING START:\n");

            // Logging the source of properties' values
            Logger.Trace("Reading Merchant Configuration from " + _propertiesSetUsing);

            // Validations
            ValidateProperties();
            //validate MLE configs
            ValidateMLEProperties();
        }

        #region Class Properties

        public string MerchantId { get; set; }

        public string PortfolioId { get; set; }

        public string MerchantSecretKey { get; set; }

        public string MerchantKeyId { get; set; }

        public string UseMetaKey { get; set; }

        public string EnableClientCert { get; set; }

        public string ClientCertDirectory { get; set; }

        public string ClientCertFile { get; set; }

        public string ClientCertPassword { get; set; }

        public string ClientId { get; set; }

        public string AccessToken { get; set; }

        public string RefreshToken { get; set; }

        public string ClientSecret { get; set; }

        public string AuthenticationType { get; set; }

        public string KeyDirectory { get; set; }

        public string KeyfileName { get; set; }

        public string RunEnvironment { get; set; }

        public string IntermediateHost { get; set; }

        public string DefaultDeveloperId { get; set; }

        public string KeyAlias { get; set; }

        public string KeyPass { get; set; }

        //public string EnableLog { get; set; } = "TRUE";

        //public string LogDirectory { get; set; } = "../../logs";

        //public string LogfileMaxSize { get; set; } = "10485760"; // 10 MB = 10485760 bytes

        //public string LogFileName { get; set; } = "cybs.log";

        public string TimeOut { get; set; }

        public string UseProxy { get; set; }

        public string ProxyAddress { get; set; }

        public string ProxyPort { get; set; }

        public string ProxyUsername { get; set; }

        public string ProxyPassword { get; set; }

        public static Logger Logger { get; set; }

        public string HostName { get; set; }

        public string P12Keyfilepath { get; set; }

        public string RequestTarget { get; set; }

        public string HttpSignRequestTarget { get; set; }

        public string RequestJsonData { get; set; }

        public string RequestType { get; set; }

        public bool IsGetRequest { get; set; }

        public bool IsPostRequest { get; set; }

        public bool IsPutRequest { get; set; }

        public bool IsDeleteRequest { get; set; }

        public bool IsPatchRequest { get; set; }

        public bool IsHttpSignAuthType { get; set; }

        public bool IsJwtTokenAuthType { get; set; }

        public bool IsOAuthTokenAuthType { get; set; }

        public string PemFileDirectory { get; set; }

        public bool EnableRequestMLEForOptionalApisGlobally { get; set; }

        public bool DisableRequestMLEForMandatoryApisGlobally { get; set; }

        // Deprecated: Use EnableRequestMLEForOptionalApisGlobally instead
        public bool UseMLEGlobally
        {
            get => EnableRequestMLEForOptionalApisGlobally;
            set => EnableRequestMLEForOptionalApisGlobally = value;
        }
        private Dictionary<string, string> _mapToControlMLEonAPI { get; set; }
        public Dictionary<string, string> MapToControlMLEonAPI
        {
            get => _mapToControlMLEonAPI;
            set
            {
                // Validate the map values of MLE Config if not null
                if (value != null)
                {
                    ValidateMapToControlMLEonAPIValues(value);
                    // Populate the internal Maps for MLE control
                    var internalMapToControlRequestMLEonAPI = new Dictionary<string, bool>();
                    var internalMapToControlResponseMLEonAPI = new Dictionary<string, bool>();

                    foreach (var entry in value)
                    {
                        var apiName = entry.Key;
                        var configValue = entry.Value;


                        if (string.IsNullOrEmpty(configValue))
                        {
                            // Throw exception if configValue is empty for the given apiName
                            throw new Exception($"Invalid MLE control map value for key '{apiName}'. Value cannot be null or empty.");
                        }
                        else if (configValue.Contains("::"))
                        {
                            // Format: "requestMLE::responseMLE"
                            var parts = configValue.Split(new[] { "::" }, StringSplitOptions.None);
                            var requestMLE = parts.Length > 0 ? parts[0] : string.Empty;
                            var responseMLE = parts.Length > 1 ? parts[1] : string.Empty;

                            // Set request MLE value
                            if (!string.IsNullOrEmpty(requestMLE))
                            {
                                internalMapToControlRequestMLEonAPI[apiName] = bool.Parse(requestMLE);
                            }

                            // Set response MLE value
                            if (!string.IsNullOrEmpty(responseMLE))
                            {
                                internalMapToControlResponseMLEonAPI[apiName] = bool.Parse(responseMLE);
                            }
                        }
                        else
                        {
                            // Format: "true" or "false" - applies to request MLE only
                            internalMapToControlRequestMLEonAPI[apiName] = bool.Parse(configValue);
                        }
                    }

                    this.InternalMapToControlRequestMLEonAPI = internalMapToControlRequestMLEonAPI;
                    this.InternalMapToControlResponseMLEonAPI = internalMapToControlResponseMLEonAPI;
                    _mapToControlMLEonAPI = value;
                }
            }
        }
        public Dictionary<string, bool> InternalMapToControlRequestMLEonAPI { get; set; }
        public Dictionary<string, bool> InternalMapToControlResponseMLEonAPI { get; set; }

        public string MleForRequestPublicCertPath { get; set; }

        public string RequestMleKeyAlias { get; set; }

        /// <summary>
        /// Flag to enable MLE (Message Level Encryption) for response body for all APIs in SDK to get MLE Response (encrypted response) if supported by API.
        /// </summary>
        public bool EnableResponseMleGlobally { get; set; }

        /// <summary>
        /// Parameter to pass the KID value for the MLE response public certificate. This value will be provided in the merchant portal when retrieving the MLE response certificate.
        /// </summary>
        public string ResponseMleKID { get; set; }

        /// <summary>
        /// Path to the private key file used for Response MLE decryption by the SDK.
        /// Supported formats: .p12, .key, .pem, etc.
        /// </summary>
        public string ResponseMlePrivateKeyFilePath { get; set; }

        /// <summary>
        /// Password for the private key file used in Response MLE decryption by the SDK.
        /// Required for .p12 files or encrypted private keys.
        /// </summary>
        public string ResponseMlePrivateKeyFilePassword { get; set; }

        /// <summary>
        /// AsymmetricAlgorithm instance used for Response MLE decryption by the SDK.
        /// Optional — either provide this object directly or specify the private key file path via configuration.
        /// </summary>
        public System.Security.Cryptography.AsymmetricAlgorithm ResponseMlePrivateKey { get; set; }

        #endregion

        public void LogMerchantConfigurationProperties()
        {
            var hiddenProperties = Constants.HideMerchantConfigProps.Split(',')
                                            .Select(property => property.Trim())
                                            .Where(property => property != null && property != "")
                                            .ToArray();

            var merchCfgLogString = string.Empty;
            var merchantConfigProperties = typeof(MerchantConfig).GetProperties();

            foreach (var property in merchantConfigProperties)
            {
                // If HiddenProperties Array does not contain any value of the current property being iterated
                // It simply means if the current property is not a hidden property, only then log it
                if (!hiddenProperties.Any(property.Name.Contains))
                {
                    var propertyValue = property.GetValue(this);
                    if (propertyValue != null && !string.IsNullOrEmpty(propertyValue.ToString()) &&
                        !property.Name.StartsWith("Is", StringComparison.OrdinalIgnoreCase))
                    {
                        merchCfgLogString += property.Name;
                        merchCfgLogString += " = ";
                        merchCfgLogString += propertyValue;
                        merchCfgLogString += "\n";
                    }
                }
            }

            Logger.Debug($"Merchant Configuration :\n{merchCfgLogString}");
        }

        private void SetValuesFromAppConfig(NameValueCollection merchantConfigSection, Dictionary<string, string> mapToControlMLEonAPI)
        {
            MerchantId = merchantConfigSection["merchantID"];
            PortfolioId = merchantConfigSection["portfolioID"];
            MerchantSecretKey = merchantConfigSection["merchantsecretKey"];
            MerchantKeyId = merchantConfigSection["merchantKeyId"];
            UseMetaKey = merchantConfigSection["useMetaKey"];
            AuthenticationType = merchantConfigSection["authenticationType"];
            KeyDirectory = merchantConfigSection["keysDirectory"];
            KeyfileName = merchantConfigSection["keyFilename"];
            RunEnvironment = merchantConfigSection["runEnvironment"];
            IntermediateHost = merchantConfigSection["intermediateHost"];
            DefaultDeveloperId = merchantConfigSection["defaultDeveloperId"];
            EnableClientCert = merchantConfigSection["enableClientCert"];
            ClientCertDirectory = merchantConfigSection["clientCertDirectory"];
            ClientCertFile = merchantConfigSection["clientCertFile"];
            ClientCertPassword = merchantConfigSection["clientCertPassword"];
            ClientId = merchantConfigSection["clientId"];
            ClientSecret = merchantConfigSection["clientSecret"];
            KeyAlias = merchantConfigSection["keyAlias"];
            KeyPass = merchantConfigSection["keyPass"];
            TimeOut = merchantConfigSection["timeout"];
            UseProxy = merchantConfigSection["useProxy"];
            ProxyAddress = merchantConfigSection["proxyAddress"];
            ProxyPort = merchantConfigSection["proxyPort"];
            ProxyUsername = merchantConfigSection["proxyUsername"];
            ProxyPassword = merchantConfigSection["proxyPassword"];
            PemFileDirectory = merchantConfigSection["pemFileDirectory"];

            if (!string.IsNullOrEmpty(merchantConfigSection["mleForRequestPublicCertPath"].Trim()))
            {
                MleForRequestPublicCertPath = merchantConfigSection["mleForRequestPublicCertPath"].Trim();
            }

            bool useMLEGloballySet = merchantConfigSection["useMLEGlobally"] != null;
            bool enableRequestMLEForOptionalApisGloballySet = merchantConfigSection["enableRequestMLEForOptionalApisGlobally"] != null;

            if (enableRequestMLEForOptionalApisGloballySet)
            {
                EnableRequestMLEForOptionalApisGlobally = bool.Parse(merchantConfigSection["enableRequestMLEForOptionalApisGlobally"]);
            }
            else if (useMLEGloballySet)
            {
                EnableRequestMLEForOptionalApisGlobally = bool.Parse(merchantConfigSection["useMLEGlobally"]);
            }
            else
            {
                EnableRequestMLEForOptionalApisGlobally = false;
            }

            if (useMLEGloballySet && enableRequestMLEForOptionalApisGloballySet)
            {
                bool useMLEGloballyValue = bool.Parse(merchantConfigSection["useMLEGlobally"]);
                bool enableRequestMLEForOptionalApisGloballyValue = bool.Parse(merchantConfigSection["enableRequestMLEForOptionalApisGlobally"]);
                if (useMLEGloballyValue != enableRequestMLEForOptionalApisGloballyValue)
                {
                    throw new Exception("Both useMLEGlobally and enableRequestMLEForOptionalApisGlobally are set but their values do not match.");
                }
            }

            if (merchantConfigSection["disableRequestMLEForMandatoryApisGlobally"] != null)
            {
                DisableRequestMLEForMandatoryApisGlobally = bool.Parse(merchantConfigSection["disableRequestMLEForMandatoryApisGlobally"]);
            }
            else
            {
                DisableRequestMLEForMandatoryApisGlobally = false;
            }

            MapToControlMLEonAPI = mapToControlMLEonAPI;

            if (!string.IsNullOrWhiteSpace(merchantConfigSection["requestMleKeyAlias"]))
            {
                RequestMleKeyAlias = merchantConfigSection["requestMleKeyAlias"]?.Trim();
            }
            else if (!string.IsNullOrWhiteSpace(merchantConfigSection["mleKeyAlias"]))
            {
                RequestMleKeyAlias = merchantConfigSection["mleKeyAlias"]?.Trim();
            }

            if(string.IsNullOrWhiteSpace(RequestMleKeyAlias?.Trim()))
            {
                RequestMleKeyAlias = Constants.DefaultMleAliasForCert;
            }

            // Adding Response MLE Related Params
            if (merchantConfigSection["enableResponseMleGlobally"] != null)
            {
                EnableResponseMleGlobally = bool.Parse(merchantConfigSection["enableResponseMleGlobally"]);
            }
            else
            {
                EnableResponseMleGlobally = false;
            }

            if (merchantConfigSection["responseMleKID"] != null && !string.IsNullOrEmpty(merchantConfigSection["responseMleKID"]?.Trim()))
            {
                ResponseMleKID = merchantConfigSection["responseMleKID"].Trim();
            }

            if (merchantConfigSection["responseMlePrivateKeyFilePath"] != null && !string.IsNullOrWhiteSpace(merchantConfigSection["responseMlePrivateKeyFilePath"]))
            {
                ResponseMlePrivateKeyFilePath = merchantConfigSection["responseMlePrivateKeyFilePath"].Trim();
            }

            if (merchantConfigSection["responseMlePrivateKeyFilePassword"] != null && !string.IsNullOrEmpty(merchantConfigSection["responseMlePrivateKeyFilePassword"]))
            {
                ResponseMlePrivateKeyFilePassword = merchantConfigSection["responseMlePrivateKeyFilePassword"];
            }
        }

        private void SetValuesUsingDictObj(IReadOnlyDictionary<string, string> merchantConfigDictionary, Dictionary<string,string> mapToControlMLEonAPI)
        {
            var key = string.Empty;

            try
            {
                if (merchantConfigDictionary != null)
                {
                    // MANDATORY KEYS
                    key = "runEnvironment";
                    RunEnvironment = merchantConfigDictionary[key];
                    key = "authenticationType";
                    AuthenticationType = merchantConfigDictionary[key];

                    key = "useMetaKey";
                    UseMetaKey = "false";
                    if (merchantConfigDictionary.ContainsKey(key))
                    {
                        UseMetaKey = merchantConfigDictionary[key];
                        if (string.IsNullOrEmpty(UseMetaKey))
                        {
                            UseMetaKey = "false";
                        }
                    }

                    key = "intermediateHost";
                    if (merchantConfigDictionary.ContainsKey(key))
                    {
                        IntermediateHost = merchantConfigDictionary[key];
                    }

                    key = "defaultDeveloperId";
                    if (merchantConfigDictionary.ContainsKey(key))
                    {
                        DefaultDeveloperId = merchantConfigDictionary[key];
                    }

                    Enum.TryParse(AuthenticationType.ToUpper(), out Enumerations.AuthenticationType authTypeInput);

                    if (Equals(authTypeInput, Enumerations.AuthenticationType.HTTP_SIGNATURE))
                    {
                        key = "merchantID";
                        MerchantId = merchantConfigDictionary[key];
                        key = "merchantsecretKey";
                        MerchantSecretKey = merchantConfigDictionary[key];
                        key = "merchantKeyId";
                        MerchantKeyId = merchantConfigDictionary[key];
                    }

                    if (Equals(bool.Parse(UseMetaKey.ToString()), true))
                    {
                        key = "portfolioID";
                        PortfolioId = merchantConfigDictionary[key];
                        if (Equals(PortfolioId, string.Empty))
                        {
                            throw new KeyNotFoundException("KeyNotFoundException : Key 'portfolioID' not found in configuration. Portfolio ID is mandatory when useMetaKey is true");
                        }
                    }

                    // OPTIONAL KEYS
                    // only if the key is passed read the value, otherwise use default / null values
                    if (Equals(authTypeInput, Enumerations.AuthenticationType.JWT))
                    {
                        key = "merchantID";
                        MerchantId = merchantConfigDictionary[key];
                        if (merchantConfigDictionary.ContainsKey("keyAlias"))
                        {
                            KeyAlias = merchantConfigDictionary["keyAlias"];
                        }

                        if (merchantConfigDictionary.ContainsKey("keyFilename"))
                        {
                            KeyfileName = merchantConfigDictionary["keyFilename"];
                        }

                        if (merchantConfigDictionary.ContainsKey("keyPass"))
                        {
                            KeyPass = merchantConfigDictionary["keyPass"];
                        }

                        if (merchantConfigDictionary.ContainsKey("keysDirectory"))
                        {
                            KeyDirectory = merchantConfigDictionary["keysDirectory"];
                        }
                    }

                    if (Equals(authTypeInput, Enumerations.AuthenticationType.OAUTH))
                    {
                        IsOAuthTokenAuthType = true;
                        key = "accessToken";
                        if (merchantConfigDictionary.ContainsKey(key) && !string.IsNullOrEmpty(merchantConfigDictionary[key]))
                        {
                            AccessToken = merchantConfigDictionary[key];
                        }
                        else
                        {
                            throw new KeyNotFoundException("KeyNotFoundException : Key 'accessToken' not found in configuration. Access Token is mandatory when Authentication Type is set to OAuth");
                        }

                        key = "refreshToken";
                        if (merchantConfigDictionary.ContainsKey(key) && !string.IsNullOrEmpty(merchantConfigDictionary[key]))
                        {
                            RefreshToken = merchantConfigDictionary[key];
                        }
                        else
                        {
                            throw new KeyNotFoundException("KeyNotFoundException : Key 'refreshToken' not found in configuration. Refresh Token is mandatory when Authentication Type is set to OAuth");
                        }
                    }

                    if (Equals(authTypeInput, Enumerations.AuthenticationType.MUTUAL_AUTH))
                    {
                        key = "clientId";
                        if (merchantConfigDictionary.ContainsKey(key) && !string.IsNullOrEmpty(merchantConfigDictionary[key]))
                        {
                            ClientId = merchantConfigDictionary[key];
                        }
                        else
                        {
                            throw new KeyNotFoundException("KeyNotFoundException : Key 'clientId' not found in configuration. Client ID is mandatory when Authentication Type is set to Mutual Auth");
                        }

                        key = "clientSecret";
                        if (merchantConfigDictionary.ContainsKey(key) && !string.IsNullOrEmpty(merchantConfigDictionary[key]))
                        {
                            ClientSecret = merchantConfigDictionary[key];
                        }
                        else
                        {
                            throw new KeyNotFoundException("KeyNotFoundException : Key 'clientSecret' not found in configuration. Client Secret is mandatory when Authentication Type is set to Mutual Auth");
                        }
                    }

                    key = "enableClientCert";
                    if (merchantConfigDictionary.ContainsKey(key) && !string.IsNullOrEmpty(merchantConfigDictionary[key]))
                    {
                        EnableClientCert = merchantConfigDictionary[key];
                    }
                    else
                    {
                        EnableClientCert = "false";
                    }

                    if (Equals(bool.Parse(EnableClientCert.ToString()), true))
                    {
                        key = "clientCertFile";
                        if (merchantConfigDictionary.ContainsKey(key) && !string.IsNullOrEmpty(merchantConfigDictionary[key]))
                        {
                            ClientCertFile = merchantConfigDictionary[key];
                        }
                        else
                        {
                            throw new KeyNotFoundException("KeyNotFoundException : Key 'clientCertFile' not found in configuration. Client Certificate File is mandatory when enableClientCert is true");
                        }

                        key = "clientCertPassword";
                        if (merchantConfigDictionary.ContainsKey(key) && !string.IsNullOrEmpty(merchantConfigDictionary[key]))
                        {
                            ClientCertPassword = merchantConfigDictionary[key];
                        }
                        else
                        {
                            throw new KeyNotFoundException("KeyNotFoundException : Key 'clientCertPassword' not found in configuration. Client Certificate Password is mandatory when enableClientCert is true");
                        }

                        key = "clientCertDirectory";
                        if (merchantConfigDictionary.ContainsKey(key) && !string.IsNullOrEmpty(merchantConfigDictionary[key]))
                        {
                            ClientCertDirectory = merchantConfigDictionary[key];
                        }
                        else
                        {
                            throw new KeyNotFoundException("KeyNotFoundException : Key 'clientCertDirectory' not found in configuration. Client Certificate Directory is mandatory when enableClientCert is true");
                        }
                    }

                    if (merchantConfigDictionary.ContainsKey("timeout"))
                    {
                        TimeOut = merchantConfigDictionary["timeout"];
                    }

                    if (merchantConfigDictionary.ContainsKey("useProxy"))
                    {
                        UseProxy = merchantConfigDictionary["useProxy"];
                    }

                    if (merchantConfigDictionary.ContainsKey("proxyAddress"))
                    {
                        ProxyAddress = merchantConfigDictionary["proxyAddress"];
                    }

                    if (merchantConfigDictionary.ContainsKey("proxyPort"))
                    {
                        ProxyPort = merchantConfigDictionary["proxyPort"];
                    }

                    if (merchantConfigDictionary.ContainsKey("proxyUsername"))
                    {
                        ProxyUsername = merchantConfigDictionary["proxyUsername"];
                    }

                    if (merchantConfigDictionary.ContainsKey("proxyPassword"))
                    {
                        ProxyPassword = merchantConfigDictionary["proxyPassword"];
                    }

                    if (merchantConfigDictionary.ContainsKey("pemFileDirectory"))
                    {
                        PemFileDirectory = merchantConfigDictionary["pemFileDirectory"];
                    }

                    bool useMLEGloballySet = merchantConfigDictionary.ContainsKey("useMLEGlobally");
                    bool enableRequestMLEForOptionalApisGloballySet = merchantConfigDictionary.ContainsKey("enableRequestMLEForOptionalApisGlobally");

                    if (enableRequestMLEForOptionalApisGloballySet)
                    {
                        EnableRequestMLEForOptionalApisGlobally = bool.Parse(merchantConfigDictionary["enableRequestMLEForOptionalApisGlobally"]);
                    }
                    else if (useMLEGloballySet)
                    {
                        EnableRequestMLEForOptionalApisGlobally = bool.Parse(merchantConfigDictionary["useMLEGlobally"]);
                    }
                    else
                    {
                        EnableRequestMLEForOptionalApisGlobally = false;
                    }

                    if (useMLEGloballySet && enableRequestMLEForOptionalApisGloballySet)
                    {
                        bool useMLEGloballyValue = bool.Parse(merchantConfigDictionary["useMLEGlobally"]);
                        bool enableRequestMLEForOptionalApisGloballyValue = bool.Parse(merchantConfigDictionary["enableRequestMLEForOptionalApisGlobally"]);
                        if (useMLEGloballyValue != enableRequestMLEForOptionalApisGloballyValue)
                        {
                            throw new Exception("Both useMLEGlobally and enableRequestMLEForOptionalApisGlobally are set but their values do not match.");
                        }
                    }

                    if (merchantConfigDictionary.ContainsKey("disableRequestMLEForMandatoryApisGlobally"))
                    {
                        DisableRequestMLEForMandatoryApisGlobally = bool.Parse(merchantConfigDictionary["disableRequestMLEForMandatoryApisGlobally"]);
                    }
                    else
                    {
                        DisableRequestMLEForMandatoryApisGlobally = false;
                    }

                    if (mapToControlMLEonAPI != null)
                    {
                        MapToControlMLEonAPI = mapToControlMLEonAPI;
                    }

                    if (merchantConfigDictionary.ContainsKey("requestMleKeyAlias"))
                    {
                        RequestMleKeyAlias = merchantConfigDictionary["requestMleKeyAlias"]?.Trim();
                    }
                    else if (merchantConfigDictionary.ContainsKey("mleKeyAlias"))
                    {
                        RequestMleKeyAlias = merchantConfigDictionary["mleKeyAlias"]?.Trim();
                    }

                    //if RequestMleKeyAlias is null or empty or contains only whitespace then set default value
                    if (string.IsNullOrWhiteSpace(RequestMleKeyAlias?.Trim()))
                    {
                        RequestMleKeyAlias = Constants.DefaultMleAliasForCert;
                    }

                    if (merchantConfigDictionary.ContainsKey("mleForRequestPublicCertPath") && !string.IsNullOrEmpty(merchantConfigDictionary["mleForRequestPublicCertPath"].Trim()))
                    {
                        MleForRequestPublicCertPath = merchantConfigDictionary["mleForRequestPublicCertPath"].Trim();
                    }

                    // Adding Response MLE Related Params
                    if (merchantConfigDictionary.ContainsKey("enableResponseMleGlobally"))
                    {
                        EnableResponseMleGlobally = bool.Parse(merchantConfigDictionary["enableResponseMleGlobally"]);
                    }
                    else
                    {
                        EnableResponseMleGlobally = false;
                    }

                    if (merchantConfigDictionary.ContainsKey("responseMleKID") && !string.IsNullOrEmpty(merchantConfigDictionary["responseMleKID"]?.Trim()))
                    {
                        ResponseMleKID = merchantConfigDictionary["responseMleKID"].Trim();
                    }

                    if (merchantConfigDictionary.ContainsKey("responseMlePrivateKeyFilePath") && !string.IsNullOrWhiteSpace(merchantConfigDictionary["responseMlePrivateKeyFilePath"]))
                    {
                        ResponseMlePrivateKeyFilePath = merchantConfigDictionary["responseMlePrivateKeyFilePath"].Trim();
                    }

                    if (merchantConfigDictionary.ContainsKey("responseMlePrivateKeyFilePassword") && !string.IsNullOrEmpty(merchantConfigDictionary["responseMlePrivateKeyFilePassword"]))
                    {
                        ResponseMlePrivateKeyFilePassword = merchantConfigDictionary["responseMlePrivateKeyFilePassword"];
                    }
                }
            }
            catch (KeyNotFoundException err)
            {
                Logger.Error($"{err.Message}");
                throw new Exception($"{Constants.ErrorPrefix} {err.Message}");
            }
        }

        private void ValidateMapToControlMLEonAPIValues(Dictionary<string, string> mapToControlMLEonAPI)
        {
            if (mapToControlMLEonAPI == null)
            {
                return;
            }

            foreach (var entry in mapToControlMLEonAPI)
            {
                var key = entry.Key;
                var value = entry.Value;

                if (string.IsNullOrEmpty(value))
                {
                    Logger.Error($"ConfigException : Invalid MLE control map value for key '{key}'. Value cannot be null or empty.");
                    throw new Exception($"Invalid MLE control map value for key '{key}'. Value cannot be null or empty.");
                }

                // Check if value contains "::" separator
                if (value.Contains("::"))
                {
                    var parts = value.Split(new[] { "::" }, StringSplitOptions.None);

                    if (parts.Length != 2)
                    {
                        Logger.Error($"ConfigException : Invalid MLE control map value format for key '{key}'. Expected format: true/false for 'requestMLE::responseMLE' but got: '{value}'");
                        throw new Exception($"Invalid MLE control map value format for key '{key}'. Expected format: true/false for 'requestMLE::responseMLE' but got: '{value}'");
                    }

                    var requestMLE = parts[0];
                    var responseMLE = parts[1];

                    // Validate first part (request MLE) - can be empty, "true", or "false"
                    if (!string.IsNullOrEmpty(requestMLE) && !Utility.IsValidBooleanString(requestMLE))
                    {
                        Logger.Error($"ConfigException : Invalid request MLE value for key '{key}'. Expected 'true', 'false', or empty but got: '{requestMLE}'");
                        throw new Exception($"Invalid request MLE value for key '{key}'. Expected 'true', 'false', or empty but got: '{requestMLE}'");
                    }

                    // Validate second part (response MLE) - can be empty, "true", or "false"
                    if (!string.IsNullOrEmpty(responseMLE) && !Utility.IsValidBooleanString(responseMLE))
                    {
                        Logger.Error($"ConfigException : Invalid response MLE value for key '{key}'. Expected 'true', 'false', or empty but got: '{responseMLE}'");
                        throw new Exception($"Invalid response MLE value for key '{key}'. Expected 'true', 'false', or empty but got: '{responseMLE}'");
                    }
                }
                else
                {
                    // Value without "::" separator - should be "true" or "false"
                    if (!Utility.IsValidBooleanString(value))
                    {
                        Logger.Error($"ConfigException : Invalid MLE control map value for key '{key}'. Expected 'true' or 'false' for requestMLE but got: '{value}'");
                        throw new Exception($"Invalid MLE control map value for key '{key}'. Expected 'true' or 'false' for requestMLE but got: '{value}'");
                    }
                }
            }
        }

        private void ValidateProperties()
        {
            // Validating and setting up Authentication type
            Enumerations.ValidateAuthenticationType(AuthenticationType);

            if (string.Equals(AuthenticationType, Enumerations.AuthenticationType.HTTP_SIGNATURE.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                IsHttpSignAuthType = true;
            }
            else if (string.Equals(AuthenticationType, Enumerations.AuthenticationType.JWT.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                IsJwtTokenAuthType = true;
            }

            if (string.IsNullOrEmpty(TimeOut))
            {
                TimeOut = string.Empty;   // In Millisec
            }

            // setting up hostname based on the run environment value
            if (string.IsNullOrEmpty(RunEnvironment))
            {
                Logger.Error("Run Environment cannot be null or empty");
                throw new Exception($"{Constants.ErrorPrefix} Merchant Config field - RunEnvironment is Mandatory");
            }
            else if (Constants.OldRunEnvironmentConstants.Contains(RunEnvironment.ToUpper()))
            {
                throw new Exception($"{Constants.DeprecationPrefix} The value \"{RunEnvironment}\" for this field `RunEnvironment` has been deprecated and will not be used anymore.\n\nPlease refer to the README file [ https://github.com/CyberSource/cybersource-rest-samples-csharp/blob/master/README.md ] for information about the new values that are accepted.");
            }

            HostName = RunEnvironment.ToLower();

            // AUTHENTICATION MECHANISM SPECIFIC CHECKS
            // 1. FOR HTTP SIGNATURE
            if (IsHttpSignAuthType)
            {
                if (string.IsNullOrEmpty(MerchantId))
                {
                    Logger.Error("Merchant ID cannot be null or empty");
                    throw new Exception($"{Constants.ErrorPrefix} Merchant Config field - MerchantID is Mandatory");
                }

                if (string.IsNullOrEmpty(MerchantKeyId))
                {
                    Logger.Error("Merchant Key ID cannot be null or empty");
                    throw new Exception($"{Constants.ErrorPrefix} Merchant Config field - MerchantKeyId is Mandatory");
                }

                if (string.IsNullOrEmpty(MerchantSecretKey))
                {
                    Logger.Error("Merchant Secret Key cannot be null or empty");
                    throw new Exception($"{Constants.ErrorPrefix} Merchant Config field - MerchantSecretKey is Mandatory");
                }
            }

            // 2. FOR JWT TOKEN
            else if (IsJwtTokenAuthType)
            {
                if (string.IsNullOrEmpty(MerchantId))
                {
                    Logger.Error("Merchant ID cannot be null or empty");
                    throw new Exception($"{Constants.ErrorPrefix} Merchant Config field - MerchantID is Mandatory");
                }

                if (string.IsNullOrEmpty(KeyAlias))
                {
                    KeyAlias = MerchantId;
                    Logger.Warn("Key Alias not provided. Assigning the value of Merchant ID");
                    throw new Exception($"{Constants.WarningPrefix} KeyAlias not provided. Assigning the value of: [MerchantID]");
                }

                if (!string.Equals(KeyAlias, MerchantId))
                {
                    KeyAlias = MerchantId;
                    Logger.Warn("Key Alias value provided is incorrect. Assigning the value of Merchant ID");
                    throw new Exception($"{Constants.WarningPrefix} Incorrect value of KeyAlias provided. Assigning the value of: [MerchantID]");
                }

                if (string.IsNullOrEmpty(KeyPass))
                {
                    KeyPass = MerchantId;
                    Logger.Warn("Key Password not provided. Assigning the value of Merchant ID");
                    throw new Exception($"{Constants.WarningPrefix} KeyPassword not provided. Assigning the value of: [MerchantID]");
                }

                if (string.IsNullOrEmpty(KeyDirectory))
                {
                    KeyDirectory = Constants.P12FileDirectory;
                    Logger.Warn($"Keys Directory not provided. Using Default Path: {KeyDirectory}");
                    throw new Exception($"{Constants.WarningPrefix} KeysDirectory not provided. Using Default Path: {KeyDirectory}");
                }

                if (string.IsNullOrEmpty(KeyfileName))
                {
                    KeyfileName = MerchantId;
                    Logger.Warn("Key Filename not provided. Assigning the value of Merchant ID");
                    throw new Exception($"{Constants.WarningPrefix} KeyfileName not provided. Assigning the value of: [MerchantId]");
                }

                var pathDirectorySeparator = Path.DirectorySeparatorChar;

                // Check the p12 file and set the keyFile to get the mleCert in case of JWT auth type
                if (!CheckKeyFile())
                {
                    throw new Exception($"{Constants.ErrorPrefix} Error finding or accessing the Key Directory or Key File. Please review the values in the merchant configuration.");
                }

                P12Keyfilepath = $"{KeyDirectory}{pathDirectorySeparator}{KeyfileName}.p12";
            }
        }

        private void ValidateMLEProperties()
        {
            
            bool requestMleConfigured = EnableRequestMLEForOptionalApisGlobally;

            if (InternalMapToControlRequestMLEonAPI != null && InternalMapToControlRequestMLEonAPI.Count > 0)
            {
                foreach (bool value in InternalMapToControlRequestMLEonAPI.Values)
                {
                    if (value)
                    {
                        requestMleConfigured = true;
                        break;
                    }
                }
            }

            //if MLE=true then check for auth Type
            if (requestMleConfigured && !Enumerations.AuthenticationType.JWT.ToString().Equals(AuthenticationType, StringComparison.OrdinalIgnoreCase))
            {
                Logger.Error("Request MLE is only supported in JWT auth type");
                throw new Exception("Request MLE is only supported in JWT auth type");
            }

            // Verify that the input path for MLE certificate is valid, else throw error in both cases (MLE=true/false)
            if (!string.IsNullOrEmpty(MleForRequestPublicCertPath))
            {
                try
                {
                    CertificateUtility.ValidatePathAndFile(MleForRequestPublicCertPath, "mleForRequestPublicCertPath");
                }
                catch (IOException err)
                {
                    Logger.Error(err.Message);
                    throw new Exception(err.Message);
                }
            }

            // Validation for MLE Response Configuration

            bool responseMleConfigured = EnableResponseMleGlobally;
            if (InternalMapToControlResponseMLEonAPI != null && InternalMapToControlResponseMLEonAPI.Count > 0)
            {
                foreach (bool value in InternalMapToControlResponseMLEonAPI.Values)
                {
                    if (value)
                    {
                        responseMleConfigured = true;
                        break;
                    }
                }
            }
            if (responseMleConfigured)
            {
                // Validate for Auth type - Currently responseMLE feature will be enabled for JWT auth type only
                if (!Enumerations.AuthenticationType.JWT.ToString().Equals(AuthenticationType, StringComparison.OrdinalIgnoreCase))
                {
                    Logger.Error("Response MLE is only supported for JWT auth type");
                    throw new Exception("Response MLE is only supported for JWT auth type");
                }

                // Check if either private key object or private key file path is provided
                if (ResponseMlePrivateKey == null && string.IsNullOrEmpty(ResponseMlePrivateKeyFilePath))
                {
                    Logger.Error("Response MLE is enabled but no private key provided. Either set ResponseMlePrivateKey object or provide ResponseMlePrivateKeyFilePath.");
                    throw new Exception("Response MLE is enabled but no private key provided. Either set ResponseMlePrivateKey object or provide ResponseMlePrivateKeyFilePath.");
                }

                // If private key file path is provided, validate the file exists
                if (!string.IsNullOrEmpty(ResponseMlePrivateKeyFilePath))
                {
                    try
                    {
                        CertificateUtility.ValidatePathAndFile(ResponseMlePrivateKeyFilePath, "responseMlePrivateKeyFilePath");
                    }
                    catch (IOException err)
                    {
                        Logger.Error("Invalid responseMlePrivateKeyFilePath - " + err.Message);
                        throw new Exception("Invalid responseMlePrivateKeyFilePath - " + err.Message);
                    }
                }
                // Validate responseMleKID is provided when response MLE is enabled
                if (string.IsNullOrEmpty(ResponseMleKID))
                {
                    Logger.Error("ConfigException : Response MLE is enabled but responseMleKID is not provided.");
                    throw new Exception("Response MLE is enabled but responseMleKID is not provided.");
                }
            }
        }

        public bool CheckKeyFile()
        {
            if (string.IsNullOrEmpty(KeyfileName))
            {
                Logger.Error("Key Filename not provided. Assigning the value of Merchant ID");
                if (!string.IsNullOrEmpty(MerchantId))
                {
                    KeyfileName = MerchantId;
                }
            }

            if (string.IsNullOrEmpty(KeyDirectory))
            {
                KeyDirectory = Constants.P12FileDirectory;
                Logger.Error($"Keys Directory not provided. Using Default Path: {KeyDirectory}");
            }

            DirectoryInfo dirInfo = new DirectoryInfo(KeyDirectory);

            if (!dirInfo.Exists)
            {
                Logger.Error($"KeyDirectory not found, Entered directory : {KeyDirectory}");
                return false;
            }

            string keyFilePath;
            FileInfo newFile;
            try
            {
                keyFilePath = Path.Combine(KeyDirectory, KeyfileName + ".p12");
                newFile = new FileInfo(keyFilePath);
                if (!newFile.Exists)
                {
                    Logger.Error($"KeyFile not found, Entered path/file name : {keyFilePath}");
                    return false;
                }

                Logger.Info($"Entered file/path value for Key File : {keyFilePath}");
            }
            catch (Exception)
            {
                return false;
            }

            bool isReadable = false;
            try
            {
                using (FileStream fs = newFile.Open(FileMode.Open, FileAccess.Read))
                {
                    isReadable = true;
                }
            }
            catch
            {
                isReadable = false;
            }

            if (isReadable)
            {
                P12Keyfilepath = keyFilePath;
                return true;
            }
            else
            {
                Logger.Info($"File cannot be accessed. Permission denied : {keyFilePath}");
                return false;
            }
        }
    }
}