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
        public MerchantConfig(IReadOnlyDictionary<string, string> merchantConfigDictionary = null, Dictionary<string,bool> mapToControlMLEonAPI=null)
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

        public Dictionary<string, bool> MapToControlMLEonAPI { get; set; }

        public string MleKeyAlias { get; set; }

        public string MaxConnectionPoolSize { get; set; }

        public string KeepAliveTime { get; set; }

        public string MleForRequestPublicCertPath { get; set; }

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

        private void SetValuesFromAppConfig(NameValueCollection merchantConfigSection, Dictionary<string, bool> mapToControlMLEonAPI)
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

            if (merchantConfigSection["mleKeyAlias"] != null)
            {
                MleKeyAlias = merchantConfigSection["mleKeyAlias"]?.Trim();
            }

            if (string.IsNullOrWhiteSpace(MleKeyAlias?.Trim()))
            {
                MleKeyAlias = Constants.DefaultMleAliasForCert;
            }

            if (merchantConfigSection["maxConnectionPoolSize"] != null)
            {
                MaxConnectionPoolSize = merchantConfigSection["maxConnectionPoolSize"];
            }
            else
            {
                MaxConnectionPoolSize = Constants.DefaultMaxConnectionPoolSize;
            }

            if (merchantConfigSection["keepAliveTime"] != null)
            {
                KeepAliveTime = merchantConfigSection["keepAliveTime"];
            }
            else
            {
                KeepAliveTime = Constants.DefaultKeepAliveTime;
            }
        }

        private void SetValuesUsingDictObj(IReadOnlyDictionary<string, string> merchantConfigDictionary, Dictionary<string,bool> mapToControlMLEonAPI)
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

                    if (merchantConfigDictionary.ContainsKey("mleKeyAlias"))
                    {
                        MleKeyAlias = merchantConfigDictionary["mleKeyAlias"]?.Trim();
                    }

                    //if MleKeyAlias is null or empty or contains only whitespace then set default value
                    if (string.IsNullOrWhiteSpace(MleKeyAlias?.Trim()))
                    {
                        MleKeyAlias = Constants.DefaultMleAliasForCert;
                    }

                    if (merchantConfigDictionary.ContainsKey("maxConnectionPoolSize"))
                    {
                        MaxConnectionPoolSize = merchantConfigDictionary["maxConnectionPoolSize"];
                    }
                    else
                    {
                        MaxConnectionPoolSize = Constants.DefaultMaxConnectionPoolSize;
                    }

                    if (merchantConfigDictionary.ContainsKey("keepAliveTime"))
                    {
                        KeepAliveTime = merchantConfigDictionary["keepAliveTime"];
                    }
                    else
                    {
                        KeepAliveTime = Constants.DefaultKeepAliveTime;
                    }

                    if (merchantConfigDictionary.ContainsKey("mleForRequestPublicCertPath") && !string.IsNullOrEmpty(merchantConfigDictionary["mleForRequestPublicCertPath"].Trim()))
                    {
                        MleForRequestPublicCertPath = merchantConfigDictionary["mleForRequestPublicCertPath"].Trim();
                    }
                }
            }
            catch (KeyNotFoundException err)
            {
                Logger.Error($"{err.Message}");
                throw new Exception($"{Constants.ErrorPrefix} {err.Message}");
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

            if (MapToControlMLEonAPI != null && MapToControlMLEonAPI.Count > 0)
            {
                foreach (bool value in MapToControlMLEonAPI.Values)
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