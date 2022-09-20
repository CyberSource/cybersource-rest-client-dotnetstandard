using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.IO;
using System.Linq;
using AuthenticationSdk.util;
using NLog;

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
        public MerchantConfig(IReadOnlyDictionary<string, string> merchantConfigDictionary = null)
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

                SetValuesUsingDictObj(merchantConfigDictionary);
            }
            else
            {
                // MerchantConfig section inside App.Config File
                var merchantConfigSection = (NameValueCollection)ConfigurationManager.GetSection("MerchantConfig");

                if (merchantConfigSection != null)
                {
                    _propertiesSetUsing = "App.Config File";

                    SetValuesFromAppConfig(merchantConfigSection);
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

        public string KeyAlias { get; set; }

        public string KeyPass { get; set; }

        public string EnableLog { get; set; } = "TRUE";

        public string LogDirectory { get; set; } = "../../logs";

        public string LogfileMaxSize { get; set; } = "10485760"; // 10 MB = 10485760 bytes

        public string LogFileName { get; set; } = "cybs.log";

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

        private void SetValuesFromAppConfig(NameValueCollection merchantConfigSection)
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
        }

        private void SetValuesUsingDictObj(IReadOnlyDictionary<string, string> merchantConfigDictionary)
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

                P12Keyfilepath = $"{KeyDirectory}{pathDirectorySeparator}{KeyfileName}.p12";
            }
        }
    }
}