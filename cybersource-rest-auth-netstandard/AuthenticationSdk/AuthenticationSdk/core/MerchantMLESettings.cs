using AuthenticationSdk.util;
using NLog;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;

using MLEKeys = AuthenticationSdk.core.MerchantConfigurationKeys.MerchantMLESettingsKeys;

namespace AuthenticationSdk.core
{
    /// <summary>
    /// Provides configuration settings for Message Level Encryption (MLE) in merchant authentication.
    /// Handles initialization and validation of MLE properties for both request and response encryption.
    /// </summary>
    public class MerchantMLESettings : IMerchantMLESettings
    {
        #region Constructors
        /// <summary>
        /// Initializes a new instance of the <see cref="MerchantMLESettings"/> class.
        /// </summary>
        /// <param name="merchantMLEDictionary">A dictionary containing merchant MLE configuration values from App.Config or custom source. If null, configuration is loaded from the MerchantConfig section in App.Config.<br/>Refer to <see cref="MerchantConfigurationKeys.MerchantMLESettingsKeys"/> for the list of possible keys</param>
        /// <param name="mapToControlMLEonAPI">Dictionary mapping API operation names to MLE control settings in format "requestMLE::responseMLE" or "requestMLE" to override global MLE configuration per API</param>
        /// <param name="responseMlePrivateKey">Optional pre-loaded asymmetric private key for decrypting MLE responses. If provided, this takes precedence over loading from file path.</param>
        /// <exception cref="Exception">Thrown when configuration is invalid or required MLE properties are missing.</exception>
        public MerchantMLESettings(IReadOnlyDictionary<string, string> merchantMLEDictionary = null, Dictionary<string, string> mapToControlMLEonAPI = null, AsymmetricAlgorithm responseMlePrivateKey = null) : this(merchantMLEDictionary, mapToControlMLEonAPI, responseMlePrivateKey, false)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MerchantMLESettings"/> class.
        /// </summary>
        /// <param name="merchantMLEDictionary">A dictionary containing merchant MLE configuration values from App.Config or custom source. If null, configuration is loaded from the MerchantConfig section in App.Config.<br/>Refer to <see cref="MerchantConfigurationKeys.MerchantMLESettingsKeys"/> for the list of possible keys</param>
        /// <param name="mapToControlMLEonAPI">Dictionary mapping API operation names to MLE control settings in format "requestMLE::responseMLE" or "requestMLE" to override global MLE configuration per API</param>
        /// <param name="responseMlePrivateKey">Optional pre-loaded asymmetric private key for decrypting MLE responses. If provided, this takes precedence over loading from file path.</param>
        /// <param name="isValidated">Indicates whether the provided MLE control settings have already been validated. If true, validation will be skipped.</param>
        /// <exception cref="Exception">Thrown when configuration is invalid or required MLE properties are missing.</exception>
        internal MerchantMLESettings(IReadOnlyDictionary<string, string> merchantMLEDictionary = null, Dictionary<string, string> mapToControlMLEonAPI = null, AsymmetricAlgorithm responseMlePrivateKey = null, bool isValidated = false) 
        {
            if (Logger == null)
            {
                Logger = LogManager.GetCurrentClassLogger();
            }

            if (merchantMLEDictionary == null)
            {
                IReadOnlyDictionary<string, string> merchantConfigSection = null;
                try
                {
                    var appSettingsSection = ConfigurationManager.GetSection("MerchantConfig") as NameValueCollection;
                    merchantConfigSection = appSettingsSection.AllKeys.ToDictionary(k => k, k => appSettingsSection[k]);

                    if (!isValidated)
                    {
                        var _validator = new MerchantMLESettingsValidator();
                        _validator.ValidateMLESettings(merchantConfigSection, mapToControlMLEonAPI, responseMlePrivateKey);
                    }

                    SetValuesFromDictionary(merchantConfigSection, mapToControlMLEonAPI, responseMlePrivateKey);
                }
                catch (ConfigurationErrorsException ex)
                {
                    throw new Exception($"{Constants.ErrorPrefix} Error accessing MerchantConfig section in App.Config: {ex.Message}", ex);
                }
                catch (Exception ex)
                {
                    throw new Exception($"{Constants.ErrorPrefix} Unexpected error accessing MerchantConfig section in App.Config: {ex.Message}", ex);
                }
            }
            else if (merchantMLEDictionary != null)
            {
                if (!isValidated)
                {
                    var _validator = new MerchantMLESettingsValidator();
                    _validator.ValidateMLESettings(merchantMLEDictionary, mapToControlMLEonAPI, responseMlePrivateKey);
                }

                SetValuesFromDictionary(merchantMLEDictionary, mapToControlMLEonAPI, responseMlePrivateKey);
            }
        }
        #endregion Constructors

        #region Private Methods
        /// <summary>
        /// Populates MLE configuration properties from the provided merchant configuration dictionary.
        /// Handles deprecated property aliases and sets default values where applicable.
        /// </summary>
        /// <param name="merchantMLEDict">A dictionary containing merchant configuration key-value pairs.</param>
        /// <param name="mapToControlMLEonAPI">A dictionary mapping API operation names to their MLE control settings.</param>
        /// <exception cref="KeyNotFoundException">Thrown when a required configuration key is not found.</exception>
        private void SetValuesFromDictionary(IReadOnlyDictionary<string, string> merchantMLEDict, Dictionary<string, string> mapToControlMLEonAPI, AsymmetricAlgorithm responseMlePrivateKey = null)
        {
            try
            {
                var enableRequestMLEForOptionalApisGlobally = merchantMLEDict.GetValueOrDefault(MLEKeys.EnableRequestMLEForOptionalApisGlobally, null);
                var useMLEGlobally = merchantMLEDict.GetValueOrDefault(MLEKeys.UseMLEGlobally, null);
                var disableRequestMLEForMandatoryApisGlobally = ExtractBooleanKeyFromDictionaryOrDefault(merchantMLEDict, MLEKeys.DisableRequestMLEForMandatoryApisGlobally, false);
                var requestMleKeyAlias = merchantMLEDict.GetValueOrDefault(MLEKeys.RequestMleKeyAlias, null);
                var mleKeyAlias = merchantMLEDict.GetValueOrDefault(MLEKeys.MleKeyAlias, null);
                var enableResponseMleGlobally = ExtractBooleanKeyFromDictionaryOrDefault(merchantMLEDict, MLEKeys.EnableResponseMleGlobally, false);
                var responseMleKID = merchantMLEDict.GetValueOrDefault(MLEKeys.ResponseMleKID, null);
                var responseMlePrivateKeyFilePath = merchantMLEDict.GetValueOrDefault(MLEKeys.ResponseMlePrivateKeyFilePath, null);
                var responseMlePrivateKeyFilePassword = Utility.ConvertStringToSecureString(merchantMLEDict.GetValueOrDefault(MLEKeys.ResponseMlePrivateKeyFilePassword, null));

                if (string.IsNullOrEmpty(enableRequestMLEForOptionalApisGlobally))
                {
                    if (!string.IsNullOrEmpty(useMLEGlobally))
                    {
                        enableRequestMLEForOptionalApisGlobally = useMLEGlobally;
                    }
                    else
                    {
                        enableRequestMLEForOptionalApisGlobally = "false";
                    }
                }

                if (string.IsNullOrEmpty(requestMleKeyAlias))
                {
                    if (!string.IsNullOrEmpty(mleKeyAlias))
                    {
                        requestMleKeyAlias = mleKeyAlias;
                    }
                    else
                    {
                        requestMleKeyAlias = Constants.DefaultMleAliasForCert;
                    }
                }

                var mleForRequestPublicCertPath = merchantMLEDict.GetValueOrDefault(MLEKeys.MleForRequestPublicCertPath, null);

                EnableRequestMLEForOptionalApisGlobally = bool.Parse(enableRequestMLEForOptionalApisGlobally);
                DisableRequestMLEForMandatoryApisGlobally = disableRequestMLEForMandatoryApisGlobally;
                RequestMleKeyAlias = requestMleKeyAlias;
                EnableResponseMleGlobally = enableResponseMleGlobally;
                ResponseMleKID = responseMleKID?.Trim();
                ResponseMlePrivateKeyFilePath = responseMlePrivateKeyFilePath;
                ResponseMlePrivateKeyFilePassword = responseMlePrivateKeyFilePassword;
                MapToControlMLEonAPI = mapToControlMLEonAPI;
                MleForRequestPublicCertPath = mleForRequestPublicCertPath;

                if (responseMlePrivateKey != null)
                {
                    ResponseMlePrivateKey = responseMlePrivateKey;
                }
            }
            catch (KeyNotFoundException err)
            {
                throw new Exception($"{Constants.ErrorPrefix} {err.Message}", err);
            }
        }

        /// <summary>
        /// Extracts a boolean configuration value from the provided dictionary using the specified key.
        /// If the key is not found or the value cannot be parsed as a boolean, returns the default value.
        /// </summary>
        /// <param name="merchantMLEDict">A dictionary containing merchant MLE configuration key-value pairs.</param>
        /// <param name="key">The configuration key to look up.</param>
        /// <param name="defaultValue">The default value to return if the key is not found or the value cannot be parsed as a boolean.</param>
        /// <returns>The parsed boolean value if the key exists and can be parsed; otherwise, the default value.</returns>
        private bool ExtractBooleanKeyFromDictionaryOrDefault(IReadOnlyDictionary<string, string> merchantMLEDict, string key, bool defaultValue)
        {
            if (merchantMLEDict.ContainsKey(key))
            {
                if (bool.TryParse(merchantMLEDict[key], out bool result))
                {
                    return result;
                }
            }

            return defaultValue;
        }
        #endregion Private Methods

        #region Properties
        /// <summary>
        /// Gets or sets the file system path to the public certificate used for MLE requests.
        /// </summary>
        public string MleForRequestPublicCertPath { get; internal set; }

        /// <summary>
        /// Gets or sets the alias of the key used for MLE in the current request.
        /// </summary>
        public string RequestMleKeyAlias { get; internal set; }

        /// <summary>
        /// Gets or sets a value indicating whether response MLE is enabled globally for all APIs.
        /// </summary>
        public bool EnableResponseMleGlobally { get; internal set; }

        /// <summary>
        /// Gets or sets the identifier (KID) for the private key used to decrypt the MLE response.
        /// </summary>
        public string ResponseMleKID { get; internal set; }

        /// <summary>
        /// Gets or sets the file path to the private key used for decrypting the MLE response.
        /// </summary>
        public string ResponseMlePrivateKeyFilePath { get; internal set; }

        /// <summary>
        /// Gets or sets the password used to access the MLE private key file for the response, stored as a secure string.
        /// </summary>
        public SecureString ResponseMlePrivateKeyFilePassword { get; internal set; }

        /// <summary>
        /// Gets or sets the asymmetric private key used for decrypting MLE responses.
        /// </summary>
        public AsymmetricAlgorithm ResponseMlePrivateKey { get; internal set; }

        /// <summary>
        /// Gets or sets the NLog logger instance for logging MLE configuration and validation messages.
        /// </summary>
        public static Logger Logger { get; internal set; }

        /// <summary>
        /// Gets or sets a value indicating whether MLE is enabled globally for all requests for optional APIs.
        /// </summary>
        public bool EnableRequestMLEForOptionalApisGlobally { get; internal set; }

        /// <summary>
        /// Gets or sets a value indicating whether MLE is disabled globally for all requests for mandatory APIs.
        /// </summary>
        public bool DisableRequestMLEForMandatoryApisGlobally { get; internal set; }

        /// <summary>
        /// The internal backing field for the MapToControlMLEonAPI property.
        /// </summary>
        private Dictionary<string, string> _mapToControlMLEonAPI { get; set; }

        /// <summary>
        /// Gets or sets a mapping of control settings for MLE on specific APIs.
        /// The key is the API operation name and the value indicates MLE control settings.
        /// Supports formats: "true"/"false" for request MLE only, or "requestMLE::responseMLE" for both.
        /// </summary>
        public Dictionary<string, string> MapToControlMLEonAPI
        {
            get => _mapToControlMLEonAPI;
            internal set
            {
                // Validate the map values of MLE Config if not null
                if (value != null)
                {
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

        /// <summary>
        /// Gets or sets an internal mapping of boolean values indicating whether to use MLE for specific API requests.
        /// The key is the API operation name and the value indicates whether MLE is enabled for that request operation.
        /// </summary>
        public Dictionary<string, bool> InternalMapToControlRequestMLEonAPI { get; internal set; }

        /// <summary>
        /// Gets or sets an internal mapping of boolean values indicating whether to use MLE for specific API responses.
        /// The key is the API operation name and the value indicates whether MLE is enabled for that response operation.
        /// </summary>
        public Dictionary<string, bool> InternalMapToControlResponseMLEonAPI { get; internal set; }
        #endregion
    }
}
