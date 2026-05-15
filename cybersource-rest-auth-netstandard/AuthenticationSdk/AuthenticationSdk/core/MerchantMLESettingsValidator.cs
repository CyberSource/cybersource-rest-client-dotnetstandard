using AuthenticationSdk.util;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using MLEKeys = AuthenticationSdk.core.MerchantConfigurationKeys.MerchantMLESettingsKeys;

namespace AuthenticationSdk.core
{
    /// <summary>
    /// Defines methods for validating merchant Message Level Encryption (MLE) configuration settings.
    /// </summary>
    public interface IMerchantMLESettingsValidator
    {
        /// <summary>
        /// Validates all MLE configuration settings including request and response MLE settings, certificate paths, and private key configuration.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant MLE configuration key-value pairs.</param>
        /// <param name="mapToControlMLEonAPI">A dictionary mapping API operation names to MLE control settings in formats "requestMLE::responseMLE" or "requestMLE".</param>
        /// <param name="responseMlePrivateKey">Optional pre-loaded asymmetric private key for decrypting MLE responses.</param>
        /// <exception cref="Exception">Thrown when MLE configuration is invalid or required settings are missing.</exception>
        void ValidateMLESettings(IReadOnlyDictionary<string, string> configurationDictionary, IDictionary<string, string> mapToControlMLEonAPI, AsymmetricAlgorithm responseMlePrivateKey = null);
    }

    public sealed class MerchantMLESettingsValidator : IMerchantMLESettingsValidator
    {
        /// <summary>
        /// Validates all MLE (Message Level Encryption) configuration settings.
        /// Performs comprehensive validation including:
        /// - Request MLE settings (enableRequestMLEForOptionalApisGlobally, mleForRequestPublicCertPath)
        /// - Response MLE settings (enableResponseMleGlobally, responseMlePrivateKey, responseMlePrivateKeyFilePath, responseMleKID)
        /// - API-specific MLE mappings (mapToControlMLEonAPI)
        /// - Private key configuration (ensures either object or file path is provided, not both)
        /// - Certificate file paths and accessibility
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant MLE configuration key-value pairs from App.Config or custom source.</param>
        /// <param name="mapToControlMLEonAPI">A dictionary mapping API operation names to MLE control settings. Supports formats:
        /// "true"/"false" for request MLE only, or "requestMLE::responseMLE" for both request and response MLE control.</param>
        /// <param name="responseMlePrivateKey">Optional pre-loaded asymmetric private key for decrypting MLE responses. If provided, takes precedence over file path.</param>
        /// <exception cref="Exception">Thrown when:
        /// - Required MLE configuration is missing or invalid
        /// - Both responseMlePrivateKey object and responseMlePrivateKeyFilePath are provided
        /// - Private key file path does not exist or is not accessible
        /// - responseMleKID is missing when required (non-P12/PFX files or when private key object is provided)
        /// - useMLEGlobally and enableRequestMLEForOptionalApisGlobally values do not match when both are provided
        /// - mapToControlMLEonAPI contains invalid values or formats</exception>
        public void ValidateMLESettings(IReadOnlyDictionary<string, string> configurationDictionary, IDictionary<string, string> mapToControlMLEonAPI, AsymmetricAlgorithm responseMlePrivateKey = null)
        {
            ValidateMapToControlMLEonAPI(mapToControlMLEonAPI, out Dictionary<string, bool> internalMapToControlRequestMLEonAPI, out Dictionary<string, bool> internalMapToControlResponseMLEonAPI);

            // Handle EnableRequestMLEForOptionalApisGlobally with useMLEGlobally as deprecated alias
            bool enableRequestMLEForOptionalApisGlobally;
            if (configurationDictionary.ContainsKey(MLEKeys.EnableRequestMLEForOptionalApisGlobally))
            {
                enableRequestMLEForOptionalApisGlobally = bool.Parse(configurationDictionary[MLEKeys.EnableRequestMLEForOptionalApisGlobally]);
            }
            else if (configurationDictionary.ContainsKey(MLEKeys.UseMLEGlobally))
            {
                enableRequestMLEForOptionalApisGlobally = bool.Parse(configurationDictionary[MLEKeys.UseMLEGlobally]);
            }
            else
            {
                enableRequestMLEForOptionalApisGlobally = false;
            }

            if (configurationDictionary.ContainsKey(MLEKeys.MleForRequestPublicCertPath) && !string.IsNullOrEmpty(configurationDictionary[MLEKeys.MleForRequestPublicCertPath].Trim()))
            {
                var mleForRequestPublicCertPath = configurationDictionary[MLEKeys.MleForRequestPublicCertPath].Trim();

                if (!string.IsNullOrEmpty(mleForRequestPublicCertPath))
                {
                    try
                    {
                        CertificateUtility.ValidatePathAndFile(mleForRequestPublicCertPath, MLEKeys.MleForRequestPublicCertPath);
                    }
                    catch (IOException err)
                    {
                        //Logger.Error(err.Message);
                        throw new Exception(err.Message);
                    }
                }
            }

            // Validation: If both are set, values must match
            if (configurationDictionary.ContainsKey(MLEKeys.UseMLEGlobally) && configurationDictionary.ContainsKey(MLEKeys.EnableRequestMLEForOptionalApisGlobally))
            {
                bool useMLEGlobally = bool.Parse(configurationDictionary[MLEKeys.UseMLEGlobally]);
                if (useMLEGlobally != enableRequestMLEForOptionalApisGlobally)
                {
                    //Logger.Error("Both useMLEGlobally and enableRequestMLEForOptionalApisGlobally are set but their values do not match.");
                    throw new Exception("Both useMLEGlobally and enableRequestMLEForOptionalApisGlobally are set but their values do not match.");
                }
            }

            bool requestMleConfigured = enableRequestMLEForOptionalApisGlobally;

            if (internalMapToControlRequestMLEonAPI != null && internalMapToControlRequestMLEonAPI.Count > 0)
            {
                foreach (bool value in internalMapToControlRequestMLEonAPI.Values)
                {
                    if (value)
                    {
                        requestMleConfigured = true;
                        break;
                    }
                }
            }

            bool enableResponseMleGlobally = false;
            if (configurationDictionary.ContainsKey(MLEKeys.EnableResponseMleGlobally))
            {
                enableResponseMleGlobally = bool.Parse(configurationDictionary[MLEKeys.EnableResponseMleGlobally]);
            }

            bool responseMleConfigured = enableResponseMleGlobally;
            if (internalMapToControlResponseMLEonAPI != null && internalMapToControlResponseMLEonAPI.Count > 0)
            {
                foreach (bool value in internalMapToControlResponseMLEonAPI.Values)
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
                string responseMlePrivateKeyFilePath = null;
                if (configurationDictionary.ContainsKey(MLEKeys.ResponseMlePrivateKeyFilePath) && !string.IsNullOrWhiteSpace(configurationDictionary[MLEKeys.ResponseMlePrivateKeyFilePath]))
                {
                    responseMlePrivateKeyFilePath = configurationDictionary[MLEKeys.ResponseMlePrivateKeyFilePath].Trim();
                }

                // Check if either private key object or private key file path is provided
                if (responseMlePrivateKey == null && string.IsNullOrEmpty(responseMlePrivateKeyFilePath))
                {
                    //Logger.Error("Response MLE is enabled but no private key provided. Either set ResponseMlePrivateKey object or provide ResponseMlePrivateKeyFilePath.");
                    throw new Exception("Response MLE is enabled but no private key provided. Either set ResponseMlePrivateKey object or provide ResponseMlePrivateKeyFilePath.");
                }

                // Check if both private key object and private key file path are provided
                if (responseMlePrivateKey != null && !string.IsNullOrEmpty(responseMlePrivateKeyFilePath))
                {
                    //Logger.Error("ConfigException : Both responseMlePrivateKey object and responseMlePrivateKeyFilePath are provided. Please provide only one of them for response mle private key.");
                    throw new Exception("Both responseMlePrivateKey object and responseMlePrivateKeyFilePath are provided. Please provide only one of them for response mle private key.");
                }

                // If private key file path is provided, validate the file exists
                if (!string.IsNullOrEmpty(responseMlePrivateKeyFilePath))
                {
                    try
                    {
                        CertificateUtility.ValidatePathAndFile(responseMlePrivateKeyFilePath, "responseMlePrivateKeyFilePath");
                    }
                    catch (IOException err)
                    {
                        //Logger.Error("Invalid responseMlePrivateKeyFilePath - " + err.Message);
                        throw new Exception("Invalid responseMlePrivateKeyFilePath - " + err.Message);
                    }
                }

                // Validate responseMleKID is provided when response MLE is enabled
                // Skip validation for P12/PFX files as KID can be auto-extracted from CyberSource-generated certificates
                bool skipKidValidation = false;

                if (!string.IsNullOrEmpty(responseMlePrivateKeyFilePath))
                {
                    string extension = CertificateUtility.GetFileExtension(responseMlePrivateKeyFilePath);
                    if (extension.Equals("p12", StringComparison.OrdinalIgnoreCase) ||
                        extension.Equals("pfx", StringComparison.OrdinalIgnoreCase))
                    {
                        skipKidValidation = true;
                        //Logger.Debug("P12/PFX file detected. responseMleKID validation will be deferred to JWT token generation time for possible auto-extraction.");
                    }
                }

                string responseMleKID = null;
                if (configurationDictionary.ContainsKey(MLEKeys.ResponseMleKID))
                {
                    string rawValue = configurationDictionary[MLEKeys.ResponseMleKID];
                    if (!string.IsNullOrWhiteSpace(rawValue))
                    {
                        responseMleKID = rawValue.Trim();
                    }
                    else
                    {
                        // Key exists but value is empty/whitespace — always invalid
                        throw new Exception("Response MLE is enabled but responseMleKID value is empty or whitespace. " +
                            "Please provide a valid responseMleKID, or remove the key to attempt auto-extraction from P12/PFX files.");
                    }
                }

                // KID is null (responseMleKID == null) and no P12 file to extract it from (!skipKidValidation) — KID is mandatory
                if (!skipKidValidation && responseMleKID == null)
                {
                    throw new Exception("Response MLE is enabled but responseMleKID is not provided. ");
                }
            }
        }

        /// <summary>
        /// Validates the mapToControlMLEonAPI configuration and extracts the internal request and response MLE control mappings.
        /// This method performs two-phase validation:
        /// 1. Inner Validation: Validates the format and values of each map entry
        /// 2. Additional Validation: Extracts and populates the internal request and response MLE control dictionaries
        /// </summary>
        /// <param name="mapToControlMLEonAPI">A dictionary mapping API operation names to MLE control settings. Supports formats:
        /// "true"/"false" for request MLE only, or "requestMLE::responseMLE" for both request and response MLE control.</param>
        /// <param name="internalMapToControlRequestMLEonAPI">Output parameter populated with API names mapped to their request MLE boolean control settings.</param>
        /// <param name="internalMapToControlResponseMLEonAPI">Output parameter populated with API names mapped to their response MLE boolean control settings.</param>
        /// <exception cref="Exception">Thrown when:
        /// - Map value is null or empty
        /// - Map value format is invalid (e.g., "requestMLE::responseMLE::extra")
        /// - Boolean values in the map are not "true", "false", or empty strings
        /// </exception>
        private void ValidateMapToControlMLEonAPI(IDictionary<string, string> mapToControlMLEonAPI, out Dictionary<string, bool> internalMapToControlRequestMLEonAPI, out Dictionary<string, bool> internalMapToControlResponseMLEonAPI)
        {
            internalMapToControlRequestMLEonAPI = new Dictionary<string, bool>();
            internalMapToControlResponseMLEonAPI = new Dictionary<string, bool>();

            if (mapToControlMLEonAPI == null)
            {
                return;
            }

            if (mapToControlMLEonAPI != null)
            {
                #region Inner Validation
                foreach (var entry in mapToControlMLEonAPI)
                {
                    var key = entry.Key;
                    var value = entry.Value;

                    if (string.IsNullOrEmpty(value))
                    {
                        //Logger.Error($"ConfigException : Invalid MLE control map value for key '{key}'. Value cannot be null or empty.");
                        throw new Exception($"Invalid MLE control map value for key '{key}'. Value cannot be null or empty.");
                    }

                    // Check if value contains "::" separator
                    if (value.Contains("::"))
                    {
                        var parts = value.Split(new[] { "::" }, StringSplitOptions.None);

                        if (parts.Length != 2)
                        {
                            //Logger.Error($"ConfigException : Invalid MLE control map value format for key '{key}'. Expected format: true/false for 'requestMLE::responseMLE' but got: '{value}'");
                            throw new Exception($"Invalid MLE control map value format for key '{key}'. Expected format: true/false for 'requestMLE::responseMLE' but got: '{value}'");
                        }

                        var requestMLE = parts[0];
                        var responseMLE = parts[1];

                        // Validate first part (request MLE) - can be empty, "true", or "false"
                        if (!string.IsNullOrEmpty(requestMLE) && !Utility.IsValidBooleanString(requestMLE))
                        {
                            //Logger.Error($"ConfigException : Invalid request MLE value for key '{key}'. Expected 'true', 'false', or empty but got: '{requestMLE}'");
                            throw new Exception($"Invalid request MLE value for key '{key}'. Expected 'true', 'false', or empty but got: '{requestMLE}'");
                        }

                        // Validate second part (response MLE) - can be empty, "true", or "false"
                        if (!string.IsNullOrEmpty(responseMLE) && !Utility.IsValidBooleanString(responseMLE))
                        {
                            //Logger.Error($"ConfigException : Invalid response MLE value for key '{key}'. Expected 'true', 'false', or empty but got: '{responseMLE}'");
                            throw new Exception($"Invalid response MLE value for key '{key}'. Expected 'true', 'false', or empty but got: '{responseMLE}'");
                        }
                    }
                    else
                    {
                        // Value without "::" separator - should be "true" or "false"
                        if (!Utility.IsValidBooleanString(value))
                        {
                            //Logger.Error($"ConfigException : Invalid MLE control map value for key '{key}'. Expected 'true' or 'false' for requestMLE but got: '{value}'");
                            throw new Exception($"Invalid MLE control map value for key '{key}'. Expected 'true' or 'false' for requestMLE but got: '{value}'");
                        }
                    }
                }
                #endregion Inner Validation

                #region Additional Validation
                foreach (var entry in mapToControlMLEonAPI)
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
                #endregion Additional Validation
            }
        }
    }
}
