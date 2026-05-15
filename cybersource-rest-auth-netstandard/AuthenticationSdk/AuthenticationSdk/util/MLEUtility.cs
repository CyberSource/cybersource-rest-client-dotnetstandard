using AuthenticationSdk.core;
using Newtonsoft.Json;
using NLog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace AuthenticationSdk.util
{
    public static class MLEUtility
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        private static readonly LogUtility logUtility = new LogUtility();

        public static bool CheckIsMLEForAPI(MerchantConfig merchantConfig, string inboundMLEStatus, string operationIds)
        {
            bool isMLEForAPI = false;

            // Handle inboundMLEStatus logic
            if (string.Equals(inboundMLEStatus, "optional", StringComparison.OrdinalIgnoreCase) && merchantConfig.EnableRequestMLEForOptionalApisGlobally)
            {
                isMLEForAPI = true;
            }

            if (string.Equals(inboundMLEStatus, "mandatory", StringComparison.OrdinalIgnoreCase))
            {
                isMLEForAPI = !merchantConfig.DisableRequestMLEForMandatoryApisGlobally;
            }

            // OperationIds are array as there are multiple public functions for apiCallFunction such as apiCall, apiCallAsync ..
            string[] operationArray = operationIds.Split(',');
            for (int i = 0; i < operationArray.Length; i++)
            {
                operationArray[i] = operationArray[i].Trim();
            }

            // Control the MLE only from map
            if (merchantConfig.InternalMapToControlRequestMLEonAPI != null && merchantConfig.InternalMapToControlRequestMLEonAPI.Count > 0)
            {
                foreach (string operationId in operationArray)
                {
                    if (merchantConfig.InternalMapToControlRequestMLEonAPI.ContainsKey(operationId))
                    {
                        isMLEForAPI = merchantConfig.InternalMapToControlRequestMLEonAPI[operationId];
                        break;
                    }
                }
            }

            return isMLEForAPI;
        }

        public static object EncryptRequestPayload(MerchantConfig merchantConfig, object requestBody)
        {
            if (requestBody == null)
            {
                return null;
            }
            string payload = requestBody.ToString();
            logUtility.LogDebugMessage(logger, Constants.LOG_REQUEST_BEFORE_MLE + payload);

            X509Certificate2 mleCertificate = GetRequestMLECertificate(merchantConfig);

            // Handling special case : MLE Certificate is not currently available for HTTP Signature
            if (mleCertificate == null && Constants.AuthMechanismHttp.Equals(merchantConfig.AuthenticationType, StringComparison.OrdinalIgnoreCase))
            {
                logger.Debug("The certificate to use for MLE for requests is not provided in the merchant configuration. Please ensure that the certificate path is provided.");
                logger.Debug("Currently, MLE for requests using HTTP Signature as authentication is not supported by Cybersource. By default, the SDK will fall back to non-encrypted requests.");
                return requestBody;
            }

            // If cert is still null for any other auth type, throw a descriptive error
            if (mleCertificate == null)
            {
                throw new MLEException("MLE_CERT_NOT_FOUND", "No certificate found for MLE Request. " +
                    "Please provide the Request MLE certificate file path via 'mleForRequestPublicCertPath' in merchant configuration. " +
                    "This is required when using jwtKeyType=SHARED_SECRET or when the P12 file does not contain the MLE certificate.");
            }

            string serialNumber = GetSerialNumberFromCertificate(mleCertificate, merchantConfig);
            var payloadBytes = Encoding.UTF8.GetBytes(payload);
            var rsa = mleCertificate.GetRSAPublicKey();
            var jweToken = JWEUtilty.EncryptJweCompact(payloadBytes, rsa, serialNumber);

            object mleRequest = CreateJsonObject(jweToken);
            logUtility.LogDebugMessage(logger, Constants.LOG_REQUEST_AFTER_MLE + mleRequest.ToString());

            return mleRequest;
        }

        private static X509Certificate2 GetRequestMLECertificate(MerchantConfig merchantConfig)
        {
            X509Certificate2 mleCertificate = Cache.GetRequestMLECertFromCache(merchantConfig);
            return mleCertificate;
        }

        private static string GetSerialNumberFromCertificate(X509Certificate2 certificate, MerchantConfig merchantConfig)
        {
            return CertificateUtility.ExtractSerialNumber(certificate);
        }

        private static object CreateJsonObject(string jweToken)
        {
            var jsonObject = new { encryptedRequest = jweToken };
            return JsonConvert.SerializeObject(jsonObject);
        }
        public static bool CheckIsResponseMLEForAPI(MerchantConfig merchantConfig, string operationIds)
        {
            // isMLE for response for an api is false by default
            bool isResponseMLEForAPI = false;

            if (merchantConfig.EnableResponseMleGlobally)
            {
                isResponseMLEForAPI = true;
            }

            // operationIds are array as there are multiple public functions for apiCallFunction such as apiCall, apiCallAsync ..
            string[] operationArray = operationIds.Split(',');
            for (int i = 0; i < operationArray.Length; i++)
            {
                operationArray[i] = operationArray[i].Trim();
            }

            // Control the Response MLE only from map
            // Special Note: If API expects MLE Response mandatory and map is saying to receive non MLE response then API might throw an error from CyberSource
            if (merchantConfig.InternalMapToControlResponseMLEonAPI != null && merchantConfig.InternalMapToControlResponseMLEonAPI.Count > 0)
            {
                foreach (string operationId in operationArray)
                {
                    if (merchantConfig.InternalMapToControlResponseMLEonAPI.ContainsKey(operationId))
                    {
                        isResponseMLEForAPI = merchantConfig.InternalMapToControlResponseMLEonAPI[operationId];
                        break;
                    }
                }
            }
            return isResponseMLEForAPI;
        }

        public static bool CheckIsMleEncryptedResponse(string responseBody)
        {
            if (string.IsNullOrWhiteSpace(responseBody))
            {
                return false;
            }
            try
            {
                var jsonObject = JsonConvert.DeserializeObject<JObject>(responseBody);
                if (jsonObject == null || jsonObject.Count != 1)
                {
                    return false;
                }
                if (jsonObject.ContainsKey("encryptedResponse"))
                {
                    var value = jsonObject["encryptedResponse"];
                    return value != null && value.Type == JTokenType.String;
                }
                return false;
            }
            catch
            {
                // If JSON parsing fails, it's not a valid JSON thus not a MLE response
                return false;
            }
        }
        private static string GetResponseMleToken(string mleResponseBody)
        {
            try
            {
                var jsonObject = JsonConvert.DeserializeObject<JObject>(mleResponseBody);
                return jsonObject?["encryptedResponse"]?.ToString();
            }
            catch (Exception e)
            {
                string errorMessage = $"Failed to extract MLE response token: {e.Message}";
                logger.Error(errorMessage, e);
                throw new MLEException("DECRYPTION", errorMessage, e);
            }
        }
        private static AsymmetricAlgorithm GetMleResponsePrivateKey(MerchantConfig merchantConfig)
        {
            // First priority - if privateKey is given in merchant config return that
            if (merchantConfig.ResponseMlePrivateKey != null)
            {
                return merchantConfig.ResponseMlePrivateKey;
            }
            // Second priority - get the privateKey from merchantConfig.ResponseMlePrivateKeyFilePath
            var responseMlePrivateKey = Cache.GetMleResponsePrivateKeyFromFilePath(merchantConfig);
            return responseMlePrivateKey;
        }
        public static string DecryptMleResponsePayload(MerchantConfig merchantConfig, string mleResponseBody)
        {
            if (!CheckIsMleEncryptedResponse(mleResponseBody))
            {
                throw new MLEException("VALIDATION", "Response body is not MLE encrypted.");
            }

            var mlePrivateKey = GetMleResponsePrivateKey(merchantConfig);
            string jweResponseToken = GetResponseMleToken(mleResponseBody);

            if (string.IsNullOrEmpty(jweResponseToken))
            {
                // When MLE token is empty or null then fall back to non MLE encrypted response
                return mleResponseBody;
            }

            try
            {
                logUtility.LogDebugMessage(logger, Constants.LOG_NETWORK_RESPONSE_BEFORE_MLE_DECRYPTION + mleResponseBody);

                // Convert AsymmetricAlgorithm to RSA if needed
                RSA rsaKey = mlePrivateKey as RSA;
                if (rsaKey == null)
                {
                    throw new MLEException("KEY_TYPE", "MLE Response private key is not an RSA key. Only RSA keys are supported for MLE decryption.");
                }
                string decryptedResponse = JWEUtilty.DecryptUsingRSAParameters(rsaKey.ExportParameters(true), jweResponseToken);
                logUtility.LogDebugMessage(logger, Constants.LOG_NETWORK_RESPONSE_AFTER_MLE_DECRYPTION + decryptedResponse);
                return decryptedResponse;
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException e)
            {
                string errorMessage = $"MLE Response decryption failed (InvalidCipherTextException): {e.Message}. " +
                                      $"Possible reason: The provided RSA private key does not match the public key used to encrypt the message.";
                logger.Error(errorMessage, e);
                throw new MLEException("JOSE_DECRYPTION", errorMessage, e);
            }
            catch (CryptographicException e)
            {
                string errorMessage = $"MLE Response decryption failed (CryptographicException): {e.Message}. " +
                                      "This may happen if the private key is incorrect or corrupted.";
                logger.Error(errorMessage, e);
                throw new MLEException("CRYPTO_DECRYPTION", errorMessage, e);
            }
            catch (Exception e)
            {
                string errorMessage = $"MLE Response decryption failed: {e.Message}";
                logger.Error(errorMessage, e);
                throw new MLEException("DECRYPTION", errorMessage, e);
            }
        }

        /// <summary>
        /// Validates and auto-extracts the Response MLE KID for JWT token generation.
        /// For CyberSource-generated P12/PFX files, attempts to extract KID automatically.
        /// For non-CyberSource files or other formats, requires manual configuration.
        /// </summary>
        /// <param name="merchantConfig">The merchant configuration</param>
        /// <returns>The validated or extracted Response MLE KID</returns>
        /// <exception cref="Exception">If KID cannot be determined</exception>
        public static string ValidateAndAutoExtractResponseMleKid(MerchantConfig merchantConfig)
        {
            // If ResponseMlePrivateKey object is provided directly, use configured responseMleKID
            if (merchantConfig.ResponseMlePrivateKey != null)
            {
                logger.Debug("responseMlePrivateKey is provided directly, using configured responseMleKID");
                return merchantConfig.ResponseMleKID;
            }

            logger.Debug("Validating responseMleKID for JWT token generation");
            string cybsKid = null;
            bool isP12File = false;

            // Check file path validity and determine if it's a P12/PFX file
            try
            {
                CertificateUtility.ValidatePathAndFile(merchantConfig.ResponseMlePrivateKeyFilePath, "responseMlePrivateKeyFilePath");
                string extension = CertificateUtility.GetFileExtension(merchantConfig.ResponseMlePrivateKeyFilePath);
                
                if (extension.Equals("p12", StringComparison.OrdinalIgnoreCase) || 
                    extension.Equals("pfx", StringComparison.OrdinalIgnoreCase))
                {
                    isP12File = true;
                }
            }
            catch (IOException e)
            {
                logger.Debug("No valid private key file path provided, skipping auto-extraction", e);
            }

            // Attempt to extract KID from CyberSource P12/PFX file
            if (isP12File)
            {
                logger.Debug("P12/PFX file detected, checking if it is a CyberSource certificate");
                CachedMLEKId cachedData = Cache.GetMLEKIdDataFromCache(merchantConfig);
                
                if (cachedData != null)
                {
                    if (cachedData.Kid != null)
                    {
                        // KID present means it's a CyberSource P12, use it
                        cybsKid = cachedData.Kid;
                    }
                    else
                    {
                        // KID is null means either non-CyberSource P12 or extraction failed
                        logger.Debug("Private key file is not a CyberSource generated P12/PFX file, skipping auto-extraction");
                    }
                }
            }
            else
            {
                logger.Debug("Private key file is not a P12/PFX file, skipping auto-extraction");
            }

            if (cybsKid != null)
            {
                logger.Debug("Successfully auto-extracted responseMleKID from CyberSource P12 certificate");
            }

            string configuredKID = merchantConfig.ResponseMleKID;

            // Determine which KID to use based on what's available
            if (cybsKid == null && configuredKID == null)
            {
                throw new ConfigurationException("responseMleKID is required when response MLE is enabled. " +
                    "Could not auto-extract from certificate and no manual configuration provided. " +
                    "Please provide responseMleKID explicitly in your configuration.");
            }
            else if (cybsKid == null)
            {
                logger.Debug("Using manually configured responseMleKID");
                return configuredKID;
            }
            else if (configuredKID == null)
            {
                logger.Debug("Using auto-extracted responseMleKID from CyberSource certificate");
                return cybsKid;
            }
            else if (!cybsKid.Equals(configuredKID))
            {
                logger.Warn("Auto-extracted responseMleKID does not match manually configured responseMleKID. Using configured value as preference");
            }

            return configuredKID;
        }

        #region NEW METHODS
        /// <summary>
        /// Decrypts an MLE-encrypted response payload using the merchant's response private key.
        /// Validates that the response is properly MLE-encrypted, extracts the JWE token, and decrypts it using RSA.
        /// </summary>
        /// <param name="merchantCredentialSettings">Object of IMerchantCredentialSettings containing merchant credentials.</param>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing merchant MLE configuration including the private key.</param>
        /// <param name="mleResponseBody">The MLE-encrypted response body containing the encryptedResponse token.</param>
        /// <returns>The decrypted response payload as a string.</returns>
        /// <exception cref="Exception">Thrown when response is not MLE-encrypted, token cannot be extracted, or decryption fails due to key mismatch or corruption.</exception>
        public static string DecryptMleResponsePayload(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, string mleResponseBody)
        {
            if (!CheckIsMleEncryptedResponse(mleResponseBody))
            {
                throw new Exception("Response body is not MLE encrypted.");
            }

            var mlePrivateKey = GetMleResponsePrivateKey(merchantCredentialSettings, merchantMLESettings);
            string jweResponseToken = GetResponseMleToken(mleResponseBody);

            if (string.IsNullOrEmpty(jweResponseToken))
            {
                // When MLE token is empty or null then fall back to non MLE encrypted response
                return mleResponseBody;
            }

            try
            {
                logUtility.LogDebugMessage(logger, Constants.LOG_NETWORK_RESPONSE_BEFORE_MLE_DECRYPTION + mleResponseBody);

                // Convert AsymmetricAlgorithm to RSA if needed
                RSA rsaKey = mlePrivateKey as RSA;
                if (rsaKey == null)
                {
                    throw new Exception("MLE Response private key is not an RSA key. Only RSA keys are supported for MLE decryption.");
                }
                string decryptedResponse = JWEUtilty.DecryptUsingRSAParameters(rsaKey.ExportParameters(true), jweResponseToken);
                logUtility.LogDebugMessage(logger, Constants.LOG_NETWORK_RESPONSE_AFTER_MLE_DECRYPTION + decryptedResponse);
                return decryptedResponse;
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException e)
            {
                string errorMessage = $"MLE Response decryption failed (InvalidCipherTextException): {e.Message}. " +
                                      $"Possible reason: The provided RSA private key does not match the public key used to encrypt the message.";
                logger.Error(errorMessage, e);
                throw new MLEException("JOSE_DECRYPTION", errorMessage, e);
            }
            catch (CryptographicException e)
            {
                string errorMessage = $"MLE Response decryption failed (CryptographicException): {e.Message}. " +
                                      "This may happen if the private key is incorrect or corrupted.";
                logger.Error(errorMessage, e);
                throw new MLEException("CRYPTO_DECRYPTION", errorMessage, e);
            }
            catch (Exception e)
            {
                string errorMessage = $"MLE Response decryption failed: {e.Message}";
                logger.Error(errorMessage, e);
                throw new MLEException("DECRYPTION", errorMessage, e);
            }
        }

        /// <summary>
        /// Retrieves the MLE response private key for decryption.
        /// Prioritizes directly provided private key objects over file-based keys.
        /// </summary>
        /// <param name="merchantCredentialSettings">Object of IMerchantCredentialSettings containing merchant credentials.</param>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing merchant MLE configuration including the private key settings.</param>
        /// <returns>The asymmetric private key used for decrypting MLE responses, or null if not configured.</returns>
        private static AsymmetricAlgorithm GetMleResponsePrivateKey(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings)
        {
            // First priority - if privateKey is given in merchant config return that
            if (merchantMLESettings.ResponseMlePrivateKey != null)
            {
                return merchantMLESettings.ResponseMlePrivateKey;
            }
            // Second priority - get the privateKey from merchantConfig.ResponseMlePrivateKeyFilePath
            var responseMlePrivateKey = Cache.GetMleResponsePrivateKeyFromFilePath(merchantCredentialSettings, merchantMLESettings);
            return responseMlePrivateKey;
        }

        /// <summary>
        /// Validates and auto-extracts the Response MLE KID for JWT token generation.
        /// For CyberSource-generated P12/PFX files, attempts to extract KID automatically.
        /// For non-CyberSource files or other formats, uses manually configured KID.
        /// </summary>
        /// <param name="merchantCredentialSettings">Object of IMerchantCredentialSettings containing merchant credentials (MerchantId, UseMetaKey, PortfolioId).</param>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing merchant MLE configuration including ResponseMleKID and private key settings.</param>
        /// <returns>The validated or auto-extracted Response MLE KID.</returns>
        /// <exception cref="Exception">Thrown when KID cannot be determined either through auto-extraction or manual configuration.</exception>
        public static string ValidateAndAutoExtractResponseMleKid(string keyIssuer, IMerchantMLESettings merchantMLESettings)
        {
            // If ResponseMlePrivateKey object is provided directly, use configured responseMleKID
            if (merchantMLESettings.ResponseMlePrivateKey != null)
            {
                logger.Debug("responseMlePrivateKey is provided directly, using configured responseMleKID");
                return merchantMLESettings.ResponseMleKID;
            }

            logger.Debug("Validating responseMleKID for JWT token generation");
            string cybsKid = null;
            bool isP12File = false;

            // Check file path validity and determine if it's a P12/PFX file
            try
            {
                CertificateUtility.ValidatePathAndFile(merchantMLESettings.ResponseMlePrivateKeyFilePath, "responseMlePrivateKeyFilePath");
                string extension = CertificateUtility.GetFileExtension(merchantMLESettings.ResponseMlePrivateKeyFilePath);

                if (extension.Equals("p12", StringComparison.OrdinalIgnoreCase) ||
                    extension.Equals("pfx", StringComparison.OrdinalIgnoreCase))
                {
                    isP12File = true;
                }
            }
            catch (IOException e)
            {
                logger.Debug("No valid private key file path provided, skipping auto-extraction", e);
            }

            // Attempt to extract KID from CyberSource P12/PFX file
            if (isP12File)
            {
                logger.Debug("P12/PFX file detected, checking if it is a CyberSource certificate");
                CachedMLEKId cachedData = Cache.GetMLEKIdDataFromCache(keyIssuer, merchantMLESettings);

                if (cachedData != null)
                {
                    if (cachedData.Kid != null)
                    {
                        // KID present means it's a CyberSource P12, use it
                        cybsKid = cachedData.Kid;
                    }
                    else
                    {
                        // KID is null means either non-CyberSource P12 or extraction failed
                        logger.Debug("Private key file is not a CyberSource generated P12/PFX file, skipping auto-extraction");
                    }
                }
            }
            else
            {
                logger.Debug("Private key file is not a P12/PFX file, skipping auto-extraction");
            }

            if (cybsKid != null)
            {
                logger.Debug("Successfully auto-extracted responseMleKID from CyberSource P12 certificate");
            }

            string configuredKID = merchantMLESettings.ResponseMleKID;

            // Determine which KID to use based on what's available
            if (cybsKid == null && configuredKID == null)
            {
                throw new Exception("responseMleKID is required when response MLE is enabled. " +
                    "Could not auto-extract from certificate and no manual configuration provided. " +
                    "Please provide responseMleKID explicitly in your configuration.");
            }
            else if (cybsKid == null)
            {
                logger.Debug("Using manually configured responseMleKID");
                return configuredKID;
            }
            else if (configuredKID == null)
            {
                logger.Debug("Using auto-extracted responseMleKID from CyberSource certificate");
                return cybsKid;
            }
            else if (!cybsKid.Equals(configuredKID))
            {
                logger.Warn("Auto-extracted responseMleKID does not match manually configured responseMleKID. Using configured value as preference");
            }

            return configuredKID;
        }

        /// <summary>
        /// Checks whether MLE should be enabled for a specific API based on merchant configuration.
        /// Evaluates the inbound MLE status (optional/mandatory) and API-specific control mappings.
        /// </summary>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing MLE global settings and API-level control mappings.</param>
        /// <param name="inboundMLEStatus">The MLE requirement status from the API specification: "optional" or "mandatory".</param>
        /// <param name="operationIds">Comma-separated list of operation IDs (API function names) to check for MLE configuration.</param>
        /// <returns>True if MLE should be enabled for the specified API operation; otherwise, false.</returns>
        public static bool CheckIsMLEForAPI(IMerchantMLESettings merchantMLESettings, string inboundMLEStatus, string operationIds)
        {
            bool isMLEForAPI = false;

            // Handle inboundMLEStatus logic
            if (string.Equals(inboundMLEStatus, "optional", StringComparison.OrdinalIgnoreCase) && merchantMLESettings.EnableRequestMLEForOptionalApisGlobally)
            {
                isMLEForAPI = true;
            }

            if (string.Equals(inboundMLEStatus, "mandatory", StringComparison.OrdinalIgnoreCase))
            {
                isMLEForAPI = !merchantMLESettings.DisableRequestMLEForMandatoryApisGlobally;
            }

            // OperationIds are array as there are multiple public functions for apiCallFunction such as apiCall, apiCallAsync ..
            string[] operationArray = operationIds.Split(',');
            for (int i = 0; i < operationArray.Length; i++)
            {
                operationArray[i] = operationArray[i].Trim();
            }

            // Control the MLE only from map
            if (merchantMLESettings.InternalMapToControlRequestMLEonAPI != null && merchantMLESettings.InternalMapToControlRequestMLEonAPI.Count > 0)
            {
                foreach (string operationId in operationArray)
                {
                    if (merchantMLESettings.InternalMapToControlRequestMLEonAPI.ContainsKey(operationId))
                    {
                        isMLEForAPI = merchantMLESettings.InternalMapToControlRequestMLEonAPI[operationId];
                        break;
                    }
                }
            }

            return isMLEForAPI;
        }

        /// <summary>
        /// Encrypts the request payload using MLE with the merchant's public certificate.
        /// Creates a JWE token with the request body and wraps it in a JSON object with the encryptedRequest key.
        /// For HTTP Signature authentication where no certificate is available, returns the unencrypted payload.
        /// </summary>
        /// <param name="merchantCredentialSettings">Object of IMerchantCredentialSettings containing merchant credentials including authentication type.</param>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing MLE configuration including the public certificate settings.</param>
        /// <param name="requestBody">The request payload object to be encrypted.</param>
        /// <returns>A JSON object containing the encrypted request if encryption is successful; otherwise, the original unencrypted request body.</returns>
        public static object EncryptRequestPayload(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, object requestBody)
        {
            if (requestBody == null)
            {
                return null;
            }
            string payload = requestBody.ToString();
            logUtility.LogDebugMessage(logger, Constants.LOG_REQUEST_BEFORE_MLE + payload);

            X509Certificate2 mleCertificate = null;
            try
            {
                 mleCertificate = GetRequestMLECertificate(merchantCredentialSettings, merchantMLESettings);

            }
            catch (Exception)
            {

                throw;
            }

            // Handling special case : MLE Certificate is not currently available for HTTP Signature
            if (mleCertificate == null && Constants.AuthMechanismHttp.Equals(merchantCredentialSettings.AuthenticationType, StringComparison.OrdinalIgnoreCase))
            {
                logger.Debug("The certificate to use for MLE for requests is not provided in the merchant configuration. Please ensure that the certificate path is provided.");
                logger.Debug("Currently, MLE for requests using HTTP Signature as authentication is not supported by Cybersource. By default, the SDK will fall back to non-encrypted requests.");
                return requestBody;
            }

            // If cert is still null for any other auth type, throw error
            if (mleCertificate == null)
            {
                throw new MLEException("MLE_CERT_NOT_FOUND", "No certificate found for MLE Request. " +
                    "Please provide the Request MLE certificate file path via 'mleForRequestPublicCertPath' in merchant configuration, " +
                    "or ensure the P12 file path is correctly configured and contains the MLE certificate.");
            }

            string serialNumber = GetSerialNumberFromCertificate(mleCertificate);
            var payloadBytes = System.Text.Encoding.UTF8.GetBytes(payload);
            var rsa = mleCertificate.GetRSAPublicKey();
            var jweToken = JWEUtilty.EncryptJweCompact(payloadBytes, rsa, serialNumber);


            object mleRequest = CreateJsonObject(jweToken);
            logUtility.LogDebugMessage(logger, Constants.LOG_REQUEST_AFTER_MLE + mleRequest.ToString());

            return mleRequest;
        }

        /// <summary>
        /// Retrieves the cached MLE request certificate from the merchant configuration and MLE settings.
        /// Used for encrypting request payloads.
        /// </summary>
        /// <param name="merchantCredentialSettings">Object of IMerchantCredentialSettings containing merchant credentials.</param>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing MLE configuration including public certificate paths.</param>
        /// <returns>The X509Certificate2 used for MLE request encryption, or null if no certificate is configured.</returns>
        private static X509Certificate2 GetRequestMLECertificate(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings)
        {
            X509Certificate2 mleCertificate = null;
            try
            {
                mleCertificate = Cache.GetRequestMLECertFromCache(merchantCredentialSettings, merchantMLESettings);
            }
            catch (Exception)
            {

                throw;
            }
            return mleCertificate;
        }

        /// <summary>
        /// Extracts the serial number from an X509 certificate.
        /// The serial number is used as the Key ID (kid) in the JWE token header for MLE request encryption.
        /// </summary>
        /// <param name="certificate">The X509Certificate2 from which to extract the serial number.</param>
        /// <returns>The certificate's serial number as a string.</returns>
        private static string GetSerialNumberFromCertificate(X509Certificate2 certificate)
        {
            return CertificateUtility.ExtractSerialNumber(certificate);
        }

        /// <summary>
        /// Checks whether MLE response decryption should be enabled for a specific API based on merchant configuration.
        /// Evaluates global MLE response settings and API-specific control mappings.
        /// </summary>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing MLE global settings and API-level response control mappings.</param>
        /// <param name="operationIds">Comma-separated list of operation IDs (API function names) to check for response MLE configuration.</param>
        /// <returns>True if response MLE should be enabled for the specified API operation; otherwise, false.</returns>
        public static bool CheckIsResponseMLEForAPI(IMerchantMLESettings merchantMLESettings, string operationIds)
        {
            // isMLE for response for an api is false by default
            bool isResponseMLEForAPI = false;

            if (merchantMLESettings.EnableResponseMleGlobally)
            {
                isResponseMLEForAPI = true;
            }

            // operationIds are array as there are multiple public functions for apiCallFunction such as apiCall, apiCallAsync ..
            string[] operationArray = operationIds.Split(',');
            for (int i = 0; i < operationArray.Length; i++)
            {
                operationArray[i] = operationArray[i].Trim();
            }

            // Control the Response MLE only from map
            // Special Note: If API expects MLE Response mandatory and map is saying to receive non MLE response then API might throw an error from CyberSource
            if (merchantMLESettings.InternalMapToControlResponseMLEonAPI != null && merchantMLESettings.InternalMapToControlResponseMLEonAPI.Count > 0)
            {
                foreach (string operationId in operationArray)
                {
                    if (merchantMLESettings.InternalMapToControlResponseMLEonAPI.ContainsKey(operationId))
                    {
                        isResponseMLEForAPI = merchantMLESettings.InternalMapToControlResponseMLEonAPI[operationId];
                        break;
                    }
                }
            }
            return isResponseMLEForAPI;
        }
        #endregion
    }
}
