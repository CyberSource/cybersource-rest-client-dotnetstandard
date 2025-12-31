using AuthenticationSdk.core;
using Newtonsoft.Json;
using NLog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;

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

            string serialNumber = GetSerialNumberFromCertificate(mleCertificate, merchantConfig);
            var payloadBytes = System.Text.Encoding.UTF8.GetBytes(payload);
            var rsa = mleCertificate.GetRSAPublicKey();
            var jweToken = Jose.JWT.EncodeBytes(
                payloadBytes,
                rsa,
                Jose.JweAlgorithm.RSA_OAEP_256,
                Jose.JweEncryption.A256GCM,
                extraHeaders: new Dictionary<string, object>
                {
                    { "kid", serialNumber },
                    { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
                });

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
                logger.Error("Failed to extract Response MLE token: " + e.Message);
                return null;
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
                throw new Exception("Response body is not MLE encrypted.");
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
                    throw new Exception("MLE Response private key is not an RSA key. Only RSA keys are supported for MLE decryption.");
                }
                string decryptedResponse = JWEUtilty.DecryptUsingRSAParameters(rsaKey.ExportParameters(true), jweResponseToken);
                logUtility.LogDebugMessage(logger, Constants.LOG_NETWORK_RESPONSE_AFTER_MLE_DECRYPTION + decryptedResponse);
                return decryptedResponse;
            }
            catch (Jose.JoseException e)
            {
                string errorMessage = $"MLE Response decryption failed (JoseException): {e.Message}. " +
                                      $"Possible reason: The provided RSA private key does not match the public key used to encrypt the message.";
                logger.Error(errorMessage, e);
                throw new Exception(errorMessage, e);
            }
            catch (CryptographicException e)
            {
                string errorMessage = $"MLE Response decryption failed (CryptographicException): {e.Message}. " +
                                      "This may happen if the private key is incorrect or corrupted.";
                logger.Error(errorMessage, e);
                throw new Exception(errorMessage, e);
            }
            catch (Exception e)
            {
                string errorMessage = $"MLE Response decryption failed: {e.Message}";
                logger.Error(errorMessage, e);
                throw new Exception(errorMessage, e);
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
                logger.Debug("No valid private key file path provided, skipping auto-extraction");
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
    }
}