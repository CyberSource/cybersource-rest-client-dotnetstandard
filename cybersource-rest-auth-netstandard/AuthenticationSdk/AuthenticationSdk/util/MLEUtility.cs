using AuthenticationSdk.core;
using Newtonsoft.Json;
using NLog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;

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
            if (merchantConfig.MapToControlMLEonAPI != null && merchantConfig.MapToControlMLEonAPI.Count > 0)
            {
                foreach (string operationId in operationArray)
                {
                    if (merchantConfig.MapToControlMLEonAPI.ContainsKey(operationId))
                    {
                        isMLEForAPI = merchantConfig.MapToControlMLEonAPI[operationId];
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

            X509Certificate2 mleCertificate = GetMLECertificate(merchantConfig);

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

        private static X509Certificate2 GetMLECertificate(MerchantConfig merchantConfig)
        {
            X509Certificate2 mleCertificate = Cache.GetRequestMLECertFromCache(merchantConfig);
            return mleCertificate;
        }

        private static string GetSerialNumberFromCertificate(X509Certificate2 certificate, MerchantConfig merchantConfig)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate), "MLE certificate is null");
            }

            string serialNumber = null;
            string[] subjectParts = certificate.Subject.Split(',');

            foreach (string part in subjectParts)
            {
                if (part.Trim().ToUpper().StartsWith("SERIALNUMBER="))
                {
                    serialNumber = part.Split('=')[1].Trim();
                    break;
                }
            }
            if (string.IsNullOrEmpty(serialNumber))
            {
                logger.Warn($"Serial number not found in MLE certificate for alias {merchantConfig.RequestMleKeyAlias} in {merchantConfig.P12Keyfilepath}.p12");
                return certificate.SerialNumber;
            }

            return serialNumber;
        }

        private static object CreateJsonObject(string jweToken)
        {
            var jsonObject = new { encryptedRequest = jweToken };
            return JsonConvert.SerializeObject(jsonObject);
        }
    }
}