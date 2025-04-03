using AuthenticationSdk.core;
using Newtonsoft.Json;
using NLog;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticationSdk.util
{
    public static class MLEUtility
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        private static readonly LogUtility logUtility = new LogUtility();
        public static bool CheckIsMLEForAPI(MerchantConfig merchantConfig, bool isMLESupportedByCybsForApi, string operationIds)
        {
            bool isMLEForAPI = false;

            // Check here useMLEGlobally True or False
            // if API is part of MLE then check for useMLEGlobally global parameter
            if (isMLESupportedByCybsForApi && merchantConfig.UseMLEGlobally)
            {
                isMLEForAPI = true;
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
            X509Certificate2Collection certs = Cache.FetchCachedCertificate(merchantConfig.P12Keyfilepath, merchantConfig.KeyPass);
            X509Certificate2 mleCertificate = Cache.GetCertBasedOnKeyAllias(certs, merchantConfig.MleKeyAlias);
            ValidateCertificateExpiry(mleCertificate, merchantConfig.MleKeyAlias);
            return mleCertificate;
        }

        private static void ValidateCertificateExpiry(X509Certificate2 certificate, string keyAlias)
        {
            if (certificate.NotAfter == DateTime.MinValue)
            {
                // Certificate does not have an expiry date
                logger.Warn("Certificate for MLE does not have an expiry date.");
            }
            else if (certificate.NotAfter < DateTime.Now)
            {
                // Certificate is already expired
                logger.Warn($"Certificate with MLE alias {keyAlias} is expired as of {certificate.NotAfter}. Please update the p12 file.");
                //throw new Exception($"Certificate required for MLE has expired on: {certificate.NotAfter}");
            }
            else
            {
                TimeSpan timeToExpire = certificate.NotAfter - DateTime.Now;
                if (timeToExpire.TotalDays < Constants.CertificateExpiryDateWarningDays)
                {
                    logger.Warn($"Certificate for MLE with alias {keyAlias} is going to expire on {certificate.NotAfter}. Please update the p12 file before that.");
                }
            }
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
                logger.Warn($"Serial number not found in MLE certificate for alias {merchantConfig.MleKeyAlias} in {merchantConfig.P12Keyfilepath}.p12");
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