using AuthenticationSdk.core;
using NLog;
using NLog.Fluent;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Caching;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace AuthenticationSdk.util
{
    public static class Cache
    {
        /// <summary>
        /// mutex to ensure that the operation is thread safe
        /// </summary>
        private static readonly object mutex = new object();

        private static readonly object mutexForPrivateKeyFromPEM = new object();

        private static readonly string regexForFileNameFromDirectory = "(^([a-z]|[A-Z]):(?=\\\\(?![\\0-\\37<>:\"/\\\\|?*])|\\/(?![\\0-\\37<>:\"/\\\\|?*])|$)|^\\\\(?=[\\\\\\/][^\\0-\\37<>:\"/\\\\|?*]+)|^(?=(\\\\|\\/)$)|^\\.(?=(\\\\|\\/)$)|^\\.\\.(?=(\\\\|\\/)$)|^(?=(\\\\|\\/)[^\\0-\\37<>:\"/\\\\|?*]+)|^\\.(?=(\\\\|\\/)[^\\0-\\37<>:\"/\\\\|?*]+)|^\\.\\.(?=(\\\\|\\/)[^\\0-\\37<>:\"/\\\\|?*]+))((\\\\|\\/)([^\\0-\\37<>:\"/\\\\|?*]+|(\\\\|\\/)$))*()$";

        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        private class CertInfo
        {
            public X509Certificate2Collection Certificates { get; set; }
            public DateTime Timestamp { get; set; }
            public X509Certificate2 MLECertificate { get; set; }
        }

        private class PrivateKeyInfo
        {
            public AsymmetricAlgorithm PrivateKey { get; set; }
            public DateTime Timestamp { get; set; }
        }

        public static X509Certificate2Collection FetchCachedCertificate(string p12FilePath, string keyPassword)
        {
            try
            {
                ObjectCache cache = MemoryCache.Default;
                var matches = Regex.Match(p12FilePath, regexForFileNameFromDirectory);
                var certFile = matches.Groups[11].ToString();
                if (!cache.Contains(certFile) || ((CertInfo)cache[certFile]).Timestamp != File.GetLastWriteTime(p12FilePath))
                {
                    var policy = new CacheItemPolicy();
                    var filePaths = new List<string>();
                    var cachedFilePath = Path.GetFullPath(p12FilePath);
                    filePaths.Add(cachedFilePath);
                    policy.ChangeMonitors.Add(new HostFileChangeMonitor(filePaths));

                    X509Certificate2Collection certificateCollection = FetchCertificateCollectionFromP12File(p12FilePath, keyPassword);

                    CertInfo certInfo = new CertInfo
                    {
                        Certificates = certificateCollection,
                        Timestamp = File.GetLastWriteTime(p12FilePath)
                    };

                    lock (mutex)
                    {
                        cache.Set(certFile, certInfo, policy);
                    }
                }

                return ((CertInfo)cache[certFile]).Certificates;
            }
            catch (Exception e)
            {
                if (e.Message.Equals("The specified network password is not correct.\r\n"))
                {
                    throw new Exception($"{Constants.ErrorPrefix} KeyPassword provided:{keyPassword} is incorrect");
                }

                throw e;
            }
        }

        [Obsolete("This method has been marked as Deprecated and will be removed in coming releases.", false)]
        public static RSAParameters FetchCachedRSAParameters(MerchantConfig merchantConfig)
        {
            lock (mutexForPrivateKeyFromPEM)
            {
                var pemFilePath = merchantConfig.PemFileDirectory;
                ObjectCache cache = MemoryCache.Default;

                var matches = Regex.Match(merchantConfig.PemFileDirectory, regexForFileNameFromDirectory);
                var certFile = matches.Groups[11].ToString();

                if (!cache.Contains(certFile))
                {
                    var policy = new CacheItemPolicy();
                    var filePaths = new List<string>();
                    var privateKey = File.ReadAllText(merchantConfig.PemFileDirectory);
                    var cachedFilePath = Path.GetFullPath(pemFilePath);
                    filePaths.Add(cachedFilePath);
                    policy.ChangeMonitors.Add(new HostFileChangeMonitor(filePaths));

                    PemReader pemReader = new PemReader(new StringReader(privateKey));
                    AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                    RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);

                    cache.Set(certFile, rsaParams, policy);
                }
                return (RSAParameters)cache[certFile];
            }
        }

        public static X509Certificate2 GetCertBasedOnKeyAlias(X509Certificate2Collection certs, String keyAlias)
        {
            foreach (var cert in certs)
            {
                if (cert.GetNameInfo(X509NameType.SimpleName, false).Equals(keyAlias, StringComparison.OrdinalIgnoreCase))
                {
                    return cert;
                }
            }
            throw new Exception($"{Constants.ErrorPrefix} Certificate with alias {keyAlias} not found.");
        }

        public static X509Certificate2 GetRequestMLECertFromCache(MerchantConfig merchantConfig)
        {
            string merchantId = merchantConfig.MerchantId;
            string certificateIdentifier;
            string certificateFilePath;

            // Priority #1: Get cert from merchantConfig.mleForRequestPublicCertPath if certPath is provided
            if (!string.IsNullOrEmpty(merchantConfig.MleForRequestPublicCertPath))
            {
                certificateIdentifier = Constants.MLE_CACHE_IDENTIFIER_FOR_CONFIG_CERT;
                certificateFilePath = merchantConfig.MleForRequestPublicCertPath;
            }
            // Priority #2: If merchantConfig.mleForRequestPublicCertPath not provided by merchant then get mlecert from merchant p12 if provided and jwt auth type
            else if (Constants.AuthMechanismJwt.Equals(merchantConfig.AuthenticationType, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(merchantConfig.P12Keyfilepath))
            {
                certificateIdentifier = Constants.MLE_CACHE_IDENTIFIER_FOR_P12_CERT;
                certificateFilePath = merchantConfig.P12Keyfilepath;
            }
            // Priority #3: Get mlecert from default mle cert in SDK as per CAS or PROD env.
            else
            {
                logger.Debug("The certificate to use for MLE for requests is not provided in the merchant configuration. Please ensure that the certificate path is provided.");
                return null;
            }

            string cacheKey = $"{merchantId}_{certificateIdentifier}";
            X509Certificate2 mleCertificate = GetMLECertBasedOnCacheKey(merchantConfig, cacheKey, certificateFilePath);

            CertificateUtility.ValidateCertificateExpiry(mleCertificate, merchantConfig.KeyAlias, certificateIdentifier);
            return mleCertificate;
        }

        private static X509Certificate2 GetMLECertBasedOnCacheKey(MerchantConfig merchantConfig, string cacheKey, string certificateFilePath)
        {
            ObjectCache cache = MemoryCache.Default;

            if (!cache.Contains(cacheKey))
            {
                SetupCache(merchantConfig, cacheKey, certificateFilePath);
            }
            else
            {
                CertInfo certInfo = (CertInfo) cache.Get(cacheKey);
                if (certInfo == null || certInfo.Timestamp != File.GetLastWriteTime(certificateFilePath))
                {
                    SetupCache(merchantConfig, cacheKey, certificateFilePath);
                }
            }

            return ((CertInfo)cache.Get(cacheKey)).MLECertificate;
        }

        private static void SetupCache(MerchantConfig merchantConfig, string cacheKey, string certificateFilePath)
        {
            var policy = new CacheItemPolicy();
            var filePaths = new List<string>();
            var cachedFilePath = Path.GetFullPath(certificateFilePath);
            filePaths.Add(cachedFilePath);
            policy.ChangeMonitors.Add(new HostFileChangeMonitor(filePaths));

            ObjectCache cache = MemoryCache.Default;

            if (cacheKey.EndsWith(Constants.MLE_CACHE_KEY_IDENTIFIER_FOR_RESPONSE_PRIVATE_KEY))
            {
                try
                {
                    string fileExtension = Path.GetExtension(certificateFilePath)?.TrimStart('.').ToLowerInvariant();
                    AsymmetricAlgorithm mlePrivateKey = null;
                    SecureString password = merchantConfig.ResponseMlePrivateKeyFilePassword;

                    // Case 1 - PKCS#12 formats (.p12, .pfx)
                    if (fileExtension.Equals("p12") || fileExtension.Equals("pfx"))
                    {
                        mlePrivateKey = Utility.ReadPrivateKeyFromP12(certificateFilePath, password);
                    }
                    // Case 2 - PEM-based formats (.pem, .key, .p8)
                    else if (fileExtension.Equals("pem") || fileExtension.Equals("key") || fileExtension.Equals("p8"))
                    {
                        mlePrivateKey = (AsymmetricAlgorithm) Utility.ExtractPrivateKeyFromFile(certificateFilePath, password);
                    }
                    else
                    {
                        throw new Exception($"Unsupported Response MLE Private Key file format: {fileExtension}. Supported formats are: .p12, .pfx, .pem, .key, .p8");
                    }

                    PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo
                    {
                        PrivateKey = mlePrivateKey,
                        Timestamp = File.GetLastWriteTime(certificateFilePath)
                    };

                    lock (mutex)
                    {
                        cache.Set(cacheKey, privateKeyInfo, policy);
                    }
                }
                catch (Exception e)
                {
                    logger.Error($"Error loading MLE response private key from: {certificateFilePath}. Error: {e.Message}");
                    throw new Exception($"Error loading MLE response private key from: {certificateFilePath}. Error: {e.Message}", e);
                }
                return;
            }

            // ... existing code for other cacheKey cases ...
            X509Certificate2 mleCertificate = null;

            if (cacheKey.EndsWith(Constants.MLE_CACHE_IDENTIFIER_FOR_CONFIG_CERT))
            {
                X509Certificate2Collection certificates = CertificateUtility.LoadCertificatesFromPemFile(certificateFilePath);

                try
                {
                    mleCertificate = GetCertBasedOnKeyAlias(certificates, merchantConfig.RequestMleKeyAlias);
                }
                catch (Exception)
                {
                    if (mleCertificate == null)
                    {
                        // If no certificate found for the specified alias, fall back to first certificate
                        string fileName = Path.GetFileName(certificateFilePath);
                        logger.Warn($"No certificate found for the specified requestMleKeyAlias '{merchantConfig.RequestMleKeyAlias}'. Using the first certificate from file {fileName} as the MLE request certificate.");
                        mleCertificate = certificates[0];
                    }
                }
            }

            if (cacheKey.EndsWith(Constants.MLE_CACHE_IDENTIFIER_FOR_P12_CERT))
            {
                try
                {
                    mleCertificate = GetCertBasedOnKeyAlias(FetchCertificateCollectionFromP12File(merchantConfig.P12Keyfilepath, merchantConfig.KeyPass), merchantConfig.RequestMleKeyAlias);
                }
                catch (Exception)
                {
                    string fileName = Path.GetFileName(merchantConfig.P12Keyfilepath);
                    logger.Error($"No certificate found for the specified requestMleKeyAlias '{merchantConfig.RequestMleKeyAlias}' in file {fileName}.");
                    throw new ArgumentException($"No certificate found for the specified requestMleKeyAlias '{merchantConfig.RequestMleKeyAlias}' in file {fileName}.");
                }
            }

            CertInfo certInfo = new CertInfo
            {
                MLECertificate = mleCertificate,
                Timestamp = File.GetLastWriteTime(certificateFilePath)
            };


            lock(mutex)
            {
                cache.Set(cacheKey, certInfo, policy);
            }
        }

        private static X509Certificate2Collection FetchCertificateCollectionFromP12File(string p12FilePath, string keyPassword)
        {
            var certificates = new X509Certificate2Collection();
            certificates.Import(p12FilePath, keyPassword, X509KeyStorageFlags.PersistKeySet);

            //return all certs in p12
            return certificates;
        }
        public static AsymmetricAlgorithm GetMleResponsePrivateKeyFromFilePath(MerchantConfig merchantConfig)
        {
            string merchantId = merchantConfig.MerchantId;
            string identifier = Constants.MLE_CACHE_KEY_IDENTIFIER_FOR_RESPONSE_PRIVATE_KEY;
            string cacheKey = $"{merchantId}_{identifier}";
            string mleResponsePrivateKeyFilePath = merchantConfig.ResponseMlePrivateKeyFilePath;

            ObjectCache cache = MemoryCache.Default;

            if (!cache.Contains(cacheKey))
            {
                SetupCache(merchantConfig, cacheKey, mleResponsePrivateKeyFilePath);
            }
            else
            {
                var responseMlePrivateKeyInfo = (PrivateKeyInfo)cache.Get(cacheKey);
                if (responseMlePrivateKeyInfo == null || responseMlePrivateKeyInfo.Timestamp != File.GetLastWriteTime(mleResponsePrivateKeyFilePath))
                {
                    SetupCache(merchantConfig, cacheKey, mleResponsePrivateKeyFilePath);
                }
            }

            var cachedResponseMlePrivateKeyInfo = (PrivateKeyInfo)cache.Get(cacheKey);

            try
            {
                if (cachedResponseMlePrivateKeyInfo == null || cachedResponseMlePrivateKeyInfo.PrivateKey == null)
                {
                    throw new Exception($"{Constants.ErrorPrefix} MLE response private key could not be retrieved from cache.");
                }
                RSA privateKey = (RSA)cachedResponseMlePrivateKeyInfo.PrivateKey;
                return cachedResponseMlePrivateKeyInfo.PrivateKey;
            }
            catch (Exception ex)
            {
                logger.Error($"Error retrieving MLE response private key: {ex.Message}");
                throw new Exception($"{Constants.ErrorPrefix} Failed to retrieve MLE response private key from cache.", ex);
            }
        }
    }
}
