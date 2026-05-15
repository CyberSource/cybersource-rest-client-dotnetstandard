using AuthenticationSdk.core;
using NLog;
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
                try
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
                catch (Exception e)
                {
                    logger.Error($"Error reading PEM file or caching RSA parameters: {e.Message}");
                    throw new Exception($"{Constants.ErrorPrefix} Error reading PEM file or caching RSA parameters: {e.Message}", e);
                }
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
            // Priority #2: If merchantConfig.mleForRequestPublicCertPath not provided by merchant then get mlecert from merchant p12 if provided and jwt auth type (not shared secret)
            else if (Constants.AuthMechanismJwt.Equals(merchantConfig.AuthenticationType, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(merchantConfig.P12Keyfilepath) && !merchantConfig.IsSharedSecretKeyType)
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
            certificates.Import(p12FilePath, keyPassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            //return all certs in p12
            return certificates;
        }
        public static AsymmetricAlgorithm GetMleResponsePrivateKeyFromFilePath(MerchantConfig merchantConfig)
        {
            string merchantId = merchantConfig.MerchantId;
            string identifier = Constants.MLE_CACHE_KEY_IDENTIFIER_FOR_RESPONSE_PRIVATE_KEY;
            string mleResponsePrivateKeyFilePath = merchantConfig.ResponseMlePrivateKeyFilePath;
            string cacheKey = $"{mleResponsePrivateKeyFilePath}_{identifier}";

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
                return cachedResponseMlePrivateKeyInfo.PrivateKey;
            }
            catch (Exception ex)
            {
                logger.Error($"Error retrieving MLE response private key: {ex.Message}");
                throw new Exception($"{Constants.ErrorPrefix} Failed to retrieve MLE response private key from cache.", ex);
            }
        }

        /// <summary>
        /// Retrieves cached MLE KID data for a P12/PFX file, or caches it if not present.
        /// </summary>
        /// <param name="merchantConfig">The merchant configuration containing the private key file path</param>
        /// <returns>CachedMLEKId containing the extracted KID (or null) and file timestamp</returns>
        public static CachedMLEKId GetMLEKIdDataFromCache(MerchantConfig merchantConfig)
        {
            string cacheKey = merchantConfig.ResponseMlePrivateKeyFilePath + Constants.RESPONSE_MLE_P12_PFX_CACHE_IDENTIFIER;
            string filePath = merchantConfig.ResponseMlePrivateKeyFilePath;

            ObjectCache cache = MemoryCache.Default;

            if (!cache.Contains(cacheKey))
            {
                SetupMLEKIdCache(merchantConfig, cacheKey, filePath);
            }
            else
            {
                var cachedMLEKId = (CachedMLEKId)cache.Get(cacheKey);
                if (cachedMLEKId == null || cachedMLEKId.LastModifiedTimeStamp != File.GetLastWriteTime(filePath))
                {
                    SetupMLEKIdCache(merchantConfig, cacheKey, filePath);
                }
            }

            return (CachedMLEKId)cache.Get(cacheKey);
        }

        /// <summary>
        /// Sets up the MLE KID cache by extracting the KID from a CyberSource P12/PFX certificate.
        /// </summary>
        /// <param name="merchantConfig">The merchant configuration</param>
        /// <param name="cacheKey">The cache key to use</param>
        /// <param name="filePath">The path to the P12/PFX file</param>
        private static void SetupMLEKIdCache(MerchantConfig merchantConfig, string cacheKey, string filePath)
        {
            try
            {
                var policy = new CacheItemPolicy();
                var filePaths = new List<string>();
                var cachedFilePath = Path.GetFullPath(filePath);
                filePaths.Add(cachedFilePath);
                policy.ChangeMonitors.Add(new HostFileChangeMonitor(filePaths));

                ObjectCache cache = MemoryCache.Default;

                bool useMetaKeyFlag = false;
                bool.TryParse(merchantConfig.UseMetaKey, out useMetaKeyFlag);
                string responseMleKeyAlias = useMetaKeyFlag ? merchantConfig.PortfolioId : merchantConfig.MerchantId;

                string extractedKid = null;
                bool isCyberSourceP12 = false;

                // Check if this is a CyberSource-generated P12
                isCyberSourceP12 = CertificateUtility.IsP12GeneratedByCyberSource(filePath, merchantConfig.ResponseMlePrivateKeyFilePassword);

                if (isCyberSourceP12)
                {
                    logger.Debug("Detected CyberSource-generated P12 file, attempting to extract KID");

                    extractedKid = CertificateUtility.ExtractResponseMleKidFromP12(
                        filePath,
                        merchantConfig.ResponseMlePrivateKeyFilePassword,
                        responseMleKeyAlias
                    );

                    if (!string.IsNullOrEmpty(extractedKid))
                    {
                        logger.Debug($"Successfully extracted KID from CyberSource P12: {extractedKid}");
                    }
                }
                else
                {
                    logger.Debug("P12 file is not CyberSource-generated, KID will not be auto-extracted");
                }

                CachedMLEKId cachedMLEKId = new CachedMLEKId
                {
                    Kid = extractedKid,
                    LastModifiedTimeStamp = File.GetLastWriteTime(filePath)
                };

                lock (mutex)
                {
                    cache.Set(cacheKey, cachedMLEKId, policy);
                }

                logger.Debug($"MLE KID cache setup complete for file: {filePath}");
            }
            catch (Exception e)
            {
                logger.Error($"Error setting up MLE KID cache for file: {filePath}. Error: {e.Message}");

                // Cache a null KID to indicate failure
                CachedMLEKId fallbackCache = new CachedMLEKId
                {
                    Kid = null,
                    LastModifiedTimeStamp = File.GetLastWriteTime(filePath)
                };

                ObjectCache cache = MemoryCache.Default;
                var policy = new CacheItemPolicy();

                lock (mutex)
                {
                    cache.Set(cacheKey, fallbackCache, policy);
                }
            }
        }
        public static void AddPublicKeyToCache(string publickey, string runEnvironment, string kid)
        {
            // Construct cache key similar to PHP logic
            string cacheKey = $"{Constants.PUBLIC_KEY_CACHE_IDENTIFIER}_{runEnvironment}_{kid}";

            ObjectCache cache = MemoryCache.Default;

            var policy = new CacheItemPolicy();
            // Optionally, set expiration or change monitors if needed

            lock (mutex)
            {
                cache.Set(cacheKey, publickey, policy);
            }
        }
        public static string GetPublicKeyFromCache(string runEnvironment, string keyId)
        {
            string cacheKey = $"{Constants.PUBLIC_KEY_CACHE_IDENTIFIER}_{runEnvironment}_{keyId}";
            ObjectCache cache = MemoryCache.Default;

            if (cache.Contains(cacheKey))
            {
                return cache.Get(cacheKey) as string;
            }
            throw new Exception($"Public key not found in cache for [RunEnvironment: {runEnvironment}, KeyId: {keyId}]");
        }

        #region NEW METHODS
        /// <summary>
        /// Retrieves the cached MLE response private key from file, or loads and caches it if not present.
        /// </summary>
        /// <param name="merchantCredentialSettings">Object of IMerchantCredentialSettings containing merchant credentials.</param>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing merchant MLE configuration.</param>
        /// <returns>The asymmetric private key used for decrypting MLE responses.</returns>
        /// <exception cref="Exception">Thrown when the private key fails to load or retrieve from cache.</exception>
        public static AsymmetricAlgorithm GetMleResponsePrivateKeyFromFilePath(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings)
        {
            string merchantId = merchantCredentialSettings.MerchantId;
            string identifier = Constants.MLE_CACHE_KEY_IDENTIFIER_FOR_RESPONSE_PRIVATE_KEY;
            string mleResponsePrivateKeyFilePath = merchantMLESettings.ResponseMlePrivateKeyFilePath;
            string cacheKey = $"{mleResponsePrivateKeyFilePath}_{identifier}";

            ObjectCache cache = MemoryCache.Default;

            if (!cache.Contains(cacheKey))
            {
                SetupCache(merchantCredentialSettings, merchantMLESettings, cacheKey, mleResponsePrivateKeyFilePath);
            }
            else
            {
                var responseMlePrivateKeyInfo = (PrivateKeyInfo)cache.Get(cacheKey);
                if (responseMlePrivateKeyInfo == null || responseMlePrivateKeyInfo.Timestamp != File.GetLastWriteTime(mleResponsePrivateKeyFilePath))
                {
                    SetupCache(merchantCredentialSettings, merchantMLESettings, cacheKey, mleResponsePrivateKeyFilePath);
                }
            }

            var cachedResponseMlePrivateKeyInfo = (PrivateKeyInfo)cache.Get(cacheKey);

            try
            {
                return cachedResponseMlePrivateKeyInfo.PrivateKey;
            }
            catch (Exception ex)
            {
                logger.Error($"Error retrieving MLE response private key: {ex.Message}");
                throw new Exception($"{Constants.ErrorPrefix} Failed to retrieve MLE response private key from cache.", ex);
            }
        }

        /// <summary>
        /// Sets up the cache for MLE response private key by loading it from the specified certificate file.
        /// Supports multiple file formats including P12, PFX, PEM, KEY, and P8.
        /// </summary>
        /// <param name="merchantCredentialSettings">Object of IMerchantCredentialSettings containing merchant credentials.</param>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing merchant MLE configuration.</param>
        /// <param name="cacheKey">The cache key to use for storing the private key.</param>
        /// <param name="certificateFilePath">The full file path to the certificate or private key file.</param>
        /// <exception cref="Exception">Thrown when the file format is unsupported or the key fails to load.</exception>
        private static void SetupCache(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, string cacheKey, string certificateFilePath)
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
                    SecureString password = merchantMLESettings.ResponseMlePrivateKeyFilePassword;

                    // Case 1 - PKCS#12 formats (.p12, .pfx)
                    if (fileExtension.Equals("p12") || fileExtension.Equals("pfx"))
                    {
                        mlePrivateKey = Utility.ReadPrivateKeyFromP12(certificateFilePath, password);
                    }
                    // Case 2 - PEM-based formats (.pem, .key, .p8)
                    else if (fileExtension.Equals("pem") || fileExtension.Equals("key") || fileExtension.Equals("p8"))
                    {
                        mlePrivateKey = (AsymmetricAlgorithm)Utility.ExtractPrivateKeyFromFile(certificateFilePath, password);
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
                    mleCertificate = GetCertBasedOnKeyAlias(certificates, merchantMLESettings.RequestMleKeyAlias);
                }
                catch (Exception)
                {
                    if (mleCertificate == null)
                    {
                        // If no certificate found for the specified alias, fall back to first certificate
                        string fileName = Path.GetFileName(certificateFilePath);
                        logger.Warn($"No certificate found for the specified requestMleKeyAlias '{merchantMLESettings.RequestMleKeyAlias}'. Using the first certificate from file {fileName} as the MLE request certificate.");
                        mleCertificate = certificates[0];
                    }
                }
            }

            if (cacheKey.EndsWith(Constants.MLE_CACHE_IDENTIFIER_FOR_P12_CERT))
            {
                try
                {
                    mleCertificate = GetCertBasedOnKeyAlias(FetchCertificateCollectionFromP12File(merchantCredentialSettings.P12Keyfilepath, merchantCredentialSettings.KeyPass), merchantMLESettings.RequestMleKeyAlias);
                }
                catch (Exception)
                {
                    string fileName = Path.GetFileName(merchantCredentialSettings.P12Keyfilepath);
                    logger.Error($"No certificate found for the specified requestMleKeyAlias '{merchantMLESettings.RequestMleKeyAlias}' in file {fileName}.");
                    throw new ArgumentException($"No certificate found for the specified requestMleKeyAlias '{merchantMLESettings.RequestMleKeyAlias}' in file {fileName}.");
                }
            }

            CertInfo certInfo = new CertInfo
            {
                MLECertificate = mleCertificate,
                Timestamp = File.GetLastWriteTime(certificateFilePath)
            };


            lock (mutex)
            {
                cache.Set(cacheKey, certInfo, policy);
            }
        }

        /// <summary>
        /// Retrieves cached MLE KID data for a P12/PFX file, or caches it if not present.
        /// Extracts the Key ID (KID) from CyberSource-generated P12/PFX certificates for use in MLE response decryption.
        /// </summary>
        /// <param name="keyIssuer">The key issuer for the MLE response.</param>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing merchant MLE credentials.</param>
        /// <returns>CachedMLEKId containing the extracted KID (or null if not a CyberSource P12) and file timestamp.</returns>
        public static CachedMLEKId GetMLEKIdDataFromCache(string keyIssuer, IMerchantMLESettings merchantMLESettings)
        {
            string cacheKey = merchantMLESettings.ResponseMlePrivateKeyFilePath + Constants.RESPONSE_MLE_P12_PFX_CACHE_IDENTIFIER;
            string filePath = merchantMLESettings.ResponseMlePrivateKeyFilePath;

            ObjectCache cache = MemoryCache.Default;

            if (!cache.Contains(cacheKey))
            {
                SetupMLEKIdCache(keyIssuer, merchantMLESettings, cacheKey, filePath);
            }
            else
            {
                var cachedMLEKId = (CachedMLEKId)cache.Get(cacheKey);
                if (cachedMLEKId == null || cachedMLEKId.LastModifiedTimeStamp != File.GetLastWriteTime(filePath))
                {
                    SetupMLEKIdCache(keyIssuer, merchantMLESettings, cacheKey, filePath);
                }
            }

            return (CachedMLEKId)cache.Get(cacheKey);
        }

        /// <summary>
        /// Sets up the MLE KID cache by extracting the KID from a CyberSource P12/PFX certificate.
        /// If the file is not CyberSource-generated or KID extraction fails, caches a null KID value.
        /// </summary>
        /// <param name="keyIssuer">The key issuer for the MLE response.</param>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing merchant MLE credentials.</param>
        /// <param name="cacheKey">The cache key to use for storing the KID data.</param>
        /// <param name="filePath">The path to the P12/PFX file.</param>
        private static void SetupMLEKIdCache(string keyIssuer, IMerchantMLESettings merchantMLESettings, string cacheKey, string filePath)
        {
            try
            {
                var policy = new CacheItemPolicy();
                var filePaths = new List<string>();
                var cachedFilePath = Path.GetFullPath(filePath);
                filePaths.Add(cachedFilePath);
                policy.ChangeMonitors.Add(new HostFileChangeMonitor(filePaths));

                ObjectCache cache = MemoryCache.Default;

                string responseMleKeyAlias = keyIssuer;

                string extractedKid = null;
                bool isCyberSourceP12 = false;

                // Check if this is a CyberSource-generated P12
                isCyberSourceP12 = CertificateUtility.IsP12GeneratedByCyberSource(filePath, merchantMLESettings.ResponseMlePrivateKeyFilePassword);

                if (isCyberSourceP12)
                {
                    logger.Debug("Detected CyberSource-generated P12 file, attempting to extract KID");

                    extractedKid = CertificateUtility.ExtractResponseMleKidFromP12(
                        filePath,
                        merchantMLESettings.ResponseMlePrivateKeyFilePassword,
                        responseMleKeyAlias
                    );

                    if (!string.IsNullOrEmpty(extractedKid))
                    {
                        logger.Debug($"Successfully extracted KID from CyberSource P12: {extractedKid}");
                    }
                }
                else
                {
                    logger.Debug("P12 file is not CyberSource-generated, KID will not be auto-extracted");
                }

                CachedMLEKId cachedMLEKId = new CachedMLEKId
                {
                    Kid = extractedKid,
                    LastModifiedTimeStamp = File.GetLastWriteTime(filePath)
                };

                lock (mutex)
                {
                    cache.Set(cacheKey, cachedMLEKId, policy);
                }

                logger.Debug($"MLE KID cache setup complete for file: {filePath}");
            }
            catch (Exception e)
            {
                logger.Error($"Error setting up MLE KID cache for file: {filePath}. Error: {e.Message}");

                // Cache a null KID to indicate failure
                CachedMLEKId fallbackCache = new CachedMLEKId
                {
                    Kid = null,
                    LastModifiedTimeStamp = File.GetLastWriteTime(filePath)
                };

                ObjectCache cache = MemoryCache.Default;
                var policy = new CacheItemPolicy();

                lock (mutex)
                {
                    cache.Set(cacheKey, fallbackCache, policy);
                }
            }
        }

        /// <summary>
        /// Retrieves the cached MLE request certificate from file, or loads and caches it if not present.
        /// Implements a priority-based search: config-provided path, P12 file for JWT auth, or default SDK certificate.
        /// </summary>
        /// <param name="merchantCredentialSettings">Object of IMerchantCredentialSettings containing merchant credentials.</param>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing merchant MLE configuration.</param>
        /// <returns>The X509Certificate2 used for MLE request encryption, or null if no certificate is configured.</returns>
        public static X509Certificate2 GetRequestMLECertFromCache(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings)
        {
            string merchantId = merchantCredentialSettings.MerchantId;
            string certificateIdentifier;
            string certificateFilePath;

            if (string.IsNullOrEmpty(merchantMLESettings.MleForRequestPublicCertPath?.Trim()) && merchantCredentialSettings.IsSharedSecretKeyType())
            {
                logger.Error("Merchant is using shared secret key type and has not provided a certificate path for MLE request encryption. Please review the value of `mleForRequestPublicCertPath` in the merchant configuration.");
                throw new ArgumentException("Merchant is using shared secret key type and has not provided a certificate path for MLE request encryption. Please review the value of `mleForRequestPublicCertPath` in the merchant configuration.");
            }

            // Priority #1: Get cert from merchantConfig.mleForRequestPublicCertPath if certPath is provided
            if (!string.IsNullOrEmpty(merchantMLESettings.MleForRequestPublicCertPath))
            {
                certificateIdentifier = Constants.MLE_CACHE_IDENTIFIER_FOR_CONFIG_CERT;
                certificateFilePath = merchantMLESettings.MleForRequestPublicCertPath;
            }
            // Priority #2: If merchantConfig.mleForRequestPublicCertPath not provided by merchant then get mlecert from merchant p12 if provided and jwt auth type (not shared secret)
            else if (Constants.AuthMechanismJwt.Equals(merchantCredentialSettings.AuthenticationType, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(merchantCredentialSettings.P12Keyfilepath) && !merchantCredentialSettings.IsSharedSecretKeyType())
            {
                certificateIdentifier = Constants.MLE_CACHE_IDENTIFIER_FOR_P12_CERT;
                certificateFilePath = merchantCredentialSettings.P12Keyfilepath;
            }
            // Priority #3: Get mlecert from default mle cert in SDK as per CAS or PROD env.
            else
            {
                logger.Debug("The certificate to use for MLE for requests is not provided in the merchant configuration. Please ensure that the certificate path is provided.");
                return null;
            }

            string cacheKey = $"{merchantId}_{certificateIdentifier}";
            X509Certificate2 mleCertificate = GetMLECertBasedOnCacheKey(merchantCredentialSettings, merchantMLESettings, cacheKey, certificateFilePath);

            CertificateUtility.ValidateCertificateExpiry(mleCertificate, merchantCredentialSettings.KeyAlias, certificateIdentifier);
            return mleCertificate;
        }

        /// <summary>
        /// Retrieves the cached MLE request certificate based on the cache key and certificate file path.
        /// Uses cache invalidation based on file modification time to ensure fresh data.
        /// </summary>
        /// <param name="merchantCredentialSettings">Object of IMerchantCredentialSettings containing merchant credentials.</param>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing merchant MLE configuration.</param>
        /// <param name="cacheKey">The unique cache key identifying this certificate.</param>
        /// <param name="certificateFilePath">The full file path to the certificate file.</param>
        /// <returns>The X509Certificate2 from cache or newly loaded from file.</returns>
        private static X509Certificate2 GetMLECertBasedOnCacheKey(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, string cacheKey, string certificateFilePath)
        {
            ObjectCache cache = MemoryCache.Default;

            if (!cache.Contains(cacheKey))
            {
                SetupCache(merchantCredentialSettings, merchantMLESettings, cacheKey, certificateFilePath);
            }
            else
            {
                CertInfo certInfo = (CertInfo)cache.Get(cacheKey);
                if (certInfo == null || certInfo.Timestamp != File.GetLastWriteTime(certificateFilePath))
                {
                    SetupCache(merchantCredentialSettings, merchantMLESettings, cacheKey, certificateFilePath);
                }
            }

            return ((CertInfo)cache.Get(cacheKey)).MLECertificate;
        }
        #endregion
    }
}
