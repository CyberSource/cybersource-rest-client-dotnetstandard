using AuthenticationSdk.core;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Caching;
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

        private class CertInfo
        {
            public X509Certificate2Collection Certificates { get; set; }
            public DateTime Timestamp { get; set; }
        }

        public static X509Certificate2Collection FetchCachedCertificate(string p12FilePath, string keyPassword)
        {
            try
            {
                lock(mutex)
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

                        var certificates = new X509Certificate2Collection();
                        certificates.Import(p12FilePath, keyPassword, X509KeyStorageFlags.PersistKeySet);

                        CertInfo certInfo = new CertInfo();
                        certInfo.Certificates = certificates;
                        certInfo.Timestamp = File.GetLastWriteTime(p12FilePath);

                        cache.Set(certFile, certInfo, policy);
                    }
                    //return all certs in p12
                    return ((CertInfo)cache[certFile]).Certificates;
                }
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

        public static X509Certificate2 GetCertBasedOnKeyAllias(X509Certificate2Collection certs, String keyAlias)
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
    }
}
