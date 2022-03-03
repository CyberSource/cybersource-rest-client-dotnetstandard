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

        public static X509Certificate2 FetchCachedCertificate(string p12FilePath, string keyPassword)
        {
            try
            {
                lock(mutex)
                {
                    ObjectCache cache = MemoryCache.Default;

                    // (^([a-z]|[A-Z]):(?=\\(?![\0-\37<>:"/\\|?*])|\/(?![\0-\37<>:"/\\|?*])|$)|^\\(?=[\\\/][^\0-\37<>:"/\\|?*]+)|^(?=(\\|\/)$)|^\.(?=(\\|\/)$)|^\.\.(?=(\\|\/)$)|^(?=(\\|\/)[^\0-\37<>:"/\\|?*]+)|^\.(?=(\\|\/)[^\0-\37<>:"/\\|?*]+)|^\.\.(?=(\\|\/)[^\0-\37<>:"/\\|?*]+))((\\|\/)[^\0-\37<>:"/\\|?*]+|(\\|\/)$)*()$

                    var pattern = "(^([a-z]|[A-Z]):(?=\\\\(?![\\0-\\37<>:\"/\\\\|?*])|\\/(?![\\0-\\37<>:\"/\\\\|?*])|$)|^\\\\(?=[\\\\\\/][^\\0-\\37<>:\"/\\\\|?*]+)|^(?=(\\\\|\\/)$)|^\\.(?=(\\\\|\\/)$)|^\\.\\.(?=(\\\\|\\/)$)|^(?=(\\\\|\\/)[^\\0-\\37<>:\"/\\\\|?*]+)|^\\.(?=(\\\\|\\/)[^\\0-\\37<>:\"/\\\\|?*]+)|^\\.\\.(?=(\\\\|\\/)[^\\0-\\37<>:\"/\\\\|?*]+))((\\\\|\\/)([^\\0-\\37<>:\"/\\\\|?*]+|(\\\\|\\/)$))*()$";

                    var matches = Regex.Match(p12FilePath, pattern);
                    var certFile = matches.Groups[11].ToString();

                    if (!cache.Contains(certFile))
                    {
                        var policy = new CacheItemPolicy();
                        var filePaths = new List<string>();
                        var cachedFilePath = Path.GetFullPath(p12FilePath);
                        filePaths.Add(cachedFilePath);
                        policy.ChangeMonitors.Add(new HostFileChangeMonitor(filePaths));

                        var certificate = new X509Certificate2(p12FilePath, keyPassword);
                        cache.Set(certFile, certificate, policy);
                        return certificate;
                    }
                    else if (cache[certFile] is X509Certificate2 cachedCertificateFromP12File)
                    {
                        return cachedCertificateFromP12File;
                    }
                    else
                    {
                        return null;
                    }
                }
            }
            catch (CryptographicException e)
            {
                if (e.Message.Equals("The specified network password is not correct.\r\n"))
                {
                    throw new Exception($"{Constants.ErrorPrefix} KeyPassword provided:{keyPassword} is incorrect");
                }

                throw e;
            }
        }
    }
}
