using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Caching;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticationSdk.util
{
    public static class Cache
    {
        public static X509Certificate2 FetchCachedCertificate(string p12FilePath, string keyPassword)
        {
            try
            {
                ObjectCache cache = MemoryCache.Default;

                var cachedCertificateFromP12File = cache["certiFromP12File"] as X509Certificate2;

                // If no entry found from cache, create a cache entry and return the created object
                if (cachedCertificateFromP12File == null)
                {
                    var policy = new CacheItemPolicy();
                    var filePaths = new List<string>();
                    var cachedFilePath = Path.GetFullPath(p12FilePath);
                    filePaths.Add(cachedFilePath);
                    policy.ChangeMonitors.Add(new HostFileChangeMonitor(filePaths));

                    var certi = new X509Certificate2(p12FilePath, keyPassword);
                    cache.Set("certiFromP12File", certi, policy);
                    return certi;
                }

                // otherwise return the cache entry
                return cachedCertificateFromP12File;
            }
            catch (CryptographicException e)
            {
                if (e.Message.Equals("The specified network password is not correct.\r\n"))
                {
                    throw new Exception($"{Constants.ErrorPrefix} KeyPassword provided:{keyPassword} is incorrect");
                }

                return null;
            }
        }
    }
}
