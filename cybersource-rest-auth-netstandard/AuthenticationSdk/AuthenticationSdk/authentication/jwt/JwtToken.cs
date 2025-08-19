﻿using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using AuthenticationSdk.core;
using AuthenticationSdk.util;

namespace AuthenticationSdk.authentication.jwt
{
    public class JwtToken : Token
    {
        public JwtToken(MerchantConfig merchantConfig)
        {
            RequestJsonData = merchantConfig.RequestJsonData;
            HostName = merchantConfig.HostName;
            P12FilePath = merchantConfig.P12Keyfilepath;

            if (!File.Exists(P12FilePath))
            {
                throw new Exception($"{Constants.ErrorPrefix} File not found at the given path: {Path.GetFullPath(P12FilePath)}");
            }

            KeyAlias = merchantConfig.KeyAlias;
            KeyPass = merchantConfig.KeyPass;
            X509Certificate2Collection certs = Cache.FetchCachedCertificate(P12FilePath, KeyPass);
            Certificate = Cache.GetCertBasedOnKeyAlias(certs, merchantConfig.KeyAlias);
        }

        public string BearerToken { get; set; }

        public string RequestJsonData { get; set; }

        public string HostName { get; set; }

        public string P12FilePath { get; set; }

        public string KeyAlias { get; set; }

        public string KeyPass { get; }

        public X509Certificate2 Certificate { get; }
    }
}