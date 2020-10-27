using System;
using System.Collections.Generic;
using AuthenticationSdk.core;
using NUnit.Framework;

namespace AuthenticationSdkTests.NetCore.util
{
    [TestFixture]
    public class MerchantConfigTests
    {
        private string resourceFolderPath =
            "..\\Resource";


        [Test]        
        public void NullMerchantId()
        {
            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", ""},
                {"merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE="},
                {"merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda"},
                {"authenticationType", "jwt"},
                {"keysDirectory", resourceFolderPath},
                {"keyFilename", ""},
                {"runEnvironment", "cybersource.environment.sandbox"},
                {"keyAlias", ""},
                {"keyPassword", ""},
                {"enableLog", ""},
                {"logDirectory", ""},
                {"logFileMaxSize", ""},
                {"timeout", ""},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };

            Assert.Throws<Exception>(() => new MerchantConfig(configurationDictionary));
        }


        [Test]        
        public void NullmerchantKeyId()
        {
            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", "testrest"},
                {"merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE="},
                {"merchantKeyId", ""},
                {"authenticationType", "http_signature"},
                {"keysDirectory", resourceFolderPath},
                {"keyFilename", ""},
                {"runEnvironment", "cybersource.environment.sandbox"},
                {"keyAlias", ""},
                {"keyPassword", ""},
                {"enableLog", ""},
                {"logDirectory", ""},
                {"logFileMaxSize", ""},
                {"timeout", ""},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };
            
            Assert.Throws<Exception>(() => new MerchantConfig(configurationDictionary));
        }

        [Test]        
        public void NullmerchantsecretKey()
        {
            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", "testrest"},
                {"keysDirectory", resourceFolderPath},
                {"merchantsecretKey", ""},
                {"merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda"},
                {"authenticationType", "http_signature"},
                {"keyFilename", ""},
                {"runEnvironment", "cybersource.environment.sandbox"},
                {"keyAlias", ""},
                {"keyPassword", ""},
                {"enableLog", ""},
                {"logDirectory", ""},
                {"logFileMaxSize", ""},
                {"timeout", ""},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };
                        
            Assert.Throws<Exception>(() => new MerchantConfig(configurationDictionary));
        }

        [Test]        
        public void MissingDictionaryKey()
        {
            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", "testrest"}
            };

            Assert.Throws<Exception>(() => new MerchantConfig(configurationDictionary));
        }

        [Test]        
        public void InvalidAuthType()
        {
            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", "testrest"},
                {"merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE="},
                {"merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda"},
                {"authenticationType", "Invalid"},
                {"keysDirectory", resourceFolderPath},
                {"keyFilename", ""},
                {"runEnvironment", ""},
                {"keyAlias", ""},
                {"keyPassword", ""},
                {"enableLog", ""},
                {"logDirectory", ""},
                {"logFileMaxSize", ""},
                {"timeout", ""},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };

            Assert.Throws<Exception>(() => new MerchantConfig(configurationDictionary));
        }

        [Test]        
        public void BlankAuthType()
        {
            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", "testrest"},
                {"merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE="},
                {"merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda"},
                {"authenticationType", ""},
                {"keysDirectory", resourceFolderPath},
                {"keyFilename", ""},
                {"runEnvironment", ""},
                {"keyAlias", ""},
                {"keyPassword", ""},
                {"enableLog", ""},
                {"logDirectory", ""},
                {"logFileMaxSize", ""},
                {"timeout", ""},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };

            Assert.Throws<Exception>(() => new MerchantConfig(configurationDictionary));
        }
    }
}
