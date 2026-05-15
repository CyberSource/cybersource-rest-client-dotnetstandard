using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Text;
using CredentialKeys = AuthenticationSdk.core.MerchantConfigurationKeys.MerchantCredentialSettingsKeys;

namespace AuthenticationSdk.core
{
    /// <summary>
    /// Provides extension methods for configuring merchant credentials based on authentication type.
    /// These methods allow fluent configuration of different authentication mechanisms including HTTP Signature, JWT, OAuth, and Mutual Auth.
    /// </summary>
    public static class MerchantCredentialSettingsExtensions
    {
        /// <summary>
        /// Configures HTTP Signature authentication credentials for the merchant settings.
        /// </summary>
        /// <param name="settings">The merchant credential settings instance to configure.</param>
        /// <param name="configurationDictionary">A dictionary containing the HTTP Signature configuration values including "merchantsecretKey" and "merchantKeyId".</param>
        /// <returns>The same merchant credential settings instance for method chaining.</returns>
        public static IMerchantCredentialSettings AddHttpSignatureCredentials(this IMerchantCredentialSettings settings, IReadOnlyDictionary<string, string> configurationDictionary)
        {
            SecureString merchantSecretKey = ConvertToSecureString(configurationDictionary.GetValueOrDefault(CredentialKeys.MerchantSecretKey, null));
            var merchantKeyId = configurationDictionary.GetValueOrDefault(CredentialKeys.MerchantKeyId, null);

            try
            {
                if (settings is IMutableMerchantCredentialSettings mutableSettings)
                {
                    mutableSettings.SetAuthenticationType("http_signature");
                    mutableSettings.SetMerchantSecretKey(ConvertFromSecureString(merchantSecretKey));
                    mutableSettings.SetMerchantKeyId(merchantKeyId);
                }

                return settings;
            }
            finally
            {
                merchantSecretKey?.Dispose();
            }
        }

        /// <summary>
        /// Configures JWT (JSON Web Token) authentication credentials for the merchant settings.
        /// Supports both P12 (certificate-based RS256) and SHARED_SECRET (HMAC-based HS256) key types.
        /// </summary>
        /// <param name="settings">The merchant credential settings instance to configure.</param>
        /// <param name="configurationDictionary">A dictionary containing the JWT configuration values.</param>
        /// <returns>The same merchant credential settings instance for method chaining.</returns>
        public static IMerchantCredentialSettings AddJwtCredentials(this IMerchantCredentialSettings settings, IReadOnlyDictionary<string, string> configurationDictionary)
        {
            var jwtKeyType = configurationDictionary.GetValueOrDefault(CredentialKeys.JwtKeyType, util.Constants.JwtKeyTypeP12);

            if (settings is IMutableMerchantCredentialSettings mutableSettings)
            {
                mutableSettings.SetAuthenticationType("jwt");
                mutableSettings.SetJwtKeyType(jwtKeyType);

                if (settings.IsSharedSecretKeyType())
                {
                    // JWT with SHARED_SECRET — use merchantKeyId and merchantsecretKey (same credentials as HTTP Signature)
                    SecureString merchantSecretKey = ConvertToSecureString(configurationDictionary.GetValueOrDefault(CredentialKeys.MerchantSecretKey, null));
                    var merchantKeyId = configurationDictionary.GetValueOrDefault(CredentialKeys.MerchantKeyId, null);

                    try
                    {
                        mutableSettings.SetMerchantSecretKey(ConvertFromSecureString(merchantSecretKey));
                        mutableSettings.SetMerchantKeyId(merchantKeyId);
                    }
                    finally
                    {
                        merchantSecretKey?.Dispose();
                    }
                }
                else
                {
                    // JWT with P12 (default) — use certificate fields
                    var keyDirectory = configurationDictionary.GetValueOrDefault(CredentialKeys.KeysDirectory, null);
                    var keyFilename = configurationDictionary.GetValueOrDefault(CredentialKeys.KeyFilename, null);
                    SecureString keyPass = ConvertToSecureString(configurationDictionary.GetValueOrDefault(CredentialKeys.KeyPassword, null));
                    var keyAlias = configurationDictionary.GetValueOrDefault(CredentialKeys.KeyAlias, null);

                    try
                    {
                        mutableSettings.SetKeyDirectory(keyDirectory);
                        mutableSettings.SetKeyfileName(keyFilename);
                        mutableSettings.SetKeyPass(ConvertFromSecureString(keyPass));
                        mutableSettings.SetKeyAlias(keyAlias);
                        mutableSettings.SetP12Keyfilepath(Path.Combine(keyDirectory, keyFilename + ".p12"));
                    }
                    finally
                    {
                        keyPass?.Dispose();
                    }
                }
            }

            return settings;
        }

        /// <summary>
        /// Returns true if the credential settings use JWT with SHARED_SECRET key type.
        /// </summary>
        /// <param name="settings">The merchant credential settings to check.</param>
        /// <returns>True if jwtKeyType is SHARED_SECRET; otherwise, false.</returns>
        public static bool IsSharedSecretKeyType(this IMerchantCredentialSettings settings)
        {
            return string.Equals(settings.JwtKeyType, util.Constants.JwtKeyTypeSharedSecret, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Configures OAuth authentication credentials for the merchant settings.
        /// </summary>
        /// <param name="settings">The merchant credential settings instance to configure.</param>
        /// <param name="configurationDictionary">A dictionary containing the OAuth configuration values including "accessToken" and "refreshToken".</param>
        /// <returns>The same merchant credential settings instance for method chaining.</returns>
        public static IMerchantCredentialSettings AddOAuthCredentials(this IMerchantCredentialSettings settings, IReadOnlyDictionary<string, string> configurationDictionary)
        {
            var accessToken = configurationDictionary.GetValueOrDefault(CredentialKeys.AccessToken, null);
            var refreshToken = configurationDictionary.GetValueOrDefault(CredentialKeys.RefreshToken, null);

            if (settings is IMutableMerchantCredentialSettings mutableSettings)
            {
                mutableSettings.SetAuthenticationType("oauth");
                mutableSettings.SetAccessToken(accessToken);
                mutableSettings.SetRefreshToken(refreshToken);
            }

            return settings;
        }

        /// <summary>
        /// Configures Mutual Auth authentication credentials for the merchant settings.
        /// </summary>
        /// <param name="settings">The merchant credential settings instance to configure.</param>
        /// <param name="configurationDictionary">A dictionary containing the Mutual Auth configuration values including "clientId" and "clientSecret".</param>
        /// <returns>The same merchant credential settings instance for method chaining.</returns>
        public static IMerchantCredentialSettings AddMutualAuthCredentials(this IMerchantCredentialSettings settings, IReadOnlyDictionary<string, string> configurationDictionary)
        {
            var clientId = configurationDictionary.GetValueOrDefault(CredentialKeys.ClientId, null);
            var clientSecret = configurationDictionary.GetValueOrDefault(CredentialKeys.ClientSecret, null);

            if (settings is IMutableMerchantCredentialSettings mutableSettings)
            {
                mutableSettings.SetAuthenticationType("mutual_auth");
                mutableSettings.SetClientId(clientId);
                mutableSettings.SetClientSecret(clientSecret);
            }

            return settings;
        }

        #region Helper Methods
        private static string ConvertFromSecureString(SecureString secureString)
        {
            if (secureString == null) { return null; }

            return new System.Net.NetworkCredential(string.Empty, secureString).Password;
        }

        private static SecureString ConvertToSecureString(string value)
        {
            if (string.IsNullOrEmpty(value)) { return null; }

            var secureString = new SecureString();
            foreach (char c in value)
            {
                secureString.AppendChar(c);
            }
            secureString.MakeReadOnly();
            return secureString;
        }
        #endregion Helper Methods
    }
}
