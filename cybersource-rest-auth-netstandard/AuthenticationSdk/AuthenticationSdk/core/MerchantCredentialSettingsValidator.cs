using AuthenticationSdk.util;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Text;
using CredentialKeys = AuthenticationSdk.core.MerchantConfigurationKeys.MerchantCredentialSettingsKeys;

namespace AuthenticationSdk.core
{
    /// <summary>
    /// Defines methods for validating merchant credential configuration settings.
    /// </summary>
    public interface IMerchantCredentialSettingsValidator
    {
        /// <summary>
        /// Validates mandatory merchant configuration settings that apply to all authentication types.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <exception cref="KeyNotFoundException">Thrown when mandatory configuration keys are missing or empty.</exception>
        /// <exception cref="InvalidDataException">Thrown when configuration values are invalid or deprecated.</exception>
        void ValidateMandatorySettings(IReadOnlyDictionary<string, string> configurationDictionary);

        /// <summary>
        /// Validates HTTP Signature authentication-specific configuration settings.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <exception cref="KeyNotFoundException">Thrown when required HTTP Signature settings are missing or empty.</exception>
        void ValidateHttpSignatureSettings(IReadOnlyDictionary<string, string> configurationDictionary);

        /// <summary>
        /// Validates JWT (JSON Web Token) authentication-specific configuration settings.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <exception cref="KeyNotFoundException">Thrown when required JWT settings are missing or empty.</exception>
        /// <exception cref="DirectoryNotFoundException">Thrown when the JWT key directory does not exist.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the JWT key file is not found or inaccessible.</exception>
        void ValidateJwtSettings(IReadOnlyDictionary<string, string> configurationDictionary);

        /// <summary>
        /// Validates OAuth authentication-specific configuration settings.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <exception cref="KeyNotFoundException">Thrown when required OAuth settings are missing or empty.</exception>
        void ValidateOAuthSettings(IReadOnlyDictionary<string, string> configurationDictionary);

        /// <summary>
        /// Validates Mutual Auth authentication-specific configuration settings.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <exception cref="KeyNotFoundException">Thrown when required Mutual Auth settings are missing or empty.</exception>
        void ValidateMutualAuthSettings(IReadOnlyDictionary<string, string> configurationDictionary);
    }

    public sealed class MerchantCredentialSettingsValidator : IMerchantCredentialSettingsValidator
    {
        #region Http Signature Settings Validation
        /// <summary>
        /// Validates HTTP Signature authentication-specific configuration settings.
        /// Ensures that both the merchant secret key and merchant key ID are present and non-empty.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <exception cref="KeyNotFoundException">Thrown when required HTTP Signature settings (merchantsecretKey or merchantKeyId) are missing or empty.</exception>
        public void ValidateHttpSignatureSettings(IReadOnlyDictionary<string, string> configurationDictionary)
        {
            ValidateForHttpSignature(configurationDictionary, CredentialKeys.MerchantSecretKey);
            ValidateForHttpSignature(configurationDictionary, CredentialKeys.MerchantKeyId);
        }

        /// <summary>
        /// Validates that a required HTTP Signature configuration key exists and is non-empty.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <param name="key">The configuration key to validate.</param>
        /// <exception cref="KeyNotFoundException">Thrown when the key is missing or the value is null or empty.</exception>
        private void ValidateForHttpSignature(IReadOnlyDictionary<string, string> configurationDictionary, string key)
        {
            if (!configurationDictionary.ContainsKey(key) || string.IsNullOrEmpty(configurationDictionary[key]))
            {
                throw new KeyNotFoundException($"KeyNotFoundException : Key '{key}' not found in configuration. This value is required when Authentication Type is set to HTTP Signature and must be provided with the key '{key}'");
            }
        }
        #endregion Http Signature Settings Validation

        #region JWT Settings Validation
        /// <summary>
        /// Validates JWT (JSON Web Token) authentication-specific configuration settings.
        /// Ensures that all required JWT settings are present and that the key file exists and is accessible.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <exception cref="KeyNotFoundException">Thrown when required JWT settings (keysDirectory, keyFilename, keyPass, or keyAlias) are missing or empty.</exception>
        /// <exception cref="DirectoryNotFoundException">Thrown when the key directory does not exist.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the key file is not found at the expected location.</exception>
        /// <exception cref="IOException">Thrown when the key file is found but not accessible due to permission issues.</exception>
        public void ValidateJwtSettings(IReadOnlyDictionary<string, string> configurationDictionary)
        {
            // Validate jwtKeyType value if provided
            ValidateJwtKeyType(configurationDictionary, CredentialKeys.JwtKeyType);

            if (configurationDictionary.ContainsKey(CredentialKeys.JwtKeyType)
                && string.Equals(configurationDictionary[CredentialKeys.JwtKeyType], util.Constants.JwtKeyTypeSharedSecret, StringComparison.OrdinalIgnoreCase))
            {
                // JWT with SHARED_SECRET — validate symmetric key fields (same as HTTP Signature)
                ValidateForJwtSharedSecret(configurationDictionary, CredentialKeys.MerchantSecretKey);
                ValidateForJwtSharedSecret(configurationDictionary, CredentialKeys.MerchantKeyId);
            }
            else
            {
                // JWT with P12 (default) — validate certificate fields
                ValidateForJWT(configurationDictionary, CredentialKeys.KeysDirectory);
                ValidateForJWT(configurationDictionary, CredentialKeys.KeyFilename);
                ValidateForJWT(configurationDictionary, CredentialKeys.KeyPassword);
                ValidateForJWT(configurationDictionary, CredentialKeys.KeyAlias);
                CheckKeyFileIsValid(configurationDictionary[CredentialKeys.KeysDirectory], configurationDictionary[CredentialKeys.KeyFilename]);
            }
        }

        /// <summary>
        /// Validates the jwtKeyType value if provided. Must be "P12" or "SHARED_SECRET".
        /// If the key is missing or empty, no error is thrown; the caller defaults to P12 behavior.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <param name="key">The configuration key to validate.</param>
        /// <exception cref="ArgumentException">Thrown when the value is not "P12" or "SHARED_SECRET".</exception>
        private void ValidateJwtKeyType(IReadOnlyDictionary<string, string> configurationDictionary, string key)
        {
            if (!configurationDictionary.ContainsKey(key))
            {
                return;
            }

            if (string.IsNullOrEmpty(configurationDictionary[key]))
            {
                throw new ArgumentException($"{Constants.InvalidJwtKeyTypeErrorMessage}Provided value is missing or is in invalid format");
            }

            List<string> allowedKeyTypes = new List<string> { Constants.JwtKeyTypeP12, Constants.JwtKeyTypeSharedSecret };
            if (!allowedKeyTypes.Contains(configurationDictionary[key], StringComparer.OrdinalIgnoreCase))
            {
                throw new ArgumentException($"{Constants.InvalidJwtKeyTypeErrorMessage}Provided value: {configurationDictionary[key]}");
            }
        }

        /// <summary>
        /// Validates that a required JWT shared secret configuration key exists and is non-empty.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <param name="key">The configuration key to validate.</param>
        /// <exception cref="KeyNotFoundException">Thrown when the key is missing or the value is null or empty.</exception>
        private void ValidateForJwtSharedSecret(IReadOnlyDictionary<string, string> configurationDictionary, string key)
        {
            if (!configurationDictionary.ContainsKey(key) || string.IsNullOrEmpty(configurationDictionary[key]))
            {
                throw new KeyNotFoundException($"KeyNotFoundException : Key '{key}' not found in configuration. This value is required when Authentication Type is set to JWT with jwtKeyType='SHARED_SECRET' and must be provided with the key '{key}'");
            }
        }

        /// <summary>
        /// Validates that a required JWT configuration key exists and is non-empty.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <param name="key">The configuration key to validate.</param>
        /// <exception cref="KeyNotFoundException">Thrown when the key is missing or the value is null or empty.</exception>
        private void ValidateForJWT(IReadOnlyDictionary<string, string> configurationDictionary, string key)
        {
            if (!configurationDictionary.ContainsKey(key) || string.IsNullOrEmpty(configurationDictionary[key]))
            {
                throw new KeyNotFoundException($"KeyNotFoundException : Key '{key}' not found in configuration. This value is required when Authentication Type is set to JWT and must be provided with the key '{key}'");
            }
        }

        /// <summary>
        /// Verifies that the JWT key file exists at the specified location and is readable.
        /// Constructs the full file path using the key directory and filename with a .p12 extension.
        /// </summary>
        /// <param name="keyDir">The directory path where the key file is located.</param>
        /// <param name="keyFile">The filename of the key file without the .p12 extension.</param>
        /// <exception cref="DirectoryNotFoundException">Thrown when the key directory does not exist.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the key file is not found at the expected location.</exception>
        /// <exception cref="IOException">Thrown when the key file is found but not accessible due to permission issues.</exception>
        private void CheckKeyFileIsValid(string keyDir, string keyFile)
        {
            bool isValid;
            DirectoryInfo dirInfo = new DirectoryInfo(keyDir);

            if (!dirInfo.Exists)
            {
                throw new DirectoryNotFoundException($"{Constants.ErrorPrefix} Key directory not found at path: {keyDir}. Please review the value in the merchant configuration.");
            }

            string keyFilePath = null;
            FileInfo newFile;
            try
            {
                keyFilePath = Path.Combine(keyDir, keyFile + ".p12");
                newFile = new FileInfo(keyFilePath);
                if (!newFile.Exists)
                {
                    throw new FileNotFoundException($"{Constants.ErrorPrefix} Key file not found at path: {keyFilePath}. Please review the value in the merchant configuration.");
                }
            }
            catch (Exception)
            {
                throw new FileNotFoundException($"{Constants.ErrorPrefix} Error accessing the key file at path: {keyFilePath}. Please review the value in the merchant configuration.");
            }

            bool isReadable = false;
            try
            {
                if (newFile != null && newFile.Exists)
                {
                    using FileStream fs = newFile.Open(FileMode.Open, FileAccess.Read);
                    isReadable = true;
                }
            }
            catch
            {
                isReadable = false;
            }

            if (isReadable)
            {
                isValid = true;
            }
            else
            {
                throw new IOException($"{Constants.ErrorPrefix} Key file found but not accessible at path: {keyFilePath}. Please review the file permissions and the value in the merchant configuration.");
            }

            if (!isValid)
            {
                //Logger.Error("Error finding or accessing the Key Directory or Key File. Please review the values in the merchant configuration.");
                throw new FileNotFoundException($"{Constants.ErrorPrefix} Error finding or accessing the Key Directory or Key File. Please review the values in the merchant configuration.");
            }
        }
        #endregion JWT Settings Validation

        #region Mandatory Settings Validation
        /// <summary>
        /// Validates all mandatory merchant configuration settings that apply regardless of authentication type.
        /// This includes merchant ID, run environment, authentication type, meta key properties, and client certificate properties.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <exception cref="KeyNotFoundException">Thrown when mandatory settings are missing or empty.</exception>
        /// <exception cref="InvalidDataException">Thrown when configuration values are deprecated.</exception>
        /// <exception cref="Exception">Thrown when configuration values are invalid.</exception>
        public void ValidateMandatorySettings(IReadOnlyDictionary<string, string> configurationDictionary)
        {
            ValidateMerchantId(configurationDictionary, CredentialKeys.MerchantId);
            ValidateRunEnvironment(configurationDictionary, CredentialKeys.RunEnvironment);
            ValidateAuthenticationType(configurationDictionary, CredentialKeys.AuthenticationType);
            ValidateMetaKeyProperties(configurationDictionary, CredentialKeys.UseMetaKey, CredentialKeys.PortfolioId);
            ValidateClientCertProperties(configurationDictionary, CredentialKeys.EnableClientCert, CredentialKeys.ClientCertDirectory, CredentialKeys.ClientCertFile, CredentialKeys.ClientCertPassword);
        }

        /// <summary>
        /// Validates that the merchant ID is present and non-empty.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <param name="key">The merchant ID configuration key.</param>
        /// <exception cref="KeyNotFoundException">Thrown when the merchant ID is missing or empty.</exception>
        private void ValidateMerchantId(IReadOnlyDictionary<string, string> configurationDictionary, string key)
        {
            if (!configurationDictionary.ContainsKey(key) || string.IsNullOrEmpty(configurationDictionary[key]))
            {
                // Logger.Error($"MerchantId is mandatory in merchant configuration and must be provided with the key '{key}'");
                throw new KeyNotFoundException($"KeyNotFoundException : Key '{key}' not found in configuration. MerchantId is mandatory in merchant configuration and must be provided with the key '{key}'");
            }
        }

        /// <summary>
        /// Validates that the run environment is present, non-empty, and not deprecated.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <param name="key">The run environment configuration key.</param>
        /// <exception cref="KeyNotFoundException">Thrown when the run environment is missing or empty.</exception>
        /// <exception cref="InvalidDataException">Thrown when the run environment value is deprecated.</exception>
        private void ValidateRunEnvironment(IReadOnlyDictionary<string, string> configurationDictionary, string key)
        {
            if (!configurationDictionary.ContainsKey(key) || string.IsNullOrEmpty(configurationDictionary[key]))
            {
                //Logger.Error($"RunEnvironment is mandatory in merchant configuration and must be provided with the key '{key}'");
                throw new KeyNotFoundException($"KeyNotFoundException : Key '{key}' not found in configuration. RunEnvironment is mandatory in merchant configuration and must be provided with the key '{key}'");
            }

            if (Constants.OldRunEnvironmentConstants.Contains(configurationDictionary[key].ToUpper()))
            {
                //Logger.Error($"Deprecated RunEnvironment value: {configurationDictionary[key]}");
                throw new InvalidDataException($"{Constants.DeprecationPrefix} The value \"{configurationDictionary[key]}\" for this field `RunEnvironment` has been deprecated and will not be used anymore.\n\nPlease refer to the README file [ https://github.com/CyberSource/cybersource-rest-samples-csharp/blob/master/README.md ] for information about the new values that are accepted.");
            }
        }

        /// <summary>
        /// Validates that the authentication type is present, non-empty, and one of the supported types.
        /// Supported types are: HTTP_SIGNATURE, JWT, OAUTH, and MUTUAL_AUTH.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <param name="key">The authentication type configuration key.</param>
        /// <exception cref="KeyNotFoundException">Thrown when the authentication type is missing or empty.</exception>
        /// <exception cref="Exception">Thrown when the authentication type value is not one of the supported types.</exception>
        private void ValidateAuthenticationType(IReadOnlyDictionary<string, string> configurationDictionary, string key)
        {
            if (!configurationDictionary.ContainsKey(key) || string.IsNullOrEmpty(configurationDictionary[key]))
            {
                //Logger.Error($"AuthenticationType is mandatory in merchant configuration and must be provided with the key '{key}'");
                throw new KeyNotFoundException($"KeyNotFoundException : Key '{key}' not found in configuration. AuthenticationType is mandatory in merchant configuration and must be provided with the key '{key}'");
            }

            var supportedAuthTypes = new[] { "HTTP_SIGNATURE", "JWT", "OAUTH", "MUTUAL_AUTH" };
            if (!supportedAuthTypes.Contains(configurationDictionary[key].ToUpper(), StringComparer.OrdinalIgnoreCase))
            {
                //Logger.Error($"Invalid AuthenticationType value: {configurationDictionary[key]}. Supported values are: {string.Join(", ", supportedAuthTypes)}");
                throw new Exception($"{Constants.ErrorPrefix} Invalid AuthenticationType value: {configurationDictionary[key]}. Supported values are: {string.Join(", ", supportedAuthTypes)}");
            }
        }

        /// <summary>
        /// Validates meta key properties. If useMetaKey is enabled (true), ensures that the portfolio ID is present and non-empty.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <param name="useMetaKeyKey">The configuration key for the useMetaKey setting.</param>
        /// <param name="portfolioIdKey">The configuration key for the portfolio ID setting.</param>
        /// <exception cref="KeyNotFoundException">Thrown when portfolio ID is missing or empty when useMetaKey is true.</exception>
        /// <exception cref="Exception">Thrown when the useMetaKey value is not a valid boolean.</exception>
        private void ValidateMetaKeyProperties(IReadOnlyDictionary<string, string> configurationDictionary, string useMetaKeyKey, string portfolioIdKey)
        {
            if (configurationDictionary.ContainsKey(useMetaKeyKey))
            {
                var useMetaKeyValue = configurationDictionary[useMetaKeyKey];

                if (string.IsNullOrEmpty(useMetaKeyValue))
                {
                    useMetaKeyValue = "false";
                }

                if (bool.TryParse(useMetaKeyValue, out bool useMetaKeyBoolValue))
                {
                    if (useMetaKeyBoolValue)
                    {
                        if (configurationDictionary.ContainsKey(portfolioIdKey))
                        {
                            var portfolioIdValue = configurationDictionary[portfolioIdKey];
                            if (string.IsNullOrEmpty(portfolioIdValue))
                            {
                                //Logger.Error("Portfolio ID is mandatory when useMetaKey is true");
                                throw new KeyNotFoundException("KeyNotFoundException : Key 'portfolioID' not found in configuration. Portfolio ID is mandatory when useMetaKey is true");
                            }
                        }
                        else
                        {
                            //Logger.Error("Portfolio ID is mandatory when useMetaKey is true");
                            throw new KeyNotFoundException("KeyNotFoundException : Key 'portfolioID' not found in configuration. Portfolio ID is mandatory when useMetaKey is true");
                        }
                    }
                }
                else
                {
                    //Logger.Error($"Invalid value for {useMetaKeyKey}: {useMetaKeyValue}. Expected 'true' or 'false'.");
                    throw new Exception($"{Constants.ErrorPrefix} Invalid value for {useMetaKeyKey}: {useMetaKeyValue}. Expected 'true' or 'false'.");
                }
            }
        }

        /// <summary>
        /// Validates client certificate properties. If client certificate authentication is enabled (true), ensures that all required certificate settings are present and non-empty.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <param name="enableKey">The configuration key for enabling client certificate authentication.</param>
        /// <param name="directoryKey">The configuration key for the client certificate directory.</param>
        /// <param name="fileKey">The configuration key for the client certificate file.</param>
        /// <param name="passwordKey">The configuration key for the client certificate password.</param>
        /// <exception cref="KeyNotFoundException">Thrown when any required client certificate setting is missing or empty when client certificate authentication is enabled.</exception>
        /// <exception cref="Exception">Thrown when the enableClientCert value is not a valid boolean.</exception>
        private void ValidateClientCertProperties(IReadOnlyDictionary<string, string> configurationDictionary, string enableKey, string directoryKey, string fileKey, string passwordKey)
        {
            if (configurationDictionary.ContainsKey(enableKey))
            {
                var enableClientCertValue = configurationDictionary[enableKey];

                if (string.IsNullOrEmpty(enableClientCertValue))
                {
                    enableClientCertValue = "false";
                }

                if (bool.TryParse(enableClientCertValue, out bool enableClientCertBoolValue))
                {
                    if (enableClientCertBoolValue)
                    {
                        if (configurationDictionary.ContainsKey(directoryKey))
                        {
                            var clientCertDirectoryValue = configurationDictionary[directoryKey];
                            if (string.IsNullOrEmpty(clientCertDirectoryValue))
                            {
                                //Logger.Error("Client Certificate Directory is mandatory when enableClientCert is true");
                                throw new KeyNotFoundException("KeyNotFoundException : Key 'clientCertDirectory' not found in configuration. Client Certificate Directory is mandatory when enableClientCert is true");
                            }
                        }
                        else
                        {
                            //Logger.Error("Client Certificate Directory is mandatory when enableClientCert is true");
                            throw new KeyNotFoundException("KeyNotFoundException : Key 'clientCertDirectory' not found in configuration. Client Certificate Directory is mandatory when enableClientCert is true");
                        }

                        if (configurationDictionary.ContainsKey(fileKey))
                        {
                            var clientCertFileValue = configurationDictionary[fileKey];
                            if (string.IsNullOrEmpty(clientCertFileValue))
                            {
                                //Logger.Error("Client Certificate File is mandatory when enableClientCert is true");
                                throw new KeyNotFoundException("KeyNotFoundException : Key 'clientCertFile' not found in configuration. Client Certificate File is mandatory when enableClientCert is true");
                            }
                        }
                        else
                        {
                            //Logger.Error("Client Certificate File is mandatory when enableClientCert is true");
                            throw new KeyNotFoundException("KeyNotFoundException : Key 'clientCertFile' not found in configuration. Client Certificate File is mandatory when enableClientCert is true");
                        }

                        if (configurationDictionary.ContainsKey(passwordKey))
                        {
                            SecureString clientCertPasswordValue = ConvertToSecureString(configurationDictionary[passwordKey]);
                            try
                            {
                                if (clientCertPasswordValue == null || clientCertPasswordValue.Length == 0)
                                {
                                    //Logger.Error("Client Certificate Password is mandatory when enableClientCert is true");
                                    throw new KeyNotFoundException("KeyNotFoundException : Key 'clientCertPassword' not found in configuration. Client Certificate Password is mandatory when enableClientCert is true");
                                }
                            }
                            finally
                            {
                                clientCertPasswordValue?.Dispose();
                            }
                        }
                        else
                        {
                            //Logger.Error("Client Certificate Password is mandatory when enableClientCert is true");
                            throw new KeyNotFoundException("KeyNotFoundException : Key 'clientCertPassword' not found in configuration. Client Certificate Password is mandatory when enableClientCert is true");
                        }
                    }
                }
                else
                {
                    //Logger.Error($"Invalid value for {enableKey}: {enableClientCertValue}. Expected 'true' or 'false'.");
                    throw new Exception($"{Constants.ErrorPrefix} Invalid value for {enableKey}: {enableClientCertValue}. Expected 'true' or 'false'.");
                }
            }
        }
        #endregion Mandatory Settings Validation

        #region Mutual Auth Settings Validation
        /// <summary>
        /// Validates Mutual Auth authentication-specific configuration settings.
        /// Ensures that both the client ID and client secret are present and non-empty.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <exception cref="KeyNotFoundException">Thrown when required Mutual Auth settings (clientId or clientSecret) are missing or empty.</exception>
        public void ValidateMutualAuthSettings(IReadOnlyDictionary<string, string> configurationDictionary)
        {
            ValidateForMutualAuth(configurationDictionary, CredentialKeys.ClientId);
            ValidateForMutualAuth(configurationDictionary, CredentialKeys.ClientSecret);
        }

        /// <summary>
        /// Validates that a required Mutual Auth configuration key exists and is non-empty.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <param name="key">The configuration key to validate.</param>
        /// <exception cref="KeyNotFoundException">Thrown when the key is missing or the value is null or empty.</exception>
        private void ValidateForMutualAuth(IReadOnlyDictionary<string, string> configurationDictionary, string key)
        {
            if (!configurationDictionary.ContainsKey(key) || string.IsNullOrEmpty(configurationDictionary[key]))
            {
                throw new KeyNotFoundException($"KeyNotFoundException : Key '{key}' not found in configuration. This value is required when Authentication Type is set to Mutual_Auth and must be provided with the key '{key}'");
            }
        }
        #endregion Mutual Auth Settings Validation

        #region OAuth Settings Validation
        /// <summary>
        /// Validates OAuth authentication-specific configuration settings.
        /// Ensures that both the access token and refresh token are present and non-empty.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <exception cref="KeyNotFoundException">Thrown when required OAuth settings (accessToken or refreshToken) are missing or empty.</exception>
        public void ValidateOAuthSettings(IReadOnlyDictionary<string, string> configurationDictionary)
        {
            ValidateForOAuth(configurationDictionary, CredentialKeys.AccessToken);
            ValidateForOAuth(configurationDictionary, CredentialKeys.RefreshToken);
        }

        /// <summary>
        /// Validates that a required OAuth configuration key exists and is non-empty.
        /// </summary>
        /// <param name="configurationDictionary">A dictionary containing merchant configuration key-value pairs.</param>
        /// <param name="key">The configuration key to validate.</param>
        /// <exception cref="KeyNotFoundException">Thrown when the key is missing or the value is null or empty.</exception>
        private void ValidateForOAuth(IReadOnlyDictionary<string, string> configurationDictionary, string key)
        {
            if (!configurationDictionary.ContainsKey(key) || string.IsNullOrEmpty(configurationDictionary[key]))
            {
                throw new KeyNotFoundException($"KeyNotFoundException : Key '{key}' not found in configuration. This value is required when Authentication Type is set to OAuth and must be provided with the key '{key}'");
            }
        }
        #endregion OAuth Settings Validation

        #region Helper Methods
        private static string ConvertFromSecureString(SecureString secureString)
        {
            if (secureString == null) { return null; }

            IntPtr ptr = System.Runtime.InteropServices.Marshal.SecureStringToGlobalAllocUnicode(secureString);
            try
            {
                return System.Runtime.InteropServices.Marshal.PtrToStringUni(ptr);
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
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
