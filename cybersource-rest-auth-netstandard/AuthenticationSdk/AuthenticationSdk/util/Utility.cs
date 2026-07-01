using NLog;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticationSdk.util
{
    public static class Utility
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        /// <summary>
        /// Determines the <see cref="X509KeyStorageFlags"/> to use when importing a PKCS#12 keystore.
        /// Uses <see cref="X509KeyStorageFlags.EphemeralKeySet"/> (key kept in memory only, never written
        /// to the on-disk key store) on platforms that support it, so the SDK works in sandboxed
        /// environments such as .NET MAUI on Windows, iOS and Android. macOS does not support
        /// EphemeralKeySet, so it falls back to <see cref="X509KeyStorageFlags.Exportable"/>.
        /// PersistKeySet is intentionally not used: it is a Windows key-container concept, and the
        /// only flow that reads the private key (JWT RS256 signing) requires the key to be exportable
        /// for BouncyCastle interop, not persisted. Cached certificates keep their in-memory key alive
        /// on Unix platforms for the duration they remain in MemoryCache.
        /// </summary>
        /// <remarks>
        /// EphemeralKeySet and PersistKeySet are mutually exclusive and must not be combined.
        /// </remarks>
        internal static X509KeyStorageFlags GetP12KeyStorageFlags()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return X509KeyStorageFlags.Exportable;
            }

            return X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet;
        }

        /// <summary>
        /// Validates that a configuration value is a positive integer.
        /// Returns the value if valid, or the default with a warning log if invalid/null.
        /// </summary>
        /// <param name="value">The configuration value to validate</param>
        /// <param name="fieldName">The name of the field (for logging purposes)</param>
        /// <param name="defaultValue">The default value to use if validation fails (can be null)</param>
        /// <returns>The validated value or default</returns>
        public static string GetPositiveIntOrDefault(string value, string fieldName, string defaultValue)
        {
            if (value != null)
            {
                if (int.TryParse(value, out int parsed) && parsed > 0)
                {
                    return value;
                }

                Logger.Warn($"Invalid {fieldName} value '{value}'. Must be a positive integer. Using default: {defaultValue ?? "null"}");
            }
            else
            {
                Logger.Warn($"{fieldName} is not set. Using default: {defaultValue ?? "null"}");
            }

            return defaultValue;
        }

        /// <summary>
        /// Reads a private key from a PKCS#12 (.p12 or .pfx) file.
        /// </summary>
        /// <param name="p12FilePath">Path to the PKCS#12 file.</param>
        /// <param name="password">Password to unlock the file as SecureString.</param>
        /// <returns>The RSA or ECDsa private key.</returns>
        /// <exception cref="FileNotFoundException">If the file doesn't exist.</exception>
        /// <exception cref="InvalidOperationException">If no private key is found.</exception>
        /// <exception cref="CryptographicException">If the file is invalid or the password is wrong.</exception>
        public static AsymmetricAlgorithm ReadPrivateKeyFromP12(string p12FilePath, SecureString password = null)
        {
            if (string.IsNullOrWhiteSpace(p12FilePath))
            {
                throw new ArgumentException("File path cannot be null or empty", nameof(p12FilePath));
            }

            try
            {
                // Load the certificate (including private key) from the P12 file
                var cert = new X509Certificate2(
                    p12FilePath,
                    password == null ? string.Empty : new System.Net.NetworkCredential(string.Empty, password).Password, GetP12KeyStorageFlags());

                // Check if private key exists
                if (!cert.HasPrivateKey)
                {
                    throw new InvalidOperationException("No private key found in the P12 file.");
                }

                // Try RSA key
                var rsaKey = cert.GetRSAPrivateKey();
                if (rsaKey != null)
                {
                    return rsaKey;
                }

                throw new InvalidOperationException("Private key found but unsupported algorithm type.");
            }
            catch (CryptographicException ex)
            {
                throw new CryptographicException("Failed to read private key. Possible causes: wrong password, corrupted file, or unsupported format.", ex);
            }
            catch (InvalidOperationException ex)
            {
                if (ex.Message.Contains("No private key found"))
                {
                    throw new InvalidOperationException("No private key found in the P12 file.", ex);
                }
                else if (ex.Message.Contains("unsupported algorithm type"))
                {
                    throw new InvalidOperationException("Private key found but unsupported algorithm type.", ex);
                }
                throw;
            }
        }

        public static SecureString ConvertStringToSecureString(string password)
        {
            if (string.IsNullOrEmpty(password))
                return null;
            var securePassword = new SecureString();
            foreach (char c in password)
            {
                securePassword.AppendChar(c);
            }
            securePassword.MakeReadOnly();
            return securePassword;
        }

        /// <summary>
        /// Checks if the provided string represents a valid boolean value ("true" or "false", case-insensitive).
        /// </summary>
        /// <param name="value">The string to validate.</param>
        /// <returns>True if the string is "true" or "false" (case-insensitive); otherwise, false.</returns>
        public static bool IsValidBooleanString(string value)
        {
            return string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(value, "false", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Extracts private key from file
        /// </summary>
        /// <param name="filePath">Path to PEM file</param>
        /// <param name="password">Password for encrypted keys (optional, SecureString)</param>
        /// <returns>RSA private key object</returns>
        public static RSA ExtractPrivateKeyFromFile(string filePath, SecureString password = null)
        {
            return PEMUtility.ExtractPrivateKeyFromFile(filePath, password);
        }

    }

}
