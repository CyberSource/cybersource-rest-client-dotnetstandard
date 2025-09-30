using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticationSdk.util
{
    public static class Utility
    {

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
                    password == null ? string.Empty : new System.Net.NetworkCredential(string.Empty, password).Password,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet
                );

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
