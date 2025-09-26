using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace AuthenticationSdk.util
{
    public static class Utility
    {
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
                // Convert SecureString to string for X509Certificate2
                string pwd = password == null ? string.Empty : new System.Net.NetworkCredential(string.Empty, password).Password;
                // Load the certificate (including private key) from the P12 file
                var cert = new X509Certificate2(
                    p12FilePath,
                    pwd,
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

        /// <summary>
        /// Extracts private key supporting PKCS#1 and PKCS#8, encrypted and unencrypted
        /// </summary>
        /// <param name="pemContent">PEM content as string</param>
        /// <param name="password">Password for encrypted keys (optional, SecureString)</param>
        /// <returns>RSA private key object</returns>
        public static RSA ExtractPrivateKey(string pemContent, SecureString password = null)
        {
            try
            {
                // First try with PemReader (handles most PEM formats)
                var privateKey = ExtractWithPemReader(pemContent, password);
                if (privateKey != null)
                {
                    return ConvertToRSA(privateKey);
                }

                // If PemReader fails, try manual parsing
                return ExtractWithManualParsing(pemContent, password);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to extract private key: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Extracts private key from file
        /// </summary>
        /// <param name="filePath">Path to PEM file</param>
        /// <param name="password">Password for encrypted keys (optional, SecureString)</param>
        /// <returns>RSA private key object</returns>
        public static RSA ExtractPrivateKeyFromFile(string filePath, SecureString password = null)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"Private key file not found: {filePath}");
            }

            string pemContent = File.ReadAllText(filePath);
            return ExtractPrivateKey(pemContent, password);
        }

        /// <summary>
        /// Extract using PemReader (handles standard PEM formats)
        /// </summary>
        /// <param name="pemContent">PEM content as string</param>
        /// <param name="password">Password for encrypted keys (optional, SecureString)</param>
        /// <returns>BouncyCastle AsymmetricKeyParameter</returns>
        private static AsymmetricKeyParameter ExtractWithPemReader(string pemContent, SecureString password)
        {
            try
            {
                using var stringReader = new StringReader(pemContent);
                var pemReader = new PemReader(stringReader, new PasswordFinder(password));

                var keyObject = pemReader.ReadObject();

                if (keyObject is AsymmetricCipherKeyPair keyPair)
                {
                    return keyPair.Private;
                }
                else if (keyObject is AsymmetricKeyParameter keyParam && keyParam.IsPrivate)
                {
                    return keyParam;
                }

                return null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Manual parsing for different key formats
        /// </summary>
        /// <param name="pemContent">PEM content as string</param>
        /// <param name="password">Password for encrypted keys (optional, SecureString)</param>
        /// <returns>RSA private key object</returns>
        private static RSA ExtractWithManualParsing(string pemContent, SecureString password)
        {
            // Remove PEM headers and decode base64
            var base64Content = ExtractBase64FromPem(pemContent);
            var keyBytes = Convert.FromBase64String(base64Content);

            // Determine the key format and handle accordingly
            if (IsKeyPkcs8Format(pemContent))
            {
                return HandlePkcs8Key(keyBytes, password);
            }
            else if (IsKeyPkcs1Format(pemContent))
            {
                return HandlePkcs1Key(keyBytes, password);
            }
            else
            {
                throw new NotSupportedException("Unsupported key format");
            }
        }

        /// <summary>
        /// Check if PEM content is PKCS#8 format
        /// </summary>
        /// <param name="pemContent">PEM content as string</param>
        /// <returns>True if PKCS#8 format</returns>
        private static bool IsKeyPkcs8Format(string pemContent)
        {
            return pemContent.Contains(Constants.PKCS8_PRIVATE_KEY_HEADER) ||
                   pemContent.Contains(Constants.PKCS8_ENCRYPTED_PRIVATE_KEY_HEADER);
        }

        /// <summary>
        /// Handle PKCS#8 format keys (encrypted and unencrypted)
        /// </summary>
        /// <param name="keyBytes">Key bytes</param>
        /// <param name="password">Password for encrypted keys (optional, SecureString)</param>
        /// <returns>RSA private key object</returns>
        private static RSA HandlePkcs8Key(byte[] keyBytes, SecureString password)
        {
            try
            {
                if (password == null || password.Length == 0)
                {
                    // Unencrypted PKCS#8
                    var privateKeyInfo = PrivateKeyInfo.GetInstance(keyBytes);
                    var privateKey = PrivateKeyFactory.CreateKey(privateKeyInfo);
                    return ConvertToRSA(privateKey);
                }
                else
                {
                    // Encrypted PKCS#8
                    char[] pwdChars = new System.Net.NetworkCredential(string.Empty, password).Password.ToCharArray();
                    var encryptedPrivateKeyInfo = EncryptedPrivateKeyInfo.GetInstance(keyBytes);
                    var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(
                        pwdChars, encryptedPrivateKeyInfo);
                    Array.Clear(pwdChars, 0, pwdChars.Length); // Clear password from memory
                    var privateKey = PrivateKeyFactory.CreateKey(privateKeyInfo);
                    return ConvertToRSA(privateKey);
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Possible causes: wrong password, corrupted file, or unsupported format.: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Check if PEM content is PKCS#1 format
        /// </summary>
        /// <param name="pemContent">PEM content as string</param>
        /// <returns>True if PKCS#1 format</returns>
        private static bool IsKeyPkcs1Format(string pemContent)
        {
            return pemContent.Contains(Constants.PKCS1_PRIVATE_KEY_HEADER);
        }

        /// <summary>
        /// Handle PKCS#1 format keys
        /// </summary>
        /// <param name="keyBytes">Key bytes</param>
        /// <param name="password">Password for encrypted keys (optional, SecureString)</param>
        /// <returns>RSA private key object</returns>
        private static RSA HandlePkcs1Key(byte[] keyBytes, SecureString password)
        {
            try
            {
                // Parse PKCS#1 RSA private key
                var rsaPrivateKey = RsaPrivateKeyStructure.GetInstance(keyBytes);
                var rsaParams = new RsaPrivateCrtKeyParameters(
                    rsaPrivateKey.Modulus,
                    rsaPrivateKey.PublicExponent,
                    rsaPrivateKey.PrivateExponent,
                    rsaPrivateKey.Prime1,
                    rsaPrivateKey.Prime2,
                    rsaPrivateKey.Exponent1,
                    rsaPrivateKey.Exponent2,
                    rsaPrivateKey.Coefficient);

                return ConvertToRSA(rsaParams);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Possible causes: wrong password, corrupted file, or unsupported format.: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Convert Bouncy Castle RSA parameters to .NET RSA object
        /// </summary>
        /// <param name="privateKey">BouncyCastle AsymmetricKeyParameter</param>
        /// <returns>.NET RSA object</returns>
        private static RSA ConvertToRSA(AsymmetricKeyParameter privateKey)
        {
            if (!(privateKey is RsaPrivateCrtKeyParameters rsaParams))
            {
                throw new InvalidOperationException("Key is not an RSA private key");
            }

            var rsa = RSA.Create();
            var parameters = new RSAParameters
            {
                Modulus = rsaParams.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaParams.PublicExponent.ToByteArrayUnsigned(),
                D = rsaParams.Exponent.ToByteArrayUnsigned(),
                P = rsaParams.P.ToByteArrayUnsigned(),
                Q = rsaParams.Q.ToByteArrayUnsigned(),
                DP = rsaParams.DP.ToByteArrayUnsigned(),
                DQ = rsaParams.DQ.ToByteArrayUnsigned(),
                InverseQ = rsaParams.QInv.ToByteArrayUnsigned()
            };

            rsa.ImportParameters(parameters);
            return rsa;
        }

        /// <summary>
        /// Extract base64 content from PEM format
        /// </summary>
        /// <param name="pemContent">PEM content as string</param>
        /// <returns>Base64 string</returns>
        private static string ExtractBase64FromPem(string pemContent)
        {
            var lines = pemContent.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            var base64Lines = new System.Collections.Generic.List<string>();

            bool inKey = false;
            foreach (var line in lines)
            {
                if (line.StartsWith("-----BEGIN"))
                {
                    inKey = true;
                    continue;
                }
                if (line.StartsWith("-----END"))
                {
                    break;
                }
                // Skip encryption headers
                if (inKey && !line.StartsWith("Proc-Type:") && !line.StartsWith("DEK-Info:"))
                {
                    base64Lines.Add(line.Trim());
                }
            }

            return string.Join("", base64Lines);
        }

        /// <summary>
        /// Password finder for encrypted keys
        /// </summary>
        private class PasswordFinder : IPasswordFinder
        {
            private readonly SecureString _password;

            /// <summary>
            /// Initializes a new instance of the PasswordFinder class.
            /// </summary>
            /// <param name="password">Password as SecureString</param>
            public PasswordFinder(SecureString password)
            {
                _password = password;
            }

            /// <summary>
            /// Returns the password as a char array for BouncyCastle
            /// </summary>
            /// <returns>Char array of password</returns>
            public char[] GetPassword()
            {
                if (_password == null || _password.Length == 0)
                {
                    return null;
                }
                var pwd = new System.Net.NetworkCredential(string.Empty, _password).Password.ToCharArray();
                return pwd;
            }
        }

        /// <summary>
        /// Get detailed information about the extracted key
        /// </summary>
        /// <param name="pemContent">PEM content as string</param>
        /// <param name="password">Password for encrypted keys (optional, SecureString)</param>
        /// <returns>KeyInfo object with details</returns>
        public static KeyInfo GetKeyInfo(string pemContent, SecureString password = null)
        {
            using var rsa = ExtractPrivateKey(pemContent, password);
            var parameters = rsa.ExportParameters(false); // Export public parameters only for info

            return new KeyInfo
            {
                KeySize = rsa.KeySize,
                KeyFormat = DetermineKeyFormat(pemContent),
                IsEncrypted = DetermineIfEncrypted(pemContent),
                ModulusSize = parameters.Modulus?.Length * 8 ?? 0
            };
        }

        /// <summary>
        /// Determines the key format from PEM content
        /// </summary>
        /// <param name="pemContent">PEM content as string</param>
        /// <returns>Key format string</returns>
        private static string DetermineKeyFormat(string pemContent)
        {
            if (IsKeyPkcs8Format(pemContent))
            {
                return "PKCS#8";
            }
            else if (IsKeyPkcs1Format(pemContent))
            {
                return "PKCS#1";
            }
            else
            {
                return "Unknown";
            }
        }

        /// <summary>
        /// Determines if the key is encrypted from PEM content
        /// </summary>
        /// <param name="pemContent">PEM content as string</param>
        /// <returns>True if encrypted</returns>
        private static bool DetermineIfEncrypted(string pemContent)
        {
            return pemContent.Contains(Constants.PKCS8_ENCRYPTED_PRIVATE_KEY_HEADER) ||
                   pemContent.Contains(Constants.PROC_TYPE_ENCRYPTED_HEADER);
        }
    }

    /// <summary>
    /// Information about a cryptographic key
    /// </summary>
    public class KeyInfo
    {
        public int KeySize { get; set; }
        public string KeyFormat { get; set; }
        public bool IsEncrypted { get; set; }
        public int ModulusSize { get; set; }

        public override string ToString()
        {
            return $"Key Size: {KeySize} bits, Format: {KeyFormat}, Encrypted: {IsEncrypted}, Modulus: {ModulusSize} bits";
        }
    }
}
