using NLog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AuthenticationSdk.util
{
    /// <summary>
    /// Utility class providing methods that can process certificates
    /// </summary>
    public class CertificateUtility
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        /// <summary>
        /// Validates that the given file path exists and is not empty.
        /// </summary>
        /// <param name="filePath">The file path to validate.</param>
        /// <param name="pathType">A description of the path type (e.g., "Input file").</param>
        /// <exception cref="ArgumentException">If the path is null or empty.</exception>
        /// <exception cref="IOException">If the file does not exist.</exception>
        public static void ValidatePathAndFile(string filePath, string pathType)
        {
            if (string.IsNullOrEmpty(filePath.Trim()))
            {
                logger.Error(pathType + " path cannot be null or empty.");
                throw new ArgumentException(pathType + " path cannot be null or empty.");
            }

            // Normalize Windows-style paths that start with a slash before the drive letter
            string normalizedPath = filePath;
            if (Path.DirectorySeparatorChar == '\\' && Regex.IsMatch(normalizedPath, @"^/[A-Za-z]:.*"))
            {
                normalizedPath = normalizedPath.Substring(1);
            }

            string path = normalizedPath;
            if (!File.Exists(path))
            {
                logger.Error($"{pathType} does not exist: {path}");
                throw new IOException($"{pathType} does not exist: {path}");
            }
            if ((File.GetAttributes(path) & FileAttributes.Directory) == FileAttributes.Directory)
            {
                logger.Error($"{pathType} does not have valid file: {path}");
                throw new IOException($"{pathType} does not have valid file: {path}");
            }
            try
            {
                using (FileStream fs = File.Open(path, FileMode.Open, FileAccess.Read))
                {
                    // File is readable
                }
            }
            catch (Exception)
            {
                logger.Error($"{pathType} is not readable: {path}");
                throw new IOException($"{pathType} is not readable: {path}");
            }
        }

        public static X509Certificate2Collection LoadCertificatesFromPemFile(string certificateFilePath)
        {
            byte[] certBytes = File.ReadAllBytes(certificateFilePath);

            var collection = new X509Certificate2Collection();
            collection.Import(certBytes);

            return collection;
        }

        public static void ValidateCertificateExpiry(X509Certificate2 certificate, string keyAlias, string mleCacheKeyIdentifier)
        {
            string warningMessageForNoExpiryDate = "Certificate does not have expiry date";
            string warningMessageForCertificateExpiringSoon = "Certificate with alias {} is going to expire on {}. Please update the certificate before then.";
            string warningMessageForExpiredCertificate = "Certificate with alias {} is expired as of {}. Please update the certificate.";

            if (Constants.MLE_CACHE_IDENTIFIER_FOR_CONFIG_CERT.Equals(mleCacheKeyIdentifier))
            {
                warningMessageForNoExpiryDate = "Certificate for MLE Requests does not have expiry date from mleForRequestPublicCertPath in merchant configuration.";
                warningMessageForCertificateExpiringSoon = "Certificate for MLE Requests with alias {} is going to expire on {}. Please update the certificate provided in mleForRequestPublicCertPath in merchant configuration before then.";
                warningMessageForExpiredCertificate = "Certificate for MLE Requests with alias {} is expired as of {}. Please update the certificate provided in mleForRequestPublicCertPath in merchant configuration.";
            }

            if (Constants.MLE_CACHE_IDENTIFIER_FOR_P12_CERT.Equals(mleCacheKeyIdentifier))
            {
                warningMessageForNoExpiryDate = "Certificate for MLE Requests does not have expiry date in the P12 file.";
                warningMessageForCertificateExpiringSoon = "Certificate for MLE Requests with alias {} is going to expire on {}. Please update the P12 file before then.";
                warningMessageForExpiredCertificate = "Certificate for MLE Requests with alias {} is expired as of {}. Please update the P12 file.";
            }

            if (certificate.NotAfter == DateTime.MinValue)
            {
                // Certificate does not have an expiry date
                logger.Warn(warningMessageForNoExpiryDate);
            }
            else if (certificate.NotAfter < DateTime.Now)
            {
                // Certificate is already expired
                logger.Warn(warningMessageForExpiredCertificate, keyAlias, certificate.NotAfter);
            }
            else
            {
                TimeSpan timeToExpire = certificate.NotAfter - DateTime.Now;
                if (timeToExpire.TotalDays < Constants.CertificateExpiryDateWarningDays)
                {
                    logger.Warn(warningMessageForCertificateExpiringSoon, keyAlias, certificate.NotAfter);
                }
            }
        }

        /// <summary>
        /// Extracts the serial number from an X509 certificate.
        /// First tries to get it from the Subject DN, then falls back to the certificate's SerialNumber property.
        /// </summary>
        /// <param name="x509Certificate">The X509 certificate to extract the serial number from.</param>
        /// <returns>The extracted serial number.</returns>
        /// <exception cref="ArgumentNullException">If the certificate is null.</exception>
        public static string ExtractSerialNumber(X509Certificate2 x509Certificate)
        {
            if (x509Certificate == null)
            {
                logger.Error("MLE certificate is null");
                throw new ArgumentNullException(nameof(x509Certificate), "MLE certificate is null");
            }

            string serialNumber = null;
            string serialNumberPrefix = "SERIALNUMBER=";
            string principal = x509Certificate.Subject.ToUpperInvariant();
            int beg = principal.IndexOf(serialNumberPrefix);
            
            if (beg >= 0)
            {
                int end = principal.IndexOf(',', beg);
                if (end > beg)
                {
                    serialNumber = principal.Substring(beg + serialNumberPrefix.Length, end - beg - serialNumberPrefix.Length).Trim();
                }
                else
                {
                    serialNumber = principal.Substring(beg + serialNumberPrefix.Length).Trim();
                }
            }

            if (string.IsNullOrEmpty(serialNumber))
            {
                logger.Warn($"Serial number not found in certificate subject DN, using certificate SerialNumber property");
                return x509Certificate.SerialNumber;
            }

            return serialNumber;
        }

        /// <summary>
        /// Retrieves a certificate by alias from a PKCS12 keystore.
        /// </summary>
        /// <param name="filePath">The path to the PKCS12 (.p12/.pfx) file</param>
        /// <param name="password">The password to unlock the keystore</param>
        /// <param name="alias">The certificate alias to search for</param>
        /// <returns>The matching X509Certificate2, or null if not found</returns>
        /// <exception cref="ArgumentException">If required parameters are invalid</exception>
        public static X509Certificate2 GetCertificateByAliasFromP12(string filePath, string password, string alias)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                throw new ArgumentException("File path cannot be null or empty", nameof(filePath));
            }

            if (string.IsNullOrEmpty(alias))
            {
                throw new ArgumentException("Alias cannot be null or empty", nameof(alias));
            }

            if (!File.Exists(filePath))
            {
                logger.Error($"P12/PFX file not found: {filePath}");
                return null;
            }

            try
            {
                X509Certificate2Collection collection = new X509Certificate2Collection();
                collection.Import(filePath, password, X509KeyStorageFlags.Exportable);

                foreach (X509Certificate2 cert in collection)
                {
                    string subjectDN = cert.Subject.ToUpperInvariant();
                    
                    // Search for alias in Common Name (CN)
                    if (subjectDN.Contains("CN=" + alias.ToUpperInvariant()))
                    {
                        logger.Debug($"Certificate found for alias '{alias}' in P12 file");
                        return cert;
                    }
                }

                logger.Debug($"No certificate found for alias '{alias}' in P12 file");
                return null;
            }
            catch (Exception ex)
            {
                logger.Error($"Error while retrieving certificate by alias from P12 file: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Checks if a P12/PFX file is generated by CyberSource by looking for the default MLE certificate alias.
        /// </summary>
        /// <param name="filePath">The path to the PKCS12 (.p12/.pfx) file</param>
        /// <param name="password">The password to unlock the keystore</param>
        /// <returns>True if the P12 is CyberSource-generated, false otherwise</returns>
        public static bool IsP12GeneratedByCyberSource(string filePath, string password)
        {
            try
            {
                X509Certificate2 cyberSourceCert = GetCertificateByAliasFromP12(
                    filePath, 
                    password, 
                    Constants.DefaultMleAliasForCert
                );
                return cyberSourceCert != null;
            }
            catch (Exception ex)
            {
                logger.Error($"Error while checking if P12 is generated by CyberSource: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Gets the file extension from a file name or path.
        /// </summary>
        /// <param name="fileName">The file name or path</param>
        /// <returns>The file extension without the dot, or empty string if no extension</returns>
        public static string GetFileExtension(string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
                return string.Empty;

            int dotIndex = fileName.LastIndexOf('.');
            return dotIndex == -1 ? string.Empty : fileName.Substring(dotIndex + 1);
        }

        /// <summary>
        /// Extracts the serial number (KID) from a certificate's subject in a P12 file where CN matches the merchantId.
        /// This is used for Response MLE KID extraction.
        /// </summary>
        /// <param name="filePath">Path to the P12 file</param>
        /// <param name="password">Password for the P12 file</param>
        /// <param name="merchantId">The merchant ID to match against the CN in the certificate subject</param>
        /// <returns>The serial number extracted from the certificate's subject, or null if not found</returns>
        public static string ExtractResponseMleKidFromP12(string filePath, string password, string merchantId)
        {
            try
            {
                logger.Debug($"Extracting MLE KID from P12 file: {filePath} for merchantId: {merchantId}");

                // Load all certificates from P12 file
                X509Certificate2Collection collection = new X509Certificate2Collection();
                collection.Import(filePath, password, X509KeyStorageFlags.Exportable);

                if (collection.Count == 0)
                {
                    logger.Error($"No certificates found in P12 file: {filePath}");
                    return null;
                }

                logger.Debug($"Found {collection.Count} certificate(s) in P12 file");

                // Iterate through certificates to find one with CN matching merchantId
                foreach (X509Certificate2 cert in collection)
                {
                    if (cert.Subject == null)
                    {
                        logger.Debug("Certificate has no subject, skipping");
                        continue;
                    }

                    // Extract CN from certificate subject
                    string cn = ExtractCommonName(cert);

                    if (string.IsNullOrEmpty(cn))
                    {
                        logger.Debug($"Certificate has no CN in subject: {cert.Subject}, skipping");
                        continue;
                    }

                    logger.Debug($"Certificate CN: {cn}");

                    // Check if CN matches merchantId (case-insensitive)
                    if (cn.Equals(merchantId, StringComparison.OrdinalIgnoreCase))
                    {
                        logger.Debug($"Found certificate with matching CN: {cn}");

                        // Extract serial number from certificate subject
                        string serialNumber = ExtractSerialNumber(cert);

                        if (!string.IsNullOrEmpty(serialNumber))
                        {
                            logger.Debug($"Serial number (MLE KID) extracted: {serialNumber}");
                            return serialNumber;
                        }
                        else
                        {
                            logger.Warn($"Certificate with CN={cn} found but has no serial number in subject");
                        }
                    }
                }

                // If we get here, no matching certificate was found
                logger.Error($"No certificate with CN matching merchantId ({merchantId}) found in P12 file: {filePath}");
                return null;

            }
            catch (Exception ex)
            {
                logger.Error($"Error extracting MLE KID from P12 file: {filePath}: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Extracts the Common Name (CN) from a certificate's subject.
        /// </summary>
        /// <param name="cert">The X509Certificate2 to extract CN from</param>
        /// <returns>The CN value, or null if not found</returns>
        private static string ExtractCommonName(X509Certificate2 cert)
        {
            if (cert == null || string.IsNullOrEmpty(cert.Subject))
            {
                return null;
            }

            // Parse the subject DN to find CN
            string subject = cert.Subject.ToUpperInvariant();
            string cnPrefix = "CN=";
            int cnIndex = subject.IndexOf(cnPrefix);

            if (cnIndex >= 0)
            {
                int startIndex = cnIndex + cnPrefix.Length;
                int endIndex = subject.IndexOf(',', startIndex);

                if (endIndex > startIndex)
                {
                    return cert.Subject.Substring(startIndex, endIndex - startIndex).Trim();
                }
                else
                {
                    return cert.Subject.Substring(startIndex).Trim();
                }
            }

            return null;
        }
    }
}
