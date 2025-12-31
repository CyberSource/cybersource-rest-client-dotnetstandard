using System;

namespace AuthenticationSdk.util
{
    /// <summary>
    /// POJO class for caching MLE KID and lastModified file timestamp.
    /// The presence or absence of the KID indicates whether the file is a CyberSource-generated P12:
    /// - kid != null: CyberSource P12 file, KID successfully extracted
    /// - kid == null: Either non-CyberSource P12 or extraction failed
    /// </summary>
    public class CachedMLEKId
    {
        /// <summary>
        /// Gets or sets the Key ID (KID) extracted from the certificate.
        /// Null indicates either a non-CyberSource P12 or extraction failure.
        /// </summary>
        public string Kid { get; set; }

        /// <summary>
        /// Gets or sets the last modified timestamp of the file.
        /// </summary>
        public DateTime LastModifiedTimeStamp { get; set; }
    }
}
