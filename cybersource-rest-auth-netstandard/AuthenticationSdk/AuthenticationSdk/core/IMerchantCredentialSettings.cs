using System;
using System.Collections.Generic;
using System.Text;

namespace AuthenticationSdk.core
{
    public interface IMerchantCredentialSettings
    {
        /// <summary>
        /// Gets the Merchant Identifier associated with this instance.
        /// </summary>
        string MerchantId { get; }

        /// <summary>
        /// Gets the Portfolio Identifier associated with this instance.
        /// </summary>
        string PortfolioId { get; }

        /// <summary>
        /// Gets the shared secret key used to authenticate requests using HTTP Signature.
        /// </summary>
        string MerchantSecretKey { get; }

        /// <summary>
        /// Gets the identifier for the shared secret key used in authentication.
        /// </summary>
        string MerchantKeyId { get; }

        /// <summary>
        /// Gets a string representation of the boolean value indicating whether to use the MetaKey for authentication.
        /// </summary>
        string UseMetaKey { get; }

        /// <summary>
        /// Gets a string representation of the boolean value indicating whether client certificate authentication is enabled.
        /// </summary>
        string EnableClientCert { get; }

        /// <summary>
        /// Gets the file system directory path where client certificates are stored.
        /// </summary>
        string ClientCertDirectory { get; }

        /// <summary>
        /// Gets the filename of the client certificate used for authentication.
        /// </summary>
        string ClientCertFile { get; }

        /// <summary>
        /// Gets the password used to access the client certificate for authentication.
        /// </summary>
        string ClientCertPassword { get; }

        /// <summary>
        /// Gets the Client Identifier to be used for mutual authentication flow.
        /// </summary>
        string ClientId { get; }

        /// <summary>
        /// Gets the OAuth 2.0 access token used for mutual authentication flow.
        /// </summary>
        string AccessToken { get; }

        /// <summary>
        /// Gets the refresh token used to obtain a new access token when the current token expires.
        /// </summary>
        string RefreshToken { get; }

        /// <summary>
        /// Gets the client secret used to authenticate the application with the mutual authentication service.
        /// </summary>
        string ClientSecret { get; }

        /// <summary>
        /// Gets the type of authentication used to identify the user.
        /// </summary>
        string AuthenticationType { get; }

        /// <summary>
        /// Gets the file system directory path where PKCS#12 certificates are stored.
        /// </summary>
        string KeyDirectory { get; }

        /// <summary>
        /// Gets the filename of the PKCS#12 file associated with the current instance.
        /// </summary>
        string KeyfileName { get; }

        /// <summary>
        /// Gets the alias name associated with the certificate inside the PKCS#12 certificate file.
        /// </summary>
        string KeyAlias { get; }

        /// <summary>
        /// Gets the password used to access the PKCS#12 certificate file.
        /// </summary>
        string KeyPass { get; }

        /// <summary>
        /// Gets the full file path to the PKCS#12 certificate file, combining the directory and filename.
        /// </summary>
        string P12Keyfilepath { get; }

        /// <summary>
        /// Gets the JWT key type. Supported values: "P12" (default) or "SHARED_SECRET".
        /// When "SHARED_SECRET", HMAC-SHA256 signing is used with MerchantKeyId and MerchantSecretKey.
        /// </summary>
        string JwtKeyType { get; }

        /// <summary>
        /// Gets the domain name of the environment to which requests will be sent.
        /// </summary>
        string RunEnvironment { get; }

        /// <summary>
        /// Gets the hostname of the server to which requests will be sent.
        /// </summary>
        string HostName { get; }

        /// <summary>
        /// Gets the hostname of the intermediate server used for network routing.
        /// </summary>
        string IntermediateHost { get; }

        /// <summary>
        /// Gets the directory path where PEM files are stored or accessed.
        /// </summary>
        string PemFileDirectory { get; }
    }
}
