using System;
using System.Collections.Generic;
using System.Text;

namespace AuthenticationSdk.core
{
    /// <summary>
    /// Internal mutable interface for merchant credential settings.
    /// Provides methods to set each property to allow configuration during initialization.
    /// </summary>
    internal interface IMutableMerchantCredentialSettings : IMerchantCredentialSettings
    {
        /// <summary>
        /// Sets the Merchant Identifier associated with this instance.
        /// </summary>
        void SetMerchantId(string value);

        /// <summary>
        /// Sets the Portfolio Identifier associated with this instance.
        /// </summary>
        void SetPortfolioId(string value);

        /// <summary>
        /// Sets the shared secret key used to authenticate requests using HTTP Signature.
        /// </summary>
        void SetMerchantSecretKey(string value);

        /// <summary>
        /// Sets the identifier for the shared secret key used in authentication.
        /// </summary>
        void SetMerchantKeyId(string value);

        /// <summary>
        /// Sets a string representation of the boolean value indicating whether to use the MetaKey for authentication.
        /// </summary>
        void SetUseMetaKey(string value);

        /// <summary>
        /// Sets a string representation of the boolean value indicating whether client certificate authentication is enabled.
        /// </summary>
        void SetEnableClientCert(string value);

        /// <summary>
        /// Sets the file system directory path where client certificates are stored.
        /// </summary>
        void SetClientCertDirectory(string value);

        /// <summary>
        /// Sets the filename of the client certificate used for authentication.
        /// </summary>
        void SetClientCertFile(string value);

        /// <summary>
        /// Sets the password used to access the client certificate for authentication.
        /// </summary>
        void SetClientCertPassword(string value);

        /// <summary>
        /// Sets the Client Identifier to be used for mutual authentication flow.
        /// </summary>
        void SetClientId(string value);

        /// <summary>
        /// Sets the OAuth 2.0 access token used for mutual authentication flow.
        /// </summary>
        void SetAccessToken(string value);

        /// <summary>
        /// Sets the refresh token used to obtain a new access token when the current token expires.
        /// </summary>
        void SetRefreshToken(string value);

        /// <summary>
        /// Sets the client secret used to authenticate the application with the mutual authentication service.
        /// </summary>
        void SetClientSecret(string value);

        /// <summary>
        /// Sets the type of authentication used to identify the user.
        /// </summary>
        void SetAuthenticationType(string value);

        /// <summary>
        /// Sets the file system directory path where PKCS#12 certificates are stored.
        /// </summary>
        void SetKeyDirectory(string value);

        /// <summary>
        /// Sets the filename of the PKCS#12 file associated with the current instance.
        /// </summary>
        void SetKeyfileName(string value);

        /// <summary>
        /// Sets the alias name associated with the certificate inside the PKCS#12 certificate file.
        /// </summary>
        void SetKeyAlias(string value);

        /// <summary>
        /// Sets the password used to access the PKCS#12 certificate file.
        /// </summary>
        void SetKeyPass(string value);

        /// <summary>
        /// Sets the full file path to the PKCS#12 certificate file, combining the directory and filename.
        /// </summary>
        void SetP12Keyfilepath(string value);

        /// <summary>
        /// Sets the JWT key type. Supported values: "P12" (default) or "SHARED_SECRET".
        /// </summary>
        void SetJwtKeyType(string value);

        /// <summary>
        /// Sets the domain name of the environment to which requests will be sent.
        /// </summary>
        void SetRunEnvironment(string value);

        /// <summary>
        /// Sets the hostname of the server to which requests will be sent.
        /// </summary>
        void SetHostName(string value);

        /// <summary>
        /// Sets the hostname of the intermediate server used for network routing.
        /// </summary>
        void SetIntermediateHost(string value);

        /// <summary>
        /// Sets the directory path where PEM files are stored or accessed.
        /// </summary>
        void SetPemFileDirectory(string value);
    }
}
