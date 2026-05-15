using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;

namespace AuthenticationSdk.core
{
    public interface IMerchantMLESettings
    {
        /// <summary>
        /// Gets the file system path to the public certificate used for MLE requests.
        /// </summary>
        string MleForRequestPublicCertPath { get; }

        /// <summary>
        /// Gets the alias of the key used for MLE in the current request.
        /// </summary>
        string RequestMleKeyAlias { get; }

        /// <summary>
        /// Gets a value indicating whether response MLE is enabled globally for all APIs.
        /// </summary>
        bool EnableResponseMleGlobally { get; }

        /// <summary>
        /// Gets the identifier for the private key used to decrypt the MLE response.
        /// </summary>
        string ResponseMleKID { get; }

        /// <summary>
        /// Gets the file path to the private key used for decrypting the MLE response.
        /// </summary>
        string ResponseMlePrivateKeyFilePath { get; }

        /// <summary>
        /// Gets the password used to access the MLE private key file for the response, stored as a secure string.
        /// </summary>
        SecureString ResponseMlePrivateKeyFilePassword { get; }

        /// <summary>
        /// Gets the asymmetric private key used for decrypting MLE responses.
        /// </summary>
        AsymmetricAlgorithm ResponseMlePrivateKey { get; }

        /// <summary>
        /// Gets a value indicating whether MLE is enabled globally for all requests for optional APIs.
        /// </summary>
        bool EnableRequestMLEForOptionalApisGlobally { get; }

        /// <summary>
        /// Gets a value indicating whether MLE is disabled globally for all requests for mandatory APIs.
        /// </summary>
        bool DisableRequestMLEForMandatoryApisGlobally { get; }

        /// <summary>
        /// Gets a mapping of boolean values indicating whether to use MLE for specific APIs,
        /// where the key is the API operation name
        /// and the value is a boolean indicating whether MLE is enabled for that operation.
        /// </summary>
        Dictionary<string, string> MapToControlMLEonAPI { get; }

        /// <summary>
        /// Gets a mapping of boolean values indicating whether to use MLE for specific API requests,
        /// where the key is the API operation name and the value indicates whether MLE is enabled for that request operation.
        /// </summary>
        Dictionary<string, bool> InternalMapToControlRequestMLEonAPI { get; }

        /// <summary>
        /// Gets a mapping of boolean values indicating whether to use MLE for specific API responses,
        /// where the key is the API operation name and the value indicates whether MLE is enabled for that response operation.
        /// </summary>
        Dictionary<string, bool> InternalMapToControlResponseMLEonAPI { get; }

    }
}
