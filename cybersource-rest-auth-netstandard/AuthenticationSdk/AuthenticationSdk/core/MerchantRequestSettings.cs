using System;
using System.Collections.Generic;
using System.Text;

namespace AuthenticationSdk.core
{
    /// <summary>
    /// Encapsulates merchant request configuration settings for CyberSource API requests.
    /// Stores the request type, target endpoint, and JSON request payload.
    /// </summary>
    public class MerchantRequestSettings : IMerchantRequestSettings
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="MerchantRequestSettings"/> class.
        /// </summary>
        /// <param name="requestType">The type of HTTP request (e.g., POST, PUT, GET, PATCH).</param>
        /// <param name="requestTarget">The target endpoint or URI path for the CyberSource API request.</param>
        /// <param name="requestJsonData">The JSON-formatted request payload data to be sent in the request body.</param>
        public MerchantRequestSettings(string requestType, string requestTarget, string requestJsonData)
        {
            var validator = new MerchantRequestSettingsValidator();
            validator.Validate(requestType, requestTarget, requestJsonData);
            RequestType = requestType;
            RequestTarget = requestTarget;
            RequestJsonData = requestJsonData;
        }

        /// <summary>
        /// Gets or sets the type of HTTP request method to be used.
        /// Examples: POST, PUT, GET, PATCH, DELETE.
        /// </summary>
        public string RequestType { get; set; }

        /// <summary>
        /// Gets or sets the target endpoint or URI path for the CyberSource API request.
        /// This is typically the relative path to the API endpoint.
        /// </summary>
        public string RequestTarget { get; set; }

        /// <summary>
        /// Gets or sets the JSON-formatted request payload data.
        /// Contains the request body content to be sent to the CyberSource API.
        /// </summary>
        public string RequestJsonData { get; set; }
    }
}
