using System;
using System.Collections.Generic;
using System.Text;

namespace AuthenticationSdk.core
{
    public interface IMerchantRequestSettings
    {
        /// <summary>
        /// Gets or sets the type of the request. Valid values are GET, POST, PUT, DELETE and PATCH. This is a required field.
        /// </summary>
        string RequestType { get; set; }

        /// <summary>
        /// Gets or sets the request target. This is the path and query parameters of the URL.
        /// For example, if the full URL is https://test.cybersource.com/pts/v2/payments?offset=10&limit=5, then the request target is /pts/v2/payments?offset=10&limit=5.
        /// This is a required field.
        /// </summary>
        string RequestTarget { get; set; }

        /// <summary>
        /// Gets or sets the JSON data to be sent in the request body.
        /// This is required for POST, PUT and PATCH requests, and should be null or empty for GET and DELETE requests.
        /// </summary>
        string RequestJsonData { get; set; }
    }
}
