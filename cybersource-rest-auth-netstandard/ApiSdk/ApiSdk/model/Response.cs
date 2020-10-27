using System;
using ApiSdk.util;

namespace ApiSdk.model
{
    public class Response
    {
        public Response(int statusCode, string headers, string data)
        {
            StatusCode = statusCode;
            Data = data;
            Headers = headers;
            StatusInfo = GetStatusInfo(statusCode);
        }

        public int StatusCode { get; }

        public string Data { get; }

        public string Headers { get; }

        public string StatusInfo { get; }

        public string GetResponseHeaderValue(string responseHeadersString, string headerToFind)
        {
            var responseHeaderarray = responseHeadersString.Split(new[] { Constants.ResponseHeadersSeparator }, StringSplitOptions.None);

            foreach (var header in responseHeaderarray)
            {
                var headerKeyValue = header.Split(':');
                var headerKey = headerKeyValue[0];

                if (headerKey == headerToFind)
                {
                    var headerValue = headerKeyValue[1];
                    return headerValue.Trim();
                }
            }

            return string.Empty;
        }

        private string GetStatusInfo(int statusCode)
        {
            switch (statusCode)
            {
                case 200:
                    return "Transaction Successful";
                case 201:
                    return "Transaction Successful";
                case 400:
                    return "Bad Request";
                case 401:
                    return "Authentication Failed";
                case 403:
                    return "Forbidden";
                case 404:
                    return "Not Found";
                case 500:
                    return "Internal Server Error";
                case 502:
                    return "Bad Gateway";
                case 503:
                    return "SERVICE UNAVAILABLE";
                case 504:
                    return "Gateway Timeout";
                default:
                    return string.Empty;
            }
        }
    }
}