using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;

namespace AuthenticationSdk.core
{
    public interface IMerchantRequestSettingsValidator
    {
        void Validate(string requestType, string requestTarget, string requestJsonData);
    }

    public sealed class MerchantRequestSettingsValidator : IMerchantRequestSettingsValidator
    {
        /// <summary>
        /// Valid HTTP verbs/methods supported by the API.
        /// </summary>
        private static readonly HashSet<string> ValidHttpVerbs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE"
        };

        public void Validate(string requestType, string requestTarget, string requestJsonData)
        {
            // Validate requestType is a valid HTTP verb
            if (string.IsNullOrWhiteSpace(requestType))
            {
                throw new ArgumentException("Request type cannot be null or empty.", nameof(requestType));
            }

            if (!ValidHttpVerbs.Contains(requestType))
            {
                throw new ArgumentException(
                    $"Invalid HTTP verb: '{requestType}'. Valid HTTP verbs are: {string.Join(", ", ValidHttpVerbs.OrderBy(v => v))}.",
                    nameof(requestType));
            }

            // Validate requestTarget is not null or empty and is a valid URL resource path
            if (string.IsNullOrWhiteSpace(requestTarget))
            {
                throw new ArgumentException("Request target cannot be null or empty.", nameof(requestTarget));
            }

            if (!IsValidUrlResourcePath(requestTarget))
            {
                throw new ArgumentException(
                    $"Invalid URL resource path: '{requestTarget}'. Path must start with '/' and contain valid characters.",
                    nameof(requestTarget));
            }

            // Validate requestJsonData is a valid JSON string (optional parameter - can be null for GET requests)
            if (!string.IsNullOrEmpty(requestJsonData))
            {
                if (!IsValidJsonString(requestJsonData))
                {
                    throw new ArgumentException(
                        $"Invalid JSON format: '{requestJsonData}'. Request body must be valid JSON.",
                        nameof(requestJsonData));
                }
            }
        }

        /// <summary>
        /// Validates if a string is a valid URL resource path.
        /// A valid path must start with '/' and contain only valid URL path characters.
        /// Supports query parameters including date-time fields in various formats.
        /// </summary>
        /// <param name="path">The URL resource path to validate.</param>
        /// <returns>True if the path is valid; otherwise, false.</returns>
        private static bool IsValidUrlResourcePath(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return false;
            }

            // Path must start with /
            if (!path.StartsWith("/"))
            {
                return false;
            }

            // Allow alphanumeric characters, hyphens, underscores, forward slashes, dots, and query strings with ?, =, &
            // Query parameters can now include colons, plus signs, and percent-encoded characters for date-time values
            // This regex allows:
            // - /path/to/resource
            // - /path/{id}
            // - /path?query=value
            // - /path?startDate=2024-01-15T10:30:00Z
            // - /path/to/resource?a=1&b=2024-12-31T23:59:59+00:00
            // - /path?date=2024-01-15%2010%3A30%3A00
            // - /path?accept-type=application/xml
            var validPathPattern = @"^/[a-zA-Z0-9\-_./{}=]*(\?[a-zA-Z0-9\-_=&:+%/.]*)?$";
            return Regex.IsMatch(path, validPathPattern);
        }

        /// <summary>
        /// Validates if a string is valid JSON format.
        /// </summary>
        /// <param name="jsonString">The JSON string to validate.</param>
        /// <returns>True if the string is valid JSON; otherwise, false.</returns>
        private static bool IsValidJsonString(string jsonString)
        {
            if (string.IsNullOrWhiteSpace(jsonString))
            {
                return true;
            }

            try
            {
                // Attempt to parse the string as a JSON token
                // This will accept both JSON objects { } and JSON arrays [ ]
                var trimmedJson = jsonString.Trim();

                // Check if it starts with { or [ (valid JSON)
                if (!((trimmedJson.StartsWith("{") && trimmedJson.EndsWith("}")) ||
                      (trimmedJson.StartsWith("[") && trimmedJson.EndsWith("]"))))
                {
                    return false;
                }

                // Try to parse it with JToken - this validates the JSON structure
                JToken.Parse(jsonString);
                return true;
            }
            catch (Exception)
            {
                // If parsing fails, it's not valid JSON
                return false;
            }
        }
    }
}