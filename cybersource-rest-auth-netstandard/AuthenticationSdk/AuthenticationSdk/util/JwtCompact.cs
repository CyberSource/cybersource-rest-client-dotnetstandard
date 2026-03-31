using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace AuthenticationSdk.util
{
    /// <summary>
    /// Lightweight helpers for JWT compact serialization — Base64Url encoding/decoding
    /// and header/payload parsing — with zero dependency on jose-jwt.
    /// All methods are pure managed code (no native/OS crypto), so they work identically
    /// on Windows, Linux, and macOS.
    /// </summary>
    internal static class JwtCompact
    {
        /// <summary>
        /// Decodes and returns the UTF-8 JSON string from the payload part (index 1)
        /// of a JWT compact serialization, without verifying the signature.
        /// </summary>
        public static string DecodePayload(string compactToken)
        {
            if (string.IsNullOrWhiteSpace(compactToken))
            {
                throw new ArgumentException("Token cannot be null or empty.", nameof(compactToken));
            }

            string[] parts = compactToken.Split('.');
            if (parts.Length < 2)
            {
                throw new FormatException("Invalid JWT: expected at least 2 parts separated by '.'.");
            }

            byte[] payloadBytes = Base64UrlEncoder.DecodeBytes(parts[1]);
            return Encoding.UTF8.GetString(payloadBytes);
        }

        /// <summary>
        /// Decodes and returns the headers from the first part of a JWT compact serialization
        /// as a dictionary, without verifying the signature.
        /// </summary>
        public static IDictionary<string, object> DecodeHeaders(string compactToken)
        {
            if (string.IsNullOrWhiteSpace(compactToken))
            {
                throw new ArgumentException("Token cannot be null or empty.", nameof(compactToken));
            }

            string[] parts = compactToken.Split('.');
            if (parts.Length < 1)
            {
                throw new FormatException("Invalid JWT: expected at least 1 part.");
            }

            byte[] headerBytes = Base64UrlEncoder.DecodeBytes(parts[0]);
            string headerJson  = Encoding.UTF8.GetString(headerBytes);

            var result = JsonConvert.DeserializeObject<Dictionary<string, object>>(headerJson);
            if (result == null)
            {
                throw new FormatException("Invalid JWT: header could not be deserialized.");
            }

            return result;
        }
    }
}
