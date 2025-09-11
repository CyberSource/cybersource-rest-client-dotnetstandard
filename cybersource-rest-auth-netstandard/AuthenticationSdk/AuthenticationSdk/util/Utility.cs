using System;
using System.Collections.Generic;
using System.Text;

namespace AuthenticationSdk.util
{
    public static class Utility
    {
        /// <summary>
        /// Checks if the provided string represents a valid boolean value ("true" or "false", case-insensitive).
        /// </summary>
        /// <param name="value">The string to validate.</param>
        /// <returns>True if the string is "true" or "false" (case-insensitive); otherwise, false.</returns>
        public static bool IsValidBooleanString(string value)
        {
            return string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(value, "false", StringComparison.OrdinalIgnoreCase);
        }
    }
}
