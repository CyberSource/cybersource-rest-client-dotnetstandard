using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace AuthenticationSdk.util
{
    public class LogUtility
    {
        private static readonly IReadOnlyList<string> sensitiveTagsList = SensitiveTags.getSensitiveTagsList();
        private static readonly HashSet<string> sensitiveTagsSet = new HashSet<string>(sensitiveTagsList);
        private static readonly IReadOnlyDictionary<string, string> sensitiveTags = SensitiveTags.getSensitiveTags();
        private static readonly IReadOnlyDictionary<string, string> authenticationTags = AuthenticationTags.getAuthenticationTags();

        // Detects 13-19 digit sequences with optional spaces or dashes between digits.
        // After matching, digits are extracted and Luhn-validated before masking — this prevents
        // false positives on long numeric IDs while catching unlabeled PAN values that field-name
        // anchored regexes would miss in HTML/XML/plain-text error bodies.
        private static readonly Regex PanCandidateRegex = new Regex(
            @"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)",
            RegexOptions.Compiled);

        public string MaskSensitiveData(string str)
        {
            if (str.StartsWith(Constants.LOG_REQUEST_BEFORE_MLE))
            {
                return Constants.LOG_REQUEST_BEFORE_MLE + MaskSensitiveData(str.Substring(Constants.LOG_REQUEST_BEFORE_MLE.Length));
            }
            if (str.StartsWith(Constants.LOG_REQUEST_AFTER_MLE))
            {
                return Constants.LOG_REQUEST_AFTER_MLE + MaskSensitiveData(str.Substring(Constants.LOG_REQUEST_AFTER_MLE.Length));
            }
            if (str.StartsWith(Constants.LOG_NETWORK_RESPONSE_BEFORE_MLE_DECRYPTION))
            {
                return Constants.LOG_NETWORK_RESPONSE_BEFORE_MLE_DECRYPTION + MaskSensitiveData(str.Substring(Constants.LOG_NETWORK_RESPONSE_BEFORE_MLE_DECRYPTION.Length));
            }
            if (str.StartsWith(Constants.LOG_NETWORK_RESPONSE_AFTER_MLE_DECRYPTION))
            {
                return Constants.LOG_NETWORK_RESPONSE_AFTER_MLE_DECRYPTION + MaskSensitiveData(str.Substring(Constants.LOG_NETWORK_RESPONSE_AFTER_MLE_DECRYPTION.Length));
            }

            try
            {
                JsonNode parsedToken = JsonNode.Parse(str);

                switch (parsedToken.GetValueKind())
                {
                    case JsonValueKind.Object:
                        MaskSensitiveDataInJsonContainer(parsedToken.AsObject());
                        return parsedToken.ToString();

                    case JsonValueKind.Array:
                        MaskSensitiveDataInJsonContainer(parsedToken.AsArray(), false);
                        return parsedToken.ToString();

                    default:
                        break;
                }
            }
            catch (Exception)
            {
                // Not valid JSON; fall through to regex masking
            }

            foreach (KeyValuePair<string, string> tag in authenticationTags)
            {
                str = Regex.Replace(str, tag.Key, tag.Value, RegexOptions.Singleline);
            }

            foreach (KeyValuePair<string, string> tag in sensitiveTags)
            {
                str = Regex.Replace(str, tag.Key, tag.Value, RegexOptions.Singleline);
            }

            // Value-shape sweep: Luhn-validated PAN candidates that escaped field-name
            // anchored patterns (bare digits in HTML/plain-text bodies, truncated streams).
            str = MaskLuhnValidPans(str);

            return str;
        }

        private static string MaskLuhnValidPans(string input)
        {
            return PanCandidateRegex.Replace(input, m =>
            {
                string match = m.Value;
                string digitsOnly = StripNonDigits(match);
                if (digitsOnly.Length < 13 || digitsOnly.Length > 19) return match;
                return IsLuhnValid(digitsOnly) ? new string('X', match.Length) : match;
            });
        }

        private static string StripNonDigits(string s)
        {
            var sb = new StringBuilder(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c >= '0' && c <= '9') sb.Append(c);
            }
            return sb.ToString();
        }

        private static bool IsLuhnValid(string digits)
        {
            int sum = 0;
            bool alt = false;
            for (int i = digits.Length - 1; i >= 0; i--)
            {
                int n = digits[i] - '0';
                if (alt) { n *= 2; if (n > 9) n -= 9; }
                sum += n;
                alt = !alt;
            }
            return sum % 10 == 0;
        }

        public void MaskSensitiveDataInJsonContainer(JsonNode container, bool isSensitiveContext = false)
        {
            switch (container)
            {
                case null:
                    return;

                case JsonObject jsonObj:
                {
                    foreach (KeyValuePair<string, JsonNode?> property in jsonObj.ToList())
                    {
                        JsonNode? propertyValue = property.Value;

                        if (propertyValue is null) { continue; }

                        bool isFieldSensitive = sensitiveTagsSet.Contains(property.Key);

                        if (TryMaskJsonValue(propertyValue, isFieldSensitive, isSensitiveContext, out JsonNode? masked))
                        {
                            jsonObj[property.Key] = masked;
                        }
                    }

                    break;
                }

                case JsonArray jsonArray:
                {
                    for (int i = 0; i < jsonArray.Count; i++)
                    {
                        JsonNode? item = jsonArray[i];

                        if (item is null) { continue; }

                        if (TryMaskJsonValue(item, isSensitiveContext, isSensitiveContext, out JsonNode? masked))
                        {
                            jsonArray[i] = masked;
                        }
                    }

                    break;
                }
            }
        }

        // Masks a single JSON value. Object/Array values are recursed in place; scalar string/number
        // values are masked when shouldMaskScalar is true. Returns true (with the replacement in
        // maskedValue) only when the caller must reassign the slot, i.e. for masked scalars.
        private bool TryMaskJsonValue(JsonNode value, bool shouldMaskScalar, bool isSensitiveContext, out JsonNode? maskedValue)
        {
            maskedValue = null;

            switch (value.GetValueKind())
            {
                case JsonValueKind.Object:
                    MaskSensitiveDataInJsonContainer(value.AsObject(), isSensitiveContext);
                    return false;
                case JsonValueKind.Array:
                    // Propagate shouldMaskScalar so that an array nested inside a sensitive
                    // field (e.g. "number": ["4111..."]) is processed in sensitive context.
                    MaskSensitiveDataInJsonContainer(value.AsArray(), shouldMaskScalar || isSensitiveContext);
                    return false;
                case JsonValueKind.String when shouldMaskScalar:
                    string? stringValue = value.GetValue<string>();
                    maskedValue = stringValue is null ? null : JsonValue.Create(new string('X', stringValue.Length));
                    return true;
                case JsonValueKind.Number when shouldMaskScalar:
                    maskedValue = JsonValue.Create("XXXXX");
                    return true;
                default:
                    return false;
            }
        }


        public void LogDebugMessage(Logger logger, String debugMessage)
        {
            logger.Debug(MaskSensitiveData(debugMessage));
        }

        public bool IsMaskingEnabled(Logger logger)
        {
            if (!(logger.Factory.Configuration?.Variables?.ContainsKey("enableMasking") ?? false))
            {
                logger.Warn("NLog configuration is missing key/value pair: enableMasking. Assuming true");
                return true;
            }

            return logger.Factory.Configuration.Variables["enableMasking"].ToString().ToLower().Contains("true");
        }

        public string ConvertDictionaryToString(Dictionary<string, string> dict)
        {
            return ConvertDictionaryToStringWithMasking(dict, maskSensitiveData: true);
        }

        public string ConvertDictionaryToStringWithMasking(Dictionary<string, string> dict, bool maskSensitiveData = true)
        {
            var stringBuilder = new StringBuilder();

            foreach (KeyValuePair<string, string> kvp in dict)
            {
                string value = (maskSensitiveData && sensitiveTagsSet.Contains(kvp.Key)) ? "***" : kvp.Value;
                stringBuilder.Append($"{kvp.Key} = {value}\n");
            }

            return stringBuilder.ToString();
        }
    }
}
