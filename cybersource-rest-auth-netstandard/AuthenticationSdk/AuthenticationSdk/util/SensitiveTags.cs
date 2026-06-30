using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text.RegularExpressions;

namespace AuthenticationSdk.util
{
    public static class SensitiveTags
    {
        private static readonly IReadOnlyDictionary<string, string> sensitiveTags;
        private static readonly IReadOnlyList<string> sensitiveTagsList;

        static SensitiveTags()
        {
            var tags = new Dictionary<string, string>(StringComparer.Ordinal);
            var tagsList = new List<string>();

            foreach (var tag in SensitiveDataConfigurationType.sensitiveTags)
            {
                string escapedName = Regex.Escape(tag.tagName);

                // JSON quoted-string value: "tagName" : "value" or "tagName":"value"
                // [^"]* is bounded so it cannot over-consume adjacent fields (unlike greedy .+)
                var jsonQuotedPattern = !string.IsNullOrEmpty(tag.pattern)
                    ? $"\\\"{escapedName}\\\"\\s*:\\s*\\\"{tag.pattern}\\\""
                    : $"\\\"{escapedName}\\\"\\s*:\\s*\\\"[^\\\"]*\\\"";
                tags[jsonQuotedPattern] = $"\"{tag.tagName}\":\"\"";

                // Truncated/unterminated quoted value: "tagName":"<chars without closing quote, to end of input>
                tags[$"\\\"{escapedName}\\\"\\s*:\\s*\\\"[^\\\"]*\\z"] = $"\"{tag.tagName}\":\"\"";

                // JSON unquoted numeric value: "tagName" : 12345
                tags[$"\\\"{escapedName}\\\"\\s*:\\s*\\d+"] = $"\"{tag.tagName}\":0";

                // XML element value (terminated): <tagName>value</tagName>
                tags[$"<{escapedName}>[^<]*</{escapedName}>"] = $"<{tag.tagName}></{tag.tagName}>";

                // XML element value (truncated/unterminated): <tagName>value... to end of input
                tags[$"<{escapedName}>[^<]*\\z"] = $"<{tag.tagName}>";

                // Form-encoded pair: tagName=value (query-string or application/x-www-form-urlencoded)
                tags[$"\\b{escapedName}=[^&\\s\\r\\n]*"] = $"{tag.tagName}=";

                tagsList.Add(tag.tagName);
            }

            sensitiveTags = new ReadOnlyDictionary<string, string>(tags);
            sensitiveTagsList = new ReadOnlyCollection<string>(tagsList);
        }

        public static IReadOnlyDictionary<string, string> getSensitiveTags()
        {
            return sensitiveTags;
        }

        public static IReadOnlyList<string> getSensitiveTagsList()
        {
            return sensitiveTagsList;
        }
    }
}
