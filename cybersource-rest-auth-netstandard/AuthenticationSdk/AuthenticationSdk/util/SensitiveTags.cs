using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace AuthenticationSdk.util
{
    public static class SensitiveTags
    {
        private static readonly IReadOnlyDictionary<string, string> sensitiveTags;
        private static readonly IReadOnlyList<string> sensitiveTagsList;

        static SensitiveTags()
        {
            var tags = new Dictionary<string, string>();
            var tagsList = new List<string>();

            foreach (var tag in SensitiveDataConfigurationType.sensitiveTags)
            {
                var pattern = !string.IsNullOrEmpty(tag.pattern)
                    ? $"\\\"{tag.tagName}\\\":\\\"{tag.pattern}\\\""
                    : $"\\\"{tag.tagName}\\\":\\\".+\\\"";

                var replacement = $"\"{tag.tagName}\":\"{tag.replacement}\"";

                tags.Add(pattern, replacement);
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
