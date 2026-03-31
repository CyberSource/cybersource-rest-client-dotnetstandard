using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace AuthenticationSdk.util
{
    public static class AuthenticationTags
    {
        private static readonly IReadOnlyDictionary<string, string> authenticationTags;

        static AuthenticationTags()
        {
            var tags = new Dictionary<string, string>();

            foreach (var tag in SensitiveDataConfigurationType.authenticationTags)
            {
                var pattern = !string.IsNullOrEmpty(tag.pattern)
                    ? $"{tag.tagName} : {tag.pattern}"
                    : tag.pattern;

                tags.Add(pattern, tag.replacement);
            }

            authenticationTags = new ReadOnlyDictionary<string, string>(tags);
        }

        public static IReadOnlyDictionary<string, string> getAuthenticationTags()
        {
            return authenticationTags;
        }
    }
}
