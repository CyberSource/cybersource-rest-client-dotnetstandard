using System.Collections.Generic;

namespace AuthenticationSdk.util
{
    public class AuthenticationTags
    {
        private static Dictionary<string, string> authenticationTags = new Dictionary<string, string>();
        private static bool isLoaded = false;

        public static Dictionary<string, string> getAuthenticationTags()
        {
            if (isLoaded)
            {
                return authenticationTags;
            }

            int authenticationTagsCount = SensitiveDataConfigurationType.authenticationTags.Length;

            for (int i = 0; i < authenticationTagsCount; i++)
            {
                string tagName = SensitiveDataConfigurationType.authenticationTags[i].tagName;
                string pattern = SensitiveDataConfigurationType.authenticationTags[i].pattern;
                string replacement = SensitiveDataConfigurationType.authenticationTags[i].replacement;

                if (!string.IsNullOrEmpty(pattern))
                {
                    pattern = $"{tagName} : {pattern}";
                }

                replacement = $"{replacement}";

                authenticationTags.Add(pattern, replacement);
            }

            isLoaded = true;

            return authenticationTags;
        }
    }
}
