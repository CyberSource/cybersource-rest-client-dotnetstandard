using System.Collections.Generic;

namespace AuthenticationSdk.util
{
    public class SensitiveTags
    {
        private static Dictionary<string, string> sensitiveTags = new Dictionary<string, string>();
        private static bool isLoaded = false;
        
        public static Dictionary<string, string> getSensitiveTags()
        {
            if (isLoaded)
            {
                return sensitiveTags;
            }

            int sensitiveTagsCount = SensitiveDataConfigurationType.sensitiveTags.Length;

            for (int i = 0; i < sensitiveTagsCount; i++)
            {
                string tagName = SensitiveDataConfigurationType.sensitiveTags[i].tagName;
                string pattern = SensitiveDataConfigurationType.sensitiveTags[i].pattern;
                string replacement = SensitiveDataConfigurationType.sensitiveTags[i].replacement;

                if (!string.IsNullOrEmpty(pattern))
                {
                    pattern = $"\\\"{tagName}\\\":\\\"{pattern}\\\"";
                }
                else
                {
                    pattern = $"\\\"{tagName}\\\":\\\".+\\\"";
                }

                replacement = $"\"{tagName}\":\"{replacement}\"";

                sensitiveTags.Add(pattern, replacement);
            }

            isLoaded = true;

            return sensitiveTags;
        }
    }
}
