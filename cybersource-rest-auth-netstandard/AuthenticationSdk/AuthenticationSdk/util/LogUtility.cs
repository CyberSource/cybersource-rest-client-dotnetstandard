using NLog;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace AuthenticationSdk.util
{
    public class LogUtility
    {
        private static Dictionary<string, string> sensitiveTags = new Dictionary<string, string>();
        private static Dictionary<string, string> authenticationTags = new Dictionary<string, string>();

        /// <summary>
        /// mutex to ensure that the operation is thread safe
        /// </summary>
        private static readonly object mutex = new object();

        /// <summary>
        /// check if the dictionaries have already been loaded
        /// </summary>
        private static bool loaded = false;


        private static void LoadSensitiveDataConfiguration()
        {
            lock (mutex)
            {
                if (loaded)
                {
                    //only load once as otherwise another thread could be iterating over the dictionaries whilst attempting to reload the dictionaries
                    return;
                }

            sensitiveTags.Clear();
            authenticationTags.Clear();

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

                loaded = true;
            }
        }

        public static string MaskSensitiveData(string str)
        {
            LoadSensitiveDataConfiguration();

            foreach (KeyValuePair<string, string> tag in sensitiveTags)
            {
                str = Regex.Replace(str, tag.Key, tag.Value);
            }

            foreach (KeyValuePair<string, string> tag in authenticationTags)
            {
                str = Regex.Replace(str, tag.Key, tag.Value);
            }

            return str;
        }

        public static bool IsMaskingEnabled(Logger logger)
        {
            if (!(logger.Factory.Configuration?.Variables?.ContainsKey("enableMasking") ?? false))
            {
                logger.Warn("NLog configuration is missing key/value pair: enableMasking. Assuming true");
                return true;
            }
            return logger.Factory.Configuration.Variables["enableMasking"].ToString().ToLower().Contains("true");
        }

        public static string ConvertDictionaryToString(Dictionary<string, string> dict)
        {
            var stringBuilder = new StringBuilder();

            foreach (KeyValuePair<string, string> kvp in dict)
            {
                stringBuilder.Append($"{kvp.Key} = {kvp.Value}\n");
            }

            return stringBuilder.ToString();
        }
    }
}
