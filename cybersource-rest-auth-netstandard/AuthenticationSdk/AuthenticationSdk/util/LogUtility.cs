using NLog;
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace AuthenticationSdk.util
{
    public class LogUtility
    {
        private static Dictionary<string, string> sensitiveTags = new Dictionary<string, string>();
        private static Dictionary<string, string> authenticationTags = new Dictionary<string, string>();

        public LogUtility()
        {
            if (!loaded)
            {
                LoadSensitiveDataConfiguration();
            }
        }

        /// <summary>
        /// mutex to ensure that the operation is thread safe
        /// </summary>
        private static readonly object mutex = new object();

        /// <summary>
        /// check if the dictionaries have already been loaded
        /// </summary>
        private static bool loaded = false;

        private void LoadSensitiveDataConfiguration()
        {
            lock(mutex)
            {
                sensitiveTags.Clear();
                authenticationTags.Clear();

                sensitiveTags = SensitiveTags.getSensitiveTags();
                authenticationTags = AuthenticationTags.getAuthenticationTags();

                loaded = true;
            }
        }

        public string MaskSensitiveData(string str)
        {
            try
            {
                foreach (KeyValuePair<string, string> tag in sensitiveTags)
                {
                    //removing the space and hypen from PAN details before masking
                    if (tag.Key.StartsWith("\\\"number\\\"") || tag.Key.StartsWith("\\\"cardNumber\\\"") || tag.Key.StartsWith("\\\"account\\\"")
                         || tag.Key.StartsWith("\\\"prefix\\\"") || tag.Key.StartsWith("\\\"bin\\\""))
                    {
                        string[] splittedStr = tag.Key.Split(':');
                        string tagName = splittedStr[0];
                        string specialPatternForPAN = "(((\\s*[s/-]*\\s*)+)\\p{N}((\\s*[s/-]*\\s*)+))+";

                        // match the patters for PAN number
                        MatchCollection matches = Regex.Matches(str, $"{tagName}:\\\"{specialPatternForPAN}\\\"");

                        //remove space and dash from the all matched pattern
                        foreach (Match match in matches)
                        {
                            String strr = match.ToString();
                            strr = strr.Replace(" ", "");
                            strr = strr.Replace("-", "");
                            //replace original value in str with match
                            str = str.Replace(match.ToString(), strr);
                        }
                    }
                    str = Regex.Replace(str, tag.Key, tag.Value);
                }
            }
            catch (Exception e)
            {
                throw e;
            }

            try
            {
                foreach (KeyValuePair<string, string> tag in authenticationTags)
                {
                    str = Regex.Replace(str, tag.Key, tag.Value);
                }
            }
            catch (Exception e)
            {
                throw e;
            }

            return str;
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
            var stringBuilder = new StringBuilder();

            foreach (KeyValuePair<string, string> kvp in dict)
            {
                stringBuilder.Append($"{kvp.Key} = {kvp.Value}\n");
            }

            return stringBuilder.ToString();
        }
    }
}
