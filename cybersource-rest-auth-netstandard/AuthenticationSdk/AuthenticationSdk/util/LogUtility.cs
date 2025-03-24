using Newtonsoft.Json.Linq;
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
        private static List<string> sensitiveTagsList = new List<string>();
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
                sensitiveTagsList.Clear();
                authenticationTags.Clear();

                sensitiveTags = SensitiveTags.getSensitiveTags();
                sensitiveTagsList = SensitiveTags.getSensitiveTagsList();
                authenticationTags = AuthenticationTags.getAuthenticationTags();

                loaded = true;
            }
        }

        public string MaskSensitiveData(string str)
        {
            bool isJsonString;
            try
            {
                JObject jsonObject = JObject.Parse(str);
                isJsonString = true;

                MaskSensitiveData(jsonObject);

                return jsonObject.ToString();
            }
            catch (Exception)
            {
                isJsonString = false;
            }

            if (!isJsonString)
            {
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
            }

            return str;
        }

        public void MaskSensitiveData(JObject jsonMsg)
        {
            foreach (var prop in jsonMsg.Properties())
            {
                bool isFieldSensitive = sensitiveTagsList.Contains(prop.Name);
                if (isFieldSensitive)
                {
                    if (prop.Value != null && prop.Value.Type != JTokenType.Null)
                    {
                        if (prop.Value.Type == JTokenType.String)
                        {
                            string originalValue = prop.Value.ToString();
                            prop.Value = new string('X', originalValue.Length);
                        }
                        else if (prop.Value.Type == JTokenType.Object)
                        {
                            MaskSensitiveData((JObject)prop.Value);
                        }
                    }
                }
                else if (prop.Value.Type == JTokenType.Object)
                {
                    MaskSensitiveData((JObject)prop.Value);
                }
            }
        }


        public void LogDebugMessage(Logger logger, String debugMessage)
        {
            if (IsMaskingEnabled(logger))
            {
                logger.Debug(MaskSensitiveData(debugMessage));
            }
            else
            {
                logger.Debug(debugMessage);
            }
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
