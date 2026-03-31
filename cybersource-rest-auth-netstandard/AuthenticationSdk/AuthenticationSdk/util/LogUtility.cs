using Newtonsoft.Json.Linq;
using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace AuthenticationSdk.util
{
    public class LogUtility
    {
        private static readonly IReadOnlyDictionary<string, string> sensitiveTags = SensitiveTags.getSensitiveTags();
        private static readonly IReadOnlyList<string> sensitiveTagsList = SensitiveTags.getSensitiveTagsList();
        private static readonly IReadOnlyDictionary<string, string> authenticationTags = AuthenticationTags.getAuthenticationTags();

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
                foreach (KeyValuePair<string, string> tag in authenticationTags)
                {
                    str = Regex.Replace(str, tag.Key, tag.Value);
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
            var stringBuilder = new StringBuilder();

            foreach (KeyValuePair<string, string> kvp in dict)
            {
                stringBuilder.Append($"{kvp.Key} = {kvp.Value}\n");
            }

            return stringBuilder.ToString();
        }
    }
}
