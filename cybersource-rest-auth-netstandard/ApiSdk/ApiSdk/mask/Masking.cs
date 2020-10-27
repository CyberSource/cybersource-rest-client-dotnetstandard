using System.Text.RegularExpressions;
using Newtonsoft.Json;

namespace ApiSdk.mask
{
    public class Masking
    {
        // Filters to be masked
        private readonly string[] _filters =
        {
            "country", "email", "cardNumber", "expirationDate", "cardCode",
            "cardType "
        };

        public string MaskMessage(string message)
        {
            message = Regex.Replace(message, @"\s+", "");
            var serializedMessage = JsonConvert.SerializeObject(message);
            var maskedMessage = Mask(serializedMessage);

            return maskedMessage;
        }

        private string Mask(string item)
        {
            foreach (var filter in _filters)
            {
                var reg = string.Concat(@"(\\""", filter, @"\\"":\\""[\w|\d|.@-]+\\"")");
                item = Regex.Replace(item, reg, string.Concat(@"""\", filter, @"\:\XXXXXXX\"));
            }

            return item;
        }
    }
}
