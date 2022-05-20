
namespace AuthenticationSdk.util
{
    public class SensitiveDataConfigurationType
    {
        public static SensitiveTag[] sensitiveTags = new SensitiveTag[]
        {
            new SensitiveTag("securityCode", "[0-9]{3,4}", "xxxxx", false),
            new SensitiveTag("number", "(\\s*\\p{N}\\s*)+(\\p{N}{4})(\\s*)", "xxxxx$2", false),
            new SensitiveTag("cardNumber", "(\\s*\\p{N}\\s*)+(\\p{N}{4})(\\s*)", "xxxxx$2", false),
            new SensitiveTag("expirationMonth", "[0-1][0-9]", "xxxx", false),
            new SensitiveTag("expirationYear", "2[0-9][0-9][0-9]", "xxxx", false),
            new SensitiveTag("account", "(\\s*\\p{N}\\s*)+(\\p{N}{4})(\\s*)", "xxxxx$2", false),
            new SensitiveTag("routingNumber", "[0-9]+", "xxxxx", false),
            new SensitiveTag("email", "[a-z0-9!#$%&'*+\\/=?^_`{|}~-]+(?:.[a-z0-9!#$%&'*+\\/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", "xxxxx", false),
            new SensitiveTag("firstName", "([a-zA-Z]+( )?[a-zA-Z]*'?-?[a-zA-Z]*( )?([a-zA-Z]*)?)", "xxxxx", false),
            new SensitiveTag("lastName", "([a-zA-Z]+( )?[a-zA-Z]*'?-?[a-zA-Z]*( )?([a-zA-Z]*)?)", "xxxxx", false),
            new SensitiveTag("phoneNumber", "(\\+[0-9]{1,2} )?\\(?[0-9]{3}\\)?[ .-]?[0-9]{3}[ .-]?[0-9]{4}", "xxxxx", false),
            new SensitiveTag("type", "[-A-Za-z0-9 ]+", "xxxxx", false),
            new SensitiveTag("token", "[-.A-Za-z0-9 ]+", "xxxxx", false),
            new SensitiveTag("signature", "[-.A-Za-z0-9 ]+", "xxxxx", false),
            new SensitiveTag("prefix", "(\\s*)(\\p{N}{4})(\\s*)(\\p{N}{2})(\\s*\\p{N}*\\s*)", "$2$4xxxxx", false),
            new SensitiveTag("bin", "(\\s*)(\\p{N}{4})(\\s*)(\\p{N}{2})(\\s*\\p{N}*\\s*)", "$2$4xxxxx", false)
        };

        public static AuthenticationSchemeTag[] authenticationTags = new AuthenticationSchemeTag[]
        {
            new AuthenticationSchemeTag("Signature", "(keyid=\\\"([\\w-]*)\\\"),([\\w\\\"\\-\\(\\),= ]*), (signature=\\\"([\\w\\/=\\+]*)\\\")", "Signature : keyid=\"XXXXX\",$3, signature=\"$5\"")
        };
    }

    public class SensitiveTag
    {
        public string tagName { get; set; }
        public string pattern { get; set; }
        public string replacement { get; set; }
        public bool disableMask { get; set; }

        public SensitiveTag(string tagName, string pattern, string replacement, bool disableMask = false)
        {
            this.tagName = tagName;
            this.pattern = pattern;
            this.replacement = replacement;
            this.disableMask = disableMask;
        }
    }

    public class AuthenticationSchemeTag
    {
        public string tagName { get; set; }
        public string pattern { get; set; }
        public string replacement { get; set; }

        public AuthenticationSchemeTag(string tagName, string pattern, string replacement)
        {
            this.tagName = tagName;
            this.pattern = pattern;
            this.replacement = replacement;
        }
    }
}
