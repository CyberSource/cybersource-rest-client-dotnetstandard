
namespace AuthenticationSdk.util
{
    public class SensitiveDataConfigurationType
    {
        public static SensitiveTag[] sensitiveTags = new SensitiveTag[]
        {
            new SensitiveTag("securityCode", "", "", false),
            new SensitiveTag("number", "", "", false),
            new SensitiveTag("cardNumber", "", "", false),
            new SensitiveTag("expirationMonth", "", "", false),
            new SensitiveTag("expirationYear", "", "", false),
            new SensitiveTag("account", "", "", false),
            new SensitiveTag("routingNumber", "", "", false),
            new SensitiveTag("email", "", "", false),
            new SensitiveTag("firstName", "", "", false),
            new SensitiveTag("lastName", "", "", false),
            new SensitiveTag("phoneNumber", "", "", false),
            new SensitiveTag("type", "", "", false),
            new SensitiveTag("token", "", "", false),
            new SensitiveTag("signature", "", "", false),
            new SensitiveTag("prefix", "", "", false),
            new SensitiveTag("bin", "", "", false),
            new SensitiveTag("encryptedRequest", "", "", false),
            new SensitiveTag("encryptedResponse", "", "", false)
        };

        public static AuthenticationSchemeTag[] authenticationTags = new AuthenticationSchemeTag[]
        {
            new AuthenticationSchemeTag("Signature", "(keyid=\\\"([\\w-]*)\\\"),([\\w\\\"\\-\\(\\),= ]*), (signature=\\\"([\\w\\/=\\+]*)\\\")", "Signature : keyid=\"XXXXX\",$3, signature=\"$5\""),
            new AuthenticationSchemeTag("Authorization", "Bearer\\s.*","Authorization : Bearer xxxxxxxxxxxxxxxx")
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
