
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
            new SensitiveTag("encryptedResponse", "", "", false),
            // Credential fields — also present in SensitiveFieldMaskingUtility.SensitiveKeys
            // (model diagnostic output masking). Keep both lists in sync: if you add a
            // credential field here, add it there too, and vice versa.
            new SensitiveTag("password", "", "", false),
            new SensitiveTag("secret", "", "", false),
            new SensitiveTag("secretKey", "", "", false),
            new SensitiveTag("apiKey", "", "", false),
            new SensitiveTag("cvv", "", "", false),
            new SensitiveTag("cvn", "", "", false),
            // Path/query parameter tokens — logged via ConvertDictionaryToString
            new SensitiveTag("paymentCredentialsReference", "", "", false),
            new SensitiveTag("transientToken", "", "", false),
            new SensitiveTag("jti", "", "", false),
            // Address and location PII (AISAST-10816: VerificationApi, AISAST-10815: PullFundsApi)
            new SensitiveTag("address1", "", "", false),
            new SensitiveTag("address2", "", "", false),
            new SensitiveTag("address3", "", "", false),
            new SensitiveTag("address4", "", "", false),
            new SensitiveTag("postalCode", "", "", false),
            // Personal identity PII (AISAST-10815: PullFundsApi sender/recipient)
            new SensitiveTag("dateOfBirth", "", "", false),
            new SensitiveTag("middleName", "", "", false),
            new SensitiveTag("middleInitial", "", "", false),
            new SensitiveTag("identificationNumber", "", "", false),
            // Payment/account identifiers (AISAST-10815: PullFundsApi)
            new SensitiveTag("accountId", "", "", false),
            new SensitiveTag("referenceNumber", "", "", false),
            new SensitiveTag("cryptogram", "", "", false),
            new SensitiveTag("cavv", "", "", false),
            // Sensitive Authentication Data (SAD) — PCI DSS prohibited in logs
            new SensitiveTag("trackData", "", "", false),
            new SensitiveTag("jis2TrackData", "", "", false),
            new SensitiveTag("ucafAuthenticationData", "", "", false),
            new SensitiveTag("proxyPan", "", "", false),
            new SensitiveTag("emv", "", "", false),
            // Additional credential fields (also in SensitiveFieldMaskingUtility)
            new SensitiveTag("accessToken", "", "", false),
            new SensitiveTag("refreshToken", "", "", false),
            new SensitiveTag("clientSecret", "", "", false),
            new SensitiveTag("clientId", "", "", false),
            new SensitiveTag("privateKey", "", "", false),
            new SensitiveTag("encryptionKey", "", "", false),
            new SensitiveTag("otpToken", "", "", false),
            new SensitiveTag("idToken", "", "", false),
            new SensitiveTag("pin", "", "", false),
            new SensitiveTag("code", "", "", false),
            new SensitiveTag("transientTokenJwt", "", "", false),
            new SensitiveTag("responseAccessToken", "", "", false),
            new SensitiveTag("transactionToken", "", "", false),
            new SensitiveTag("legacyToken", "", "", false),
            new SensitiveTag("thirdPartyToken", "", "", false),
            // Additional CHD / PAN
            new SensitiveTag("accountNumber", "", "", false),
            new SensitiveTag("ssn", "", "", false),
            // Additional PII
            new SensitiveTag("mobilePhone", "", "", false),
            new SensitiveTag("ipAddress", "", "", false),
            new SensitiveTag("taxId", "", "", false),
            new SensitiveTag("taxIdNumber", "", "", false),
            new SensitiveTag("passportNumber", "", "", false),
            new SensitiveTag("nationalId", "", "", false),
            new SensitiveTag("birthDate", "", "", false),
            new SensitiveTag("countryOfBirth", "", "", false),
            new SensitiveTag("vatRegistrationNumber", "", "", false),
            new SensitiveTag("companyTaxId", "", "", false),
            new SensitiveTag("personalIdentification", "", "", false),
            new SensitiveTag("alternateEmail", "", "", false),
            new SensitiveTag("alternatePhoneNumber", "", "", false),
            new SensitiveTag("workPhone", "", "", false),
            new SensitiveTag("fullName", "", "", false),
            new SensitiveTag("legalName", "", "", false),
            new SensitiveTag("beneficiaryName", "", "", false),
            // Bank / financial identifiers
            new SensitiveTag("iban", "", "", false),
            new SensitiveTag("swiftCode", "", "", false),
            new SensitiveTag("bankAccount", "", "", false),
            new SensitiveTag("accountHolderName", "", "", false),
            new SensitiveTag("accountRoutingNumber", "", "", false),
            new SensitiveTag("correctedAccountNumber", "", "", false),
            new SensitiveTag("correctedRoutingNumber", "", "", false)
        };

        public static AuthenticationSchemeTag[] authenticationTags = new AuthenticationSchemeTag[]
        {
            new AuthenticationSchemeTag("Signature", "(keyid=\\\"([\\w-]*)\\\"),([\\w\\\"\\-\\(\\),= ]*), (signature=\\\"([\\w\\/=\\+]*)\\\")", "Signature : keyid=\"XXXXX\",$3, signature=\"XXXXX\""),
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
