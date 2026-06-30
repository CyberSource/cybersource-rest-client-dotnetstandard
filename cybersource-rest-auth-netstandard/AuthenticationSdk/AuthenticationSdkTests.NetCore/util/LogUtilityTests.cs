using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;
using NUnit.Framework;
using AuthenticationSdk.util;

namespace AuthenticationSdkTests.NetCore.util
{
    [TestFixture]
    public class LogUtilityTests
    {
        private LogUtility logUtility;

        [SetUp]
        public void SetUp()
        {
            logUtility = new LogUtility();
        }

        // --- MaskSensitiveData(string) with JsonObject input ---

        [Test]
        public void MaskSensitiveData_JsonObject_MasksSensitiveStringFields()
        {
            string input = "{\"number\":\"4111111111111111\",\"merchantId\":\"testMerchant\"}";
            string result = logUtility.MaskSensitiveData(input);

            JsonObject parsed = JsonNode.Parse(result).AsObject();
            Assert.AreEqual("XXXXXXXXXXXXXXXX", parsed["number"].ToString());
            // merchantId is not in sensitive tags, should remain unchanged
            Assert.AreEqual("testMerchant", parsed["merchantId"].ToString());
        }

        [Test]
        public void MaskSensitiveData_JsonObject_MasksSensitiveIntegerFields()
        {
            string input = "{\"securityCode\":123,\"amount\":500}";
            string result = logUtility.MaskSensitiveData(input);

            JsonObject parsed = JsonNode.Parse(result).AsObject();
            Assert.AreEqual("XXXXX", parsed["securityCode"].ToString());
            // amount is not sensitive
            Assert.AreEqual(500, parsed["amount"].GetValue<int>());
        }

        [Test]
        public void MaskSensitiveData_JsonObject_MasksNestedSensitiveFields()
        {
            string input = "{\"payment\":{\"number\":\"4111111111111111\",\"securityCode\":\"123\"}}";
            string result = logUtility.MaskSensitiveData(input);

            JsonObject parsed = JsonNode.Parse(result).AsObject();
            JsonObject payment = parsed["payment"].AsObject();
            Assert.AreEqual("XXXXXXXXXXXXXXXX", payment["number"].ToString());
            Assert.AreEqual("XXX", payment["securityCode"].ToString());
        }

        [Test]
        public void MaskSensitiveData_JsonObject_NonSensitiveFieldsUnchanged()
        {
            string input = "{\"merchantId\":\"test\",\"currency\":\"USD\"}";
            string result = logUtility.MaskSensitiveData(input);

            JsonObject parsed = JsonNode.Parse(result).AsObject();
            Assert.AreEqual("test", parsed["merchantId"].ToString());
            Assert.AreEqual("USD", parsed["currency"].ToString());
        }

        // --- MaskSensitiveData(string) with JsonArray input ---

        [Test]
        public void MaskSensitiveData_JsonArray_MasksSensitiveFieldsInObjectElements()
        {
            string input = "[{\"number\":\"4111111111111111\"},{\"merchantId\":\"test\"}]";
            string result = logUtility.MaskSensitiveData(input);

            JsonArray parsed = JsonNode.Parse(result).AsArray();
            Assert.AreEqual("XXXXXXXXXXXXXXXX", parsed[0]["number"].ToString());
            Assert.AreEqual("test", parsed[1]["merchantId"].ToString());
        }

        [Test]
        public void MaskSensitiveData_JsonArray_TopLevelArrayNotInSensitiveContext()
        {
            // Top-level arrays are parsed with isSensitiveContext=false,
            // so primitive values in the array should NOT be masked
            string input = "[\"plainValue\",123]";
            string result = logUtility.MaskSensitiveData(input);

            JsonArray parsed = JsonNode.Parse(result).AsArray();
            Assert.AreEqual("plainValue", parsed[0].ToString());
            Assert.AreEqual(123, parsed[1].GetValue<int>());
        }

        // --- MaskSensitiveData(string) with non-JSON input ---

        [Test]
        public void MaskSensitiveData_NonJsonString_AppliesRegexMasking()
        {
            // Non-JSON strings fall through to regex masking with authentication tags
            string input = "This is plain text with no JSON";
            string result = logUtility.MaskSensitiveData(input);

            // Should not throw, result should be a string (regex applied if matched)
            Assert.IsNotNull(result);
        }

        // --- MaskSensitiveDataInJsonContainer with JsonObject ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_MasksSensitiveFields()
        {
            JsonObject obj = JsonNode.Parse("{\"number\":\"4111111111111111\",\"merchantId\":\"test\"}").AsObject();
            logUtility.MaskSensitiveDataInJsonContainer(obj);

            Assert.AreEqual("XXXXXXXXXXXXXXXX", obj["number"].ToString());
            Assert.AreEqual("test", obj["merchantId"].ToString());
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_HandlesNullValue()
        {
            JsonObject obj = JsonNode.Parse("{\"number\":null}").AsObject();
            logUtility.MaskSensitiveDataInJsonContainer(obj);

            // In System.Text.Json.Nodes, JSON null is represented as null JsonNode
            Assert.IsNull(obj["number"]);
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_MasksArrayUnderSensitiveProperty()
        {
            // When a sensitive property contains an array, the array elements should be masked
            JsonObject obj = JsonNode.Parse("{\"number\":[\"4111111111111111\",\"5500000000000004\"]}").AsObject();
            logUtility.MaskSensitiveDataInJsonContainer(obj);

            JsonArray arr = obj["number"].AsArray();
            Assert.AreEqual("XXXXXXXXXXXXXXXX", arr[0].ToString());
            Assert.AreEqual("XXXXXXXXXXXXXXXX", arr[1].ToString());
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_DoesNotMaskArrayUnderNonSensitiveProperty()
        {
            // When a non-sensitive property contains an array of primitives, they stay unmasked
            JsonObject obj = JsonNode.Parse("{\"items\":[\"item1\",\"item2\"]}").AsObject();
            logUtility.MaskSensitiveDataInJsonContainer(obj);

            JsonArray arr = obj["items"].AsArray();
            Assert.AreEqual("item1", arr[0].ToString());
            Assert.AreEqual("item2", arr[1].ToString());
        }

        // --- MaskSensitiveDataInJsonContainer with JsonArray ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_SensitiveContext_MasksPrimitives()
        {
            JsonArray arr = JsonNode.Parse("[\"sensitive1\",\"sensitive2\",123]").AsArray();
            logUtility.MaskSensitiveDataInJsonContainer(arr, isSensitiveContext: true);

            Assert.AreEqual("XXXXXXXXXX", arr[0].ToString());
            Assert.AreEqual("XXXXXXXXXX", arr[1].ToString());
            Assert.AreEqual("XXXXX", arr[2].ToString());
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_NonSensitiveContext_DoesNotMaskPrimitives()
        {
            JsonArray arr = JsonNode.Parse("[\"value1\",\"value2\",456]").AsArray();
            logUtility.MaskSensitiveDataInJsonContainer(arr, isSensitiveContext: false);

            Assert.AreEqual("value1", arr[0].ToString());
            Assert.AreEqual("value2", arr[1].ToString());
            Assert.AreEqual(456, arr[2].GetValue<int>());
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_MasksObjectElementsSensitiveFields()
        {
            JsonArray arr = JsonNode.Parse("[{\"number\":\"4111111111111111\",\"amount\":100}]").AsArray();
            logUtility.MaskSensitiveDataInJsonContainer(arr);

            JsonObject element = arr[0].AsObject();
            Assert.AreEqual("XXXXXXXXXXXXXXXX", element["number"].ToString());
            Assert.AreEqual(100, element["amount"].GetValue<int>());
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_NestedArrayInSensitiveContext()
        {
            JsonArray arr = JsonNode.Parse("[[\"nested1\",\"nested2\"]]").AsArray();
            logUtility.MaskSensitiveDataInJsonContainer(arr, isSensitiveContext: true);

            JsonArray inner = arr[0].AsArray();
            Assert.AreEqual("XXXXXXX", inner[0].ToString());
            Assert.AreEqual("XXXXXXX", inner[1].ToString());
        }

        // --- MLE prefix handling ---

        [Test]
        public void MaskSensitiveData_WithMlePrefix_StripsPrefixMasksAndReattaches()
        {
            string json = "{\"number\":\"4111111111111111\"}";
            string input = Constants.LOG_REQUEST_BEFORE_MLE + json;
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsTrue(result.StartsWith(Constants.LOG_REQUEST_BEFORE_MLE));
            string masked = result.Substring(Constants.LOG_REQUEST_BEFORE_MLE.Length);
            JsonObject parsed = JsonNode.Parse(masked).AsObject();
            Assert.AreEqual("XXXXXXXXXXXXXXXX", parsed["number"].ToString());
        }

        // --- Edge cases ---

        [Test]
        public void MaskSensitiveData_EmptyJsonObject_ReturnsEmptyObject()
        {
            string input = "{}";
            string result = logUtility.MaskSensitiveData(input);

            JsonObject parsed = JsonNode.Parse(result).AsObject();
            Assert.AreEqual(0, parsed.Count);
        }

        [Test]
        public void MaskSensitiveData_EmptyJsonArray_ReturnsEmptyArray()
        {
            string input = "[]";
            string result = logUtility.MaskSensitiveData(input);

            JsonArray parsed = JsonNode.Parse(result).AsArray();
            Assert.AreEqual(0, parsed.Count);
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_DeeplyNestedStructure()
        {
            string json = @"{
                ""orderInfo"": {
                    ""billTo"": {
                        ""firstName"": ""John"",
                        ""lastName"": ""Doe"",
                        ""email"": ""john@example.com""
                    },
                    ""amount"": ""100.00""
                }
            }";
            JsonObject obj = JsonNode.Parse(json).AsObject();
            logUtility.MaskSensitiveDataInJsonContainer(obj);

            JsonObject billTo = obj["orderInfo"]["billTo"].AsObject();
            Assert.AreEqual("XXXX", billTo["firstName"].ToString());
            Assert.AreEqual("XXX", billTo["lastName"].ToString());
            Assert.AreEqual("XXXXXXXXXXXXXXXX", billTo["email"].ToString());
            // amount is not in the sensitive list
            Assert.AreEqual("100.00", obj["orderInfo"]["amount"].ToString());
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_FloatInSensitiveContext()
        {
            JsonArray arr = JsonNode.Parse("[1.5, 2.7]").AsArray();
            logUtility.MaskSensitiveDataInJsonContainer(arr, isSensitiveContext: true);

            Assert.AreEqual("XXXXX", arr[0].ToString());
            Assert.AreEqual("XXXXX", arr[1].ToString());
        }

        [Test]
        public void MaskSensitiveData_MultipleSensitiveFields()
        {
            string input = "{\"number\":\"4111111111111111\",\"securityCode\":\"123\",\"expirationMonth\":\"12\",\"expirationYear\":\"2025\"}";
            string result = logUtility.MaskSensitiveData(input);

            JsonObject parsed = JsonNode.Parse(result).AsObject();
            Assert.AreEqual("XXXXXXXXXXXXXXXX", parsed["number"].ToString());
            Assert.AreEqual("XXX", parsed["securityCode"].ToString());
            Assert.AreEqual("XX", parsed["expirationMonth"].ToString());
            Assert.AreEqual("XXXX", parsed["expirationYear"].ToString());
        }

        // --- Sensitive field with Object value ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_SensitiveFieldWithObjectValue_RecursesInto()
        {
            // "token" is a sensitive field; its value is an object — should recurse and mask inner sensitive fields
            JsonObject obj = JsonNode.Parse("{\"token\":{\"number\":\"4111\",\"merchantId\":\"test\"}}").AsObject();
            logUtility.MaskSensitiveDataInJsonContainer(obj);

            JsonObject tokenObj = obj["token"].AsObject();
            Assert.AreEqual("XXXX", tokenObj["number"].ToString());
            Assert.AreEqual("test", tokenObj["merchantId"].ToString());
        }

        // --- Sensitive field with Float value ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_SensitiveFieldWithFloatValue()
        {
            JsonObject obj = JsonNode.Parse("{\"account\":3.14}").AsObject();
            logUtility.MaskSensitiveDataInJsonContainer(obj);

            Assert.AreEqual("XXXXX", obj["account"].ToString());
        }

        // --- Boolean value in sensitive field (no masking — no case handles it) ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_SensitiveFieldWithBooleanValue_NotMasked()
        {
            // Boolean type has no masking case — should be left untouched
            JsonObject obj = JsonNode.Parse("{\"token\":true}").AsObject();
            logUtility.MaskSensitiveDataInJsonContainer(obj);

            // In System.Text.Json, boolean true has ValueKind = JsonValueKind.True
            Assert.AreEqual(JsonValueKind.True, obj["token"].GetValueKind());
            Assert.IsTrue(obj["token"].GetValue<bool>());
        }

        // --- Array with mixed types in sensitive context ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_SensitiveContext_MixedTypes()
        {
            JsonArray arr = JsonNode.Parse("[\"secret\", 42, 3.14, true, null]").AsArray();
            logUtility.MaskSensitiveDataInJsonContainer(arr, isSensitiveContext: true);

            Assert.AreEqual("XXXXXX", arr[0].ToString());  // string masked
            Assert.AreEqual("XXXXX", arr[1].ToString());   // integer masked
            Assert.AreEqual("XXXXX", arr[2].ToString());   // float masked
            Assert.IsTrue(arr[3].GetValue<bool>());        // boolean untouched
            Assert.IsNull(arr[4]);                          // null is null JsonNode
        }

        // --- Nested array in non-sensitive context ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_NestedArrayInNonSensitiveContext()
        {
            JsonArray arr = JsonNode.Parse("[[\"value1\",\"value2\"]]").AsArray();
            logUtility.MaskSensitiveDataInJsonContainer(arr, isSensitiveContext: false);

            JsonArray inner = arr[0].AsArray();
            Assert.AreEqual("value1", inner[0].ToString());
            Assert.AreEqual("value2", inner[1].ToString());
        }

        // --- Object inside array inside sensitive field ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_SensitiveArrayContainingObjects()
        {
            // "number" is sensitive, value is array of objects — recurse into objects
            JsonObject obj = JsonNode.Parse("{\"number\":[{\"email\":\"a@b.com\",\"city\":\"NYC\"}]}").AsObject();
            logUtility.MaskSensitiveDataInJsonContainer(obj);

            JsonObject inner = obj["number"].AsArray()[0].AsObject();
            Assert.AreEqual("XXXXXXX", inner["email"].ToString());  // email is sensitive
            Assert.AreEqual("NYC", inner["city"].ToString());         // city is not sensitive
        }

        // --- All MLE prefix variants ---

        [Test]
        public void MaskSensitiveData_WithAfterMlePrefix()
        {
            string json = "{\"securityCode\":\"999\"}";
            string input = Constants.LOG_REQUEST_AFTER_MLE + json;
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsTrue(result.StartsWith(Constants.LOG_REQUEST_AFTER_MLE));
            string masked = result.Substring(Constants.LOG_REQUEST_AFTER_MLE.Length);
            JsonObject parsed = JsonNode.Parse(masked).AsObject();
            Assert.AreEqual("XXX", parsed["securityCode"].ToString());
        }

        [Test]
        public void MaskSensitiveData_WithNetworkResponseBeforeMlePrefix()
        {
            string json = "{\"number\":\"4111\"}";
            string input = Constants.LOG_NETWORK_RESPONSE_BEFORE_MLE_DECRYPTION + json;
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsTrue(result.StartsWith(Constants.LOG_NETWORK_RESPONSE_BEFORE_MLE_DECRYPTION));
            string masked = result.Substring(Constants.LOG_NETWORK_RESPONSE_BEFORE_MLE_DECRYPTION.Length);
            JsonObject parsed = JsonNode.Parse(masked).AsObject();
            Assert.AreEqual("XXXX", parsed["number"].ToString());
        }

        [Test]
        public void MaskSensitiveData_WithNetworkResponseAfterMlePrefix()
        {
            string json = "{\"email\":\"test@test.com\"}";
            string input = Constants.LOG_NETWORK_RESPONSE_AFTER_MLE_DECRYPTION + json;
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsTrue(result.StartsWith(Constants.LOG_NETWORK_RESPONSE_AFTER_MLE_DECRYPTION));
            string masked = result.Substring(Constants.LOG_NETWORK_RESPONSE_AFTER_MLE_DECRYPTION.Length);
            JsonObject parsed = JsonNode.Parse(masked).AsObject();
            Assert.AreEqual("XXXXXXXXXXXXX", parsed["email"].ToString());
        }

        // --- Regex fallback: Signature header ---

        [Test]
        public void MaskSensitiveData_SignatureHeader_MasksKeyIdAndSignature()
        {
            // Format must match: Signature : keyid="...",<middle>, signature="..."
            string input = "Signature : keyid=\"merchant-123\",algorithm=\"HmacSHA256\" headers=\"host\", signature=\"abc123def=\"";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsTrue(result.Contains("XXXXX"));
            Assert.IsFalse(result.Contains("merchant-123"));
            Assert.IsFalse(result.Contains("abc123def="));
        }

        // --- Regex fallback: Bearer token ---

        [Test]
        public void MaskSensitiveData_BearerToken_MasksToken()
        {
            string input = "Authorization : Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsTrue(result.Contains("xxxxxxxxxxxxxxxx"));
            Assert.IsFalse(result.Contains("eyJhbGciOiJIUzI1NiJ9"));
        }

        // --- JSON primitive input (default: break → regex fallback) ---

        [Test]
        public void MaskSensitiveData_JsonPrimitive_FallsToRegex()
        {
            // A bare integer is valid JSON but hits default case
            string input = "42";
            string result = logUtility.MaskSensitiveData(input);

            // No regex matches, so returned as-is
            Assert.AreEqual("42", result);
        }

        [Test]
        public void MaskSensitiveData_JsonStringPrimitive_FallsToRegex()
        {
            // A bare quoted string is valid JSON but hits default case
            string input = "\"hello world\"";
            string result = logUtility.MaskSensitiveData(input);

            Assert.AreEqual("\"hello world\"", result);
        }

        // --- Non-sensitive field with nested object containing sensitive fields ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_NonSensitiveParentWithSensitiveChildren()
        {
            JsonObject obj = JsonNode.Parse("{\"paymentInfo\":{\"cardNumber\":\"4111222233334444\",\"currency\":\"USD\"}}").AsObject();
            logUtility.MaskSensitiveDataInJsonContainer(obj);

            JsonObject payment = obj["paymentInfo"].AsObject();
            Assert.AreEqual("XXXXXXXXXXXXXXXX", payment["cardNumber"].ToString());
            Assert.AreEqual("USD", payment["currency"].ToString());
        }

        // --- Non-sensitive array containing objects with sensitive fields ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_NonSensitiveContextWithObjectsContainingSensitiveFields()
        {
            JsonArray arr = JsonNode.Parse("[{\"firstName\":\"Alice\",\"id\":\"123\"}]").AsArray();
            logUtility.MaskSensitiveDataInJsonContainer(arr, isSensitiveContext: false);

            JsonObject element = arr[0].AsObject();
            Assert.AreEqual("XXXXX", element["firstName"].ToString());  // firstName is sensitive
            Assert.AreEqual("123", element["id"].ToString());            // id is not sensitive
        }

        // --- Date-like string value in sensitive field ---
        // Note: In System.Text.Json, dates are represented as strings (no native date type).
        // These tests use ISO date strings to exercise masking of string-valued date fields.

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_SensitiveFieldWithDateStringValue()
        {
            // Using a string representation of a date (ISO format)
            JsonObject obj = new JsonObject { ["expirationMonth"] = JsonValue.Create("2025-12-01") };
            logUtility.MaskSensitiveDataInJsonContainer(obj);

            // "2025-12-01" is 10 chars → masked to 10 X's
            Assert.AreEqual("XXXXXXXXXX", obj["expirationMonth"].ToString());
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_DateStringInSensitiveContext()
        {
            JsonArray arr = new JsonArray { JsonValue.Create("2025-06-15") };
            logUtility.MaskSensitiveDataInJsonContainer(arr, isSensitiveContext: true);

            // "2025-06-15" is 10 chars → masked to 10 X's
            Assert.AreEqual("XXXXXXXXXX", arr[0].ToString());
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_NonSensitiveFieldWithDateStringValue_NotMasked()
        {
            JsonObject obj = new JsonObject { ["createdDate"] = JsonValue.Create("2025-01-01") };
            logUtility.MaskSensitiveDataInJsonContainer(obj);

            // "createdDate" is not in the sensitive list, so it should remain untouched
            Assert.AreEqual("2025-01-01", obj["createdDate"].ToString());
        }

        // --- Non-JSON payload masking (sensitiveTags regex) ---

        [Test]
        public void MaskSensitiveData_NonJson_MasksSensitiveFieldsInQuotedJson()
        {
            string input = "error: \"number\":\"4111111111111111\",\"securityCode\":\"123\"";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
            Assert.IsFalse(result.Contains("\"securityCode\":\"123\""));
            Assert.IsTrue(result.Contains("\"number\":\"\""));
            Assert.IsTrue(result.Contains("\"securityCode\":\"\""));
        }

        [Test]
        public void MaskSensitiveData_NonJson_MasksSpacedJson()
        {
            // "key" : "value" with spaces around the colon — valid JSON, goes through JSON masking path
            string input = "{ \"number\" : \"4111111111111111\", \"securityCode\" : \"123\" }";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
            Assert.IsFalse(result.Contains("\"securityCode\" : \"123\""));
        }

        [Test]
        public void MaskSensitiveData_NonJson_MasksXmlPayloads()
        {
            string input = "<response><number>4111111111111111</number><securityCode>123</securityCode></response>";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
            Assert.IsFalse(result.Contains("<securityCode>123</securityCode>"));
            Assert.IsTrue(result.Contains("<number></number>"));
            Assert.IsTrue(result.Contains("<securityCode></securityCode>"));
        }

        [Test]
        public void MaskSensitiveData_NonJson_MasksFormEncodedPayloads()
        {
            string input = "number=4111111111111111&securityCode=123&amount=100";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
            Assert.IsFalse(result.Contains("securityCode=123"));
            Assert.IsTrue(result.Contains("number=&") || result.Contains("number="));
            Assert.IsTrue(result.Contains("securityCode=&") || result.Contains("securityCode="));
            Assert.IsTrue(result.Contains("amount=100")); // non-sensitive field preserved
        }

        [Test]
        public void MaskSensitiveData_NonJson_MasksMultilinePayloads()
        {
            string input = "error occurred\n\"number\":\"4111111111111111\"\n\"securityCode\":\"123\"";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
            Assert.IsFalse(result.Contains("\"securityCode\":\"123\""));
        }

        [Test]
        public void MaskSensitiveData_NonJson_MasksUnquotedNumericPayloads()
        {
            // Numeric card number not quoted — invalid JSON, falls to non-JSON path
            string input = "invalid { \"number\":4111111111111111, \"securityCode\":\"123\" }";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
            Assert.IsFalse(result.Contains("\"securityCode\":\"123\""));
        }

        [Test]
        public void MaskSensitiveData_NonJson_MasksTruncatedQuotedPayloads()
        {
            // Stream cut mid-value — no closing quote. Must still mask the PAN.
            string input = "error chunk: \"number\":\"4111111111111111";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
        }

        [Test]
        public void MaskSensitiveData_NonJson_MasksTruncatedXmlPayloads()
        {
            string input = "<response><number>4111111111111111";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
        }

        // --- Luhn PAN detection in free text ---

        [Test]
        public void MaskSensitiveData_MasksBareLuhnValidPanInFreeText()
        {
            // HTML/plain-text gateway error page with an unlabeled PAN — caught by Luhn sweep.
            string input = "<html>Gateway error: card 4111111111111111 was declined.</html>";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
        }

        [Test]
        public void MaskSensitiveData_MasksBarePanWithSeparatorsInFreeText()
        {
            string input = "Plain error: 4111-1111-1111-1111 invalid";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111-1111-1111-1111"));
            Assert.IsFalse(result.Contains("4111111111111111"));
        }

        [Test]
        public void MaskSensitiveData_DoesNotMaskNonLuhnLongDigitsInFreeText()
        {
            // Long numeric IDs that are not Luhn-valid (e.g. transaction IDs) must NOT be masked.
            string input = "Transaction id 1234567890123456 was processed";
            string result = logUtility.MaskSensitiveData(input);

            // 1234567890123456 is not Luhn-valid → preserved
            Assert.IsTrue(result.Contains("1234567890123456"));
        }

        // --- Sensitive field with array of strings (JSON path) ---

        [Test]
        public void MaskSensitiveData_MasksSensitiveFieldWithArrayOfStrings()
        {
            string input = "{\"firstName\":[\"John\",\"Jane\"],\"lastName\":[\"Doe\"],\"email\":[\"john@example.com\"]}";
            string result = logUtility.MaskSensitiveData(input);
            var resultJson = JsonNode.Parse(result).AsObject();

            Assert.AreEqual("XXXX", resultJson["firstName"][0].ToString());
            Assert.AreEqual("XXXX", resultJson["firstName"][1].ToString());
            Assert.AreEqual("XXX", resultJson["lastName"][0].ToString());
            Assert.AreEqual("XXXXXXXXXXXXXXXX", resultJson["email"][0].ToString());
        }

        [Test]
        public void MaskSensitiveData_MasksSensitiveFieldWithNestedArrayOfStrings()
        {
            string input = "{\"email\":[[\"john@example.com\",\"jane@example.com\"]]}";
            string result = logUtility.MaskSensitiveData(input);
            var resultJson = JsonNode.Parse(result).AsObject();

            Assert.AreEqual("XXXXXXXXXXXXXXXX", resultJson["email"][0][0].ToString());
            Assert.AreEqual("XXXXXXXXXXXXXXXX", resultJson["email"][0][1].ToString());
        }

        [Test]
        public void MaskSensitiveData_DoesNotMaskNonSensitiveArrayStrings()
        {
            string input = "{\"amount\":[\"100\",\"200\"],\"currency\":\"USD\"}";
            string result = logUtility.MaskSensitiveData(input);
            var resultJson = JsonNode.Parse(result).AsObject();

            Assert.AreEqual("100", resultJson["amount"][0].ToString());
            Assert.AreEqual("200", resultJson["amount"][1].ToString());
            Assert.AreEqual("USD", resultJson["currency"].ToString());
        }

        // --- Deeply nested arrays in JSON ---

        [Test]
        public void MaskSensitiveData_MasksSensitiveFieldsInsideArrayObjects()
        {
            string input = "{\"paymentInstruments\":[{\"card\":{\"number\":\"4111111111111111\",\"securityCode\":\"123\"}}]}";
            string result = logUtility.MaskSensitiveData(input);
            var resultJson = JsonNode.Parse(result).AsObject();

            Assert.AreEqual("XXXXXXXXXXXXXXXX", resultJson["paymentInstruments"][0]["card"]["number"].ToString());
            Assert.AreEqual("XXX", resultJson["paymentInstruments"][0]["card"]["securityCode"].ToString());
        }

        [Test]
        public void MaskSensitiveData_MasksSensitiveFieldsInNestedArrays()
        {
            string input = "{\"groups\":[[{\"number\":\"5555555555554444\",\"securityCode\":\"123\"}]]}";
            string result = logUtility.MaskSensitiveData(input);
            var resultJson = JsonNode.Parse(result).AsObject();

            Assert.AreEqual("XXXXXXXXXXXXXXXX", resultJson["groups"][0][0]["number"].ToString());
            Assert.AreEqual("XXX", resultJson["groups"][0][0]["securityCode"].ToString());
        }

        // --- ConvertDictionaryToStringWithMasking ---

        [Test]
        public void ConvertDictionaryToStringWithMasking_MasksSensitiveKeys()
        {
            var dict = new Dictionary<string, string>
            {
                { "number", "4111111111111111" },
                { "merchantId", "testMerchant" }
            };

            string result = logUtility.ConvertDictionaryToStringWithMasking(dict);

            Assert.IsTrue(result.Contains("number = ***"));
            Assert.IsTrue(result.Contains("merchantId = testMerchant"));
            Assert.IsFalse(result.Contains("4111111111111111"));
        }

        [Test]
        public void ConvertDictionaryToStringWithMasking_DisabledMasking_ShowsAllValues()
        {
            var dict = new Dictionary<string, string>
            {
                { "number", "4111111111111111" },
                { "merchantId", "testMerchant" }
            };

            string result = logUtility.ConvertDictionaryToStringWithMasking(dict, maskSensitiveData: false);

            Assert.IsTrue(result.Contains("number = 4111111111111111"));
            Assert.IsTrue(result.Contains("merchantId = testMerchant"));
        }

        [Test]
        public void ConvertDictionaryToString_MasksByDefault()
        {
            var dict = new Dictionary<string, string>
            {
                { "number", "4111111111111111" },
                { "amount", "100" }
            };

            string result = logUtility.ConvertDictionaryToString(dict);

            Assert.IsTrue(result.Contains("number = ***"));
            Assert.IsTrue(result.Contains("amount = 100"));
            Assert.IsFalse(result.Contains("4111111111111111"));
        }
    }
}
