using System.Collections.Generic;
using System.IO;
using ApiSdk.controller;
using ApiSdk.model;
using AuthenticationSdk.core;
using Newtonsoft.Json;
using NUnit.Framework;

namespace ApiSdkTests.controller
{
    [TestFixture]
    public class APIControllerTests
    {
        private string resourceFolderPath =
            "C:\\CYBS\\CyberSource_Authentication_SDK_dotNet\\src\\References\\ApiSdk\\ApiSdkTests\\Resource";

        //Supporting Functions

        private MerchantConfig MerchantConfigObj(string authType, string requestType)
        {
            System.Net.WebRequest.DefaultWebProxy.Credentials
                = System.Net.CredentialCache.DefaultNetworkCredentials;

            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", "testrest"},
                {"merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE="},
                {"merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda"},
                {"authenticationType", authType},
                {"keysDirectory", resourceFolderPath},
                {"keyFilename", ""},
                {"runEnvironment", "apitest.cybersource.com"},
                {"keyAlias", ""},
                {"keyPass", ""},
                {"enableLog", ""},
                {"logDirectory", ""},
                {"logFileMaxSize", ""},
                {"logFileName", ""},
                {"timeout", "10000"},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };

            var obj = new MerchantConfig(configurationDictionary) { RequestType = requestType };

            return obj;
        }

        public string SamplePaymentsData()
        {
            //Create the Sample Data using Model Classes of Payments API
            

            var clientReferenceInformation = new ClientReferenceInformation { code = "TC50171_3" };

            var processingInformation = new ProcessingInformation { commerceIndicator = "internet" };

            var subMerchant = new SubMerchant
            {
                cardAcceptorID = "1234567890",
                country = "US",
                phoneNumber = "650-432-0000",
                address1 = "900 Metro Center",
                postalCode = "94404-2775",
                locality = "Foster Cit",
                name = "Visa Inc",
                administrativeArea = "CA",
                region = "PEN",
                email = "test@cybs.com"
            };

            var aggregatorInformation = new AggregatorInformation
            {
                subMerchant = subMerchant,
                name = "V-Internatio",
                aggregatorID = "123456789"
            };

            var billTo = new BillTo
            {
                country = "US",
                lastName = "VDP",
                address2 = "Address 2",
                address1 = "201 S. Division St.",
                postalCode = "48104-2201",
                locality = "Ann Arbor",
                administrativeArea = "MI",
                firstName = "RTS",
                phoneNumber = "999999999",
                district = "MI",
                buildingNumber = "123",
                company = "Visa",
                email = "test@cybs.com"
            };

            var amountDetails = new AmountDetails
            {
                totalAmount = "102.21",
                currency = "USD"
            };

            var orderInformation = new OrderInformation
            {
                billTo = billTo,
                amountDetails = amountDetails
            };

            var card = new Card
            {
                expirationYear = "2031",
                number = "5555555555554444",
                securityCode = "123",
                expirationMonth = "12",
                type = "002"
            };

            var paymentInformation = new PaymentInformation { card = card };

            var payments = new Payments
            {
                clientReferenceInformation = clientReferenceInformation,
                processingInformation = processingInformation,
                aggregatorInformation = aggregatorInformation,
                orderInformation = orderInformation,
                paymentInformation = paymentInformation
            };

            return JsonConvert.SerializeObject(payments, Formatting.Indented);            
        }

        public void RedoPut()
        {
            string requestJsonData;

            using (var r = new StreamReader(resourceFolderPath + "\\TRRReport_csv.json"))
            {
                requestJsonData = r.ReadToEnd();
            }

            var merchantConfig = MerchantConfigObj("jwt", "PUT");

            merchantConfig.RequestTarget = "/reporting/v2/reportSubscriptions/TRRReport?organizationId=testrest";
            merchantConfig.RequestJsonData = requestJsonData;

            var apiControllerObj = new APIController(merchantConfig);
            var responseObj = apiControllerObj.PutPayment();

            if (responseObj.StatusCode == 400)
            {
                using (var r = new StreamReader(resourceFolderPath + "\\TRRReport_xml.json"))
                {
                    requestJsonData = r.ReadToEnd();
                }

                merchantConfig.RequestJsonData = requestJsonData;

                var apiControllerObjRetry = new APIController(merchantConfig);
                var responseObjRetry = apiControllerObjRetry.PutPayment();                
            }
        }

        //Tests for HTTP_SIGNATURE Authentication type

        [Test]
        public void GetPayment_Test_httpSign()
        {
            var merchantConfig = MerchantConfigObj("http_signature", "GET");

            merchantConfig.RequestTarget = "/pts/v2/captures/5289697403596987704107";            

            var apiControllerObj = new APIController(merchantConfig);

            var responseObj = apiControllerObj.GetPayment();
            
            Assert.AreEqual(200, responseObj.StatusCode);
        }

        [Test]
        public void PostPayment_Test_httpSign()
        {            
            var merchantConfig = MerchantConfigObj("http_signature", "POST");

            merchantConfig.RequestTarget = "/pts/v2/payments/";            

            merchantConfig.RequestJsonData = SamplePaymentsData();

            var apiControllerObj = new APIController(merchantConfig);
            var responseObj = apiControllerObj.PostPayment();

            Assert.AreEqual(201, responseObj.StatusCode);
        }


        [Test]
        public void PutPayment_Test_httpSign()
        {
            string requestJsonData;

            using (var r = new StreamReader(resourceFolderPath + "\\TRRReport_csv.json"))
            {
                requestJsonData = r.ReadToEnd();
            }

            var merchantConfig = MerchantConfigObj("http_signature", "PUT");

            merchantConfig.RequestTarget = "/reporting/v2/reportSubscriptions/TRRReport?organizationId=testrest";           
            merchantConfig.RequestJsonData = requestJsonData;

            var apiControllerObj = new APIController(merchantConfig);
            var responseObj = apiControllerObj.PutPayment();

            if (responseObj.StatusCode == 400)
            {
                using (var r = new StreamReader(resourceFolderPath+"\\TRRReport_xml.json"))
                {
                    requestJsonData = r.ReadToEnd();
                }

                merchantConfig.RequestJsonData = requestJsonData;

                var apiControllerObjRetry = new APIController(merchantConfig);
                var responseObjRetry = apiControllerObjRetry.PutPayment();

                Assert.AreEqual(201, responseObjRetry.StatusCode);
            }
            else
            {
                Assert.AreEqual(201, responseObj.StatusCode);
            }
        }

        [Test]
        public void DeletePayment_Test_httpSign()
        {
            var merchantConfig = MerchantConfigObj("http_signature", "DELETE");

            merchantConfig.RequestTarget = "/reporting/v2/reportSubscriptions/TRRReport?organizationId=testrest";

            var apiControllerObj = new APIController(merchantConfig);
            var responseObj = apiControllerObj.DeletePayment();

            if (responseObj.StatusCode == 404)
            {
                RedoPut();
                responseObj = apiControllerObj.DeletePayment();
            }

            Assert.AreEqual(200, responseObj.StatusCode);
        }


        //Tests for JWT token Authentication Type

        [Test]
        public void GetPayment_Test_jwt()
        {
            var merchantConfig = MerchantConfigObj("jwt", "GET");

            merchantConfig.RequestTarget = "/pts/v2/captures/5289697403596987704107";

            var apiControllerObj = new APIController(merchantConfig);

            var responseObj = apiControllerObj.GetPayment();

            Assert.AreEqual(200, responseObj.StatusCode);
        }

        [Test]
        public void GetPayment_Test_jwt_timeoutException()
        {
            var merchantConfig = MerchantConfigObj("jwt", "GET");

            merchantConfig.RequestTarget = "/pts/v2/captures/5289697403596987704107";
            merchantConfig.TimeOut = "1";

            var apiControllerObj = new APIController(merchantConfig);

            Assert.AreEqual(null, apiControllerObj.GetPayment());
        }

        [Test]
        public void PostPayment_Test_jwt()
        {
            string requestJsonData;

            using (var r = new StreamReader(resourceFolderPath+"\\request_payments.json"))
            {
                requestJsonData = r.ReadToEnd();
            }

            var merchantConfig = MerchantConfigObj("jwt", "POST");

            merchantConfig.RequestTarget = "/pts/v2/payments/";
            merchantConfig.RequestJsonData = requestJsonData;

            var apiControllerObj = new APIController(merchantConfig);
            var responseObj = apiControllerObj.PostPayment();

            Assert.AreEqual(201, responseObj.StatusCode);
        }


        [Test]
        public void PostPayment_Test_jwt_timeoutException()
        {
            string requestJsonData;

            using (var r = new StreamReader(resourceFolderPath + "\\request_payments.json"))
            {
                requestJsonData = r.ReadToEnd();
            }

            var merchantConfig = MerchantConfigObj("jwt", "POST");

            merchantConfig.RequestTarget = "/pts/v2/payments/";
            merchantConfig.RequestJsonData = requestJsonData;
            merchantConfig.TimeOut = "1";

            var apiControllerObj = new APIController(merchantConfig);            

            Assert.AreEqual(null, apiControllerObj.PostPayment());
        }

        [Test]
        public void PutPayment_Test_jwt()
        {
            string requestJsonData;

            using (var r = new StreamReader(resourceFolderPath+"\\TRRReport_csv.json"))
            {
                requestJsonData = r.ReadToEnd();
            }

            var merchantConfig = MerchantConfigObj("jwt", "PUT");

            merchantConfig.RequestTarget = "/reporting/v2/reportSubscriptions/TRRReport?organizationId=testrest";
            merchantConfig.RequestJsonData = requestJsonData;

            var apiControllerObj = new APIController(merchantConfig);
            var responseObj = apiControllerObj.PutPayment();

            if (responseObj.StatusCode == 400)
            {
                using (var r = new StreamReader(resourceFolderPath+"\\TRRReport_xml.json"))
                {
                    requestJsonData = r.ReadToEnd();
                }

                merchantConfig.RequestJsonData = requestJsonData;

                var apiControllerObjRetry = new APIController(merchantConfig);
                var responseObjRetry = apiControllerObjRetry.PutPayment();

                Assert.AreEqual(201, responseObjRetry.StatusCode);
            }
            else
            {
                Assert.AreEqual(201, responseObj.StatusCode);
            }
        }

        [Test]
        public void PutPayment_Test_jwt_timeoutException()
        {
            string requestJsonData;

            using (var r = new StreamReader(resourceFolderPath + "\\TRRReport_csv.json"))
            {
                requestJsonData = r.ReadToEnd();
            }

            var merchantConfig = MerchantConfigObj("jwt", "PUT");

            merchantConfig.RequestTarget = "/reporting/v2/reportSubscriptions/TRRReport?organizationId=testrest";
            merchantConfig.RequestJsonData = requestJsonData;
            merchantConfig.TimeOut = "1";

            var apiControllerObj = new APIController(merchantConfig);            

            Assert.AreEqual(null, apiControllerObj.PutPayment());            
        }

        [Test]
        public void DeletePayment_Test_jwt()
        {
            var merchantConfig = MerchantConfigObj("jwt", "DELETE");

            merchantConfig.RequestTarget = "/reporting/v2/reportSubscriptions/TRRReport?organizationId=testrest";

            var apiControllerObj = new APIController(merchantConfig);
            var responseObj = apiControllerObj.DeletePayment();

            if (responseObj.StatusCode == 404)
            {
                RedoPut();
                responseObj = apiControllerObj.DeletePayment();
            }

            Assert.AreEqual(200, responseObj.StatusCode);
        }

        [Test]
        public void DeletePayment_Test_jwt_timeoutException()
        {
            var merchantConfig = MerchantConfigObj("jwt", "DELETE");

            merchantConfig.RequestTarget = "/reporting/v2/reportSubscriptions/TRRReport?organizationId=testrest";
            merchantConfig.TimeOut = "1";

            var apiControllerObj = new APIController(merchantConfig);            

            Assert.AreEqual(null, apiControllerObj.DeletePayment());
        }
    }
}
