/* 
 * CyberSource Merged Spec
 *
 * All CyberSource API specs merged together. These are available at https://developer.cybersource.com/api/reference/api-reference.html
 *
 * OpenAPI spec version: 0.0.1
 * 
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

using System;
using System.IO;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reflection;
using RestSharp;
using NUnit.Framework;

using CyberSource.Client;
using CyberSource.Api;
using CyberSource.Model;

namespace CyberSource.Test
{
    /// <summary>
    ///  Class for testing PaymentsApi
    /// </summary>
    /// <remarks>
    /// This file is automatically generated by Swagger Codegen.
    /// Please update the test case below to test the API endpoint.
    /// </remarks>
    [TestFixture]
    public class PaymentsApiTests
    {
        private PaymentsApi instance;

        /// <summary>
        /// Setup before each unit test
        /// </summary>
        [SetUp]
        public void Init()
        {
            instance = new PaymentsApi();
        }

        /// <summary>
        /// Clean up after each unit test
        /// </summary>
        [TearDown]
        public void Cleanup()
        {

        }

        /// <summary>
        /// Test an instance of PaymentsApi
        /// </summary>
        [Test]
        public void InstanceTest()
        {
            // TODO uncomment below to test 'IsInstanceOfType' PaymentsApi
            //Assert.IsInstanceOfType(typeof(PaymentsApi), instance, "instance is a PaymentsApi");
        }

        
        /// <summary>
        /// Test CreateOrderRequest
        /// </summary>
        [Test]
        public void CreateOrderRequestTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //OrderPaymentRequest orderPaymentRequest = null;
            //string id = null;
            //var response = instance.CreateOrderRequest(orderPaymentRequest, id);
            //Assert.IsInstanceOf<PtsV2PaymentsOrderPost201Response> (response, "response is PtsV2PaymentsOrderPost201Response");
        }
        
        /// <summary>
        /// Test CreatePayment
        /// </summary>
        [Test]
        public void CreatePaymentTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //CreatePaymentRequest createPaymentRequest = null;
            //var response = instance.CreatePayment(createPaymentRequest);
            //Assert.IsInstanceOf<PtsV2PaymentsPost201Response> (response, "response is PtsV2PaymentsPost201Response");
        }
        
        /// <summary>
        /// Test CreateSessionRequest
        /// </summary>
        [Test]
        public void CreateSessionRequestTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //CreateSessionReq createSessionReq = null;
            //var response = instance.CreateSessionRequest(createSessionReq);
            //Assert.IsInstanceOf<PtsV2PaymentsPost201Response2> (response, "response is PtsV2PaymentsPost201Response2");
        }
        
        /// <summary>
        /// Test IncrementAuth
        /// </summary>
        [Test]
        public void IncrementAuthTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string id = null;
            //IncrementAuthRequest incrementAuthRequest = null;
            //var response = instance.IncrementAuth(id, incrementAuthRequest);
            //Assert.IsInstanceOf<PtsV2IncrementalAuthorizationPatch201Response> (response, "response is PtsV2IncrementalAuthorizationPatch201Response");
        }
        
        /// <summary>
        /// Test RefreshPaymentStatus
        /// </summary>
        [Test]
        public void RefreshPaymentStatusTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string id = null;
            //RefreshPaymentStatusRequest refreshPaymentStatusRequest = null;
            //var response = instance.RefreshPaymentStatus(id, refreshPaymentStatusRequest);
            //Assert.IsInstanceOf<PtsV2PaymentsPost201Response1> (response, "response is PtsV2PaymentsPost201Response1");
        }
        
        /// <summary>
        /// Test UpdateSessionReq
        /// </summary>
        [Test]
        public void UpdateSessionReqTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //CreateSessionRequest createSessionRequest = null;
            //string id = null;
            //var response = instance.UpdateSessionReq(createSessionRequest, id);
            //Assert.IsInstanceOf<PtsV2PaymentsPost201Response2> (response, "response is PtsV2PaymentsPost201Response2");
        }
        
    }

}
