/* 
 * CyberSource Merged Spec
 *
 * All CyberSource API specs merged together. These are available at https://developer.cybersource.com/api/reference/api-reference.html
 *
 * OpenAPI spec version: 0.0.1
 * 
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */


using NUnit.Framework;

using System;
using System.Linq;
using System.IO;
using System.Collections.Generic;
using CyberSource.Api;
using CyberSource.Model;
using CyberSource.Client;
using System.Reflection;

namespace CyberSource.Test
{
    /// <summary>
    ///  Class for testing Ptsv2paymentsProcessingInformation
    /// </summary>
    /// <remarks>
    /// This file is automatically generated by Swagger Codegen.
    /// Please update the test case below to test the model.
    /// </remarks>
    [TestFixture]
    public class Ptsv2paymentsProcessingInformationTests
    {
        // TODO uncomment below to declare an instance variable for Ptsv2paymentsProcessingInformation
        //private Ptsv2paymentsProcessingInformation instance;

        /// <summary>
        /// Setup before each test
        /// </summary>
        [SetUp]
        public void Init()
        {
            // TODO uncomment below to create an instance of Ptsv2paymentsProcessingInformation
            //instance = new Ptsv2paymentsProcessingInformation();
        }

        /// <summary>
        /// Clean up after each test
        /// </summary>
        [TearDown]
        public void Cleanup()
        {

        }

        /// <summary>
        /// Test an instance of Ptsv2paymentsProcessingInformation
        /// </summary>
        [Test]
        public void Ptsv2paymentsProcessingInformationInstanceTest()
        {
            // TODO uncomment below to test "IsInstanceOfType" Ptsv2paymentsProcessingInformation
            //Assert.IsInstanceOfType<Ptsv2paymentsProcessingInformation> (instance, "variable 'instance' is a Ptsv2paymentsProcessingInformation");
        }

        /// <summary>
        /// Test the property 'ActionList'
        /// </summary>
        [Test]
        public void ActionListTest()
        {
            // TODO unit test for the property 'ActionList'
        }
        /// <summary>
        /// Test the property 'EnableEscrowOption'
        /// </summary>
        [Test]
        public void EnableEscrowOptionTest()
        {
            // TODO unit test for the property 'EnableEscrowOption'
        }
        /// <summary>
        /// Test the property 'ActionTokenTypes'
        /// </summary>
        [Test]
        public void ActionTokenTypesTest()
        {
            // TODO unit test for the property 'ActionTokenTypes'
        }
        /// <summary>
        /// Test the property 'BinSource'
        /// </summary>
        [Test]
        public void BinSourceTest()
        {
            // TODO unit test for the property 'BinSource'
        }
        /// <summary>
        /// Test the property 'Capture'
        /// </summary>
        [Test]
        public void CaptureTest()
        {
            // TODO unit test for the property 'Capture'
        }
        /// <summary>
        /// Test the property 'ProcessorId'
        /// </summary>
        [Test]
        public void ProcessorIdTest()
        {
            // TODO unit test for the property 'ProcessorId'
        }
        /// <summary>
        /// Test the property 'BusinessApplicationId'
        /// </summary>
        [Test]
        public void BusinessApplicationIdTest()
        {
            // TODO unit test for the property 'BusinessApplicationId'
        }
        /// <summary>
        /// Test the property 'CommerceIndicator'
        /// </summary>
        [Test]
        public void CommerceIndicatorTest()
        {
            // TODO unit test for the property 'CommerceIndicator'
        }
        /// <summary>
        /// Test the property 'CommerceIndicatorLabel'
        /// </summary>
        [Test]
        public void CommerceIndicatorLabelTest()
        {
            // TODO unit test for the property 'CommerceIndicatorLabel'
        }
        /// <summary>
        /// Test the property 'PaymentSolution'
        /// </summary>
        [Test]
        public void PaymentSolutionTest()
        {
            // TODO unit test for the property 'PaymentSolution'
        }
        /// <summary>
        /// Test the property 'ReconciliationId'
        /// </summary>
        [Test]
        public void ReconciliationIdTest()
        {
            // TODO unit test for the property 'ReconciliationId'
        }
        /// <summary>
        /// Test the property 'LinkId'
        /// </summary>
        [Test]
        public void LinkIdTest()
        {
            // TODO unit test for the property 'LinkId'
        }
        /// <summary>
        /// Test the property 'PurchaseLevel'
        /// </summary>
        [Test]
        public void PurchaseLevelTest()
        {
            // TODO unit test for the property 'PurchaseLevel'
        }
        /// <summary>
        /// Test the property 'TransactionTimeout'
        /// </summary>
        [Test]
        public void TransactionTimeoutTest()
        {
            // TODO unit test for the property 'TransactionTimeout'
        }
        /// <summary>
        /// Test the property 'IntentsId'
        /// </summary>
        [Test]
        public void IntentsIdTest()
        {
            // TODO unit test for the property 'IntentsId'
        }
        /// <summary>
        /// Test the property 'ReportGroup'
        /// </summary>
        [Test]
        public void ReportGroupTest()
        {
            // TODO unit test for the property 'ReportGroup'
        }
        /// <summary>
        /// Test the property 'VisaCheckoutId'
        /// </summary>
        [Test]
        public void VisaCheckoutIdTest()
        {
            // TODO unit test for the property 'VisaCheckoutId'
        }
        /// <summary>
        /// Test the property 'IndustryDataType'
        /// </summary>
        [Test]
        public void IndustryDataTypeTest()
        {
            // TODO unit test for the property 'IndustryDataType'
        }
        /// <summary>
        /// Test the property 'AuthorizationOptions'
        /// </summary>
        [Test]
        public void AuthorizationOptionsTest()
        {
            // TODO unit test for the property 'AuthorizationOptions'
        }
        /// <summary>
        /// Test the property 'CaptureOptions'
        /// </summary>
        [Test]
        public void CaptureOptionsTest()
        {
            // TODO unit test for the property 'CaptureOptions'
        }
        /// <summary>
        /// Test the property 'RecurringOptions'
        /// </summary>
        [Test]
        public void RecurringOptionsTest()
        {
            // TODO unit test for the property 'RecurringOptions'
        }
        /// <summary>
        /// Test the property 'BankTransferOptions'
        /// </summary>
        [Test]
        public void BankTransferOptionsTest()
        {
            // TODO unit test for the property 'BankTransferOptions'
        }
        /// <summary>
        /// Test the property 'PurchaseOptions'
        /// </summary>
        [Test]
        public void PurchaseOptionsTest()
        {
            // TODO unit test for the property 'PurchaseOptions'
        }
        /// <summary>
        /// Test the property 'ElectronicBenefitsTransfer'
        /// </summary>
        [Test]
        public void ElectronicBenefitsTransferTest()
        {
            // TODO unit test for the property 'ElectronicBenefitsTransfer'
        }
        /// <summary>
        /// Test the property 'LoanOptions'
        /// </summary>
        [Test]
        public void LoanOptionsTest()
        {
            // TODO unit test for the property 'LoanOptions'
        }
        /// <summary>
        /// Test the property 'WalletType'
        /// </summary>
        [Test]
        public void WalletTypeTest()
        {
            // TODO unit test for the property 'WalletType'
        }
        /// <summary>
        /// Test the property 'NationalNetDomesticData'
        /// </summary>
        [Test]
        public void NationalNetDomesticDataTest()
        {
            // TODO unit test for the property 'NationalNetDomesticData'
        }
        /// <summary>
        /// Test the property 'JapanPaymentOptions'
        /// </summary>
        [Test]
        public void JapanPaymentOptionsTest()
        {
            // TODO unit test for the property 'JapanPaymentOptions'
        }
        /// <summary>
        /// Test the property 'MobileRemotePaymentType'
        /// </summary>
        [Test]
        public void MobileRemotePaymentTypeTest()
        {
            // TODO unit test for the property 'MobileRemotePaymentType'
        }
        /// <summary>
        /// Test the property 'ExtendedCreditTotalCount'
        /// </summary>
        [Test]
        public void ExtendedCreditTotalCountTest()
        {
            // TODO unit test for the property 'ExtendedCreditTotalCount'
        }
        /// <summary>
        /// Test the property 'NetworkRoutingOrder'
        /// </summary>
        [Test]
        public void NetworkRoutingOrderTest()
        {
            // TODO unit test for the property 'NetworkRoutingOrder'
        }
        /// <summary>
        /// Test the property 'PayByPointsIndicator'
        /// </summary>
        [Test]
        public void PayByPointsIndicatorTest()
        {
            // TODO unit test for the property 'PayByPointsIndicator'
        }
        /// <summary>
        /// Test the property 'Timeout'
        /// </summary>
        [Test]
        public void TimeoutTest()
        {
            // TODO unit test for the property 'Timeout'
        }
        /// <summary>
        /// Test the property 'IsReturnAuthRecordEnabled'
        /// </summary>
        [Test]
        public void IsReturnAuthRecordEnabledTest()
        {
            // TODO unit test for the property 'IsReturnAuthRecordEnabled'
        }
        /// <summary>
        /// Test the property 'NetworkPartnerId'
        /// </summary>
        [Test]
        public void NetworkPartnerIdTest()
        {
            // TODO unit test for the property 'NetworkPartnerId'
        }
        /// <summary>
        /// Test the property 'PaymentType'
        /// </summary>
        [Test]
        public void PaymentTypeTest()
        {
            // TODO unit test for the property 'PaymentType'
        }
        /// <summary>
        /// Test the property 'EnablerId'
        /// </summary>
        [Test]
        public void EnablerIdTest()
        {
            // TODO unit test for the property 'EnablerId'
        }
        /// <summary>
        /// Test the property 'ProcessingInstruction'
        /// </summary>
        [Test]
        public void ProcessingInstructionTest()
        {
            // TODO unit test for the property 'ProcessingInstruction'
        }
        /// <summary>
        /// Test the property 'TransactionTypeIndicator'
        /// </summary>
        [Test]
        public void TransactionTypeIndicatorTest()
        {
            // TODO unit test for the property 'TransactionTypeIndicator'
        }
        /// <summary>
        /// Test the property 'PurposeOfPayment'
        /// </summary>
        [Test]
        public void PurposeOfPaymentTest()
        {
            // TODO unit test for the property 'PurposeOfPayment'
        }
        /// <summary>
        /// Test the property 'LanguageCode'
        /// </summary>
        [Test]
        public void LanguageCodeTest()
        {
            // TODO unit test for the property 'LanguageCode'
        }
        /// <summary>
        /// Test the property 'OriginalPaymentId'
        /// </summary>
        [Test]
        public void OriginalPaymentIdTest()
        {
            // TODO unit test for the property 'OriginalPaymentId'
        }

    }

}
