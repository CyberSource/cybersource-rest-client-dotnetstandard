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
using System.Linq;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Runtime.Serialization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System.ComponentModel.DataAnnotations;
using SwaggerDateConverter = CyberSource.Client.SwaggerDateConverter;

namespace CyberSource.Model
{
    /// <summary>
    /// ReportingV3PurchaseRefundDetailsGet200ResponseSettlements
    /// </summary>
    [DataContract]
    public partial class ReportingV3PurchaseRefundDetailsGet200ResponseSettlements :  IEquatable<ReportingV3PurchaseRefundDetailsGet200ResponseSettlements>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ReportingV3PurchaseRefundDetailsGet200ResponseSettlements" /> class.
        /// </summary>
        /// <param name="RequestId">An unique identification number assigned by CyberSource to identify the submitted request..</param>
        /// <param name="TransactionType">Transaction Type.</param>
        /// <param name="SubmissionTime">Submission Date.</param>
        /// <param name="Amount">Amount.</param>
        /// <param name="CurrencyCode">Valid ISO 4217 ALPHA-3 currency code.</param>
        /// <param name="PaymentMethod">payment method.</param>
        /// <param name="WalletType">Solution Type (Wallet).</param>
        /// <param name="PaymentType">Payment Type.</param>
        /// <param name="AccountSuffix">Account Suffix.</param>
        /// <param name="CybersourceBatchTime">Cybersource Batch Time.</param>
        /// <param name="CybersourceBatchId">Cybersource Batch Id.</param>
        /// <param name="CardType">Card Type.</param>
        /// <param name="DebitNetwork">Debit Network.</param>
        public ReportingV3PurchaseRefundDetailsGet200ResponseSettlements(string RequestId = default(string), string TransactionType = default(string), DateTime? SubmissionTime = default(DateTime?), string Amount = default(string), string CurrencyCode = default(string), string PaymentMethod = default(string), string WalletType = default(string), string PaymentType = default(string), string AccountSuffix = default(string), DateTime? CybersourceBatchTime = default(DateTime?), string CybersourceBatchId = default(string), string CardType = default(string), string DebitNetwork = default(string))
        {
            this.RequestId = RequestId;
            this.TransactionType = TransactionType;
            this.SubmissionTime = SubmissionTime;
            this.Amount = Amount;
            this.CurrencyCode = CurrencyCode;
            this.PaymentMethod = PaymentMethod;
            this.WalletType = WalletType;
            this.PaymentType = PaymentType;
            this.AccountSuffix = AccountSuffix;
            this.CybersourceBatchTime = CybersourceBatchTime;
            this.CybersourceBatchId = CybersourceBatchId;
            this.CardType = CardType;
            this.DebitNetwork = DebitNetwork;
        }
        
        /// <summary>
        /// An unique identification number assigned by CyberSource to identify the submitted request.
        /// </summary>
        /// <value>An unique identification number assigned by CyberSource to identify the submitted request.</value>
        [DataMember(Name="requestId", EmitDefaultValue=false)]
        public string RequestId { get; set; }

        /// <summary>
        /// Transaction Type
        /// </summary>
        /// <value>Transaction Type</value>
        [DataMember(Name="transactionType", EmitDefaultValue=false)]
        public string TransactionType { get; set; }

        /// <summary>
        /// Submission Date
        /// </summary>
        /// <value>Submission Date</value>
        [DataMember(Name="submissionTime", EmitDefaultValue=false)]
        public DateTime? SubmissionTime { get; set; }

        /// <summary>
        /// Amount
        /// </summary>
        /// <value>Amount</value>
        [DataMember(Name="amount", EmitDefaultValue=false)]
        public string Amount { get; set; }

        /// <summary>
        /// Valid ISO 4217 ALPHA-3 currency code
        /// </summary>
        /// <value>Valid ISO 4217 ALPHA-3 currency code</value>
        [DataMember(Name="currencyCode", EmitDefaultValue=false)]
        public string CurrencyCode { get; set; }

        /// <summary>
        /// payment method
        /// </summary>
        /// <value>payment method</value>
        [DataMember(Name="paymentMethod", EmitDefaultValue=false)]
        public string PaymentMethod { get; set; }

        /// <summary>
        /// Solution Type (Wallet)
        /// </summary>
        /// <value>Solution Type (Wallet)</value>
        [DataMember(Name="walletType", EmitDefaultValue=false)]
        public string WalletType { get; set; }

        /// <summary>
        /// Payment Type
        /// </summary>
        /// <value>Payment Type</value>
        [DataMember(Name="paymentType", EmitDefaultValue=false)]
        public string PaymentType { get; set; }

        /// <summary>
        /// Account Suffix
        /// </summary>
        /// <value>Account Suffix</value>
        [DataMember(Name="accountSuffix", EmitDefaultValue=false)]
        public string AccountSuffix { get; set; }

        /// <summary>
        /// Cybersource Batch Time
        /// </summary>
        /// <value>Cybersource Batch Time</value>
        [DataMember(Name="cybersourceBatchTime", EmitDefaultValue=false)]
        public DateTime? CybersourceBatchTime { get; set; }

        /// <summary>
        /// Cybersource Batch Id
        /// </summary>
        /// <value>Cybersource Batch Id</value>
        [DataMember(Name="cybersourceBatchId", EmitDefaultValue=false)]
        public string CybersourceBatchId { get; set; }

        /// <summary>
        /// Card Type
        /// </summary>
        /// <value>Card Type</value>
        [DataMember(Name="cardType", EmitDefaultValue=false)]
        public string CardType { get; set; }

        /// <summary>
        /// Debit Network
        /// </summary>
        /// <value>Debit Network</value>
        [DataMember(Name="debitNetwork", EmitDefaultValue=false)]
        public string DebitNetwork { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class ReportingV3PurchaseRefundDetailsGet200ResponseSettlements {\n");
            if (RequestId != null) sb.Append("  RequestId: ").Append(RequestId).Append("\n");
            if (TransactionType != null) sb.Append("  TransactionType: ").Append(TransactionType).Append("\n");
            if (SubmissionTime != null) sb.Append("  SubmissionTime: ").Append(SubmissionTime).Append("\n");
            if (Amount != null) sb.Append("  Amount: ").Append(Amount).Append("\n");
            if (CurrencyCode != null) sb.Append("  CurrencyCode: ").Append(CurrencyCode).Append("\n");
            if (PaymentMethod != null) sb.Append("  PaymentMethod: ").Append(PaymentMethod).Append("\n");
            if (WalletType != null) sb.Append("  WalletType: ").Append(WalletType).Append("\n");
            if (PaymentType != null) sb.Append("  PaymentType: ").Append(PaymentType).Append("\n");
            if (AccountSuffix != null) sb.Append("  AccountSuffix: ").Append(AccountSuffix).Append("\n");
            if (CybersourceBatchTime != null) sb.Append("  CybersourceBatchTime: ").Append(CybersourceBatchTime).Append("\n");
            if (CybersourceBatchId != null) sb.Append("  CybersourceBatchId: ").Append(CybersourceBatchId).Append("\n");
            if (CardType != null) sb.Append("  CardType: ").Append(CardType).Append("\n");
            if (DebitNetwork != null) sb.Append("  DebitNetwork: ").Append(DebitNetwork).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }
  
        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public string ToJson()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="obj">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object obj)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            return this.Equals(obj as ReportingV3PurchaseRefundDetailsGet200ResponseSettlements);
        }

        /// <summary>
        /// Returns true if ReportingV3PurchaseRefundDetailsGet200ResponseSettlements instances are equal
        /// </summary>
        /// <param name="other">Instance of ReportingV3PurchaseRefundDetailsGet200ResponseSettlements to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ReportingV3PurchaseRefundDetailsGet200ResponseSettlements other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.RequestId == other.RequestId ||
                    this.RequestId != null &&
                    this.RequestId.Equals(other.RequestId)
                ) && 
                (
                    this.TransactionType == other.TransactionType ||
                    this.TransactionType != null &&
                    this.TransactionType.Equals(other.TransactionType)
                ) && 
                (
                    this.SubmissionTime == other.SubmissionTime ||
                    this.SubmissionTime != null &&
                    this.SubmissionTime.Equals(other.SubmissionTime)
                ) && 
                (
                    this.Amount == other.Amount ||
                    this.Amount != null &&
                    this.Amount.Equals(other.Amount)
                ) && 
                (
                    this.CurrencyCode == other.CurrencyCode ||
                    this.CurrencyCode != null &&
                    this.CurrencyCode.Equals(other.CurrencyCode)
                ) && 
                (
                    this.PaymentMethod == other.PaymentMethod ||
                    this.PaymentMethod != null &&
                    this.PaymentMethod.Equals(other.PaymentMethod)
                ) && 
                (
                    this.WalletType == other.WalletType ||
                    this.WalletType != null &&
                    this.WalletType.Equals(other.WalletType)
                ) && 
                (
                    this.PaymentType == other.PaymentType ||
                    this.PaymentType != null &&
                    this.PaymentType.Equals(other.PaymentType)
                ) && 
                (
                    this.AccountSuffix == other.AccountSuffix ||
                    this.AccountSuffix != null &&
                    this.AccountSuffix.Equals(other.AccountSuffix)
                ) && 
                (
                    this.CybersourceBatchTime == other.CybersourceBatchTime ||
                    this.CybersourceBatchTime != null &&
                    this.CybersourceBatchTime.Equals(other.CybersourceBatchTime)
                ) && 
                (
                    this.CybersourceBatchId == other.CybersourceBatchId ||
                    this.CybersourceBatchId != null &&
                    this.CybersourceBatchId.Equals(other.CybersourceBatchId)
                ) && 
                (
                    this.CardType == other.CardType ||
                    this.CardType != null &&
                    this.CardType.Equals(other.CardType)
                ) && 
                (
                    this.DebitNetwork == other.DebitNetwork ||
                    this.DebitNetwork != null &&
                    this.DebitNetwork.Equals(other.DebitNetwork)
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            // credit: http://stackoverflow.com/a/263416/677735
            unchecked // Overflow is fine, just wrap
            {
                int hash = 41;
                // Suitable nullity checks etc, of course :)
                if (this.RequestId != null)
                    hash = hash * 59 + this.RequestId.GetHashCode();
                if (this.TransactionType != null)
                    hash = hash * 59 + this.TransactionType.GetHashCode();
                if (this.SubmissionTime != null)
                    hash = hash * 59 + this.SubmissionTime.GetHashCode();
                if (this.Amount != null)
                    hash = hash * 59 + this.Amount.GetHashCode();
                if (this.CurrencyCode != null)
                    hash = hash * 59 + this.CurrencyCode.GetHashCode();
                if (this.PaymentMethod != null)
                    hash = hash * 59 + this.PaymentMethod.GetHashCode();
                if (this.WalletType != null)
                    hash = hash * 59 + this.WalletType.GetHashCode();
                if (this.PaymentType != null)
                    hash = hash * 59 + this.PaymentType.GetHashCode();
                if (this.AccountSuffix != null)
                    hash = hash * 59 + this.AccountSuffix.GetHashCode();
                if (this.CybersourceBatchTime != null)
                    hash = hash * 59 + this.CybersourceBatchTime.GetHashCode();
                if (this.CybersourceBatchId != null)
                    hash = hash * 59 + this.CybersourceBatchId.GetHashCode();
                if (this.CardType != null)
                    hash = hash * 59 + this.CardType.GetHashCode();
                if (this.DebitNetwork != null)
                    hash = hash * 59 + this.DebitNetwork.GetHashCode();
                return hash;
            }
        }

        /// <summary>
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> IValidatableObject.Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

}
