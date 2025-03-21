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
    /// ReportingV3PaymentBatchSummariesGet200ResponsePaymentBatchSummaries
    /// </summary>
    [DataContract]
    public partial class ReportingV3PaymentBatchSummariesGet200ResponsePaymentBatchSummaries :  IEquatable<ReportingV3PaymentBatchSummariesGet200ResponsePaymentBatchSummaries>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ReportingV3PaymentBatchSummariesGet200ResponsePaymentBatchSummaries" /> class.
        /// </summary>
        /// <param name="CurrencyCode">CurrencyCode.</param>
        /// <param name="PaymentSubTypeDescription">PaymentSubTypeDescription.</param>
        /// <param name="StartTime">StartTime.</param>
        /// <param name="EndTime">EndTime.</param>
        /// <param name="SalesCount">SalesCount.</param>
        /// <param name="SalesAmount">SalesAmount.</param>
        /// <param name="CreditCount">CreditCount.</param>
        /// <param name="CreditAmount">CreditAmount.</param>
        /// <param name="AccountName">AccountName.</param>
        /// <param name="AccountId">AccountId.</param>
        /// <param name="MerchantId">MerchantId.</param>
        /// <param name="MerchantName">MerchantName.</param>
        public ReportingV3PaymentBatchSummariesGet200ResponsePaymentBatchSummaries(string CurrencyCode = default(string), string PaymentSubTypeDescription = default(string), DateTime? StartTime = default(DateTime?), DateTime? EndTime = default(DateTime?), int? SalesCount = default(int?), string SalesAmount = default(string), int? CreditCount = default(int?), string CreditAmount = default(string), string AccountName = default(string), string AccountId = default(string), string MerchantId = default(string), string MerchantName = default(string))
        {
            this.CurrencyCode = CurrencyCode;
            this.PaymentSubTypeDescription = PaymentSubTypeDescription;
            this.StartTime = StartTime;
            this.EndTime = EndTime;
            this.SalesCount = SalesCount;
            this.SalesAmount = SalesAmount;
            this.CreditCount = CreditCount;
            this.CreditAmount = CreditAmount;
            this.AccountName = AccountName;
            this.AccountId = AccountId;
            this.MerchantId = MerchantId;
            this.MerchantName = MerchantName;
        }
        
        /// <summary>
        /// Gets or Sets CurrencyCode
        /// </summary>
        [DataMember(Name="currencyCode", EmitDefaultValue=false)]
        public string CurrencyCode { get; set; }

        /// <summary>
        /// Gets or Sets PaymentSubTypeDescription
        /// </summary>
        [DataMember(Name="paymentSubTypeDescription", EmitDefaultValue=false)]
        public string PaymentSubTypeDescription { get; set; }

        /// <summary>
        /// Gets or Sets StartTime
        /// </summary>
        [DataMember(Name="startTime", EmitDefaultValue=false)]
        public DateTime? StartTime { get; set; }

        /// <summary>
        /// Gets or Sets EndTime
        /// </summary>
        [DataMember(Name="endTime", EmitDefaultValue=false)]
        public DateTime? EndTime { get; set; }

        /// <summary>
        /// Gets or Sets SalesCount
        /// </summary>
        [DataMember(Name="salesCount", EmitDefaultValue=false)]
        public int? SalesCount { get; set; }

        /// <summary>
        /// Gets or Sets SalesAmount
        /// </summary>
        [DataMember(Name="salesAmount", EmitDefaultValue=false)]
        public string SalesAmount { get; set; }

        /// <summary>
        /// Gets or Sets CreditCount
        /// </summary>
        [DataMember(Name="creditCount", EmitDefaultValue=false)]
        public int? CreditCount { get; set; }

        /// <summary>
        /// Gets or Sets CreditAmount
        /// </summary>
        [DataMember(Name="creditAmount", EmitDefaultValue=false)]
        public string CreditAmount { get; set; }

        /// <summary>
        /// Gets or Sets AccountName
        /// </summary>
        [DataMember(Name="accountName", EmitDefaultValue=false)]
        public string AccountName { get; set; }

        /// <summary>
        /// Gets or Sets AccountId
        /// </summary>
        [DataMember(Name="accountId", EmitDefaultValue=false)]
        public string AccountId { get; set; }

        /// <summary>
        /// Gets or Sets MerchantId
        /// </summary>
        [DataMember(Name="merchantId", EmitDefaultValue=false)]
        public string MerchantId { get; set; }

        /// <summary>
        /// Gets or Sets MerchantName
        /// </summary>
        [DataMember(Name="merchantName", EmitDefaultValue=false)]
        public string MerchantName { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class ReportingV3PaymentBatchSummariesGet200ResponsePaymentBatchSummaries {\n");
            if (CurrencyCode != null) sb.Append("  CurrencyCode: ").Append(CurrencyCode).Append("\n");
            if (PaymentSubTypeDescription != null) sb.Append("  PaymentSubTypeDescription: ").Append(PaymentSubTypeDescription).Append("\n");
            if (StartTime != null) sb.Append("  StartTime: ").Append(StartTime).Append("\n");
            if (EndTime != null) sb.Append("  EndTime: ").Append(EndTime).Append("\n");
            if (SalesCount != null) sb.Append("  SalesCount: ").Append(SalesCount).Append("\n");
            if (SalesAmount != null) sb.Append("  SalesAmount: ").Append(SalesAmount).Append("\n");
            if (CreditCount != null) sb.Append("  CreditCount: ").Append(CreditCount).Append("\n");
            if (CreditAmount != null) sb.Append("  CreditAmount: ").Append(CreditAmount).Append("\n");
            if (AccountName != null) sb.Append("  AccountName: ").Append(AccountName).Append("\n");
            if (AccountId != null) sb.Append("  AccountId: ").Append(AccountId).Append("\n");
            if (MerchantId != null) sb.Append("  MerchantId: ").Append(MerchantId).Append("\n");
            if (MerchantName != null) sb.Append("  MerchantName: ").Append(MerchantName).Append("\n");
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
            return this.Equals(obj as ReportingV3PaymentBatchSummariesGet200ResponsePaymentBatchSummaries);
        }

        /// <summary>
        /// Returns true if ReportingV3PaymentBatchSummariesGet200ResponsePaymentBatchSummaries instances are equal
        /// </summary>
        /// <param name="other">Instance of ReportingV3PaymentBatchSummariesGet200ResponsePaymentBatchSummaries to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ReportingV3PaymentBatchSummariesGet200ResponsePaymentBatchSummaries other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.CurrencyCode == other.CurrencyCode ||
                    this.CurrencyCode != null &&
                    this.CurrencyCode.Equals(other.CurrencyCode)
                ) && 
                (
                    this.PaymentSubTypeDescription == other.PaymentSubTypeDescription ||
                    this.PaymentSubTypeDescription != null &&
                    this.PaymentSubTypeDescription.Equals(other.PaymentSubTypeDescription)
                ) && 
                (
                    this.StartTime == other.StartTime ||
                    this.StartTime != null &&
                    this.StartTime.Equals(other.StartTime)
                ) && 
                (
                    this.EndTime == other.EndTime ||
                    this.EndTime != null &&
                    this.EndTime.Equals(other.EndTime)
                ) && 
                (
                    this.SalesCount == other.SalesCount ||
                    this.SalesCount != null &&
                    this.SalesCount.Equals(other.SalesCount)
                ) && 
                (
                    this.SalesAmount == other.SalesAmount ||
                    this.SalesAmount != null &&
                    this.SalesAmount.Equals(other.SalesAmount)
                ) && 
                (
                    this.CreditCount == other.CreditCount ||
                    this.CreditCount != null &&
                    this.CreditCount.Equals(other.CreditCount)
                ) && 
                (
                    this.CreditAmount == other.CreditAmount ||
                    this.CreditAmount != null &&
                    this.CreditAmount.Equals(other.CreditAmount)
                ) && 
                (
                    this.AccountName == other.AccountName ||
                    this.AccountName != null &&
                    this.AccountName.Equals(other.AccountName)
                ) && 
                (
                    this.AccountId == other.AccountId ||
                    this.AccountId != null &&
                    this.AccountId.Equals(other.AccountId)
                ) && 
                (
                    this.MerchantId == other.MerchantId ||
                    this.MerchantId != null &&
                    this.MerchantId.Equals(other.MerchantId)
                ) && 
                (
                    this.MerchantName == other.MerchantName ||
                    this.MerchantName != null &&
                    this.MerchantName.Equals(other.MerchantName)
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
                if (this.CurrencyCode != null)
                    hash = hash * 59 + this.CurrencyCode.GetHashCode();
                if (this.PaymentSubTypeDescription != null)
                    hash = hash * 59 + this.PaymentSubTypeDescription.GetHashCode();
                if (this.StartTime != null)
                    hash = hash * 59 + this.StartTime.GetHashCode();
                if (this.EndTime != null)
                    hash = hash * 59 + this.EndTime.GetHashCode();
                if (this.SalesCount != null)
                    hash = hash * 59 + this.SalesCount.GetHashCode();
                if (this.SalesAmount != null)
                    hash = hash * 59 + this.SalesAmount.GetHashCode();
                if (this.CreditCount != null)
                    hash = hash * 59 + this.CreditCount.GetHashCode();
                if (this.CreditAmount != null)
                    hash = hash * 59 + this.CreditAmount.GetHashCode();
                if (this.AccountName != null)
                    hash = hash * 59 + this.AccountName.GetHashCode();
                if (this.AccountId != null)
                    hash = hash * 59 + this.AccountId.GetHashCode();
                if (this.MerchantId != null)
                    hash = hash * 59 + this.MerchantId.GetHashCode();
                if (this.MerchantName != null)
                    hash = hash * 59 + this.MerchantName.GetHashCode();
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
