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
    /// CardProcessingConfigFeaturesCardNotPresentPayoutsCurrencies
    /// </summary>
    [DataContract]
    public partial class CardProcessingConfigFeaturesCardNotPresentPayoutsCurrencies :  IEquatable<CardProcessingConfigFeaturesCardNotPresentPayoutsCurrencies>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CardProcessingConfigFeaturesCardNotPresentPayoutsCurrencies" /> class.
        /// </summary>
        /// <param name="Enabled">Enabled.</param>
        /// <param name="EnabledCardPresent">Indicates whether the card-present transaction is activated for the selected currency. If both enabledCardPresent and enabledCardNotPresent are set to null, then enabledCardPresent will have the value of enabled. .</param>
        /// <param name="EnabledCardNotPresent">Indicates whether the card-present transaction is activated for the selected currency. If both enabledCardPresent and enabledCardNotPresent are set to null, then enabledCardNotPresent will have the value of enabled. .</param>
        /// <param name="MerchantId">Merchant ID assigned by an acquirer or a processor. Should not be overriden by any other party..</param>
        /// <param name="TerminalId">The &#39;Terminal Id&#39; aka TID, is an identifier used for with your payments processor. Depending on the processor and payment acceptance type this may also be the default Terminal ID used for Card Present and Virtual Terminal transactions. .</param>
        /// <param name="TerminalIds">Applicable for Prisma (prisma) processor..</param>
        /// <param name="ServiceEnablementNumber">Service Establishment Number (a.k.a. SE Number) is a unique ten-digit number assigned by American Express to a merchant that accepts American Express cards. 10 digit number provided by acquirer currency. This may be unique for each currency, however it depends on the way the processor is set up for the merchant. .</param>
        public CardProcessingConfigFeaturesCardNotPresentPayoutsCurrencies(bool? Enabled = default(bool?), bool? EnabledCardPresent = default(bool?), bool? EnabledCardNotPresent = default(bool?), string MerchantId = default(string), string TerminalId = default(string), List<string> TerminalIds = default(List<string>), string ServiceEnablementNumber = default(string))
        {
            this.Enabled = Enabled;
            this.EnabledCardPresent = EnabledCardPresent;
            this.EnabledCardNotPresent = EnabledCardNotPresent;
            this.MerchantId = MerchantId;
            this.TerminalId = TerminalId;
            this.TerminalIds = TerminalIds;
            this.ServiceEnablementNumber = ServiceEnablementNumber;
        }
        
        /// <summary>
        /// Gets or Sets Enabled
        /// </summary>
        [DataMember(Name="enabled", EmitDefaultValue=false)]
        public bool? Enabled { get; set; }

        /// <summary>
        /// Indicates whether the card-present transaction is activated for the selected currency. If both enabledCardPresent and enabledCardNotPresent are set to null, then enabledCardPresent will have the value of enabled. 
        /// </summary>
        /// <value>Indicates whether the card-present transaction is activated for the selected currency. If both enabledCardPresent and enabledCardNotPresent are set to null, then enabledCardPresent will have the value of enabled. </value>
        [DataMember(Name="enabledCardPresent", EmitDefaultValue=false)]
        public bool? EnabledCardPresent { get; set; }

        /// <summary>
        /// Indicates whether the card-present transaction is activated for the selected currency. If both enabledCardPresent and enabledCardNotPresent are set to null, then enabledCardNotPresent will have the value of enabled. 
        /// </summary>
        /// <value>Indicates whether the card-present transaction is activated for the selected currency. If both enabledCardPresent and enabledCardNotPresent are set to null, then enabledCardNotPresent will have the value of enabled. </value>
        [DataMember(Name="enabledCardNotPresent", EmitDefaultValue=false)]
        public bool? EnabledCardNotPresent { get; set; }

        /// <summary>
        /// Merchant ID assigned by an acquirer or a processor. Should not be overriden by any other party.
        /// </summary>
        /// <value>Merchant ID assigned by an acquirer or a processor. Should not be overriden by any other party.</value>
        [DataMember(Name="merchantId", EmitDefaultValue=false)]
        public string MerchantId { get; set; }

        /// <summary>
        /// The &#39;Terminal Id&#39; aka TID, is an identifier used for with your payments processor. Depending on the processor and payment acceptance type this may also be the default Terminal ID used for Card Present and Virtual Terminal transactions. 
        /// </summary>
        /// <value>The &#39;Terminal Id&#39; aka TID, is an identifier used for with your payments processor. Depending on the processor and payment acceptance type this may also be the default Terminal ID used for Card Present and Virtual Terminal transactions. </value>
        [DataMember(Name="terminalId", EmitDefaultValue=false)]
        public string TerminalId { get; set; }

        /// <summary>
        /// Applicable for Prisma (prisma) processor.
        /// </summary>
        /// <value>Applicable for Prisma (prisma) processor.</value>
        [DataMember(Name="terminalIds", EmitDefaultValue=false)]
        public List<string> TerminalIds { get; set; }

        /// <summary>
        /// Service Establishment Number (a.k.a. SE Number) is a unique ten-digit number assigned by American Express to a merchant that accepts American Express cards. 10 digit number provided by acquirer currency. This may be unique for each currency, however it depends on the way the processor is set up for the merchant. 
        /// </summary>
        /// <value>Service Establishment Number (a.k.a. SE Number) is a unique ten-digit number assigned by American Express to a merchant that accepts American Express cards. 10 digit number provided by acquirer currency. This may be unique for each currency, however it depends on the way the processor is set up for the merchant. </value>
        [DataMember(Name="serviceEnablementNumber", EmitDefaultValue=false)]
        public string ServiceEnablementNumber { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class CardProcessingConfigFeaturesCardNotPresentPayoutsCurrencies {\n");
            if (Enabled != null) sb.Append("  Enabled: ").Append(Enabled).Append("\n");
            if (EnabledCardPresent != null) sb.Append("  EnabledCardPresent: ").Append(EnabledCardPresent).Append("\n");
            if (EnabledCardNotPresent != null) sb.Append("  EnabledCardNotPresent: ").Append(EnabledCardNotPresent).Append("\n");
            if (MerchantId != null) sb.Append("  MerchantId: ").Append(MerchantId).Append("\n");
            if (TerminalId != null) sb.Append("  TerminalId: ").Append(TerminalId).Append("\n");
            if (TerminalIds != null) sb.Append("  TerminalIds: ").Append(TerminalIds).Append("\n");
            if (ServiceEnablementNumber != null) sb.Append("  ServiceEnablementNumber: ").Append(ServiceEnablementNumber).Append("\n");
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
            return this.Equals(obj as CardProcessingConfigFeaturesCardNotPresentPayoutsCurrencies);
        }

        /// <summary>
        /// Returns true if CardProcessingConfigFeaturesCardNotPresentPayoutsCurrencies instances are equal
        /// </summary>
        /// <param name="other">Instance of CardProcessingConfigFeaturesCardNotPresentPayoutsCurrencies to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(CardProcessingConfigFeaturesCardNotPresentPayoutsCurrencies other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Enabled == other.Enabled ||
                    this.Enabled != null &&
                    this.Enabled.Equals(other.Enabled)
                ) && 
                (
                    this.EnabledCardPresent == other.EnabledCardPresent ||
                    this.EnabledCardPresent != null &&
                    this.EnabledCardPresent.Equals(other.EnabledCardPresent)
                ) && 
                (
                    this.EnabledCardNotPresent == other.EnabledCardNotPresent ||
                    this.EnabledCardNotPresent != null &&
                    this.EnabledCardNotPresent.Equals(other.EnabledCardNotPresent)
                ) && 
                (
                    this.MerchantId == other.MerchantId ||
                    this.MerchantId != null &&
                    this.MerchantId.Equals(other.MerchantId)
                ) && 
                (
                    this.TerminalId == other.TerminalId ||
                    this.TerminalId != null &&
                    this.TerminalId.Equals(other.TerminalId)
                ) && 
                (
                    this.TerminalIds == other.TerminalIds ||
                    this.TerminalIds != null &&
                    this.TerminalIds.SequenceEqual(other.TerminalIds)
                ) && 
                (
                    this.ServiceEnablementNumber == other.ServiceEnablementNumber ||
                    this.ServiceEnablementNumber != null &&
                    this.ServiceEnablementNumber.Equals(other.ServiceEnablementNumber)
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
                if (this.Enabled != null)
                    hash = hash * 59 + this.Enabled.GetHashCode();
                if (this.EnabledCardPresent != null)
                    hash = hash * 59 + this.EnabledCardPresent.GetHashCode();
                if (this.EnabledCardNotPresent != null)
                    hash = hash * 59 + this.EnabledCardNotPresent.GetHashCode();
                if (this.MerchantId != null)
                    hash = hash * 59 + this.MerchantId.GetHashCode();
                if (this.TerminalId != null)
                    hash = hash * 59 + this.TerminalId.GetHashCode();
                if (this.TerminalIds != null)
                    hash = hash * 59 + this.TerminalIds.GetHashCode();
                if (this.ServiceEnablementNumber != null)
                    hash = hash * 59 + this.ServiceEnablementNumber.GetHashCode();
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
