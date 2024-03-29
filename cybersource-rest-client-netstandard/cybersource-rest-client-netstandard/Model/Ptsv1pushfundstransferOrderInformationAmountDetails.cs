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
    /// Ptsv1pushfundstransferOrderInformationAmountDetails
    /// </summary>
    [DataContract]
    public partial class Ptsv1pushfundstransferOrderInformationAmountDetails :  IEquatable<Ptsv1pushfundstransferOrderInformationAmountDetails>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Ptsv1pushfundstransferOrderInformationAmountDetails" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected Ptsv1pushfundstransferOrderInformationAmountDetails() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="Ptsv1pushfundstransferOrderInformationAmountDetails" /> class.
        /// </summary>
        /// <param name="TotalAmount">Grand total for the order. This value cannot be negative. You can include a decimal point (.), but no other special characters. CyberSource truncates the amount to the correct number of decimal places.  The disbursement amount. Numeric integer, 1-999999999999. The decimal point is implied based on the relevant currency exponent. For example, a US Dollar $53 amount is a value of 5300.  Processor Amount Ranges: Visa Platform Connect: .01-9999999999.99  Mastercard Send: 1-9999999999.99  FDC Compass: .01- 9999999999.99  Chase Paymentech: .01-9999999999.99  (required).</param>
        /// <param name="Currency">Use a 3-character alpha currency code for currency of the sender.  ISO standard currencies: http://apps.cybersource.com/library/documentation/sbc/quickref/currencies.pdf  Currency must be supported by the processor.  (required).</param>
        public Ptsv1pushfundstransferOrderInformationAmountDetails(string TotalAmount = default(string), string Currency = default(string))
        {
            // to ensure "TotalAmount" is required (not null)
            if (TotalAmount == null)
            {
                throw new InvalidDataException("TotalAmount is a required property for Ptsv1pushfundstransferOrderInformationAmountDetails and cannot be null");
            }
            else
            {
                this.TotalAmount = TotalAmount;
            }
            // to ensure "Currency" is required (not null)
            if (Currency == null)
            {
                throw new InvalidDataException("Currency is a required property for Ptsv1pushfundstransferOrderInformationAmountDetails and cannot be null");
            }
            else
            {
                this.Currency = Currency;
            }
        }
        
        /// <summary>
        /// Grand total for the order. This value cannot be negative. You can include a decimal point (.), but no other special characters. CyberSource truncates the amount to the correct number of decimal places.  The disbursement amount. Numeric integer, 1-999999999999. The decimal point is implied based on the relevant currency exponent. For example, a US Dollar $53 amount is a value of 5300.  Processor Amount Ranges: Visa Platform Connect: .01-9999999999.99  Mastercard Send: 1-9999999999.99  FDC Compass: .01- 9999999999.99  Chase Paymentech: .01-9999999999.99 
        /// </summary>
        /// <value>Grand total for the order. This value cannot be negative. You can include a decimal point (.), but no other special characters. CyberSource truncates the amount to the correct number of decimal places.  The disbursement amount. Numeric integer, 1-999999999999. The decimal point is implied based on the relevant currency exponent. For example, a US Dollar $53 amount is a value of 5300.  Processor Amount Ranges: Visa Platform Connect: .01-9999999999.99  Mastercard Send: 1-9999999999.99  FDC Compass: .01- 9999999999.99  Chase Paymentech: .01-9999999999.99 </value>
        [DataMember(Name="totalAmount", EmitDefaultValue=false)]
        public string TotalAmount { get; set; }

        /// <summary>
        /// Use a 3-character alpha currency code for currency of the sender.  ISO standard currencies: http://apps.cybersource.com/library/documentation/sbc/quickref/currencies.pdf  Currency must be supported by the processor. 
        /// </summary>
        /// <value>Use a 3-character alpha currency code for currency of the sender.  ISO standard currencies: http://apps.cybersource.com/library/documentation/sbc/quickref/currencies.pdf  Currency must be supported by the processor. </value>
        [DataMember(Name="currency", EmitDefaultValue=false)]
        public string Currency { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class Ptsv1pushfundstransferOrderInformationAmountDetails {\n");
            sb.Append("  TotalAmount: ").Append(TotalAmount).Append("\n");
            sb.Append("  Currency: ").Append(Currency).Append("\n");
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
            return this.Equals(obj as Ptsv1pushfundstransferOrderInformationAmountDetails);
        }

        /// <summary>
        /// Returns true if Ptsv1pushfundstransferOrderInformationAmountDetails instances are equal
        /// </summary>
        /// <param name="other">Instance of Ptsv1pushfundstransferOrderInformationAmountDetails to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(Ptsv1pushfundstransferOrderInformationAmountDetails other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.TotalAmount == other.TotalAmount ||
                    this.TotalAmount != null &&
                    this.TotalAmount.Equals(other.TotalAmount)
                ) && 
                (
                    this.Currency == other.Currency ||
                    this.Currency != null &&
                    this.Currency.Equals(other.Currency)
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
                if (this.TotalAmount != null)
                    hash = hash * 59 + this.TotalAmount.GetHashCode();
                if (this.Currency != null)
                    hash = hash * 59 + this.Currency.GetHashCode();
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
