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
    /// TmsNullify
    /// </summary>
    [DataContract]
    public partial class TmsNullify :  IEquatable<TmsNullify>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TmsNullify" /> class.
        /// </summary>
        /// <param name="InstrumentIdentifierCardNumber">Indicates if the card number should be nullified (i.e. not stored).</param>
        /// <param name="InstrumentIdentifierCardExpiration">Indicates if the expiration date associated to the instrument identifier should be nullified (i.e. not stored).</param>
        /// <param name="PaymentInstrumentCardDetails">Indicates if the card details should be nullified (i.e. not stored).</param>
        public TmsNullify(bool? InstrumentIdentifierCardNumber = default(bool?), bool? InstrumentIdentifierCardExpiration = default(bool?), bool? PaymentInstrumentCardDetails = default(bool?))
        {
            this.InstrumentIdentifierCardNumber = InstrumentIdentifierCardNumber;
            this.InstrumentIdentifierCardExpiration = InstrumentIdentifierCardExpiration;
            this.PaymentInstrumentCardDetails = PaymentInstrumentCardDetails;
        }
        
        /// <summary>
        /// Indicates if the card number should be nullified (i.e. not stored)
        /// </summary>
        /// <value>Indicates if the card number should be nullified (i.e. not stored)</value>
        [DataMember(Name="instrumentIdentifierCardNumber", EmitDefaultValue=false)]
        public bool? InstrumentIdentifierCardNumber { get; set; }

        /// <summary>
        /// Indicates if the expiration date associated to the instrument identifier should be nullified (i.e. not stored)
        /// </summary>
        /// <value>Indicates if the expiration date associated to the instrument identifier should be nullified (i.e. not stored)</value>
        [DataMember(Name="instrumentIdentifierCardExpiration", EmitDefaultValue=false)]
        public bool? InstrumentIdentifierCardExpiration { get; set; }

        /// <summary>
        /// Indicates if the card details should be nullified (i.e. not stored)
        /// </summary>
        /// <value>Indicates if the card details should be nullified (i.e. not stored)</value>
        [DataMember(Name="paymentInstrumentCardDetails", EmitDefaultValue=false)]
        public bool? PaymentInstrumentCardDetails { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class TmsNullify {\n");
            if (InstrumentIdentifierCardNumber != null) sb.Append("  InstrumentIdentifierCardNumber: ").Append(InstrumentIdentifierCardNumber).Append("\n");
            if (InstrumentIdentifierCardExpiration != null) sb.Append("  InstrumentIdentifierCardExpiration: ").Append(InstrumentIdentifierCardExpiration).Append("\n");
            if (PaymentInstrumentCardDetails != null) sb.Append("  PaymentInstrumentCardDetails: ").Append(PaymentInstrumentCardDetails).Append("\n");
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
            return this.Equals(obj as TmsNullify);
        }

        /// <summary>
        /// Returns true if TmsNullify instances are equal
        /// </summary>
        /// <param name="other">Instance of TmsNullify to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(TmsNullify other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.InstrumentIdentifierCardNumber == other.InstrumentIdentifierCardNumber ||
                    this.InstrumentIdentifierCardNumber != null &&
                    this.InstrumentIdentifierCardNumber.Equals(other.InstrumentIdentifierCardNumber)
                ) && 
                (
                    this.InstrumentIdentifierCardExpiration == other.InstrumentIdentifierCardExpiration ||
                    this.InstrumentIdentifierCardExpiration != null &&
                    this.InstrumentIdentifierCardExpiration.Equals(other.InstrumentIdentifierCardExpiration)
                ) && 
                (
                    this.PaymentInstrumentCardDetails == other.PaymentInstrumentCardDetails ||
                    this.PaymentInstrumentCardDetails != null &&
                    this.PaymentInstrumentCardDetails.Equals(other.PaymentInstrumentCardDetails)
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
                if (this.InstrumentIdentifierCardNumber != null)
                    hash = hash * 59 + this.InstrumentIdentifierCardNumber.GetHashCode();
                if (this.InstrumentIdentifierCardExpiration != null)
                    hash = hash * 59 + this.InstrumentIdentifierCardExpiration.GetHashCode();
                if (this.PaymentInstrumentCardDetails != null)
                    hash = hash * 59 + this.PaymentInstrumentCardDetails.GetHashCode();
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
