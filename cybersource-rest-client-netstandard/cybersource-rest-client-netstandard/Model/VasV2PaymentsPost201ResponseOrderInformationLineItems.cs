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
    /// VasV2PaymentsPost201ResponseOrderInformationLineItems
    /// </summary>
    [DataContract]
    public partial class VasV2PaymentsPost201ResponseOrderInformationLineItems :  IEquatable<VasV2PaymentsPost201ResponseOrderInformationLineItems>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="VasV2PaymentsPost201ResponseOrderInformationLineItems" /> class.
        /// </summary>
        /// <param name="TaxDetails">TaxDetails.</param>
        /// <param name="Jurisdiction">Jurisdiction.</param>
        /// <param name="ExemptAmount">Exempt amount for the lineItem. Returned only if the &#x60;taxInformation.showTaxPerLineItem&#x60; field is set to &#x60;Yes&#x60;. .</param>
        /// <param name="TaxableAmount">Portion of the item amount that is taxable. .</param>
        /// <param name="TaxAmount">Total tax for the item. This value is the sum of all taxes applied to the item. .</param>
        public VasV2PaymentsPost201ResponseOrderInformationLineItems(List<VasV2PaymentsPost201ResponseOrderInformationTaxDetails> TaxDetails = default(List<VasV2PaymentsPost201ResponseOrderInformationTaxDetails>), List<VasV2PaymentsPost201ResponseOrderInformationJurisdiction> Jurisdiction = default(List<VasV2PaymentsPost201ResponseOrderInformationJurisdiction>), string ExemptAmount = default(string), string TaxableAmount = default(string), string TaxAmount = default(string))
        {
            this.TaxDetails = TaxDetails;
            this.Jurisdiction = Jurisdiction;
            this.ExemptAmount = ExemptAmount;
            this.TaxableAmount = TaxableAmount;
            this.TaxAmount = TaxAmount;
        }
        
        /// <summary>
        /// Gets or Sets TaxDetails
        /// </summary>
        [DataMember(Name="taxDetails", EmitDefaultValue=false)]
        public List<VasV2PaymentsPost201ResponseOrderInformationTaxDetails> TaxDetails { get; set; }

        /// <summary>
        /// Gets or Sets Jurisdiction
        /// </summary>
        [DataMember(Name="jurisdiction", EmitDefaultValue=false)]
        public List<VasV2PaymentsPost201ResponseOrderInformationJurisdiction> Jurisdiction { get; set; }

        /// <summary>
        /// Exempt amount for the lineItem. Returned only if the &#x60;taxInformation.showTaxPerLineItem&#x60; field is set to &#x60;Yes&#x60;. 
        /// </summary>
        /// <value>Exempt amount for the lineItem. Returned only if the &#x60;taxInformation.showTaxPerLineItem&#x60; field is set to &#x60;Yes&#x60;. </value>
        [DataMember(Name="exemptAmount", EmitDefaultValue=false)]
        public string ExemptAmount { get; set; }

        /// <summary>
        /// Portion of the item amount that is taxable. 
        /// </summary>
        /// <value>Portion of the item amount that is taxable. </value>
        [DataMember(Name="taxableAmount", EmitDefaultValue=false)]
        public string TaxableAmount { get; set; }

        /// <summary>
        /// Total tax for the item. This value is the sum of all taxes applied to the item. 
        /// </summary>
        /// <value>Total tax for the item. This value is the sum of all taxes applied to the item. </value>
        [DataMember(Name="taxAmount", EmitDefaultValue=false)]
        public string TaxAmount { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class VasV2PaymentsPost201ResponseOrderInformationLineItems {\n");
            sb.Append("  TaxDetails: ").Append(TaxDetails).Append("\n");
            sb.Append("  Jurisdiction: ").Append(Jurisdiction).Append("\n");
            sb.Append("  ExemptAmount: ").Append(ExemptAmount).Append("\n");
            sb.Append("  TaxableAmount: ").Append(TaxableAmount).Append("\n");
            sb.Append("  TaxAmount: ").Append(TaxAmount).Append("\n");
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
            return this.Equals(obj as VasV2PaymentsPost201ResponseOrderInformationLineItems);
        }

        /// <summary>
        /// Returns true if VasV2PaymentsPost201ResponseOrderInformationLineItems instances are equal
        /// </summary>
        /// <param name="other">Instance of VasV2PaymentsPost201ResponseOrderInformationLineItems to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(VasV2PaymentsPost201ResponseOrderInformationLineItems other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.TaxDetails == other.TaxDetails ||
                    this.TaxDetails != null &&
                    this.TaxDetails.SequenceEqual(other.TaxDetails)
                ) && 
                (
                    this.Jurisdiction == other.Jurisdiction ||
                    this.Jurisdiction != null &&
                    this.Jurisdiction.SequenceEqual(other.Jurisdiction)
                ) && 
                (
                    this.ExemptAmount == other.ExemptAmount ||
                    this.ExemptAmount != null &&
                    this.ExemptAmount.Equals(other.ExemptAmount)
                ) && 
                (
                    this.TaxableAmount == other.TaxableAmount ||
                    this.TaxableAmount != null &&
                    this.TaxableAmount.Equals(other.TaxableAmount)
                ) && 
                (
                    this.TaxAmount == other.TaxAmount ||
                    this.TaxAmount != null &&
                    this.TaxAmount.Equals(other.TaxAmount)
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
                if (this.TaxDetails != null)
                    hash = hash * 59 + this.TaxDetails.GetHashCode();
                if (this.Jurisdiction != null)
                    hash = hash * 59 + this.Jurisdiction.GetHashCode();
                if (this.ExemptAmount != null)
                    hash = hash * 59 + this.ExemptAmount.GetHashCode();
                if (this.TaxableAmount != null)
                    hash = hash * 59 + this.TaxableAmount.GetHashCode();
                if (this.TaxAmount != null)
                    hash = hash * 59 + this.TaxAmount.GetHashCode();
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
            // ExemptAmount (string) maxLength
            if(this.ExemptAmount != null && this.ExemptAmount.Length >= 15)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for ExemptAmount, length must be less than or equal to 15.", new [] { "ExemptAmount" });
            }

            // TaxableAmount (string) maxLength
            if(this.TaxableAmount != null && this.TaxableAmount.Length >= 15)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for TaxableAmount, length must be less than or equal to 15.", new [] { "TaxableAmount" });
            }

            // TaxAmount (string) maxLength
            if(this.TaxAmount != null && this.TaxAmount.Length >= 15)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for TaxAmount, length must be less than or equal to 15.", new [] { "TaxAmount" });
            }

            yield break;
        }
    }

}