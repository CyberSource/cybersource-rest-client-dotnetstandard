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
    /// Ptsv2paymentsProcessingInformationLoanOptions
    /// </summary>
    [DataContract]
    public partial class Ptsv2paymentsProcessingInformationLoanOptions :  IEquatable<Ptsv2paymentsProcessingInformationLoanOptions>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Ptsv2paymentsProcessingInformationLoanOptions" /> class.
        /// </summary>
        /// <param name="Type">Type of loan based on an agreement between you and the issuer. Examples: AGROCUSTEIO, AGRO-INVEST, BNDES-Type1, CBN, FINAME. This field is supported only for these kinds of payments: - BNDES transactions on CyberSource through VisaNet. - Installment payments with Mastercard on CyberSource through VisaNet in Brazil.  For BNDES transactions, the value for this field corresponds to the following data in the TC 33 capture file: - Record: CP07 TCR2, Position: 27-46, Field: Loan Type  For installment payments with Mastercard in Brazil, the value for this field corresponds to the following data in the TC 33 capture file: - Record: CP07 TCR4, Position: 5-24,Field: Financing Type .</param>
        /// <param name="AssetType">Indicates whether a loan is for a recoverable item or a non-recoverable item. Possible values: - &#x60;N&#x60;: non-recoverable item - &#x60;R&#x60;: recoverable item This field is supported only for BNDES transactions on CyberSource through VisaNet. The value for this field corresponds to the following data in the TC 33 capture file5:  Record: CP07 TCR2, Position: 26, Field: Asset Indicator .</param>
        public Ptsv2paymentsProcessingInformationLoanOptions(string Type = default(string), string AssetType = default(string))
        {
            this.Type = Type;
            this.AssetType = AssetType;
        }
        
        /// <summary>
        /// Type of loan based on an agreement between you and the issuer. Examples: AGROCUSTEIO, AGRO-INVEST, BNDES-Type1, CBN, FINAME. This field is supported only for these kinds of payments: - BNDES transactions on CyberSource through VisaNet. - Installment payments with Mastercard on CyberSource through VisaNet in Brazil.  For BNDES transactions, the value for this field corresponds to the following data in the TC 33 capture file: - Record: CP07 TCR2, Position: 27-46, Field: Loan Type  For installment payments with Mastercard in Brazil, the value for this field corresponds to the following data in the TC 33 capture file: - Record: CP07 TCR4, Position: 5-24,Field: Financing Type 
        /// </summary>
        /// <value>Type of loan based on an agreement between you and the issuer. Examples: AGROCUSTEIO, AGRO-INVEST, BNDES-Type1, CBN, FINAME. This field is supported only for these kinds of payments: - BNDES transactions on CyberSource through VisaNet. - Installment payments with Mastercard on CyberSource through VisaNet in Brazil.  For BNDES transactions, the value for this field corresponds to the following data in the TC 33 capture file: - Record: CP07 TCR2, Position: 27-46, Field: Loan Type  For installment payments with Mastercard in Brazil, the value for this field corresponds to the following data in the TC 33 capture file: - Record: CP07 TCR4, Position: 5-24,Field: Financing Type </value>
        [DataMember(Name="type", EmitDefaultValue=false)]
        public string Type { get; set; }

        /// <summary>
        /// Indicates whether a loan is for a recoverable item or a non-recoverable item. Possible values: - &#x60;N&#x60;: non-recoverable item - &#x60;R&#x60;: recoverable item This field is supported only for BNDES transactions on CyberSource through VisaNet. The value for this field corresponds to the following data in the TC 33 capture file5:  Record: CP07 TCR2, Position: 26, Field: Asset Indicator 
        /// </summary>
        /// <value>Indicates whether a loan is for a recoverable item or a non-recoverable item. Possible values: - &#x60;N&#x60;: non-recoverable item - &#x60;R&#x60;: recoverable item This field is supported only for BNDES transactions on CyberSource through VisaNet. The value for this field corresponds to the following data in the TC 33 capture file5:  Record: CP07 TCR2, Position: 26, Field: Asset Indicator </value>
        [DataMember(Name="assetType", EmitDefaultValue=false)]
        public string AssetType { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class Ptsv2paymentsProcessingInformationLoanOptions {\n");
            if (Type != null) sb.Append("  Type: ").Append(Type).Append("\n");
            if (AssetType != null) sb.Append("  AssetType: ").Append(AssetType).Append("\n");
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
            return this.Equals(obj as Ptsv2paymentsProcessingInformationLoanOptions);
        }

        /// <summary>
        /// Returns true if Ptsv2paymentsProcessingInformationLoanOptions instances are equal
        /// </summary>
        /// <param name="other">Instance of Ptsv2paymentsProcessingInformationLoanOptions to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(Ptsv2paymentsProcessingInformationLoanOptions other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Type == other.Type ||
                    this.Type != null &&
                    this.Type.Equals(other.Type)
                ) && 
                (
                    this.AssetType == other.AssetType ||
                    this.AssetType != null &&
                    this.AssetType.Equals(other.AssetType)
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
                if (this.Type != null)
                    hash = hash * 59 + this.Type.GetHashCode();
                if (this.AssetType != null)
                    hash = hash * 59 + this.AssetType.GetHashCode();
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
