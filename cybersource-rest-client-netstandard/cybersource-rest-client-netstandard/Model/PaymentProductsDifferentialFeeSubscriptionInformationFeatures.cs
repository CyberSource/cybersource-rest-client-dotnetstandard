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
    /// PaymentProductsDifferentialFeeSubscriptionInformationFeatures
    /// </summary>
    [DataContract]
    public partial class PaymentProductsDifferentialFeeSubscriptionInformationFeatures :  IEquatable<PaymentProductsDifferentialFeeSubscriptionInformationFeatures>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PaymentProductsDifferentialFeeSubscriptionInformationFeatures" /> class.
        /// </summary>
        /// <param name="Surcharge">Surcharge.</param>
        public PaymentProductsDifferentialFeeSubscriptionInformationFeatures(PaymentProductsCardProcessingSubscriptionInformationFeatures Surcharge = default(PaymentProductsCardProcessingSubscriptionInformationFeatures))
        {
            this.Surcharge = Surcharge;
        }
        
        /// <summary>
        /// Gets or Sets Surcharge
        /// </summary>
        [DataMember(Name="surcharge", EmitDefaultValue=false)]
        public PaymentProductsCardProcessingSubscriptionInformationFeatures Surcharge { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class PaymentProductsDifferentialFeeSubscriptionInformationFeatures {\n");
            sb.Append("  Surcharge: ").Append(Surcharge).Append("\n");
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
            return this.Equals(obj as PaymentProductsDifferentialFeeSubscriptionInformationFeatures);
        }

        /// <summary>
        /// Returns true if PaymentProductsDifferentialFeeSubscriptionInformationFeatures instances are equal
        /// </summary>
        /// <param name="other">Instance of PaymentProductsDifferentialFeeSubscriptionInformationFeatures to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(PaymentProductsDifferentialFeeSubscriptionInformationFeatures other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Surcharge == other.Surcharge ||
                    this.Surcharge != null &&
                    this.Surcharge.Equals(other.Surcharge)
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
                if (this.Surcharge != null)
                    hash = hash * 59 + this.Surcharge.GetHashCode();
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