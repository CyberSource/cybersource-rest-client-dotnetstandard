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
    /// PaymentProductsPayoutsConfigurationInformationConfigurations
    /// </summary>
    [DataContract]
    public partial class PaymentProductsPayoutsConfigurationInformationConfigurations :  IEquatable<PaymentProductsPayoutsConfigurationInformationConfigurations>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PaymentProductsPayoutsConfigurationInformationConfigurations" /> class.
        /// </summary>
        /// <param name="Pullfunds">Pullfunds.</param>
        /// <param name="Pushfunds">Pushfunds.</param>
        public PaymentProductsPayoutsConfigurationInformationConfigurations(Dictionary<string, PaymentProductsPayoutsConfigurationInformationConfigurationsPullfunds> Pullfunds = default(Dictionary<string, PaymentProductsPayoutsConfigurationInformationConfigurationsPullfunds>), Dictionary<string, PaymentProductsPayoutsConfigurationInformationConfigurationsPushfunds> Pushfunds = default(Dictionary<string, PaymentProductsPayoutsConfigurationInformationConfigurationsPushfunds>))
        {
            this.Pullfunds = Pullfunds;
            this.Pushfunds = Pushfunds;
        }
        
        /// <summary>
        /// Gets or Sets Pullfunds
        /// </summary>
        [DataMember(Name="pullfunds", EmitDefaultValue=false)]
        public Dictionary<string, PaymentProductsPayoutsConfigurationInformationConfigurationsPullfunds> Pullfunds { get; set; }

        /// <summary>
        /// Gets or Sets Pushfunds
        /// </summary>
        [DataMember(Name="pushfunds", EmitDefaultValue=false)]
        public Dictionary<string, PaymentProductsPayoutsConfigurationInformationConfigurationsPushfunds> Pushfunds { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class PaymentProductsPayoutsConfigurationInformationConfigurations {\n");
            sb.Append("  Pullfunds: ").Append(Pullfunds).Append("\n");
            sb.Append("  Pushfunds: ").Append(Pushfunds).Append("\n");
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
            return this.Equals(obj as PaymentProductsPayoutsConfigurationInformationConfigurations);
        }

        /// <summary>
        /// Returns true if PaymentProductsPayoutsConfigurationInformationConfigurations instances are equal
        /// </summary>
        /// <param name="other">Instance of PaymentProductsPayoutsConfigurationInformationConfigurations to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(PaymentProductsPayoutsConfigurationInformationConfigurations other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Pullfunds == other.Pullfunds ||
                    this.Pullfunds != null &&
                    this.Pullfunds.SequenceEqual(other.Pullfunds)
                ) && 
                (
                    this.Pushfunds == other.Pushfunds ||
                    this.Pushfunds != null &&
                    this.Pushfunds.SequenceEqual(other.Pushfunds)
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
                if (this.Pullfunds != null)
                    hash = hash * 59 + this.Pullfunds.GetHashCode();
                if (this.Pushfunds != null)
                    hash = hash * 59 + this.Pushfunds.GetHashCode();
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