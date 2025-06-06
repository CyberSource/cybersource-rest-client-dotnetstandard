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
    /// Ptsv1pushfundstransferPointOfServiceInformation
    /// </summary>
    [DataContract]
    public partial class Ptsv1pushfundstransferPointOfServiceInformation :  IEquatable<Ptsv1pushfundstransferPointOfServiceInformation>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Ptsv1pushfundstransferPointOfServiceInformation" /> class.
        /// </summary>
        /// <param name="Emv">Emv.</param>
        public Ptsv1pushfundstransferPointOfServiceInformation(Ptsv1pushfundstransferPointOfServiceInformationEmv Emv = default(Ptsv1pushfundstransferPointOfServiceInformationEmv))
        {
            this.Emv = Emv;
        }
        
        /// <summary>
        /// Gets or Sets Emv
        /// </summary>
        [DataMember(Name="emv", EmitDefaultValue=false)]
        public Ptsv1pushfundstransferPointOfServiceInformationEmv Emv { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class Ptsv1pushfundstransferPointOfServiceInformation {\n");
            if (Emv != null) sb.Append("  Emv: ").Append(Emv).Append("\n");
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
            return this.Equals(obj as Ptsv1pushfundstransferPointOfServiceInformation);
        }

        /// <summary>
        /// Returns true if Ptsv1pushfundstransferPointOfServiceInformation instances are equal
        /// </summary>
        /// <param name="other">Instance of Ptsv1pushfundstransferPointOfServiceInformation to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(Ptsv1pushfundstransferPointOfServiceInformation other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Emv == other.Emv ||
                    this.Emv != null &&
                    this.Emv.Equals(other.Emv)
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
                if (this.Emv != null)
                    hash = hash * 59 + this.Emv.GetHashCode();
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
