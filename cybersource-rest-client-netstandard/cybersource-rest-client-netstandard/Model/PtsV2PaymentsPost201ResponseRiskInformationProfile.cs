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
    /// PtsV2PaymentsPost201ResponseRiskInformationProfile
    /// </summary>
    [DataContract]
    public partial class PtsV2PaymentsPost201ResponseRiskInformationProfile :  IEquatable<PtsV2PaymentsPost201ResponseRiskInformationProfile>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PtsV2PaymentsPost201ResponseRiskInformationProfile" /> class.
        /// </summary>
        /// <param name="Name">Name of the active profile chosen by the profile selector. If no profile selector exists, the default active profile is chosen.  **Note** By default, your default profile is the active profile, or the Profile Selector chooses the active profile. Use this field only if you want to specify the name of a different profile. The passed-in profile will then become the active profile. .</param>
        /// <param name="DesinationQueue">Name of the queue where orders that are not automatically accepted are sent. .</param>
        /// <param name="SelectorRule">Name of the profile selector rule that chooses the profile to use for the transaction. If no profile selector exists, the value is Default Active Profile. .</param>
        public PtsV2PaymentsPost201ResponseRiskInformationProfile(string Name = default(string), string DesinationQueue = default(string), string SelectorRule = default(string))
        {
            this.Name = Name;
            this.DesinationQueue = DesinationQueue;
            this.SelectorRule = SelectorRule;
        }
        
        /// <summary>
        /// Name of the active profile chosen by the profile selector. If no profile selector exists, the default active profile is chosen.  **Note** By default, your default profile is the active profile, or the Profile Selector chooses the active profile. Use this field only if you want to specify the name of a different profile. The passed-in profile will then become the active profile. 
        /// </summary>
        /// <value>Name of the active profile chosen by the profile selector. If no profile selector exists, the default active profile is chosen.  **Note** By default, your default profile is the active profile, or the Profile Selector chooses the active profile. Use this field only if you want to specify the name of a different profile. The passed-in profile will then become the active profile. </value>
        [DataMember(Name="name", EmitDefaultValue=false)]
        public string Name { get; set; }

        /// <summary>
        /// Name of the queue where orders that are not automatically accepted are sent. 
        /// </summary>
        /// <value>Name of the queue where orders that are not automatically accepted are sent. </value>
        [DataMember(Name="desinationQueue", EmitDefaultValue=false)]
        public string DesinationQueue { get; set; }

        /// <summary>
        /// Name of the profile selector rule that chooses the profile to use for the transaction. If no profile selector exists, the value is Default Active Profile. 
        /// </summary>
        /// <value>Name of the profile selector rule that chooses the profile to use for the transaction. If no profile selector exists, the value is Default Active Profile. </value>
        [DataMember(Name="selectorRule", EmitDefaultValue=false)]
        public string SelectorRule { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class PtsV2PaymentsPost201ResponseRiskInformationProfile {\n");
            if (Name != null) sb.Append("  Name: ").Append(Name).Append("\n");
            if (DesinationQueue != null) sb.Append("  DesinationQueue: ").Append(DesinationQueue).Append("\n");
            if (SelectorRule != null) sb.Append("  SelectorRule: ").Append(SelectorRule).Append("\n");
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
            return this.Equals(obj as PtsV2PaymentsPost201ResponseRiskInformationProfile);
        }

        /// <summary>
        /// Returns true if PtsV2PaymentsPost201ResponseRiskInformationProfile instances are equal
        /// </summary>
        /// <param name="other">Instance of PtsV2PaymentsPost201ResponseRiskInformationProfile to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(PtsV2PaymentsPost201ResponseRiskInformationProfile other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Name == other.Name ||
                    this.Name != null &&
                    this.Name.Equals(other.Name)
                ) && 
                (
                    this.DesinationQueue == other.DesinationQueue ||
                    this.DesinationQueue != null &&
                    this.DesinationQueue.Equals(other.DesinationQueue)
                ) && 
                (
                    this.SelectorRule == other.SelectorRule ||
                    this.SelectorRule != null &&
                    this.SelectorRule.Equals(other.SelectorRule)
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
                if (this.Name != null)
                    hash = hash * 59 + this.Name.GetHashCode();
                if (this.DesinationQueue != null)
                    hash = hash * 59 + this.DesinationQueue.GetHashCode();
                if (this.SelectorRule != null)
                    hash = hash * 59 + this.SelectorRule.GetHashCode();
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
