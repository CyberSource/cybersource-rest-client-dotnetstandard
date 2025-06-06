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
    /// Ptsv2paymentsidvoidsProcessingInformation
    /// </summary>
    [DataContract]
    public partial class Ptsv2paymentsidvoidsProcessingInformation :  IEquatable<Ptsv2paymentsidvoidsProcessingInformation>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Ptsv2paymentsidvoidsProcessingInformation" /> class.
        /// </summary>
        /// <param name="ActionList">Array of actions (one or more) to be included in the void to invoke bundled services along with void. Possible values: - &#x60;AP_CANCEL&#x60;: Use this when Alternative Payment Void service is requested. .</param>
        public Ptsv2paymentsidvoidsProcessingInformation(List<string> ActionList = default(List<string>))
        {
            this.ActionList = ActionList;
        }
        
        /// <summary>
        /// Array of actions (one or more) to be included in the void to invoke bundled services along with void. Possible values: - &#x60;AP_CANCEL&#x60;: Use this when Alternative Payment Void service is requested. 
        /// </summary>
        /// <value>Array of actions (one or more) to be included in the void to invoke bundled services along with void. Possible values: - &#x60;AP_CANCEL&#x60;: Use this when Alternative Payment Void service is requested. </value>
        [DataMember(Name="actionList", EmitDefaultValue=false)]
        public List<string> ActionList { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class Ptsv2paymentsidvoidsProcessingInformation {\n");
            if (ActionList != null) sb.Append("  ActionList: ").Append(ActionList).Append("\n");
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
            return this.Equals(obj as Ptsv2paymentsidvoidsProcessingInformation);
        }

        /// <summary>
        /// Returns true if Ptsv2paymentsidvoidsProcessingInformation instances are equal
        /// </summary>
        /// <param name="other">Instance of Ptsv2paymentsidvoidsProcessingInformation to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(Ptsv2paymentsidvoidsProcessingInformation other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.ActionList == other.ActionList ||
                    this.ActionList != null &&
                    this.ActionList.SequenceEqual(other.ActionList)
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
                if (this.ActionList != null)
                    hash = hash * 59 + this.ActionList.GetHashCode();
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
