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
    /// InlineResponse2011PaymentAccountInformationNetwork
    /// </summary>
    [DataContract]
    public partial class InlineResponse2011PaymentAccountInformationNetwork :  IEquatable<InlineResponse2011PaymentAccountInformationNetwork>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InlineResponse2011PaymentAccountInformationNetwork" /> class.
        /// </summary>
        /// <param name="Id">This field contains a code that identifies the network. [List of Network ID and Sharing Group Code](https://developer.visa.com/request_response_codes#network_id_and_sharing_group_code) .</param>
        public InlineResponse2011PaymentAccountInformationNetwork(string Id = default(string))
        {
            this.Id = Id;
        }
        
        /// <summary>
        /// This field contains a code that identifies the network. [List of Network ID and Sharing Group Code](https://developer.visa.com/request_response_codes#network_id_and_sharing_group_code) 
        /// </summary>
        /// <value>This field contains a code that identifies the network. [List of Network ID and Sharing Group Code](https://developer.visa.com/request_response_codes#network_id_and_sharing_group_code) </value>
        [DataMember(Name="id", EmitDefaultValue=false)]
        public string Id { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class InlineResponse2011PaymentAccountInformationNetwork {\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
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
            return this.Equals(obj as InlineResponse2011PaymentAccountInformationNetwork);
        }

        /// <summary>
        /// Returns true if InlineResponse2011PaymentAccountInformationNetwork instances are equal
        /// </summary>
        /// <param name="other">Instance of InlineResponse2011PaymentAccountInformationNetwork to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(InlineResponse2011PaymentAccountInformationNetwork other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Id == other.Id ||
                    this.Id != null &&
                    this.Id.Equals(other.Id)
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
                if (this.Id != null)
                    hash = hash * 59 + this.Id.GetHashCode();
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
