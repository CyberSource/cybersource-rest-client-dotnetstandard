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
    /// PostDeviceSearchRequestV3
    /// </summary>
    [DataContract]
    public partial class PostDeviceSearchRequestV3 :  IEquatable<PostDeviceSearchRequestV3>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PostDeviceSearchRequestV3" /> class.
        /// </summary>
        /// <param name="Query">The Search Query to retrieve the Terminals.(Example :- serialNumber:456345234 AND readerId:509353f0-86ca-4af4-a1c9-c2702bfd7431  AND terminalId:7854922 AND status:Inactive AND statusChangeReason:Other AND organizationId:London Store).</param>
        /// <param name="Sort">terminalCreationDate:desc (default) or serialNumber or terminalUpdationDate.</param>
        /// <param name="Offset">The offset or page number..</param>
        /// <param name="Limit">Number of devices to retrieve in one request..</param>
        public PostDeviceSearchRequestV3(string Query = default(string), string Sort = default(string), long? Offset = default(long?), long? Limit = default(long?))
        {
            this.Query = Query;
            this.Sort = Sort;
            this.Offset = Offset;
            this.Limit = Limit;
        }
        
        /// <summary>
        /// The Search Query to retrieve the Terminals.(Example :- serialNumber:456345234 AND readerId:509353f0-86ca-4af4-a1c9-c2702bfd7431  AND terminalId:7854922 AND status:Inactive AND statusChangeReason:Other AND organizationId:London Store)
        /// </summary>
        /// <value>The Search Query to retrieve the Terminals.(Example :- serialNumber:456345234 AND readerId:509353f0-86ca-4af4-a1c9-c2702bfd7431  AND terminalId:7854922 AND status:Inactive AND statusChangeReason:Other AND organizationId:London Store)</value>
        [DataMember(Name="query", EmitDefaultValue=false)]
        public string Query { get; set; }

        /// <summary>
        /// terminalCreationDate:desc (default) or serialNumber or terminalUpdationDate
        /// </summary>
        /// <value>terminalCreationDate:desc (default) or serialNumber or terminalUpdationDate</value>
        [DataMember(Name="sort", EmitDefaultValue=false)]
        public string Sort { get; set; }

        /// <summary>
        /// The offset or page number.
        /// </summary>
        /// <value>The offset or page number.</value>
        [DataMember(Name="offset", EmitDefaultValue=false)]
        public long? Offset { get; set; }

        /// <summary>
        /// Number of devices to retrieve in one request.
        /// </summary>
        /// <value>Number of devices to retrieve in one request.</value>
        [DataMember(Name="limit", EmitDefaultValue=false)]
        public long? Limit { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class PostDeviceSearchRequestV3 {\n");
            if (Query != null) sb.Append("  Query: ").Append(Query).Append("\n");
            if (Sort != null) sb.Append("  Sort: ").Append(Sort).Append("\n");
            if (Offset != null) sb.Append("  Offset: ").Append(Offset).Append("\n");
            if (Limit != null) sb.Append("  Limit: ").Append(Limit).Append("\n");
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
            return this.Equals(obj as PostDeviceSearchRequestV3);
        }

        /// <summary>
        /// Returns true if PostDeviceSearchRequestV3 instances are equal
        /// </summary>
        /// <param name="other">Instance of PostDeviceSearchRequestV3 to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(PostDeviceSearchRequestV3 other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Query == other.Query ||
                    this.Query != null &&
                    this.Query.Equals(other.Query)
                ) && 
                (
                    this.Sort == other.Sort ||
                    this.Sort != null &&
                    this.Sort.Equals(other.Sort)
                ) && 
                (
                    this.Offset == other.Offset ||
                    this.Offset != null &&
                    this.Offset.Equals(other.Offset)
                ) && 
                (
                    this.Limit == other.Limit ||
                    this.Limit != null &&
                    this.Limit.Equals(other.Limit)
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
                if (this.Query != null)
                    hash = hash * 59 + this.Query.GetHashCode();
                if (this.Sort != null)
                    hash = hash * 59 + this.Sort.GetHashCode();
                if (this.Offset != null)
                    hash = hash * 59 + this.Offset.GetHashCode();
                if (this.Limit != null)
                    hash = hash * 59 + this.Limit.GetHashCode();
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
