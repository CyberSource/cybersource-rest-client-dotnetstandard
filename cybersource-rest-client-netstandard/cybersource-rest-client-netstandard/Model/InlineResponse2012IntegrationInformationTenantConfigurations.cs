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
    /// InlineResponse2012IntegrationInformationTenantConfigurations
    /// </summary>
    [DataContract]
    public partial class InlineResponse2012IntegrationInformationTenantConfigurations :  IEquatable<InlineResponse2012IntegrationInformationTenantConfigurations>, IValidatableObject
    {
        /// <summary>
        /// Gets or Sets Status
        /// </summary>
        [JsonConverter(typeof(StringEnumConverter))]
        public enum StatusEnum
        {
            
            /// <summary>
            /// Enum LIVE for "LIVE"
            /// </summary>
            [EnumMember(Value = "LIVE")]
            LIVE,
            
            /// <summary>
            /// Enum INACTIVE for "INACTIVE"
            /// </summary>
            [EnumMember(Value = "INACTIVE")]
            INACTIVE,
            
            /// <summary>
            /// Enum TEST for "TEST"
            /// </summary>
            [EnumMember(Value = "TEST")]
            TEST
        }
        /// <summary>
        /// Gets or Sets Status
        /// </summary>
        [DataMember(Name="status", EmitDefaultValue=false)]
        public StatusEnum? Status { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="InlineResponse2012IntegrationInformationTenantConfigurations" /> class.
        /// </summary>
        /// <param name="SolutionId">The solutionId is the unique identifier for this system resource. Partner can use it to reference the specific solution through out the system. .</param>
        /// <param name="TenantConfigurationId">The tenantConfigurationId is the unique identifier for this system resource. You will see various places where it must be referenced in the URI path, or when querying the hierarchy for ancestors or descendants. .</param>
        /// <param name="Status">Status.</param>
        /// <param name="SubmitTimeUtc">Time of request in UTC..</param>
        public InlineResponse2012IntegrationInformationTenantConfigurations(string SolutionId = default(string), string TenantConfigurationId = default(string), StatusEnum? Status = default(StatusEnum?), DateTime? SubmitTimeUtc = default(DateTime?))
        {
            this.SolutionId = SolutionId;
            this.TenantConfigurationId = TenantConfigurationId;
            this.Status = Status;
            this.SubmitTimeUtc = SubmitTimeUtc;
        }
        
        /// <summary>
        /// The solutionId is the unique identifier for this system resource. Partner can use it to reference the specific solution through out the system. 
        /// </summary>
        /// <value>The solutionId is the unique identifier for this system resource. Partner can use it to reference the specific solution through out the system. </value>
        [DataMember(Name="solutionId", EmitDefaultValue=false)]
        public string SolutionId { get; set; }

        /// <summary>
        /// The tenantConfigurationId is the unique identifier for this system resource. You will see various places where it must be referenced in the URI path, or when querying the hierarchy for ancestors or descendants. 
        /// </summary>
        /// <value>The tenantConfigurationId is the unique identifier for this system resource. You will see various places where it must be referenced in the URI path, or when querying the hierarchy for ancestors or descendants. </value>
        [DataMember(Name="tenantConfigurationId", EmitDefaultValue=false)]
        public string TenantConfigurationId { get; set; }


        /// <summary>
        /// Time of request in UTC.
        /// </summary>
        /// <value>Time of request in UTC.</value>
        [DataMember(Name="submitTimeUtc", EmitDefaultValue=false)]
        public DateTime? SubmitTimeUtc { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class InlineResponse2012IntegrationInformationTenantConfigurations {\n");
            sb.Append("  SolutionId: ").Append(SolutionId).Append("\n");
            sb.Append("  TenantConfigurationId: ").Append(TenantConfigurationId).Append("\n");
            sb.Append("  Status: ").Append(Status).Append("\n");
            sb.Append("  SubmitTimeUtc: ").Append(SubmitTimeUtc).Append("\n");
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
            return this.Equals(obj as InlineResponse2012IntegrationInformationTenantConfigurations);
        }

        /// <summary>
        /// Returns true if InlineResponse2012IntegrationInformationTenantConfigurations instances are equal
        /// </summary>
        /// <param name="other">Instance of InlineResponse2012IntegrationInformationTenantConfigurations to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(InlineResponse2012IntegrationInformationTenantConfigurations other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.SolutionId == other.SolutionId ||
                    this.SolutionId != null &&
                    this.SolutionId.Equals(other.SolutionId)
                ) && 
                (
                    this.TenantConfigurationId == other.TenantConfigurationId ||
                    this.TenantConfigurationId != null &&
                    this.TenantConfigurationId.Equals(other.TenantConfigurationId)
                ) && 
                (
                    this.Status == other.Status ||
                    this.Status != null &&
                    this.Status.Equals(other.Status)
                ) && 
                (
                    this.SubmitTimeUtc == other.SubmitTimeUtc ||
                    this.SubmitTimeUtc != null &&
                    this.SubmitTimeUtc.Equals(other.SubmitTimeUtc)
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
                if (this.SolutionId != null)
                    hash = hash * 59 + this.SolutionId.GetHashCode();
                if (this.TenantConfigurationId != null)
                    hash = hash * 59 + this.TenantConfigurationId.GetHashCode();
                if (this.Status != null)
                    hash = hash * 59 + this.Status.GetHashCode();
                if (this.SubmitTimeUtc != null)
                    hash = hash * 59 + this.SubmitTimeUtc.GetHashCode();
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