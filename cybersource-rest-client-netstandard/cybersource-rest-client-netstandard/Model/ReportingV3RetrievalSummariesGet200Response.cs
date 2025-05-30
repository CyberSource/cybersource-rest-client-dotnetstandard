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
    /// ReportingV3RetrievalSummariesGet200Response
    /// </summary>
    [DataContract]
    public partial class ReportingV3RetrievalSummariesGet200Response :  IEquatable<ReportingV3RetrievalSummariesGet200Response>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ReportingV3RetrievalSummariesGet200Response" /> class.
        /// </summary>
        /// <param name="OrganizationId">Organization Id.</param>
        /// <param name="StartTime">Report Start Date.</param>
        /// <param name="EndTime">Report Start Date.</param>
        /// <param name="RetrievalSummaries">List of Summary values.</param>
        public ReportingV3RetrievalSummariesGet200Response(string OrganizationId = default(string), DateTime? StartTime = default(DateTime?), string EndTime = default(string), List<ReportingV3ChargebackSummariesGet200ResponseChargebackSummaries> RetrievalSummaries = default(List<ReportingV3ChargebackSummariesGet200ResponseChargebackSummaries>))
        {
            this.OrganizationId = OrganizationId;
            this.StartTime = StartTime;
            this.EndTime = EndTime;
            this.RetrievalSummaries = RetrievalSummaries;
        }
        
        /// <summary>
        /// Organization Id
        /// </summary>
        /// <value>Organization Id</value>
        [DataMember(Name="organizationId", EmitDefaultValue=false)]
        public string OrganizationId { get; set; }

        /// <summary>
        /// Report Start Date
        /// </summary>
        /// <value>Report Start Date</value>
        [DataMember(Name="startTime", EmitDefaultValue=false)]
        public DateTime? StartTime { get; set; }

        /// <summary>
        /// Report Start Date
        /// </summary>
        /// <value>Report Start Date</value>
        [DataMember(Name="endTime", EmitDefaultValue=false)]
        public string EndTime { get; set; }

        /// <summary>
        /// List of Summary values
        /// </summary>
        /// <value>List of Summary values</value>
        [DataMember(Name="retrievalSummaries", EmitDefaultValue=false)]
        public List<ReportingV3ChargebackSummariesGet200ResponseChargebackSummaries> RetrievalSummaries { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class ReportingV3RetrievalSummariesGet200Response {\n");
            if (OrganizationId != null) sb.Append("  OrganizationId: ").Append(OrganizationId).Append("\n");
            if (StartTime != null) sb.Append("  StartTime: ").Append(StartTime).Append("\n");
            if (EndTime != null) sb.Append("  EndTime: ").Append(EndTime).Append("\n");
            if (RetrievalSummaries != null) sb.Append("  RetrievalSummaries: ").Append(RetrievalSummaries).Append("\n");
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
            return this.Equals(obj as ReportingV3RetrievalSummariesGet200Response);
        }

        /// <summary>
        /// Returns true if ReportingV3RetrievalSummariesGet200Response instances are equal
        /// </summary>
        /// <param name="other">Instance of ReportingV3RetrievalSummariesGet200Response to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ReportingV3RetrievalSummariesGet200Response other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.OrganizationId == other.OrganizationId ||
                    this.OrganizationId != null &&
                    this.OrganizationId.Equals(other.OrganizationId)
                ) && 
                (
                    this.StartTime == other.StartTime ||
                    this.StartTime != null &&
                    this.StartTime.Equals(other.StartTime)
                ) && 
                (
                    this.EndTime == other.EndTime ||
                    this.EndTime != null &&
                    this.EndTime.Equals(other.EndTime)
                ) && 
                (
                    this.RetrievalSummaries == other.RetrievalSummaries ||
                    this.RetrievalSummaries != null &&
                    this.RetrievalSummaries.SequenceEqual(other.RetrievalSummaries)
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
                if (this.OrganizationId != null)
                    hash = hash * 59 + this.OrganizationId.GetHashCode();
                if (this.StartTime != null)
                    hash = hash * 59 + this.StartTime.GetHashCode();
                if (this.EndTime != null)
                    hash = hash * 59 + this.EndTime.GetHashCode();
                if (this.RetrievalSummaries != null)
                    hash = hash * 59 + this.RetrievalSummaries.GetHashCode();
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
