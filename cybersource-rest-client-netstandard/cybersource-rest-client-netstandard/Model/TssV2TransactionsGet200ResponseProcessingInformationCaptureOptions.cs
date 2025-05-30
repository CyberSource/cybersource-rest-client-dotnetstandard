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
    /// TssV2TransactionsGet200ResponseProcessingInformationCaptureOptions
    /// </summary>
    [DataContract]
    public partial class TssV2TransactionsGet200ResponseProcessingInformationCaptureOptions :  IEquatable<TssV2TransactionsGet200ResponseProcessingInformationCaptureOptions>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TssV2TransactionsGet200ResponseProcessingInformationCaptureOptions" /> class.
        /// </summary>
        /// <param name="TotalCaptureCount">Total number of captures when requesting multiple partial captures for one payment. Used along with &#x60;captureSequenceNumber&#x60; field to track which capture is being processed.  For example, the second of five captures would be passed to CyberSource as:   - &#x60;captureSequenceNumber &#x3D; 2&#x60;, and   - &#x60;totalCaptureCount &#x3D; 5&#x60; .</param>
        /// <param name="CaptureSequenceNumber">Capture number when requesting multiple partial captures for one authorization. Used along with &#x60;totalCaptureCount&#x60; to track which capture is being processed.  For example, the second of five captures would be passed to CyberSource as:   - &#x60;captureSequenceNumber_ &#x3D; 2&#x60;, and   - &#x60;totalCaptureCount &#x3D; 5&#x60; .</param>
        public TssV2TransactionsGet200ResponseProcessingInformationCaptureOptions(int? TotalCaptureCount = default(int?), int? CaptureSequenceNumber = default(int?))
        {
            this.TotalCaptureCount = TotalCaptureCount;
            this.CaptureSequenceNumber = CaptureSequenceNumber;
        }
        
        /// <summary>
        /// Total number of captures when requesting multiple partial captures for one payment. Used along with &#x60;captureSequenceNumber&#x60; field to track which capture is being processed.  For example, the second of five captures would be passed to CyberSource as:   - &#x60;captureSequenceNumber &#x3D; 2&#x60;, and   - &#x60;totalCaptureCount &#x3D; 5&#x60; 
        /// </summary>
        /// <value>Total number of captures when requesting multiple partial captures for one payment. Used along with &#x60;captureSequenceNumber&#x60; field to track which capture is being processed.  For example, the second of five captures would be passed to CyberSource as:   - &#x60;captureSequenceNumber &#x3D; 2&#x60;, and   - &#x60;totalCaptureCount &#x3D; 5&#x60; </value>
        [DataMember(Name="totalCaptureCount", EmitDefaultValue=false)]
        public int? TotalCaptureCount { get; set; }

        /// <summary>
        /// Capture number when requesting multiple partial captures for one authorization. Used along with &#x60;totalCaptureCount&#x60; to track which capture is being processed.  For example, the second of five captures would be passed to CyberSource as:   - &#x60;captureSequenceNumber_ &#x3D; 2&#x60;, and   - &#x60;totalCaptureCount &#x3D; 5&#x60; 
        /// </summary>
        /// <value>Capture number when requesting multiple partial captures for one authorization. Used along with &#x60;totalCaptureCount&#x60; to track which capture is being processed.  For example, the second of five captures would be passed to CyberSource as:   - &#x60;captureSequenceNumber_ &#x3D; 2&#x60;, and   - &#x60;totalCaptureCount &#x3D; 5&#x60; </value>
        [DataMember(Name="captureSequenceNumber", EmitDefaultValue=false)]
        public int? CaptureSequenceNumber { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class TssV2TransactionsGet200ResponseProcessingInformationCaptureOptions {\n");
            if (TotalCaptureCount != null) sb.Append("  TotalCaptureCount: ").Append(TotalCaptureCount).Append("\n");
            if (CaptureSequenceNumber != null) sb.Append("  CaptureSequenceNumber: ").Append(CaptureSequenceNumber).Append("\n");
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
            return this.Equals(obj as TssV2TransactionsGet200ResponseProcessingInformationCaptureOptions);
        }

        /// <summary>
        /// Returns true if TssV2TransactionsGet200ResponseProcessingInformationCaptureOptions instances are equal
        /// </summary>
        /// <param name="other">Instance of TssV2TransactionsGet200ResponseProcessingInformationCaptureOptions to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(TssV2TransactionsGet200ResponseProcessingInformationCaptureOptions other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.TotalCaptureCount == other.TotalCaptureCount ||
                    this.TotalCaptureCount != null &&
                    this.TotalCaptureCount.Equals(other.TotalCaptureCount)
                ) && 
                (
                    this.CaptureSequenceNumber == other.CaptureSequenceNumber ||
                    this.CaptureSequenceNumber != null &&
                    this.CaptureSequenceNumber.Equals(other.CaptureSequenceNumber)
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
                if (this.TotalCaptureCount != null)
                    hash = hash * 59 + this.TotalCaptureCount.GetHashCode();
                if (this.CaptureSequenceNumber != null)
                    hash = hash * 59 + this.CaptureSequenceNumber.GetHashCode();
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
