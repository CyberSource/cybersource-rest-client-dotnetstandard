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
    /// PushFunds201ResponseProcessorInformationSettlement
    /// </summary>
    [DataContract]
    public partial class PushFunds201ResponseProcessorInformationSettlement :  IEquatable<PushFunds201ResponseProcessorInformationSettlement>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PushFunds201ResponseProcessorInformationSettlement" /> class.
        /// </summary>
        /// <param name="ResponsibilityFlag">Settlement Responsibility Flag: VisaNet sets this flag.  This flag is set to true to indicate that VisaNet has settlement responsibility for this transaction. This flag does not indicate the transaction will be settled. .</param>
        /// <param name="ServiceFlag">Settlement Service for the transaction.  Values:  VIP: V.I.P. to decide; or not applicable  INTERNATIONAL_SETTLEMENT: International   NATIONAL_NET_SETTLEMENT: National Net Settlement .</param>
        public PushFunds201ResponseProcessorInformationSettlement(bool? ResponsibilityFlag = default(bool?), string ServiceFlag = default(string))
        {
            this.ResponsibilityFlag = ResponsibilityFlag;
            this.ServiceFlag = ServiceFlag;
        }
        
        /// <summary>
        /// Settlement Responsibility Flag: VisaNet sets this flag.  This flag is set to true to indicate that VisaNet has settlement responsibility for this transaction. This flag does not indicate the transaction will be settled. 
        /// </summary>
        /// <value>Settlement Responsibility Flag: VisaNet sets this flag.  This flag is set to true to indicate that VisaNet has settlement responsibility for this transaction. This flag does not indicate the transaction will be settled. </value>
        [DataMember(Name="responsibilityFlag", EmitDefaultValue=false)]
        public bool? ResponsibilityFlag { get; set; }

        /// <summary>
        /// Settlement Service for the transaction.  Values:  VIP: V.I.P. to decide; or not applicable  INTERNATIONAL_SETTLEMENT: International   NATIONAL_NET_SETTLEMENT: National Net Settlement 
        /// </summary>
        /// <value>Settlement Service for the transaction.  Values:  VIP: V.I.P. to decide; or not applicable  INTERNATIONAL_SETTLEMENT: International   NATIONAL_NET_SETTLEMENT: National Net Settlement </value>
        [DataMember(Name="serviceFlag", EmitDefaultValue=false)]
        public string ServiceFlag { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class PushFunds201ResponseProcessorInformationSettlement {\n");
            if (ResponsibilityFlag != null) sb.Append("  ResponsibilityFlag: ").Append(ResponsibilityFlag).Append("\n");
            if (ServiceFlag != null) sb.Append("  ServiceFlag: ").Append(ServiceFlag).Append("\n");
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
            return this.Equals(obj as PushFunds201ResponseProcessorInformationSettlement);
        }

        /// <summary>
        /// Returns true if PushFunds201ResponseProcessorInformationSettlement instances are equal
        /// </summary>
        /// <param name="other">Instance of PushFunds201ResponseProcessorInformationSettlement to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(PushFunds201ResponseProcessorInformationSettlement other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.ResponsibilityFlag == other.ResponsibilityFlag ||
                    this.ResponsibilityFlag != null &&
                    this.ResponsibilityFlag.Equals(other.ResponsibilityFlag)
                ) && 
                (
                    this.ServiceFlag == other.ServiceFlag ||
                    this.ServiceFlag != null &&
                    this.ServiceFlag.Equals(other.ServiceFlag)
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
                if (this.ResponsibilityFlag != null)
                    hash = hash * 59 + this.ResponsibilityFlag.GetHashCode();
                if (this.ServiceFlag != null)
                    hash = hash * 59 + this.ServiceFlag.GetHashCode();
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
