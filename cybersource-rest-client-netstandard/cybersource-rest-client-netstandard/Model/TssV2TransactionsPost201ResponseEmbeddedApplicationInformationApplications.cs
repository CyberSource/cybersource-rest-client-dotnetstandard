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
    /// TssV2TransactionsPost201ResponseEmbeddedApplicationInformationApplications
    /// </summary>
    [DataContract]
    public partial class TssV2TransactionsPost201ResponseEmbeddedApplicationInformationApplications :  IEquatable<TssV2TransactionsPost201ResponseEmbeddedApplicationInformationApplications>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TssV2TransactionsPost201ResponseEmbeddedApplicationInformationApplications" /> class.
        /// </summary>
        /// <param name="Name">The name of the CyberSource transaction type (such as CC settlement or CC authorization) that the merchant wants to process in a transaction request. More than one transaction type can included in a transaction request. Each transaction type separately returns their own status, reasonCode, rCode, and rFlag messages. .</param>
        /// <param name="ReasonCode">3-digit reason code that indicates why the customer profile payment succeeded or failed..</param>
        /// <param name="Status">The status of the submitted transaction. Note: This field may not be returned for all transactions. .</param>
        /// <param name="Reason">Description of why a request failed. Note: This field may not be returned for all transactions. .</param>
        /// <param name="RCode">Indicates whether the service request was successful. Possible values:  - &#x60;-1&#x60;: An error occurred. - &#x60;0&#x60;: The request was declined. - &#x60;1&#x60;: The request was successful. .</param>
        /// <param name="RFlag">One-word description of the result of the application. .</param>
        /// <param name="ReconciliationId">Reference number that you use to reconcile your CyberSource reports with your processor reports. .</param>
        /// <param name="RMessage">Message that explains the reply flag for the application. .</param>
        /// <param name="ReturnCode">The description for this field is not available..</param>
        public TssV2TransactionsPost201ResponseEmbeddedApplicationInformationApplications(string Name = default(string), string ReasonCode = default(string), string Status = default(string), string Reason = default(string), string RCode = default(string), string RFlag = default(string), string ReconciliationId = default(string), string RMessage = default(string), int? ReturnCode = default(int?))
        {
            this.Name = Name;
            this.ReasonCode = ReasonCode;
            this.Status = Status;
            this.Reason = Reason;
            this.RCode = RCode;
            this.RFlag = RFlag;
            this.ReconciliationId = ReconciliationId;
            this.RMessage = RMessage;
            this.ReturnCode = ReturnCode;
        }
        
        /// <summary>
        /// The name of the CyberSource transaction type (such as CC settlement or CC authorization) that the merchant wants to process in a transaction request. More than one transaction type can included in a transaction request. Each transaction type separately returns their own status, reasonCode, rCode, and rFlag messages. 
        /// </summary>
        /// <value>The name of the CyberSource transaction type (such as CC settlement or CC authorization) that the merchant wants to process in a transaction request. More than one transaction type can included in a transaction request. Each transaction type separately returns their own status, reasonCode, rCode, and rFlag messages. </value>
        [DataMember(Name="name", EmitDefaultValue=false)]
        public string Name { get; set; }

        /// <summary>
        /// 3-digit reason code that indicates why the customer profile payment succeeded or failed.
        /// </summary>
        /// <value>3-digit reason code that indicates why the customer profile payment succeeded or failed.</value>
        [DataMember(Name="reasonCode", EmitDefaultValue=false)]
        public string ReasonCode { get; set; }

        /// <summary>
        /// The status of the submitted transaction. Note: This field may not be returned for all transactions. 
        /// </summary>
        /// <value>The status of the submitted transaction. Note: This field may not be returned for all transactions. </value>
        [DataMember(Name="status", EmitDefaultValue=false)]
        public string Status { get; set; }

        /// <summary>
        /// Description of why a request failed. Note: This field may not be returned for all transactions. 
        /// </summary>
        /// <value>Description of why a request failed. Note: This field may not be returned for all transactions. </value>
        [DataMember(Name="reason", EmitDefaultValue=false)]
        public string Reason { get; set; }

        /// <summary>
        /// Indicates whether the service request was successful. Possible values:  - &#x60;-1&#x60;: An error occurred. - &#x60;0&#x60;: The request was declined. - &#x60;1&#x60;: The request was successful. 
        /// </summary>
        /// <value>Indicates whether the service request was successful. Possible values:  - &#x60;-1&#x60;: An error occurred. - &#x60;0&#x60;: The request was declined. - &#x60;1&#x60;: The request was successful. </value>
        [DataMember(Name="rCode", EmitDefaultValue=false)]
        public string RCode { get; set; }

        /// <summary>
        /// One-word description of the result of the application. 
        /// </summary>
        /// <value>One-word description of the result of the application. </value>
        [DataMember(Name="rFlag", EmitDefaultValue=false)]
        public string RFlag { get; set; }

        /// <summary>
        /// Reference number that you use to reconcile your CyberSource reports with your processor reports. 
        /// </summary>
        /// <value>Reference number that you use to reconcile your CyberSource reports with your processor reports. </value>
        [DataMember(Name="reconciliationId", EmitDefaultValue=false)]
        public string ReconciliationId { get; set; }

        /// <summary>
        /// Message that explains the reply flag for the application. 
        /// </summary>
        /// <value>Message that explains the reply flag for the application. </value>
        [DataMember(Name="rMessage", EmitDefaultValue=false)]
        public string RMessage { get; set; }

        /// <summary>
        /// The description for this field is not available.
        /// </summary>
        /// <value>The description for this field is not available.</value>
        [DataMember(Name="returnCode", EmitDefaultValue=false)]
        public int? ReturnCode { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class TssV2TransactionsPost201ResponseEmbeddedApplicationInformationApplications {\n");
            if (Name != null) sb.Append("  Name: ").Append(Name).Append("\n");
            if (ReasonCode != null) sb.Append("  ReasonCode: ").Append(ReasonCode).Append("\n");
            if (Status != null) sb.Append("  Status: ").Append(Status).Append("\n");
            if (Reason != null) sb.Append("  Reason: ").Append(Reason).Append("\n");
            if (RCode != null) sb.Append("  RCode: ").Append(RCode).Append("\n");
            if (RFlag != null) sb.Append("  RFlag: ").Append(RFlag).Append("\n");
            if (ReconciliationId != null) sb.Append("  ReconciliationId: ").Append(ReconciliationId).Append("\n");
            if (RMessage != null) sb.Append("  RMessage: ").Append(RMessage).Append("\n");
            if (ReturnCode != null) sb.Append("  ReturnCode: ").Append(ReturnCode).Append("\n");
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
            return this.Equals(obj as TssV2TransactionsPost201ResponseEmbeddedApplicationInformationApplications);
        }

        /// <summary>
        /// Returns true if TssV2TransactionsPost201ResponseEmbeddedApplicationInformationApplications instances are equal
        /// </summary>
        /// <param name="other">Instance of TssV2TransactionsPost201ResponseEmbeddedApplicationInformationApplications to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(TssV2TransactionsPost201ResponseEmbeddedApplicationInformationApplications other)
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
                    this.ReasonCode == other.ReasonCode ||
                    this.ReasonCode != null &&
                    this.ReasonCode.Equals(other.ReasonCode)
                ) && 
                (
                    this.Status == other.Status ||
                    this.Status != null &&
                    this.Status.Equals(other.Status)
                ) && 
                (
                    this.Reason == other.Reason ||
                    this.Reason != null &&
                    this.Reason.Equals(other.Reason)
                ) && 
                (
                    this.RCode == other.RCode ||
                    this.RCode != null &&
                    this.RCode.Equals(other.RCode)
                ) && 
                (
                    this.RFlag == other.RFlag ||
                    this.RFlag != null &&
                    this.RFlag.Equals(other.RFlag)
                ) && 
                (
                    this.ReconciliationId == other.ReconciliationId ||
                    this.ReconciliationId != null &&
                    this.ReconciliationId.Equals(other.ReconciliationId)
                ) && 
                (
                    this.RMessage == other.RMessage ||
                    this.RMessage != null &&
                    this.RMessage.Equals(other.RMessage)
                ) && 
                (
                    this.ReturnCode == other.ReturnCode ||
                    this.ReturnCode != null &&
                    this.ReturnCode.Equals(other.ReturnCode)
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
                if (this.ReasonCode != null)
                    hash = hash * 59 + this.ReasonCode.GetHashCode();
                if (this.Status != null)
                    hash = hash * 59 + this.Status.GetHashCode();
                if (this.Reason != null)
                    hash = hash * 59 + this.Reason.GetHashCode();
                if (this.RCode != null)
                    hash = hash * 59 + this.RCode.GetHashCode();
                if (this.RFlag != null)
                    hash = hash * 59 + this.RFlag.GetHashCode();
                if (this.ReconciliationId != null)
                    hash = hash * 59 + this.ReconciliationId.GetHashCode();
                if (this.RMessage != null)
                    hash = hash * 59 + this.RMessage.GetHashCode();
                if (this.ReturnCode != null)
                    hash = hash * 59 + this.ReturnCode.GetHashCode();
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
