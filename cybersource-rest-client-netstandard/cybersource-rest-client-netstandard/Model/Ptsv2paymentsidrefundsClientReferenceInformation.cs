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
    /// Ptsv2paymentsidrefundsClientReferenceInformation
    /// </summary>
    [DataContract]
    public partial class Ptsv2paymentsidrefundsClientReferenceInformation :  IEquatable<Ptsv2paymentsidrefundsClientReferenceInformation>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Ptsv2paymentsidrefundsClientReferenceInformation" /> class.
        /// </summary>
        /// <param name="Code">Merchant-generated order reference or tracking number. It is recommended that you send a unique value for each transaction so that you can perform meaningful searches for the transaction.  #### Used by **Authorization** Required field.  #### PIN Debit Requests for PIN debit reversals need to use the same merchant reference number that was used in the transaction that is being reversed.  Required field for all PIN Debit requests (purchase, credit, and reversal).  #### FDC Nashville Global Certain circumstances can cause the processor to truncate this value to 15 or 17 characters for Level II and Level III processing, which can cause a discrepancy between the value you submit and the value included in some processor reports. .</param>
        /// <param name="ReconciliationId">Reference number for the transaction. Depending on how your Cybersource account is configured, this value could either be provided in the API request or generated by CyberSource. The actual value used in the request to the processor is provided back to you by Cybersource in the response. .</param>
        /// <param name="ReturnReconciliationId">A new ID which is created for refund.</param>
        /// <param name="PausedRequestId">Used to resume a transaction that was paused for an order modification rule to allow for payer authentication to complete. To resume and continue with the authorization/decision service flow, call the services and include the request id from the prior decision call. .</param>
        /// <param name="TransactionId">Identifier that you assign to the transaction. Normally generated by a client server to identify a unique API request.  **Note** Use this field only if you want to support merchant-initiated reversal and void operations.  #### Used by **Authorization, Authorization Reversal, Capture, Credit, and Void** Optional field.  #### PIN Debit For a PIN debit reversal, your request must include a request ID or a merchant transaction identifier. Optional field for PIN debit purchase or credit requests. .</param>
        /// <param name="Comments">Brief description of the order or any comment you wish to add to the order..</param>
        /// <param name="Partner">Partner.</param>
        /// <param name="ApplicationName">The name of the Connection Method client (such as Virtual Terminal or SOAP Toolkit API) that the merchant uses to send a transaction request to CyberSource. .</param>
        /// <param name="ApplicationVersion">Version of the CyberSource application or integration used for a transaction. .</param>
        /// <param name="ApplicationUser">The entity that is responsible for running the transaction and submitting the processing request to CyberSource. This could be a person, a system, or a connection method. .</param>
        public Ptsv2paymentsidrefundsClientReferenceInformation(string Code = default(string), string ReconciliationId = default(string), string ReturnReconciliationId = default(string), string PausedRequestId = default(string), string TransactionId = default(string), string Comments = default(string), Ptsv2paymentsClientReferenceInformationPartner Partner = default(Ptsv2paymentsClientReferenceInformationPartner), string ApplicationName = default(string), string ApplicationVersion = default(string), string ApplicationUser = default(string))
        {
            this.Code = Code;
            this.ReconciliationId = ReconciliationId;
            this.ReturnReconciliationId = ReturnReconciliationId;
            this.PausedRequestId = PausedRequestId;
            this.TransactionId = TransactionId;
            this.Comments = Comments;
            this.Partner = Partner;
            this.ApplicationName = ApplicationName;
            this.ApplicationVersion = ApplicationVersion;
            this.ApplicationUser = ApplicationUser;
        }
        
        /// <summary>
        /// Merchant-generated order reference or tracking number. It is recommended that you send a unique value for each transaction so that you can perform meaningful searches for the transaction.  #### Used by **Authorization** Required field.  #### PIN Debit Requests for PIN debit reversals need to use the same merchant reference number that was used in the transaction that is being reversed.  Required field for all PIN Debit requests (purchase, credit, and reversal).  #### FDC Nashville Global Certain circumstances can cause the processor to truncate this value to 15 or 17 characters for Level II and Level III processing, which can cause a discrepancy between the value you submit and the value included in some processor reports. 
        /// </summary>
        /// <value>Merchant-generated order reference or tracking number. It is recommended that you send a unique value for each transaction so that you can perform meaningful searches for the transaction.  #### Used by **Authorization** Required field.  #### PIN Debit Requests for PIN debit reversals need to use the same merchant reference number that was used in the transaction that is being reversed.  Required field for all PIN Debit requests (purchase, credit, and reversal).  #### FDC Nashville Global Certain circumstances can cause the processor to truncate this value to 15 or 17 characters for Level II and Level III processing, which can cause a discrepancy between the value you submit and the value included in some processor reports. </value>
        [DataMember(Name="code", EmitDefaultValue=false)]
        public string Code { get; set; }

        /// <summary>
        /// Reference number for the transaction. Depending on how your Cybersource account is configured, this value could either be provided in the API request or generated by CyberSource. The actual value used in the request to the processor is provided back to you by Cybersource in the response. 
        /// </summary>
        /// <value>Reference number for the transaction. Depending on how your Cybersource account is configured, this value could either be provided in the API request or generated by CyberSource. The actual value used in the request to the processor is provided back to you by Cybersource in the response. </value>
        [DataMember(Name="reconciliationId", EmitDefaultValue=false)]
        public string ReconciliationId { get; set; }

        /// <summary>
        /// A new ID which is created for refund
        /// </summary>
        /// <value>A new ID which is created for refund</value>
        [DataMember(Name="returnReconciliationId", EmitDefaultValue=false)]
        public string ReturnReconciliationId { get; set; }

        /// <summary>
        /// Used to resume a transaction that was paused for an order modification rule to allow for payer authentication to complete. To resume and continue with the authorization/decision service flow, call the services and include the request id from the prior decision call. 
        /// </summary>
        /// <value>Used to resume a transaction that was paused for an order modification rule to allow for payer authentication to complete. To resume and continue with the authorization/decision service flow, call the services and include the request id from the prior decision call. </value>
        [DataMember(Name="pausedRequestId", EmitDefaultValue=false)]
        public string PausedRequestId { get; set; }

        /// <summary>
        /// Identifier that you assign to the transaction. Normally generated by a client server to identify a unique API request.  **Note** Use this field only if you want to support merchant-initiated reversal and void operations.  #### Used by **Authorization, Authorization Reversal, Capture, Credit, and Void** Optional field.  #### PIN Debit For a PIN debit reversal, your request must include a request ID or a merchant transaction identifier. Optional field for PIN debit purchase or credit requests. 
        /// </summary>
        /// <value>Identifier that you assign to the transaction. Normally generated by a client server to identify a unique API request.  **Note** Use this field only if you want to support merchant-initiated reversal and void operations.  #### Used by **Authorization, Authorization Reversal, Capture, Credit, and Void** Optional field.  #### PIN Debit For a PIN debit reversal, your request must include a request ID or a merchant transaction identifier. Optional field for PIN debit purchase or credit requests. </value>
        [DataMember(Name="transactionId", EmitDefaultValue=false)]
        public string TransactionId { get; set; }

        /// <summary>
        /// Brief description of the order or any comment you wish to add to the order.
        /// </summary>
        /// <value>Brief description of the order or any comment you wish to add to the order.</value>
        [DataMember(Name="comments", EmitDefaultValue=false)]
        public string Comments { get; set; }

        /// <summary>
        /// Gets or Sets Partner
        /// </summary>
        [DataMember(Name="partner", EmitDefaultValue=false)]
        public Ptsv2paymentsClientReferenceInformationPartner Partner { get; set; }

        /// <summary>
        /// The name of the Connection Method client (such as Virtual Terminal or SOAP Toolkit API) that the merchant uses to send a transaction request to CyberSource. 
        /// </summary>
        /// <value>The name of the Connection Method client (such as Virtual Terminal or SOAP Toolkit API) that the merchant uses to send a transaction request to CyberSource. </value>
        [DataMember(Name="applicationName", EmitDefaultValue=false)]
        public string ApplicationName { get; set; }

        /// <summary>
        /// Version of the CyberSource application or integration used for a transaction. 
        /// </summary>
        /// <value>Version of the CyberSource application or integration used for a transaction. </value>
        [DataMember(Name="applicationVersion", EmitDefaultValue=false)]
        public string ApplicationVersion { get; set; }

        /// <summary>
        /// The entity that is responsible for running the transaction and submitting the processing request to CyberSource. This could be a person, a system, or a connection method. 
        /// </summary>
        /// <value>The entity that is responsible for running the transaction and submitting the processing request to CyberSource. This could be a person, a system, or a connection method. </value>
        [DataMember(Name="applicationUser", EmitDefaultValue=false)]
        public string ApplicationUser { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class Ptsv2paymentsidrefundsClientReferenceInformation {\n");
            if (Code != null) sb.Append("  Code: ").Append(Code).Append("\n");
            if (ReconciliationId != null) sb.Append("  ReconciliationId: ").Append(ReconciliationId).Append("\n");
            if (ReturnReconciliationId != null) sb.Append("  ReturnReconciliationId: ").Append(ReturnReconciliationId).Append("\n");
            if (PausedRequestId != null) sb.Append("  PausedRequestId: ").Append(PausedRequestId).Append("\n");
            if (TransactionId != null) sb.Append("  TransactionId: ").Append(TransactionId).Append("\n");
            if (Comments != null) sb.Append("  Comments: ").Append(Comments).Append("\n");
            if (Partner != null) sb.Append("  Partner: ").Append(Partner).Append("\n");
            if (ApplicationName != null) sb.Append("  ApplicationName: ").Append(ApplicationName).Append("\n");
            if (ApplicationVersion != null) sb.Append("  ApplicationVersion: ").Append(ApplicationVersion).Append("\n");
            if (ApplicationUser != null) sb.Append("  ApplicationUser: ").Append(ApplicationUser).Append("\n");
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
            return this.Equals(obj as Ptsv2paymentsidrefundsClientReferenceInformation);
        }

        /// <summary>
        /// Returns true if Ptsv2paymentsidrefundsClientReferenceInformation instances are equal
        /// </summary>
        /// <param name="other">Instance of Ptsv2paymentsidrefundsClientReferenceInformation to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(Ptsv2paymentsidrefundsClientReferenceInformation other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Code == other.Code ||
                    this.Code != null &&
                    this.Code.Equals(other.Code)
                ) && 
                (
                    this.ReconciliationId == other.ReconciliationId ||
                    this.ReconciliationId != null &&
                    this.ReconciliationId.Equals(other.ReconciliationId)
                ) && 
                (
                    this.ReturnReconciliationId == other.ReturnReconciliationId ||
                    this.ReturnReconciliationId != null &&
                    this.ReturnReconciliationId.Equals(other.ReturnReconciliationId)
                ) && 
                (
                    this.PausedRequestId == other.PausedRequestId ||
                    this.PausedRequestId != null &&
                    this.PausedRequestId.Equals(other.PausedRequestId)
                ) && 
                (
                    this.TransactionId == other.TransactionId ||
                    this.TransactionId != null &&
                    this.TransactionId.Equals(other.TransactionId)
                ) && 
                (
                    this.Comments == other.Comments ||
                    this.Comments != null &&
                    this.Comments.Equals(other.Comments)
                ) && 
                (
                    this.Partner == other.Partner ||
                    this.Partner != null &&
                    this.Partner.Equals(other.Partner)
                ) && 
                (
                    this.ApplicationName == other.ApplicationName ||
                    this.ApplicationName != null &&
                    this.ApplicationName.Equals(other.ApplicationName)
                ) && 
                (
                    this.ApplicationVersion == other.ApplicationVersion ||
                    this.ApplicationVersion != null &&
                    this.ApplicationVersion.Equals(other.ApplicationVersion)
                ) && 
                (
                    this.ApplicationUser == other.ApplicationUser ||
                    this.ApplicationUser != null &&
                    this.ApplicationUser.Equals(other.ApplicationUser)
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
                if (this.Code != null)
                    hash = hash * 59 + this.Code.GetHashCode();
                if (this.ReconciliationId != null)
                    hash = hash * 59 + this.ReconciliationId.GetHashCode();
                if (this.ReturnReconciliationId != null)
                    hash = hash * 59 + this.ReturnReconciliationId.GetHashCode();
                if (this.PausedRequestId != null)
                    hash = hash * 59 + this.PausedRequestId.GetHashCode();
                if (this.TransactionId != null)
                    hash = hash * 59 + this.TransactionId.GetHashCode();
                if (this.Comments != null)
                    hash = hash * 59 + this.Comments.GetHashCode();
                if (this.Partner != null)
                    hash = hash * 59 + this.Partner.GetHashCode();
                if (this.ApplicationName != null)
                    hash = hash * 59 + this.ApplicationName.GetHashCode();
                if (this.ApplicationVersion != null)
                    hash = hash * 59 + this.ApplicationVersion.GetHashCode();
                if (this.ApplicationUser != null)
                    hash = hash * 59 + this.ApplicationUser.GetHashCode();
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
