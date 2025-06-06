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
    /// A list of invoices.
    /// </summary>
    [DataContract]
    public partial class InvoicingV2InvoicesAllGet200ResponseInvoices :  IEquatable<InvoicingV2InvoicesAllGet200ResponseInvoices>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InvoicingV2InvoicesAllGet200ResponseInvoices" /> class.
        /// </summary>
        /// <param name="Links">Links.</param>
        /// <param name="Id">An unique identification number generated by Cybersource to identify the submitted request. Returned by all services. It is also appended to the endpoint of the resource. On incremental authorizations, this value with be the same as the identification number returned in the original authorization response. .</param>
        /// <param name="Status">The status of the invoice.  Possible values: - DRAFT - CREATED - SENT - PARTIAL - PAID - CANCELED - PENDING .</param>
        /// <param name="CreatedDate">Date and time (UTC) the invoice was created.  Format: YYYY-MM-DDThh:mm:ssZ Example 2016-08-11T22:47:57Z equals August 11, 2016, at 22:47:57 (10:47:57 p.m.). The T separates the date and the time. The Z indicates UTC. .</param>
        /// <param name="CustomerInformation">CustomerInformation.</param>
        /// <param name="InvoiceInformation">InvoiceInformation.</param>
        /// <param name="OrderInformation">OrderInformation.</param>
        public InvoicingV2InvoicesAllGet200ResponseInvoices(InvoicingV2InvoicesAllGet200ResponseLinks Links = default(InvoicingV2InvoicesAllGet200ResponseLinks), string Id = default(string), string Status = default(string), string CreatedDate = default(string), InvoicingV2InvoicesAllGet200ResponseCustomerInformation CustomerInformation = default(InvoicingV2InvoicesAllGet200ResponseCustomerInformation), InvoicingV2InvoicesAllGet200ResponseInvoiceInformation InvoiceInformation = default(InvoicingV2InvoicesAllGet200ResponseInvoiceInformation), InvoicingV2InvoicesAllGet200ResponseOrderInformation OrderInformation = default(InvoicingV2InvoicesAllGet200ResponseOrderInformation))
        {
            this.Links = Links;
            this.Id = Id;
            this.Status = Status;
            this.CreatedDate = CreatedDate;
            this.CustomerInformation = CustomerInformation;
            this.InvoiceInformation = InvoiceInformation;
            this.OrderInformation = OrderInformation;
        }
        
        /// <summary>
        /// Gets or Sets Links
        /// </summary>
        [DataMember(Name="_links", EmitDefaultValue=false)]
        public InvoicingV2InvoicesAllGet200ResponseLinks Links { get; set; }

        /// <summary>
        /// An unique identification number generated by Cybersource to identify the submitted request. Returned by all services. It is also appended to the endpoint of the resource. On incremental authorizations, this value with be the same as the identification number returned in the original authorization response. 
        /// </summary>
        /// <value>An unique identification number generated by Cybersource to identify the submitted request. Returned by all services. It is also appended to the endpoint of the resource. On incremental authorizations, this value with be the same as the identification number returned in the original authorization response. </value>
        [DataMember(Name="id", EmitDefaultValue=false)]
        public string Id { get; set; }

        /// <summary>
        /// The status of the invoice.  Possible values: - DRAFT - CREATED - SENT - PARTIAL - PAID - CANCELED - PENDING 
        /// </summary>
        /// <value>The status of the invoice.  Possible values: - DRAFT - CREATED - SENT - PARTIAL - PAID - CANCELED - PENDING </value>
        [DataMember(Name="status", EmitDefaultValue=false)]
        public string Status { get; set; }

        /// <summary>
        /// Date and time (UTC) the invoice was created.  Format: YYYY-MM-DDThh:mm:ssZ Example 2016-08-11T22:47:57Z equals August 11, 2016, at 22:47:57 (10:47:57 p.m.). The T separates the date and the time. The Z indicates UTC. 
        /// </summary>
        /// <value>Date and time (UTC) the invoice was created.  Format: YYYY-MM-DDThh:mm:ssZ Example 2016-08-11T22:47:57Z equals August 11, 2016, at 22:47:57 (10:47:57 p.m.). The T separates the date and the time. The Z indicates UTC. </value>
        [DataMember(Name="createdDate", EmitDefaultValue=false)]
        public string CreatedDate { get; set; }

        /// <summary>
        /// Gets or Sets CustomerInformation
        /// </summary>
        [DataMember(Name="customerInformation", EmitDefaultValue=false)]
        public InvoicingV2InvoicesAllGet200ResponseCustomerInformation CustomerInformation { get; set; }

        /// <summary>
        /// Gets or Sets InvoiceInformation
        /// </summary>
        [DataMember(Name="invoiceInformation", EmitDefaultValue=false)]
        public InvoicingV2InvoicesAllGet200ResponseInvoiceInformation InvoiceInformation { get; set; }

        /// <summary>
        /// Gets or Sets OrderInformation
        /// </summary>
        [DataMember(Name="orderInformation", EmitDefaultValue=false)]
        public InvoicingV2InvoicesAllGet200ResponseOrderInformation OrderInformation { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class InvoicingV2InvoicesAllGet200ResponseInvoices {\n");
            if (Links != null) sb.Append("  Links: ").Append(Links).Append("\n");
            if (Id != null) sb.Append("  Id: ").Append(Id).Append("\n");
            if (Status != null) sb.Append("  Status: ").Append(Status).Append("\n");
            if (CreatedDate != null) sb.Append("  CreatedDate: ").Append(CreatedDate).Append("\n");
            if (CustomerInformation != null) sb.Append("  CustomerInformation: ").Append(CustomerInformation).Append("\n");
            if (InvoiceInformation != null) sb.Append("  InvoiceInformation: ").Append(InvoiceInformation).Append("\n");
            if (OrderInformation != null) sb.Append("  OrderInformation: ").Append(OrderInformation).Append("\n");
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
            return this.Equals(obj as InvoicingV2InvoicesAllGet200ResponseInvoices);
        }

        /// <summary>
        /// Returns true if InvoicingV2InvoicesAllGet200ResponseInvoices instances are equal
        /// </summary>
        /// <param name="other">Instance of InvoicingV2InvoicesAllGet200ResponseInvoices to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(InvoicingV2InvoicesAllGet200ResponseInvoices other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Links == other.Links ||
                    this.Links != null &&
                    this.Links.Equals(other.Links)
                ) && 
                (
                    this.Id == other.Id ||
                    this.Id != null &&
                    this.Id.Equals(other.Id)
                ) && 
                (
                    this.Status == other.Status ||
                    this.Status != null &&
                    this.Status.Equals(other.Status)
                ) && 
                (
                    this.CreatedDate == other.CreatedDate ||
                    this.CreatedDate != null &&
                    this.CreatedDate.Equals(other.CreatedDate)
                ) && 
                (
                    this.CustomerInformation == other.CustomerInformation ||
                    this.CustomerInformation != null &&
                    this.CustomerInformation.Equals(other.CustomerInformation)
                ) && 
                (
                    this.InvoiceInformation == other.InvoiceInformation ||
                    this.InvoiceInformation != null &&
                    this.InvoiceInformation.Equals(other.InvoiceInformation)
                ) && 
                (
                    this.OrderInformation == other.OrderInformation ||
                    this.OrderInformation != null &&
                    this.OrderInformation.Equals(other.OrderInformation)
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
                if (this.Links != null)
                    hash = hash * 59 + this.Links.GetHashCode();
                if (this.Id != null)
                    hash = hash * 59 + this.Id.GetHashCode();
                if (this.Status != null)
                    hash = hash * 59 + this.Status.GetHashCode();
                if (this.CreatedDate != null)
                    hash = hash * 59 + this.CreatedDate.GetHashCode();
                if (this.CustomerInformation != null)
                    hash = hash * 59 + this.CustomerInformation.GetHashCode();
                if (this.InvoiceInformation != null)
                    hash = hash * 59 + this.InvoiceInformation.GetHashCode();
                if (this.OrderInformation != null)
                    hash = hash * 59 + this.OrderInformation.GetHashCode();
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
