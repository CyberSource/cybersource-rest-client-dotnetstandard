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
    /// PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformation
    /// </summary>
    [DataContract]
    public partial class PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformation :  IEquatable<PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformation>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformation" /> class.
        /// </summary>
        /// <param name="Header">Header.</param>
        /// <param name="OrderInformation">OrderInformation.</param>
        /// <param name="EmailReceipt">EmailReceipt.</param>
        public PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformation(PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformationHeader Header = default(PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformationHeader), PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformationOrderInformation OrderInformation = default(PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformationOrderInformation), PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformationEmailReceipt EmailReceipt = default(PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformationEmailReceipt))
        {
            this.Header = Header;
            this.OrderInformation = OrderInformation;
            this.EmailReceipt = EmailReceipt;
        }
        
        /// <summary>
        /// Gets or Sets Header
        /// </summary>
        [DataMember(Name="header", EmitDefaultValue=false)]
        public PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformationHeader Header { get; set; }

        /// <summary>
        /// Gets or Sets OrderInformation
        /// </summary>
        [DataMember(Name="orderInformation", EmitDefaultValue=false)]
        public PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformationOrderInformation OrderInformation { get; set; }

        /// <summary>
        /// Gets or Sets EmailReceipt
        /// </summary>
        [DataMember(Name="emailReceipt", EmitDefaultValue=false)]
        public PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformationEmailReceipt EmailReceipt { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformation {\n");
            sb.Append("  Header: ").Append(Header).Append("\n");
            sb.Append("  OrderInformation: ").Append(OrderInformation).Append("\n");
            sb.Append("  EmailReceipt: ").Append(EmailReceipt).Append("\n");
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
            return this.Equals(obj as PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformation);
        }

        /// <summary>
        /// Returns true if PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformation instances are equal
        /// </summary>
        /// <param name="other">Instance of PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformation to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformation other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Header == other.Header ||
                    this.Header != null &&
                    this.Header.Equals(other.Header)
                ) && 
                (
                    this.OrderInformation == other.OrderInformation ||
                    this.OrderInformation != null &&
                    this.OrderInformation.Equals(other.OrderInformation)
                ) && 
                (
                    this.EmailReceipt == other.EmailReceipt ||
                    this.EmailReceipt != null &&
                    this.EmailReceipt.Equals(other.EmailReceipt)
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
                if (this.Header != null)
                    hash = hash * 59 + this.Header.GetHashCode();
                if (this.OrderInformation != null)
                    hash = hash * 59 + this.OrderInformation.GetHashCode();
                if (this.EmailReceipt != null)
                    hash = hash * 59 + this.EmailReceipt.GetHashCode();
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