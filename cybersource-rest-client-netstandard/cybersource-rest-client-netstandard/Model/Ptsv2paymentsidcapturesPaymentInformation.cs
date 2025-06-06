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
    /// Ptsv2paymentsidcapturesPaymentInformation
    /// </summary>
    [DataContract]
    public partial class Ptsv2paymentsidcapturesPaymentInformation :  IEquatable<Ptsv2paymentsidcapturesPaymentInformation>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Ptsv2paymentsidcapturesPaymentInformation" /> class.
        /// </summary>
        /// <param name="Customer">Customer.</param>
        /// <param name="Card">Card.</param>
        /// <param name="PaymentType">PaymentType.</param>
        public Ptsv2paymentsidcapturesPaymentInformation(Ptsv2paymentsPaymentInformationCustomer Customer = default(Ptsv2paymentsPaymentInformationCustomer), Ptsv2paymentsidcapturesPaymentInformationCard Card = default(Ptsv2paymentsidcapturesPaymentInformationCard), Ptsv2paymentsidcapturesPaymentInformationPaymentType PaymentType = default(Ptsv2paymentsidcapturesPaymentInformationPaymentType))
        {
            this.Customer = Customer;
            this.Card = Card;
            this.PaymentType = PaymentType;
        }
        
        /// <summary>
        /// Gets or Sets Customer
        /// </summary>
        [DataMember(Name="customer", EmitDefaultValue=false)]
        public Ptsv2paymentsPaymentInformationCustomer Customer { get; set; }

        /// <summary>
        /// Gets or Sets Card
        /// </summary>
        [DataMember(Name="card", EmitDefaultValue=false)]
        public Ptsv2paymentsidcapturesPaymentInformationCard Card { get; set; }

        /// <summary>
        /// Gets or Sets PaymentType
        /// </summary>
        [DataMember(Name="paymentType", EmitDefaultValue=false)]
        public Ptsv2paymentsidcapturesPaymentInformationPaymentType PaymentType { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class Ptsv2paymentsidcapturesPaymentInformation {\n");
            if (Customer != null) sb.Append("  Customer: ").Append(Customer).Append("\n");
            if (Card != null) sb.Append("  Card: ").Append(Card).Append("\n");
            if (PaymentType != null) sb.Append("  PaymentType: ").Append(PaymentType).Append("\n");
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
            return this.Equals(obj as Ptsv2paymentsidcapturesPaymentInformation);
        }

        /// <summary>
        /// Returns true if Ptsv2paymentsidcapturesPaymentInformation instances are equal
        /// </summary>
        /// <param name="other">Instance of Ptsv2paymentsidcapturesPaymentInformation to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(Ptsv2paymentsidcapturesPaymentInformation other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Customer == other.Customer ||
                    this.Customer != null &&
                    this.Customer.Equals(other.Customer)
                ) && 
                (
                    this.Card == other.Card ||
                    this.Card != null &&
                    this.Card.Equals(other.Card)
                ) && 
                (
                    this.PaymentType == other.PaymentType ||
                    this.PaymentType != null &&
                    this.PaymentType.Equals(other.PaymentType)
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
                if (this.Customer != null)
                    hash = hash * 59 + this.Customer.GetHashCode();
                if (this.Card != null)
                    hash = hash * 59 + this.Card.GetHashCode();
                if (this.PaymentType != null)
                    hash = hash * 59 + this.PaymentType.GetHashCode();
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
