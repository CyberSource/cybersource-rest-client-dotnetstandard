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
    /// TssV2TransactionsGet200ResponsePaymentInformationIssuerInformation
    /// </summary>
    [DataContract]
    public partial class TssV2TransactionsGet200ResponsePaymentInformationIssuerInformation :  IEquatable<TssV2TransactionsGet200ResponsePaymentInformationIssuerInformation>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TssV2TransactionsGet200ResponsePaymentInformationIssuerInformation" /> class.
        /// </summary>
        /// <param name="Name">This field contains the issuer name. .</param>
        /// <param name="Country">This field contains [2-character ISO Country Codes](http://apps.cybersource.com/library/documentation/sbc/quickref/countries_alpha_list.pdf) for the issuer. .</param>
        /// <param name="BinLength">This field contains the length of the BIN. .</param>
        /// <param name="PhoneNumber">This field contains the customer service phone number for the issuer. .</param>
        /// <param name="TransactionInformation">In a Mastercard Transaction, this field contains the unique identifier (Transaction Link ID) for the first transaction in a transaction life cycle.  This ID is crucial for maintaining continuity and linking subsequent operations to the original transaction. .</param>
        public TssV2TransactionsGet200ResponsePaymentInformationIssuerInformation(string Name = default(string), string Country = default(string), string BinLength = default(string), string PhoneNumber = default(string), string TransactionInformation = default(string))
        {
            this.Name = Name;
            this.Country = Country;
            this.BinLength = BinLength;
            this.PhoneNumber = PhoneNumber;
            this.TransactionInformation = TransactionInformation;
        }
        
        /// <summary>
        /// This field contains the issuer name. 
        /// </summary>
        /// <value>This field contains the issuer name. </value>
        [DataMember(Name="name", EmitDefaultValue=false)]
        public string Name { get; set; }

        /// <summary>
        /// This field contains [2-character ISO Country Codes](http://apps.cybersource.com/library/documentation/sbc/quickref/countries_alpha_list.pdf) for the issuer. 
        /// </summary>
        /// <value>This field contains [2-character ISO Country Codes](http://apps.cybersource.com/library/documentation/sbc/quickref/countries_alpha_list.pdf) for the issuer. </value>
        [DataMember(Name="country", EmitDefaultValue=false)]
        public string Country { get; set; }

        /// <summary>
        /// This field contains the length of the BIN. 
        /// </summary>
        /// <value>This field contains the length of the BIN. </value>
        [DataMember(Name="binLength", EmitDefaultValue=false)]
        public string BinLength { get; set; }

        /// <summary>
        /// This field contains the customer service phone number for the issuer. 
        /// </summary>
        /// <value>This field contains the customer service phone number for the issuer. </value>
        [DataMember(Name="phoneNumber", EmitDefaultValue=false)]
        public string PhoneNumber { get; set; }

        /// <summary>
        /// In a Mastercard Transaction, this field contains the unique identifier (Transaction Link ID) for the first transaction in a transaction life cycle.  This ID is crucial for maintaining continuity and linking subsequent operations to the original transaction. 
        /// </summary>
        /// <value>In a Mastercard Transaction, this field contains the unique identifier (Transaction Link ID) for the first transaction in a transaction life cycle.  This ID is crucial for maintaining continuity and linking subsequent operations to the original transaction. </value>
        [DataMember(Name="transactionInformation", EmitDefaultValue=false)]
        public string TransactionInformation { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class TssV2TransactionsGet200ResponsePaymentInformationIssuerInformation {\n");
            if (Name != null) sb.Append("  Name: ").Append(Name).Append("\n");
            if (Country != null) sb.Append("  Country: ").Append(Country).Append("\n");
            if (BinLength != null) sb.Append("  BinLength: ").Append(BinLength).Append("\n");
            if (PhoneNumber != null) sb.Append("  PhoneNumber: ").Append(PhoneNumber).Append("\n");
            if (TransactionInformation != null) sb.Append("  TransactionInformation: ").Append(TransactionInformation).Append("\n");
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
            return this.Equals(obj as TssV2TransactionsGet200ResponsePaymentInformationIssuerInformation);
        }

        /// <summary>
        /// Returns true if TssV2TransactionsGet200ResponsePaymentInformationIssuerInformation instances are equal
        /// </summary>
        /// <param name="other">Instance of TssV2TransactionsGet200ResponsePaymentInformationIssuerInformation to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(TssV2TransactionsGet200ResponsePaymentInformationIssuerInformation other)
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
                    this.Country == other.Country ||
                    this.Country != null &&
                    this.Country.Equals(other.Country)
                ) && 
                (
                    this.BinLength == other.BinLength ||
                    this.BinLength != null &&
                    this.BinLength.Equals(other.BinLength)
                ) && 
                (
                    this.PhoneNumber == other.PhoneNumber ||
                    this.PhoneNumber != null &&
                    this.PhoneNumber.Equals(other.PhoneNumber)
                ) && 
                (
                    this.TransactionInformation == other.TransactionInformation ||
                    this.TransactionInformation != null &&
                    this.TransactionInformation.Equals(other.TransactionInformation)
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
                if (this.Country != null)
                    hash = hash * 59 + this.Country.GetHashCode();
                if (this.BinLength != null)
                    hash = hash * 59 + this.BinLength.GetHashCode();
                if (this.PhoneNumber != null)
                    hash = hash * 59 + this.PhoneNumber.GetHashCode();
                if (this.TransactionInformation != null)
                    hash = hash * 59 + this.TransactionInformation.GetHashCode();
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
