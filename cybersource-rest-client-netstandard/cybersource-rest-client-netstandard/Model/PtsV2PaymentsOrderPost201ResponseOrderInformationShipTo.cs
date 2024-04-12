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
    /// PtsV2PaymentsOrderPost201ResponseOrderInformationShipTo
    /// </summary>
    [DataContract]
    public partial class PtsV2PaymentsOrderPost201ResponseOrderInformationShipTo :  IEquatable<PtsV2PaymentsOrderPost201ResponseOrderInformationShipTo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PtsV2PaymentsOrderPost201ResponseOrderInformationShipTo" /> class.
        /// </summary>
        /// <param name="Method">shipping method for the product. Possible values are: - &#x60;sameday&#x60; - &#x60;oneday&#x60; - &#x60;twoday&#x60; - &#x60;threeday&#x60; - &#x60;lowcost&#x60; - &#x60;pickup&#x60; - &#x60;other&#x60; - &#x60;none&#x60; .</param>
        /// <param name="FirstName">First name of the recipient. .</param>
        /// <param name="LastName">Last name of the recipient. .</param>
        /// <param name="Address1">First line of the shipping address. .</param>
        /// <param name="Address2">Second line of the shipping address .</param>
        /// <param name="Locality">City of the shipping address. .</param>
        /// <param name="PostalCode">Postal code of shipping address. Consists of 5 to 9 digits. .</param>
        /// <param name="AdministrativeArea">State or province of shipping address. This is a State, Province, and Territory Codes for the United States and Canada. .</param>
        /// <param name="Country">Country of shipping address. This is a two-character ISO Standard Country Codes. .</param>
        /// <param name="PhoneNumber">Phone number of shipping address. .</param>
        public PtsV2PaymentsOrderPost201ResponseOrderInformationShipTo(string Method = default(string), string FirstName = default(string), string LastName = default(string), string Address1 = default(string), string Address2 = default(string), string Locality = default(string), string PostalCode = default(string), string AdministrativeArea = default(string), string Country = default(string), string PhoneNumber = default(string))
        {
            this.Method = Method;
            this.FirstName = FirstName;
            this.LastName = LastName;
            this.Address1 = Address1;
            this.Address2 = Address2;
            this.Locality = Locality;
            this.PostalCode = PostalCode;
            this.AdministrativeArea = AdministrativeArea;
            this.Country = Country;
            this.PhoneNumber = PhoneNumber;
        }
        
        /// <summary>
        /// shipping method for the product. Possible values are: - &#x60;sameday&#x60; - &#x60;oneday&#x60; - &#x60;twoday&#x60; - &#x60;threeday&#x60; - &#x60;lowcost&#x60; - &#x60;pickup&#x60; - &#x60;other&#x60; - &#x60;none&#x60; 
        /// </summary>
        /// <value>shipping method for the product. Possible values are: - &#x60;sameday&#x60; - &#x60;oneday&#x60; - &#x60;twoday&#x60; - &#x60;threeday&#x60; - &#x60;lowcost&#x60; - &#x60;pickup&#x60; - &#x60;other&#x60; - &#x60;none&#x60; </value>
        [DataMember(Name="method", EmitDefaultValue=false)]
        public string Method { get; set; }

        /// <summary>
        /// First name of the recipient. 
        /// </summary>
        /// <value>First name of the recipient. </value>
        [DataMember(Name="firstName", EmitDefaultValue=false)]
        public string FirstName { get; set; }

        /// <summary>
        /// Last name of the recipient. 
        /// </summary>
        /// <value>Last name of the recipient. </value>
        [DataMember(Name="lastName", EmitDefaultValue=false)]
        public string LastName { get; set; }

        /// <summary>
        /// First line of the shipping address. 
        /// </summary>
        /// <value>First line of the shipping address. </value>
        [DataMember(Name="address1", EmitDefaultValue=false)]
        public string Address1 { get; set; }

        /// <summary>
        /// Second line of the shipping address 
        /// </summary>
        /// <value>Second line of the shipping address </value>
        [DataMember(Name="address2", EmitDefaultValue=false)]
        public string Address2 { get; set; }

        /// <summary>
        /// City of the shipping address. 
        /// </summary>
        /// <value>City of the shipping address. </value>
        [DataMember(Name="locality", EmitDefaultValue=false)]
        public string Locality { get; set; }

        /// <summary>
        /// Postal code of shipping address. Consists of 5 to 9 digits. 
        /// </summary>
        /// <value>Postal code of shipping address. Consists of 5 to 9 digits. </value>
        [DataMember(Name="postalCode", EmitDefaultValue=false)]
        public string PostalCode { get; set; }

        /// <summary>
        /// State or province of shipping address. This is a State, Province, and Territory Codes for the United States and Canada. 
        /// </summary>
        /// <value>State or province of shipping address. This is a State, Province, and Territory Codes for the United States and Canada. </value>
        [DataMember(Name="administrativeArea", EmitDefaultValue=false)]
        public string AdministrativeArea { get; set; }

        /// <summary>
        /// Country of shipping address. This is a two-character ISO Standard Country Codes. 
        /// </summary>
        /// <value>Country of shipping address. This is a two-character ISO Standard Country Codes. </value>
        [DataMember(Name="country", EmitDefaultValue=false)]
        public string Country { get; set; }

        /// <summary>
        /// Phone number of shipping address. 
        /// </summary>
        /// <value>Phone number of shipping address. </value>
        [DataMember(Name="phoneNumber", EmitDefaultValue=false)]
        public string PhoneNumber { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class PtsV2PaymentsOrderPost201ResponseOrderInformationShipTo {\n");
            sb.Append("  Method: ").Append(Method).Append("\n");
            sb.Append("  FirstName: ").Append(FirstName).Append("\n");
            sb.Append("  LastName: ").Append(LastName).Append("\n");
            sb.Append("  Address1: ").Append(Address1).Append("\n");
            sb.Append("  Address2: ").Append(Address2).Append("\n");
            sb.Append("  Locality: ").Append(Locality).Append("\n");
            sb.Append("  PostalCode: ").Append(PostalCode).Append("\n");
            sb.Append("  AdministrativeArea: ").Append(AdministrativeArea).Append("\n");
            sb.Append("  Country: ").Append(Country).Append("\n");
            sb.Append("  PhoneNumber: ").Append(PhoneNumber).Append("\n");
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
            return this.Equals(obj as PtsV2PaymentsOrderPost201ResponseOrderInformationShipTo);
        }

        /// <summary>
        /// Returns true if PtsV2PaymentsOrderPost201ResponseOrderInformationShipTo instances are equal
        /// </summary>
        /// <param name="other">Instance of PtsV2PaymentsOrderPost201ResponseOrderInformationShipTo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(PtsV2PaymentsOrderPost201ResponseOrderInformationShipTo other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Method == other.Method ||
                    this.Method != null &&
                    this.Method.Equals(other.Method)
                ) && 
                (
                    this.FirstName == other.FirstName ||
                    this.FirstName != null &&
                    this.FirstName.Equals(other.FirstName)
                ) && 
                (
                    this.LastName == other.LastName ||
                    this.LastName != null &&
                    this.LastName.Equals(other.LastName)
                ) && 
                (
                    this.Address1 == other.Address1 ||
                    this.Address1 != null &&
                    this.Address1.Equals(other.Address1)
                ) && 
                (
                    this.Address2 == other.Address2 ||
                    this.Address2 != null &&
                    this.Address2.Equals(other.Address2)
                ) && 
                (
                    this.Locality == other.Locality ||
                    this.Locality != null &&
                    this.Locality.Equals(other.Locality)
                ) && 
                (
                    this.PostalCode == other.PostalCode ||
                    this.PostalCode != null &&
                    this.PostalCode.Equals(other.PostalCode)
                ) && 
                (
                    this.AdministrativeArea == other.AdministrativeArea ||
                    this.AdministrativeArea != null &&
                    this.AdministrativeArea.Equals(other.AdministrativeArea)
                ) && 
                (
                    this.Country == other.Country ||
                    this.Country != null &&
                    this.Country.Equals(other.Country)
                ) && 
                (
                    this.PhoneNumber == other.PhoneNumber ||
                    this.PhoneNumber != null &&
                    this.PhoneNumber.Equals(other.PhoneNumber)
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
                if (this.Method != null)
                    hash = hash * 59 + this.Method.GetHashCode();
                if (this.FirstName != null)
                    hash = hash * 59 + this.FirstName.GetHashCode();
                if (this.LastName != null)
                    hash = hash * 59 + this.LastName.GetHashCode();
                if (this.Address1 != null)
                    hash = hash * 59 + this.Address1.GetHashCode();
                if (this.Address2 != null)
                    hash = hash * 59 + this.Address2.GetHashCode();
                if (this.Locality != null)
                    hash = hash * 59 + this.Locality.GetHashCode();
                if (this.PostalCode != null)
                    hash = hash * 59 + this.PostalCode.GetHashCode();
                if (this.AdministrativeArea != null)
                    hash = hash * 59 + this.AdministrativeArea.GetHashCode();
                if (this.Country != null)
                    hash = hash * 59 + this.Country.GetHashCode();
                if (this.PhoneNumber != null)
                    hash = hash * 59 + this.PhoneNumber.GetHashCode();
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