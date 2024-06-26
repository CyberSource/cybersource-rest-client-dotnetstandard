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
    /// key information 
    /// </summary>
    [DataContract]
    public partial class Kmsv2keysasymKeyInformation :  IEquatable<Kmsv2keysasymKeyInformation>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Kmsv2keysasymKeyInformation" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected Kmsv2keysasymKeyInformation() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="Kmsv2keysasymKeyInformation" /> class.
        /// </summary>
        /// <param name="OrganizationId">Merchant Id  (required).</param>
        /// <param name="ReferenceNumber">Reference number is a unique identifier provided by the client along with the organization Id. This is an optional field provided solely for the client&#39;s convenience. If client specifies value for this field in the request, it is expected to be available in the response. .</param>
        /// <param name="Cert">Certificate Signing Request(csr), one needs to use the contents of the csr created for the same organizationId. Please extract string from &#39;\\n&#39; and &#39;- -- --BEGIN CERTIFICATE REQUEST- -- --&#39;,&#39;- -- --END CERTIFICATE REQUEST- -- --&#39;  (required).</param>
        public Kmsv2keysasymKeyInformation(string OrganizationId = default(string), string ReferenceNumber = default(string), string Cert = default(string))
        {
            this.OrganizationId = OrganizationId;
            this.ReferenceNumber = ReferenceNumber;
            this.Cert = Cert;
        }
        
        /// <summary>
        /// Merchant Id 
        /// </summary>
        /// <value>Merchant Id </value>
        [DataMember(Name="organizationId", EmitDefaultValue=false)]
        public string OrganizationId { get; set; }

        /// <summary>
        /// Reference number is a unique identifier provided by the client along with the organization Id. This is an optional field provided solely for the client&#39;s convenience. If client specifies value for this field in the request, it is expected to be available in the response. 
        /// </summary>
        /// <value>Reference number is a unique identifier provided by the client along with the organization Id. This is an optional field provided solely for the client&#39;s convenience. If client specifies value for this field in the request, it is expected to be available in the response. </value>
        [DataMember(Name="referenceNumber", EmitDefaultValue=false)]
        public string ReferenceNumber { get; set; }

        /// <summary>
        /// Certificate Signing Request(csr), one needs to use the contents of the csr created for the same organizationId. Please extract string from &#39;\\n&#39; and &#39;- -- --BEGIN CERTIFICATE REQUEST- -- --&#39;,&#39;- -- --END CERTIFICATE REQUEST- -- --&#39; 
        /// </summary>
        /// <value>Certificate Signing Request(csr), one needs to use the contents of the csr created for the same organizationId. Please extract string from &#39;\\n&#39; and &#39;- -- --BEGIN CERTIFICATE REQUEST- -- --&#39;,&#39;- -- --END CERTIFICATE REQUEST- -- --&#39; </value>
        [DataMember(Name="cert", EmitDefaultValue=false)]
        public string Cert { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class Kmsv2keysasymKeyInformation {\n");
            sb.Append("  OrganizationId: ").Append(OrganizationId).Append("\n");
            sb.Append("  ReferenceNumber: ").Append(ReferenceNumber).Append("\n");
            sb.Append("  Cert: ").Append(Cert).Append("\n");
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
            return this.Equals(obj as Kmsv2keysasymKeyInformation);
        }

        /// <summary>
        /// Returns true if Kmsv2keysasymKeyInformation instances are equal
        /// </summary>
        /// <param name="other">Instance of Kmsv2keysasymKeyInformation to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(Kmsv2keysasymKeyInformation other)
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
                    this.ReferenceNumber == other.ReferenceNumber ||
                    this.ReferenceNumber != null &&
                    this.ReferenceNumber.Equals(other.ReferenceNumber)
                ) && 
                (
                    this.Cert == other.Cert ||
                    this.Cert != null &&
                    this.Cert.Equals(other.Cert)
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
                if (this.ReferenceNumber != null)
                    hash = hash * 59 + this.ReferenceNumber.GetHashCode();
                if (this.Cert != null)
                    hash = hash * 59 + this.Cert.GetHashCode();
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
