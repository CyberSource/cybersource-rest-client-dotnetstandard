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
    /// TmsNetworkTokenServicesVisaTokenService
    /// </summary>
    [DataContract]
    public partial class TmsNetworkTokenServicesVisaTokenService :  IEquatable<TmsNetworkTokenServicesVisaTokenService>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TmsNetworkTokenServicesVisaTokenService" /> class.
        /// </summary>
        /// <param name="EnableService">Indicates if the service for network tokens for the Visa card association are enabled.</param>
        /// <param name="EnableTransactionalTokens">Indicates if network tokens for the Visa card association are enabled for transactions.</param>
        /// <param name="TokenRequestorId">Token Requestor ID provided by Visa during the registration process for the Tokenization Service  Pattern: ^[0-9]{11}\\\\z$\&quot; Min Length: 11 Max Length: 11 Example:  \&quot;40000000082\&quot; .</param>
        /// <param name="RelationshipId">Relationship ID provided by visa  Min Length: 1 Max Length: 100 Example: \&quot;24681921-40000000082\&quot; .</param>
        public TmsNetworkTokenServicesVisaTokenService(bool? EnableService = default(bool?), bool? EnableTransactionalTokens = default(bool?), string TokenRequestorId = default(string), string RelationshipId = default(string))
        {
            this.EnableService = EnableService;
            this.EnableTransactionalTokens = EnableTransactionalTokens;
            this.TokenRequestorId = TokenRequestorId;
            this.RelationshipId = RelationshipId;
        }
        
        /// <summary>
        /// Indicates if the service for network tokens for the Visa card association are enabled
        /// </summary>
        /// <value>Indicates if the service for network tokens for the Visa card association are enabled</value>
        [DataMember(Name="enableService", EmitDefaultValue=false)]
        public bool? EnableService { get; set; }

        /// <summary>
        /// Indicates if network tokens for the Visa card association are enabled for transactions
        /// </summary>
        /// <value>Indicates if network tokens for the Visa card association are enabled for transactions</value>
        [DataMember(Name="enableTransactionalTokens", EmitDefaultValue=false)]
        public bool? EnableTransactionalTokens { get; set; }

        /// <summary>
        /// Token Requestor ID provided by Visa during the registration process for the Tokenization Service  Pattern: ^[0-9]{11}\\\\z$\&quot; Min Length: 11 Max Length: 11 Example:  \&quot;40000000082\&quot; 
        /// </summary>
        /// <value>Token Requestor ID provided by Visa during the registration process for the Tokenization Service  Pattern: ^[0-9]{11}\\\\z$\&quot; Min Length: 11 Max Length: 11 Example:  \&quot;40000000082\&quot; </value>
        [DataMember(Name="tokenRequestorId", EmitDefaultValue=false)]
        public string TokenRequestorId { get; set; }

        /// <summary>
        /// Relationship ID provided by visa  Min Length: 1 Max Length: 100 Example: \&quot;24681921-40000000082\&quot; 
        /// </summary>
        /// <value>Relationship ID provided by visa  Min Length: 1 Max Length: 100 Example: \&quot;24681921-40000000082\&quot; </value>
        [DataMember(Name="relationshipId", EmitDefaultValue=false)]
        public string RelationshipId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class TmsNetworkTokenServicesVisaTokenService {\n");
            if (EnableService != null) sb.Append("  EnableService: ").Append(EnableService).Append("\n");
            if (EnableTransactionalTokens != null) sb.Append("  EnableTransactionalTokens: ").Append(EnableTransactionalTokens).Append("\n");
            if (TokenRequestorId != null) sb.Append("  TokenRequestorId: ").Append(TokenRequestorId).Append("\n");
            if (RelationshipId != null) sb.Append("  RelationshipId: ").Append(RelationshipId).Append("\n");
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
            return this.Equals(obj as TmsNetworkTokenServicesVisaTokenService);
        }

        /// <summary>
        /// Returns true if TmsNetworkTokenServicesVisaTokenService instances are equal
        /// </summary>
        /// <param name="other">Instance of TmsNetworkTokenServicesVisaTokenService to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(TmsNetworkTokenServicesVisaTokenService other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.EnableService == other.EnableService ||
                    this.EnableService != null &&
                    this.EnableService.Equals(other.EnableService)
                ) && 
                (
                    this.EnableTransactionalTokens == other.EnableTransactionalTokens ||
                    this.EnableTransactionalTokens != null &&
                    this.EnableTransactionalTokens.Equals(other.EnableTransactionalTokens)
                ) && 
                (
                    this.TokenRequestorId == other.TokenRequestorId ||
                    this.TokenRequestorId != null &&
                    this.TokenRequestorId.Equals(other.TokenRequestorId)
                ) && 
                (
                    this.RelationshipId == other.RelationshipId ||
                    this.RelationshipId != null &&
                    this.RelationshipId.Equals(other.RelationshipId)
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
                if (this.EnableService != null)
                    hash = hash * 59 + this.EnableService.GetHashCode();
                if (this.EnableTransactionalTokens != null)
                    hash = hash * 59 + this.EnableTransactionalTokens.GetHashCode();
                if (this.TokenRequestorId != null)
                    hash = hash * 59 + this.TokenRequestorId.GetHashCode();
                if (this.RelationshipId != null)
                    hash = hash * 59 + this.RelationshipId.GetHashCode();
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
