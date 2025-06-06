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
    /// RiskV1AuthenticationSetupsPost201ResponseConsumerAuthenticationInformation
    /// </summary>
    [DataContract]
    public partial class RiskV1AuthenticationSetupsPost201ResponseConsumerAuthenticationInformation :  IEquatable<RiskV1AuthenticationSetupsPost201ResponseConsumerAuthenticationInformation>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RiskV1AuthenticationSetupsPost201ResponseConsumerAuthenticationInformation" /> class.
        /// </summary>
        /// <param name="AccessToken">JSON Web Token (JWT) used to authenticate the consumer with the authentication provider, such as, CardinalCommerce or Rupay. Note - Max Length of this field is 2048 characters. .</param>
        /// <param name="ReferenceId">This identifier represents cardinal has started device data collection session and this must be passed in Authentication JWT to Cardinal when invoking the deviceDataCollectionUrl. .</param>
        /// <param name="DeviceDataCollectionUrl">The deviceDataCollectionUrl is the location to send the Authentication JWT when invoking the Device Data collection process. .</param>
        public RiskV1AuthenticationSetupsPost201ResponseConsumerAuthenticationInformation(string AccessToken = default(string), string ReferenceId = default(string), string DeviceDataCollectionUrl = default(string))
        {
            this.AccessToken = AccessToken;
            this.ReferenceId = ReferenceId;
            this.DeviceDataCollectionUrl = DeviceDataCollectionUrl;
        }
        
        /// <summary>
        /// JSON Web Token (JWT) used to authenticate the consumer with the authentication provider, such as, CardinalCommerce or Rupay. Note - Max Length of this field is 2048 characters. 
        /// </summary>
        /// <value>JSON Web Token (JWT) used to authenticate the consumer with the authentication provider, such as, CardinalCommerce or Rupay. Note - Max Length of this field is 2048 characters. </value>
        [DataMember(Name="accessToken", EmitDefaultValue=false)]
        public string AccessToken { get; set; }

        /// <summary>
        /// This identifier represents cardinal has started device data collection session and this must be passed in Authentication JWT to Cardinal when invoking the deviceDataCollectionUrl. 
        /// </summary>
        /// <value>This identifier represents cardinal has started device data collection session and this must be passed in Authentication JWT to Cardinal when invoking the deviceDataCollectionUrl. </value>
        [DataMember(Name="referenceId", EmitDefaultValue=false)]
        public string ReferenceId { get; set; }

        /// <summary>
        /// The deviceDataCollectionUrl is the location to send the Authentication JWT when invoking the Device Data collection process. 
        /// </summary>
        /// <value>The deviceDataCollectionUrl is the location to send the Authentication JWT when invoking the Device Data collection process. </value>
        [DataMember(Name="deviceDataCollectionUrl", EmitDefaultValue=false)]
        public string DeviceDataCollectionUrl { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class RiskV1AuthenticationSetupsPost201ResponseConsumerAuthenticationInformation {\n");
            if (AccessToken != null) sb.Append("  AccessToken: ").Append(AccessToken).Append("\n");
            if (ReferenceId != null) sb.Append("  ReferenceId: ").Append(ReferenceId).Append("\n");
            if (DeviceDataCollectionUrl != null) sb.Append("  DeviceDataCollectionUrl: ").Append(DeviceDataCollectionUrl).Append("\n");
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
            return this.Equals(obj as RiskV1AuthenticationSetupsPost201ResponseConsumerAuthenticationInformation);
        }

        /// <summary>
        /// Returns true if RiskV1AuthenticationSetupsPost201ResponseConsumerAuthenticationInformation instances are equal
        /// </summary>
        /// <param name="other">Instance of RiskV1AuthenticationSetupsPost201ResponseConsumerAuthenticationInformation to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(RiskV1AuthenticationSetupsPost201ResponseConsumerAuthenticationInformation other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.AccessToken == other.AccessToken ||
                    this.AccessToken != null &&
                    this.AccessToken.Equals(other.AccessToken)
                ) && 
                (
                    this.ReferenceId == other.ReferenceId ||
                    this.ReferenceId != null &&
                    this.ReferenceId.Equals(other.ReferenceId)
                ) && 
                (
                    this.DeviceDataCollectionUrl == other.DeviceDataCollectionUrl ||
                    this.DeviceDataCollectionUrl != null &&
                    this.DeviceDataCollectionUrl.Equals(other.DeviceDataCollectionUrl)
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
                if (this.AccessToken != null)
                    hash = hash * 59 + this.AccessToken.GetHashCode();
                if (this.ReferenceId != null)
                    hash = hash * 59 + this.ReferenceId.GetHashCode();
                if (this.DeviceDataCollectionUrl != null)
                    hash = hash * 59 + this.DeviceDataCollectionUrl.GetHashCode();
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
