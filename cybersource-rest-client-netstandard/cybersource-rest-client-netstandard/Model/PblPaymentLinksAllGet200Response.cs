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
    /// PblPaymentLinksAllGet200Response
    /// </summary>
    [DataContract]
    public partial class PblPaymentLinksAllGet200Response :  IEquatable<PblPaymentLinksAllGet200Response>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PblPaymentLinksAllGet200Response" /> class.
        /// </summary>
        /// <param name="Links">Links.</param>
        /// <param name="SubmitTimeUtc">Time of request in UTC. Format: &#x60;YYYY-MM-DDThh:mm:ssZ&#x60; **Example** &#x60;2016-08-11T22:47:57Z&#x60; equals August 11, 2016, at 22:47:57 (10:47:57 p.m.). The &#x60;T&#x60; separates the date and the time. The &#x60;Z&#x60; indicates UTC.  Returned by Cybersource for all services. .</param>
        /// <param name="TotalLinks">TotalLinks.</param>
        /// <param name="SdkLinks">SdkLinks.</param>
        public PblPaymentLinksAllGet200Response(GetAllPlansResponseLinks Links = default(GetAllPlansResponseLinks), string SubmitTimeUtc = default(string), int? TotalLinks = default(int?), List<PblPaymentLinksAllGet200ResponseSdkLinks> SdkLinks = default(List<PblPaymentLinksAllGet200ResponseSdkLinks>))
        {
            this.Links = Links;
            this.SubmitTimeUtc = SubmitTimeUtc;
            this.TotalLinks = TotalLinks;
            this.SdkLinks = SdkLinks;
        }
        
        /// <summary>
        /// Gets or Sets Links
        /// </summary>
        [DataMember(Name="_links", EmitDefaultValue=false)]
        public GetAllPlansResponseLinks Links { get; set; }

        /// <summary>
        /// Time of request in UTC. Format: &#x60;YYYY-MM-DDThh:mm:ssZ&#x60; **Example** &#x60;2016-08-11T22:47:57Z&#x60; equals August 11, 2016, at 22:47:57 (10:47:57 p.m.). The &#x60;T&#x60; separates the date and the time. The &#x60;Z&#x60; indicates UTC.  Returned by Cybersource for all services. 
        /// </summary>
        /// <value>Time of request in UTC. Format: &#x60;YYYY-MM-DDThh:mm:ssZ&#x60; **Example** &#x60;2016-08-11T22:47:57Z&#x60; equals August 11, 2016, at 22:47:57 (10:47:57 p.m.). The &#x60;T&#x60; separates the date and the time. The &#x60;Z&#x60; indicates UTC.  Returned by Cybersource for all services. </value>
        [DataMember(Name="submitTimeUtc", EmitDefaultValue=false)]
        public string SubmitTimeUtc { get; set; }

        /// <summary>
        /// Gets or Sets TotalLinks
        /// </summary>
        [DataMember(Name="totalLinks", EmitDefaultValue=false)]
        public int? TotalLinks { get; set; }

        /// <summary>
        /// Gets or Sets SdkLinks
        /// </summary>
        [DataMember(Name="links", EmitDefaultValue=false)]
        public List<PblPaymentLinksAllGet200ResponseSdkLinks> SdkLinks { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class PblPaymentLinksAllGet200Response {\n");
            if (Links != null) sb.Append("  Links: ").Append(Links).Append("\n");
            if (SubmitTimeUtc != null) sb.Append("  SubmitTimeUtc: ").Append(SubmitTimeUtc).Append("\n");
            if (TotalLinks != null) sb.Append("  TotalLinks: ").Append(TotalLinks).Append("\n");
            if (SdkLinks != null) sb.Append("  SdkLinks: ").Append(SdkLinks).Append("\n");
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
            return this.Equals(obj as PblPaymentLinksAllGet200Response);
        }

        /// <summary>
        /// Returns true if PblPaymentLinksAllGet200Response instances are equal
        /// </summary>
        /// <param name="other">Instance of PblPaymentLinksAllGet200Response to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(PblPaymentLinksAllGet200Response other)
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
                    this.SubmitTimeUtc == other.SubmitTimeUtc ||
                    this.SubmitTimeUtc != null &&
                    this.SubmitTimeUtc.Equals(other.SubmitTimeUtc)
                ) && 
                (
                    this.TotalLinks == other.TotalLinks ||
                    this.TotalLinks != null &&
                    this.TotalLinks.Equals(other.TotalLinks)
                ) && 
                (
                    this.SdkLinks == other.SdkLinks ||
                    this.SdkLinks != null &&
                    this.SdkLinks.SequenceEqual(other.SdkLinks)
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
                if (this.SubmitTimeUtc != null)
                    hash = hash * 59 + this.SubmitTimeUtc.GetHashCode();
                if (this.TotalLinks != null)
                    hash = hash * 59 + this.TotalLinks.GetHashCode();
                if (this.SdkLinks != null)
                    hash = hash * 59 + this.SdkLinks.GetHashCode();
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

