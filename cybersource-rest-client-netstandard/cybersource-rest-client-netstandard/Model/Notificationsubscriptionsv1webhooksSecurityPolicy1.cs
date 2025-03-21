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
    /// The security option to authenticate with your API or client server.
    /// </summary>
    [DataContract]
    public partial class Notificationsubscriptionsv1webhooksSecurityPolicy1 :  IEquatable<Notificationsubscriptionsv1webhooksSecurityPolicy1>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Notificationsubscriptionsv1webhooksSecurityPolicy1" /> class.
        /// </summary>
        /// <param name="SecurityType">Security Policy of the client server..</param>
        /// <param name="ProxyType">Internal client proxy type to be used by security policy..</param>
        /// <param name="Config">Config.</param>
        public Notificationsubscriptionsv1webhooksSecurityPolicy1(string SecurityType = default(string), string ProxyType = default(string), Notificationsubscriptionsv1webhooksSecurityPolicy1Config Config = default(Notificationsubscriptionsv1webhooksSecurityPolicy1Config))
        {
            this.SecurityType = SecurityType;
            this.ProxyType = ProxyType;
            this.Config = Config;
        }
        
        /// <summary>
        /// Security Policy of the client server.
        /// </summary>
        /// <value>Security Policy of the client server.</value>
        [DataMember(Name="securityType", EmitDefaultValue=false)]
        public string SecurityType { get; set; }

        /// <summary>
        /// Internal client proxy type to be used by security policy.
        /// </summary>
        /// <value>Internal client proxy type to be used by security policy.</value>
        [DataMember(Name="proxyType", EmitDefaultValue=false)]
        public string ProxyType { get; set; }

        /// <summary>
        /// Gets or Sets Config
        /// </summary>
        [DataMember(Name="config", EmitDefaultValue=false)]
        public Notificationsubscriptionsv1webhooksSecurityPolicy1Config Config { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class Notificationsubscriptionsv1webhooksSecurityPolicy1 {\n");
            if (SecurityType != null) sb.Append("  SecurityType: ").Append(SecurityType).Append("\n");
            if (ProxyType != null) sb.Append("  ProxyType: ").Append(ProxyType).Append("\n");
            if (Config != null) sb.Append("  Config: ").Append(Config).Append("\n");
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
            return this.Equals(obj as Notificationsubscriptionsv1webhooksSecurityPolicy1);
        }

        /// <summary>
        /// Returns true if Notificationsubscriptionsv1webhooksSecurityPolicy1 instances are equal
        /// </summary>
        /// <param name="other">Instance of Notificationsubscriptionsv1webhooksSecurityPolicy1 to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(Notificationsubscriptionsv1webhooksSecurityPolicy1 other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.SecurityType == other.SecurityType ||
                    this.SecurityType != null &&
                    this.SecurityType.Equals(other.SecurityType)
                ) && 
                (
                    this.ProxyType == other.ProxyType ||
                    this.ProxyType != null &&
                    this.ProxyType.Equals(other.ProxyType)
                ) && 
                (
                    this.Config == other.Config ||
                    this.Config != null &&
                    this.Config.Equals(other.Config)
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
                if (this.SecurityType != null)
                    hash = hash * 59 + this.SecurityType.GetHashCode();
                if (this.ProxyType != null)
                    hash = hash * 59 + this.ProxyType.GetHashCode();
                if (this.Config != null)
                    hash = hash * 59 + this.Config.GetHashCode();
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
