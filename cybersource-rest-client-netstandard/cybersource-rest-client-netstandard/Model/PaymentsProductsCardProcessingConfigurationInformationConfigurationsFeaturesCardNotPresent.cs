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
    /// PaymentsProductsCardProcessingConfigurationInformationConfigurationsFeaturesCardNotPresent
    /// </summary>
    [DataContract]
    public partial class PaymentsProductsCardProcessingConfigurationInformationConfigurationsFeaturesCardNotPresent :  IEquatable<PaymentsProductsCardProcessingConfigurationInformationConfigurationsFeaturesCardNotPresent>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PaymentsProductsCardProcessingConfigurationInformationConfigurationsFeaturesCardNotPresent" /> class.
        /// </summary>
        /// <param name="Processors">e.g. * amexdirect * barclays2 * CUP * EFTPOS * fdiglobal * gpx * smartfdc * tsys * vero * VPC  For VPC, CUP and EFTPOS processors, replace the processor name from VPC or CUP or EFTPOS to the actual processor name in the sample request. e.g. replace VPC with &amp;lt;your vpc processor&amp;gt; .</param>
        /// <param name="IgnoreAddressVerificationSystem">Flag for a sale request that indicates whether to allow the capture service to run even when the authorization receives an AVS decline. Applicable for VPC, FDI Global (fdiglobal), GPX (gpx) and GPN (gpn) processors..</param>
        /// <param name="VisaStraightThroughProcessingOnly">Indicates if a merchant is enabled for Straight Through Processing - B2B invoice payments. Applicable for FDI Global (fdiglobal), TSYS (tsys), VPC and GPX (gpx) processors..</param>
        /// <param name="AmexTransactionAdviceAddendum1">Advice addendum field. It is used to display descriptive information about a transaction on customer&#39;s American Express card statement. Applicable for TSYS (tsys), FDI Global (fdiglobal) and American Express Direct (amexdirect) processors..</param>
        /// <param name="Installment">Installment.</param>
        public PaymentsProductsCardProcessingConfigurationInformationConfigurationsFeaturesCardNotPresent(Dictionary<string, PaymentsProductsCardProcessingConfigurationInformationConfigurationsFeaturesCardNotPresentProcessors> Processors = default(Dictionary<string, PaymentsProductsCardProcessingConfigurationInformationConfigurationsFeaturesCardNotPresentProcessors>), bool? IgnoreAddressVerificationSystem = default(bool?), bool? VisaStraightThroughProcessingOnly = default(bool?), string AmexTransactionAdviceAddendum1 = default(string), PaymentsProductsCardProcessingConfigurationInformationConfigurationsFeaturesCardNotPresentInstallment Installment = default(PaymentsProductsCardProcessingConfigurationInformationConfigurationsFeaturesCardNotPresentInstallment))
        {
            this.Processors = Processors;
            this.IgnoreAddressVerificationSystem = IgnoreAddressVerificationSystem;
            this.VisaStraightThroughProcessingOnly = VisaStraightThroughProcessingOnly;
            this.AmexTransactionAdviceAddendum1 = AmexTransactionAdviceAddendum1;
            this.Installment = Installment;
        }
        
        /// <summary>
        /// e.g. * amexdirect * barclays2 * CUP * EFTPOS * fdiglobal * gpx * smartfdc * tsys * vero * VPC  For VPC, CUP and EFTPOS processors, replace the processor name from VPC or CUP or EFTPOS to the actual processor name in the sample request. e.g. replace VPC with &amp;lt;your vpc processor&amp;gt; 
        /// </summary>
        /// <value>e.g. * amexdirect * barclays2 * CUP * EFTPOS * fdiglobal * gpx * smartfdc * tsys * vero * VPC  For VPC, CUP and EFTPOS processors, replace the processor name from VPC or CUP or EFTPOS to the actual processor name in the sample request. e.g. replace VPC with &amp;lt;your vpc processor&amp;gt; </value>
        [DataMember(Name="processors", EmitDefaultValue=false)]
        public Dictionary<string, PaymentsProductsCardProcessingConfigurationInformationConfigurationsFeaturesCardNotPresentProcessors> Processors { get; set; }

        /// <summary>
        /// Flag for a sale request that indicates whether to allow the capture service to run even when the authorization receives an AVS decline. Applicable for VPC, FDI Global (fdiglobal), GPX (gpx) and GPN (gpn) processors.
        /// </summary>
        /// <value>Flag for a sale request that indicates whether to allow the capture service to run even when the authorization receives an AVS decline. Applicable for VPC, FDI Global (fdiglobal), GPX (gpx) and GPN (gpn) processors.</value>
        [DataMember(Name="ignoreAddressVerificationSystem", EmitDefaultValue=false)]
        public bool? IgnoreAddressVerificationSystem { get; set; }

        /// <summary>
        /// Indicates if a merchant is enabled for Straight Through Processing - B2B invoice payments. Applicable for FDI Global (fdiglobal), TSYS (tsys), VPC and GPX (gpx) processors.
        /// </summary>
        /// <value>Indicates if a merchant is enabled for Straight Through Processing - B2B invoice payments. Applicable for FDI Global (fdiglobal), TSYS (tsys), VPC and GPX (gpx) processors.</value>
        [DataMember(Name="visaStraightThroughProcessingOnly", EmitDefaultValue=false)]
        public bool? VisaStraightThroughProcessingOnly { get; set; }

        /// <summary>
        /// Advice addendum field. It is used to display descriptive information about a transaction on customer&#39;s American Express card statement. Applicable for TSYS (tsys), FDI Global (fdiglobal) and American Express Direct (amexdirect) processors.
        /// </summary>
        /// <value>Advice addendum field. It is used to display descriptive information about a transaction on customer&#39;s American Express card statement. Applicable for TSYS (tsys), FDI Global (fdiglobal) and American Express Direct (amexdirect) processors.</value>
        [DataMember(Name="amexTransactionAdviceAddendum1", EmitDefaultValue=false)]
        public string AmexTransactionAdviceAddendum1 { get; set; }

        /// <summary>
        /// Gets or Sets Installment
        /// </summary>
        [DataMember(Name="installment", EmitDefaultValue=false)]
        public PaymentsProductsCardProcessingConfigurationInformationConfigurationsFeaturesCardNotPresentInstallment Installment { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class PaymentsProductsCardProcessingConfigurationInformationConfigurationsFeaturesCardNotPresent {\n");
            sb.Append("  Processors: ").Append(Processors).Append("\n");
            sb.Append("  IgnoreAddressVerificationSystem: ").Append(IgnoreAddressVerificationSystem).Append("\n");
            sb.Append("  VisaStraightThroughProcessingOnly: ").Append(VisaStraightThroughProcessingOnly).Append("\n");
            sb.Append("  AmexTransactionAdviceAddendum1: ").Append(AmexTransactionAdviceAddendum1).Append("\n");
            sb.Append("  Installment: ").Append(Installment).Append("\n");
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
            return this.Equals(obj as PaymentsProductsCardProcessingConfigurationInformationConfigurationsFeaturesCardNotPresent);
        }

        /// <summary>
        /// Returns true if PaymentsProductsCardProcessingConfigurationInformationConfigurationsFeaturesCardNotPresent instances are equal
        /// </summary>
        /// <param name="other">Instance of PaymentsProductsCardProcessingConfigurationInformationConfigurationsFeaturesCardNotPresent to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(PaymentsProductsCardProcessingConfigurationInformationConfigurationsFeaturesCardNotPresent other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Processors == other.Processors ||
                    this.Processors != null &&
                    this.Processors.SequenceEqual(other.Processors)
                ) && 
                (
                    this.IgnoreAddressVerificationSystem == other.IgnoreAddressVerificationSystem ||
                    this.IgnoreAddressVerificationSystem != null &&
                    this.IgnoreAddressVerificationSystem.Equals(other.IgnoreAddressVerificationSystem)
                ) && 
                (
                    this.VisaStraightThroughProcessingOnly == other.VisaStraightThroughProcessingOnly ||
                    this.VisaStraightThroughProcessingOnly != null &&
                    this.VisaStraightThroughProcessingOnly.Equals(other.VisaStraightThroughProcessingOnly)
                ) && 
                (
                    this.AmexTransactionAdviceAddendum1 == other.AmexTransactionAdviceAddendum1 ||
                    this.AmexTransactionAdviceAddendum1 != null &&
                    this.AmexTransactionAdviceAddendum1.Equals(other.AmexTransactionAdviceAddendum1)
                ) && 
                (
                    this.Installment == other.Installment ||
                    this.Installment != null &&
                    this.Installment.Equals(other.Installment)
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
                if (this.Processors != null)
                    hash = hash * 59 + this.Processors.GetHashCode();
                if (this.IgnoreAddressVerificationSystem != null)
                    hash = hash * 59 + this.IgnoreAddressVerificationSystem.GetHashCode();
                if (this.VisaStraightThroughProcessingOnly != null)
                    hash = hash * 59 + this.VisaStraightThroughProcessingOnly.GetHashCode();
                if (this.AmexTransactionAdviceAddendum1 != null)
                    hash = hash * 59 + this.AmexTransactionAdviceAddendum1.GetHashCode();
                if (this.Installment != null)
                    hash = hash * 59 + this.Installment.GetHashCode();
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