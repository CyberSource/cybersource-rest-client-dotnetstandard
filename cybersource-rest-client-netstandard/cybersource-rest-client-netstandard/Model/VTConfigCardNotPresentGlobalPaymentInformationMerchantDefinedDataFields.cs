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
    /// VTConfigCardNotPresentGlobalPaymentInformationMerchantDefinedDataFields
    /// </summary>
    [DataContract]
    public partial class VTConfigCardNotPresentGlobalPaymentInformationMerchantDefinedDataFields :  IEquatable<VTConfigCardNotPresentGlobalPaymentInformationMerchantDefinedDataFields>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="VTConfigCardNotPresentGlobalPaymentInformationMerchantDefinedDataFields" /> class.
        /// </summary>
        /// <param name="DisplayMerchantDefinedData1">DisplayMerchantDefinedData1.</param>
        /// <param name="DisplayMerchantDefinedData2">DisplayMerchantDefinedData2.</param>
        /// <param name="DisplayMerchantDefinedData3">DisplayMerchantDefinedData3.</param>
        /// <param name="DisplayMerchantDefinedData4">DisplayMerchantDefinedData4.</param>
        /// <param name="DisplayMerchantDefinedData5">DisplayMerchantDefinedData5.</param>
        /// <param name="MerchantDefinedData1DefaultValue">MerchantDefinedData1DefaultValue.</param>
        /// <param name="MerchantDefinedData1Label">MerchantDefinedData1Label.</param>
        /// <param name="RequireMerchantDefinedData1">RequireMerchantDefinedData1.</param>
        /// <param name="MerchantDefinedData2DefaultValue">MerchantDefinedData2DefaultValue.</param>
        /// <param name="MerchantDefinedData2Label">MerchantDefinedData2Label.</param>
        /// <param name="RequireMerchantDefinedData2">RequireMerchantDefinedData2.</param>
        /// <param name="MerchantDefinedData3DefaultValue">MerchantDefinedData3DefaultValue.</param>
        /// <param name="MerchantDefinedData3Label">MerchantDefinedData3Label.</param>
        /// <param name="RequireMerchantDefinedData3">RequireMerchantDefinedData3.</param>
        /// <param name="MerchantDefinedData4DefaultValue">MerchantDefinedData4DefaultValue.</param>
        /// <param name="MerchantDefinedData4Label">MerchantDefinedData4Label.</param>
        /// <param name="RequireMerchantDefinedData4">RequireMerchantDefinedData4.</param>
        /// <param name="MerchantDefinedData5DefaultValue">MerchantDefinedData5DefaultValue.</param>
        /// <param name="MerchantDefinedData5Label">MerchantDefinedData5Label.</param>
        /// <param name="RequireMerchantDefinedData5">RequireMerchantDefinedData5.</param>
        /// <param name="MerchantDefinedData1DisplayOnReceipt">MerchantDefinedData1DisplayOnReceipt.</param>
        /// <param name="MerchantDefinedData2DisplayOnReceipt">MerchantDefinedData2DisplayOnReceipt.</param>
        /// <param name="MerchantDefinedData3DisplayOnReceipt">MerchantDefinedData3DisplayOnReceipt.</param>
        /// <param name="MerchantDefinedData4DisplayOnReceipt">MerchantDefinedData4DisplayOnReceipt.</param>
        /// <param name="MerchantDefinedData5DisplayOnReceipt">MerchantDefinedData5DisplayOnReceipt.</param>
        public VTConfigCardNotPresentGlobalPaymentInformationMerchantDefinedDataFields(bool? DisplayMerchantDefinedData1 = default(bool?), bool? DisplayMerchantDefinedData2 = default(bool?), bool? DisplayMerchantDefinedData3 = default(bool?), bool? DisplayMerchantDefinedData4 = default(bool?), bool? DisplayMerchantDefinedData5 = default(bool?), string MerchantDefinedData1DefaultValue = default(string), string MerchantDefinedData1Label = default(string), bool? RequireMerchantDefinedData1 = default(bool?), string MerchantDefinedData2DefaultValue = default(string), string MerchantDefinedData2Label = default(string), bool? RequireMerchantDefinedData2 = default(bool?), string MerchantDefinedData3DefaultValue = default(string), string MerchantDefinedData3Label = default(string), bool? RequireMerchantDefinedData3 = default(bool?), string MerchantDefinedData4DefaultValue = default(string), string MerchantDefinedData4Label = default(string), bool? RequireMerchantDefinedData4 = default(bool?), string MerchantDefinedData5DefaultValue = default(string), string MerchantDefinedData5Label = default(string), bool? RequireMerchantDefinedData5 = default(bool?), bool? MerchantDefinedData1DisplayOnReceipt = default(bool?), bool? MerchantDefinedData2DisplayOnReceipt = default(bool?), bool? MerchantDefinedData3DisplayOnReceipt = default(bool?), bool? MerchantDefinedData4DisplayOnReceipt = default(bool?), bool? MerchantDefinedData5DisplayOnReceipt = default(bool?))
        {
            this.DisplayMerchantDefinedData1 = DisplayMerchantDefinedData1;
            this.DisplayMerchantDefinedData2 = DisplayMerchantDefinedData2;
            this.DisplayMerchantDefinedData3 = DisplayMerchantDefinedData3;
            this.DisplayMerchantDefinedData4 = DisplayMerchantDefinedData4;
            this.DisplayMerchantDefinedData5 = DisplayMerchantDefinedData5;
            this.MerchantDefinedData1DefaultValue = MerchantDefinedData1DefaultValue;
            this.MerchantDefinedData1Label = MerchantDefinedData1Label;
            this.RequireMerchantDefinedData1 = RequireMerchantDefinedData1;
            this.MerchantDefinedData2DefaultValue = MerchantDefinedData2DefaultValue;
            this.MerchantDefinedData2Label = MerchantDefinedData2Label;
            this.RequireMerchantDefinedData2 = RequireMerchantDefinedData2;
            this.MerchantDefinedData3DefaultValue = MerchantDefinedData3DefaultValue;
            this.MerchantDefinedData3Label = MerchantDefinedData3Label;
            this.RequireMerchantDefinedData3 = RequireMerchantDefinedData3;
            this.MerchantDefinedData4DefaultValue = MerchantDefinedData4DefaultValue;
            this.MerchantDefinedData4Label = MerchantDefinedData4Label;
            this.RequireMerchantDefinedData4 = RequireMerchantDefinedData4;
            this.MerchantDefinedData5DefaultValue = MerchantDefinedData5DefaultValue;
            this.MerchantDefinedData5Label = MerchantDefinedData5Label;
            this.RequireMerchantDefinedData5 = RequireMerchantDefinedData5;
            this.MerchantDefinedData1DisplayOnReceipt = MerchantDefinedData1DisplayOnReceipt;
            this.MerchantDefinedData2DisplayOnReceipt = MerchantDefinedData2DisplayOnReceipt;
            this.MerchantDefinedData3DisplayOnReceipt = MerchantDefinedData3DisplayOnReceipt;
            this.MerchantDefinedData4DisplayOnReceipt = MerchantDefinedData4DisplayOnReceipt;
            this.MerchantDefinedData5DisplayOnReceipt = MerchantDefinedData5DisplayOnReceipt;
        }
        
        /// <summary>
        /// Gets or Sets DisplayMerchantDefinedData1
        /// </summary>
        [DataMember(Name="displayMerchantDefinedData1", EmitDefaultValue=false)]
        public bool? DisplayMerchantDefinedData1 { get; set; }

        /// <summary>
        /// Gets or Sets DisplayMerchantDefinedData2
        /// </summary>
        [DataMember(Name="displayMerchantDefinedData2", EmitDefaultValue=false)]
        public bool? DisplayMerchantDefinedData2 { get; set; }

        /// <summary>
        /// Gets or Sets DisplayMerchantDefinedData3
        /// </summary>
        [DataMember(Name="displayMerchantDefinedData3", EmitDefaultValue=false)]
        public bool? DisplayMerchantDefinedData3 { get; set; }

        /// <summary>
        /// Gets or Sets DisplayMerchantDefinedData4
        /// </summary>
        [DataMember(Name="displayMerchantDefinedData4", EmitDefaultValue=false)]
        public bool? DisplayMerchantDefinedData4 { get; set; }

        /// <summary>
        /// Gets or Sets DisplayMerchantDefinedData5
        /// </summary>
        [DataMember(Name="displayMerchantDefinedData5", EmitDefaultValue=false)]
        public bool? DisplayMerchantDefinedData5 { get; set; }

        /// <summary>
        /// Gets or Sets MerchantDefinedData1DefaultValue
        /// </summary>
        [DataMember(Name="merchantDefinedData1DefaultValue", EmitDefaultValue=false)]
        public string MerchantDefinedData1DefaultValue { get; set; }

        /// <summary>
        /// Gets or Sets MerchantDefinedData1Label
        /// </summary>
        [DataMember(Name="merchantDefinedData1Label", EmitDefaultValue=false)]
        public string MerchantDefinedData1Label { get; set; }

        /// <summary>
        /// Gets or Sets RequireMerchantDefinedData1
        /// </summary>
        [DataMember(Name="requireMerchantDefinedData1", EmitDefaultValue=false)]
        public bool? RequireMerchantDefinedData1 { get; set; }

        /// <summary>
        /// Gets or Sets MerchantDefinedData2DefaultValue
        /// </summary>
        [DataMember(Name="merchantDefinedData2DefaultValue", EmitDefaultValue=false)]
        public string MerchantDefinedData2DefaultValue { get; set; }

        /// <summary>
        /// Gets or Sets MerchantDefinedData2Label
        /// </summary>
        [DataMember(Name="merchantDefinedData2Label", EmitDefaultValue=false)]
        public string MerchantDefinedData2Label { get; set; }

        /// <summary>
        /// Gets or Sets RequireMerchantDefinedData2
        /// </summary>
        [DataMember(Name="requireMerchantDefinedData2", EmitDefaultValue=false)]
        public bool? RequireMerchantDefinedData2 { get; set; }

        /// <summary>
        /// Gets or Sets MerchantDefinedData3DefaultValue
        /// </summary>
        [DataMember(Name="merchantDefinedData3DefaultValue", EmitDefaultValue=false)]
        public string MerchantDefinedData3DefaultValue { get; set; }

        /// <summary>
        /// Gets or Sets MerchantDefinedData3Label
        /// </summary>
        [DataMember(Name="merchantDefinedData3Label", EmitDefaultValue=false)]
        public string MerchantDefinedData3Label { get; set; }

        /// <summary>
        /// Gets or Sets RequireMerchantDefinedData3
        /// </summary>
        [DataMember(Name="requireMerchantDefinedData3", EmitDefaultValue=false)]
        public bool? RequireMerchantDefinedData3 { get; set; }

        /// <summary>
        /// Gets or Sets MerchantDefinedData4DefaultValue
        /// </summary>
        [DataMember(Name="merchantDefinedData4DefaultValue", EmitDefaultValue=false)]
        public string MerchantDefinedData4DefaultValue { get; set; }

        /// <summary>
        /// Gets or Sets MerchantDefinedData4Label
        /// </summary>
        [DataMember(Name="merchantDefinedData4Label", EmitDefaultValue=false)]
        public string MerchantDefinedData4Label { get; set; }

        /// <summary>
        /// Gets or Sets RequireMerchantDefinedData4
        /// </summary>
        [DataMember(Name="requireMerchantDefinedData4", EmitDefaultValue=false)]
        public bool? RequireMerchantDefinedData4 { get; set; }

        /// <summary>
        /// Gets or Sets MerchantDefinedData5DefaultValue
        /// </summary>
        [DataMember(Name="merchantDefinedData5DefaultValue", EmitDefaultValue=false)]
        public string MerchantDefinedData5DefaultValue { get; set; }

        /// <summary>
        /// Gets or Sets MerchantDefinedData5Label
        /// </summary>
        [DataMember(Name="merchantDefinedData5Label", EmitDefaultValue=false)]
        public string MerchantDefinedData5Label { get; set; }

        /// <summary>
        /// Gets or Sets RequireMerchantDefinedData5
        /// </summary>
        [DataMember(Name="requireMerchantDefinedData5", EmitDefaultValue=false)]
        public bool? RequireMerchantDefinedData5 { get; set; }

        /// <summary>
        /// Gets or Sets MerchantDefinedData1DisplayOnReceipt
        /// </summary>
        [DataMember(Name="merchantDefinedData1DisplayOnReceipt", EmitDefaultValue=false)]
        public bool? MerchantDefinedData1DisplayOnReceipt { get; set; }

        /// <summary>
        /// Gets or Sets MerchantDefinedData2DisplayOnReceipt
        /// </summary>
        [DataMember(Name="merchantDefinedData2DisplayOnReceipt", EmitDefaultValue=false)]
        public bool? MerchantDefinedData2DisplayOnReceipt { get; set; }

        /// <summary>
        /// Gets or Sets MerchantDefinedData3DisplayOnReceipt
        /// </summary>
        [DataMember(Name="merchantDefinedData3DisplayOnReceipt", EmitDefaultValue=false)]
        public bool? MerchantDefinedData3DisplayOnReceipt { get; set; }

        /// <summary>
        /// Gets or Sets MerchantDefinedData4DisplayOnReceipt
        /// </summary>
        [DataMember(Name="merchantDefinedData4DisplayOnReceipt", EmitDefaultValue=false)]
        public bool? MerchantDefinedData4DisplayOnReceipt { get; set; }

        /// <summary>
        /// Gets or Sets MerchantDefinedData5DisplayOnReceipt
        /// </summary>
        [DataMember(Name="merchantDefinedData5DisplayOnReceipt", EmitDefaultValue=false)]
        public bool? MerchantDefinedData5DisplayOnReceipt { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class VTConfigCardNotPresentGlobalPaymentInformationMerchantDefinedDataFields {\n");
            if (DisplayMerchantDefinedData1 != null) sb.Append("  DisplayMerchantDefinedData1: ").Append(DisplayMerchantDefinedData1).Append("\n");
            if (DisplayMerchantDefinedData2 != null) sb.Append("  DisplayMerchantDefinedData2: ").Append(DisplayMerchantDefinedData2).Append("\n");
            if (DisplayMerchantDefinedData3 != null) sb.Append("  DisplayMerchantDefinedData3: ").Append(DisplayMerchantDefinedData3).Append("\n");
            if (DisplayMerchantDefinedData4 != null) sb.Append("  DisplayMerchantDefinedData4: ").Append(DisplayMerchantDefinedData4).Append("\n");
            if (DisplayMerchantDefinedData5 != null) sb.Append("  DisplayMerchantDefinedData5: ").Append(DisplayMerchantDefinedData5).Append("\n");
            if (MerchantDefinedData1DefaultValue != null) sb.Append("  MerchantDefinedData1DefaultValue: ").Append(MerchantDefinedData1DefaultValue).Append("\n");
            if (MerchantDefinedData1Label != null) sb.Append("  MerchantDefinedData1Label: ").Append(MerchantDefinedData1Label).Append("\n");
            if (RequireMerchantDefinedData1 != null) sb.Append("  RequireMerchantDefinedData1: ").Append(RequireMerchantDefinedData1).Append("\n");
            if (MerchantDefinedData2DefaultValue != null) sb.Append("  MerchantDefinedData2DefaultValue: ").Append(MerchantDefinedData2DefaultValue).Append("\n");
            if (MerchantDefinedData2Label != null) sb.Append("  MerchantDefinedData2Label: ").Append(MerchantDefinedData2Label).Append("\n");
            if (RequireMerchantDefinedData2 != null) sb.Append("  RequireMerchantDefinedData2: ").Append(RequireMerchantDefinedData2).Append("\n");
            if (MerchantDefinedData3DefaultValue != null) sb.Append("  MerchantDefinedData3DefaultValue: ").Append(MerchantDefinedData3DefaultValue).Append("\n");
            if (MerchantDefinedData3Label != null) sb.Append("  MerchantDefinedData3Label: ").Append(MerchantDefinedData3Label).Append("\n");
            if (RequireMerchantDefinedData3 != null) sb.Append("  RequireMerchantDefinedData3: ").Append(RequireMerchantDefinedData3).Append("\n");
            if (MerchantDefinedData4DefaultValue != null) sb.Append("  MerchantDefinedData4DefaultValue: ").Append(MerchantDefinedData4DefaultValue).Append("\n");
            if (MerchantDefinedData4Label != null) sb.Append("  MerchantDefinedData4Label: ").Append(MerchantDefinedData4Label).Append("\n");
            if (RequireMerchantDefinedData4 != null) sb.Append("  RequireMerchantDefinedData4: ").Append(RequireMerchantDefinedData4).Append("\n");
            if (MerchantDefinedData5DefaultValue != null) sb.Append("  MerchantDefinedData5DefaultValue: ").Append(MerchantDefinedData5DefaultValue).Append("\n");
            if (MerchantDefinedData5Label != null) sb.Append("  MerchantDefinedData5Label: ").Append(MerchantDefinedData5Label).Append("\n");
            if (RequireMerchantDefinedData5 != null) sb.Append("  RequireMerchantDefinedData5: ").Append(RequireMerchantDefinedData5).Append("\n");
            if (MerchantDefinedData1DisplayOnReceipt != null) sb.Append("  MerchantDefinedData1DisplayOnReceipt: ").Append(MerchantDefinedData1DisplayOnReceipt).Append("\n");
            if (MerchantDefinedData2DisplayOnReceipt != null) sb.Append("  MerchantDefinedData2DisplayOnReceipt: ").Append(MerchantDefinedData2DisplayOnReceipt).Append("\n");
            if (MerchantDefinedData3DisplayOnReceipt != null) sb.Append("  MerchantDefinedData3DisplayOnReceipt: ").Append(MerchantDefinedData3DisplayOnReceipt).Append("\n");
            if (MerchantDefinedData4DisplayOnReceipt != null) sb.Append("  MerchantDefinedData4DisplayOnReceipt: ").Append(MerchantDefinedData4DisplayOnReceipt).Append("\n");
            if (MerchantDefinedData5DisplayOnReceipt != null) sb.Append("  MerchantDefinedData5DisplayOnReceipt: ").Append(MerchantDefinedData5DisplayOnReceipt).Append("\n");
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
            return this.Equals(obj as VTConfigCardNotPresentGlobalPaymentInformationMerchantDefinedDataFields);
        }

        /// <summary>
        /// Returns true if VTConfigCardNotPresentGlobalPaymentInformationMerchantDefinedDataFields instances are equal
        /// </summary>
        /// <param name="other">Instance of VTConfigCardNotPresentGlobalPaymentInformationMerchantDefinedDataFields to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(VTConfigCardNotPresentGlobalPaymentInformationMerchantDefinedDataFields other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.DisplayMerchantDefinedData1 == other.DisplayMerchantDefinedData1 ||
                    this.DisplayMerchantDefinedData1 != null &&
                    this.DisplayMerchantDefinedData1.Equals(other.DisplayMerchantDefinedData1)
                ) && 
                (
                    this.DisplayMerchantDefinedData2 == other.DisplayMerchantDefinedData2 ||
                    this.DisplayMerchantDefinedData2 != null &&
                    this.DisplayMerchantDefinedData2.Equals(other.DisplayMerchantDefinedData2)
                ) && 
                (
                    this.DisplayMerchantDefinedData3 == other.DisplayMerchantDefinedData3 ||
                    this.DisplayMerchantDefinedData3 != null &&
                    this.DisplayMerchantDefinedData3.Equals(other.DisplayMerchantDefinedData3)
                ) && 
                (
                    this.DisplayMerchantDefinedData4 == other.DisplayMerchantDefinedData4 ||
                    this.DisplayMerchantDefinedData4 != null &&
                    this.DisplayMerchantDefinedData4.Equals(other.DisplayMerchantDefinedData4)
                ) && 
                (
                    this.DisplayMerchantDefinedData5 == other.DisplayMerchantDefinedData5 ||
                    this.DisplayMerchantDefinedData5 != null &&
                    this.DisplayMerchantDefinedData5.Equals(other.DisplayMerchantDefinedData5)
                ) && 
                (
                    this.MerchantDefinedData1DefaultValue == other.MerchantDefinedData1DefaultValue ||
                    this.MerchantDefinedData1DefaultValue != null &&
                    this.MerchantDefinedData1DefaultValue.Equals(other.MerchantDefinedData1DefaultValue)
                ) && 
                (
                    this.MerchantDefinedData1Label == other.MerchantDefinedData1Label ||
                    this.MerchantDefinedData1Label != null &&
                    this.MerchantDefinedData1Label.Equals(other.MerchantDefinedData1Label)
                ) && 
                (
                    this.RequireMerchantDefinedData1 == other.RequireMerchantDefinedData1 ||
                    this.RequireMerchantDefinedData1 != null &&
                    this.RequireMerchantDefinedData1.Equals(other.RequireMerchantDefinedData1)
                ) && 
                (
                    this.MerchantDefinedData2DefaultValue == other.MerchantDefinedData2DefaultValue ||
                    this.MerchantDefinedData2DefaultValue != null &&
                    this.MerchantDefinedData2DefaultValue.Equals(other.MerchantDefinedData2DefaultValue)
                ) && 
                (
                    this.MerchantDefinedData2Label == other.MerchantDefinedData2Label ||
                    this.MerchantDefinedData2Label != null &&
                    this.MerchantDefinedData2Label.Equals(other.MerchantDefinedData2Label)
                ) && 
                (
                    this.RequireMerchantDefinedData2 == other.RequireMerchantDefinedData2 ||
                    this.RequireMerchantDefinedData2 != null &&
                    this.RequireMerchantDefinedData2.Equals(other.RequireMerchantDefinedData2)
                ) && 
                (
                    this.MerchantDefinedData3DefaultValue == other.MerchantDefinedData3DefaultValue ||
                    this.MerchantDefinedData3DefaultValue != null &&
                    this.MerchantDefinedData3DefaultValue.Equals(other.MerchantDefinedData3DefaultValue)
                ) && 
                (
                    this.MerchantDefinedData3Label == other.MerchantDefinedData3Label ||
                    this.MerchantDefinedData3Label != null &&
                    this.MerchantDefinedData3Label.Equals(other.MerchantDefinedData3Label)
                ) && 
                (
                    this.RequireMerchantDefinedData3 == other.RequireMerchantDefinedData3 ||
                    this.RequireMerchantDefinedData3 != null &&
                    this.RequireMerchantDefinedData3.Equals(other.RequireMerchantDefinedData3)
                ) && 
                (
                    this.MerchantDefinedData4DefaultValue == other.MerchantDefinedData4DefaultValue ||
                    this.MerchantDefinedData4DefaultValue != null &&
                    this.MerchantDefinedData4DefaultValue.Equals(other.MerchantDefinedData4DefaultValue)
                ) && 
                (
                    this.MerchantDefinedData4Label == other.MerchantDefinedData4Label ||
                    this.MerchantDefinedData4Label != null &&
                    this.MerchantDefinedData4Label.Equals(other.MerchantDefinedData4Label)
                ) && 
                (
                    this.RequireMerchantDefinedData4 == other.RequireMerchantDefinedData4 ||
                    this.RequireMerchantDefinedData4 != null &&
                    this.RequireMerchantDefinedData4.Equals(other.RequireMerchantDefinedData4)
                ) && 
                (
                    this.MerchantDefinedData5DefaultValue == other.MerchantDefinedData5DefaultValue ||
                    this.MerchantDefinedData5DefaultValue != null &&
                    this.MerchantDefinedData5DefaultValue.Equals(other.MerchantDefinedData5DefaultValue)
                ) && 
                (
                    this.MerchantDefinedData5Label == other.MerchantDefinedData5Label ||
                    this.MerchantDefinedData5Label != null &&
                    this.MerchantDefinedData5Label.Equals(other.MerchantDefinedData5Label)
                ) && 
                (
                    this.RequireMerchantDefinedData5 == other.RequireMerchantDefinedData5 ||
                    this.RequireMerchantDefinedData5 != null &&
                    this.RequireMerchantDefinedData5.Equals(other.RequireMerchantDefinedData5)
                ) && 
                (
                    this.MerchantDefinedData1DisplayOnReceipt == other.MerchantDefinedData1DisplayOnReceipt ||
                    this.MerchantDefinedData1DisplayOnReceipt != null &&
                    this.MerchantDefinedData1DisplayOnReceipt.Equals(other.MerchantDefinedData1DisplayOnReceipt)
                ) && 
                (
                    this.MerchantDefinedData2DisplayOnReceipt == other.MerchantDefinedData2DisplayOnReceipt ||
                    this.MerchantDefinedData2DisplayOnReceipt != null &&
                    this.MerchantDefinedData2DisplayOnReceipt.Equals(other.MerchantDefinedData2DisplayOnReceipt)
                ) && 
                (
                    this.MerchantDefinedData3DisplayOnReceipt == other.MerchantDefinedData3DisplayOnReceipt ||
                    this.MerchantDefinedData3DisplayOnReceipt != null &&
                    this.MerchantDefinedData3DisplayOnReceipt.Equals(other.MerchantDefinedData3DisplayOnReceipt)
                ) && 
                (
                    this.MerchantDefinedData4DisplayOnReceipt == other.MerchantDefinedData4DisplayOnReceipt ||
                    this.MerchantDefinedData4DisplayOnReceipt != null &&
                    this.MerchantDefinedData4DisplayOnReceipt.Equals(other.MerchantDefinedData4DisplayOnReceipt)
                ) && 
                (
                    this.MerchantDefinedData5DisplayOnReceipt == other.MerchantDefinedData5DisplayOnReceipt ||
                    this.MerchantDefinedData5DisplayOnReceipt != null &&
                    this.MerchantDefinedData5DisplayOnReceipt.Equals(other.MerchantDefinedData5DisplayOnReceipt)
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
                if (this.DisplayMerchantDefinedData1 != null)
                    hash = hash * 59 + this.DisplayMerchantDefinedData1.GetHashCode();
                if (this.DisplayMerchantDefinedData2 != null)
                    hash = hash * 59 + this.DisplayMerchantDefinedData2.GetHashCode();
                if (this.DisplayMerchantDefinedData3 != null)
                    hash = hash * 59 + this.DisplayMerchantDefinedData3.GetHashCode();
                if (this.DisplayMerchantDefinedData4 != null)
                    hash = hash * 59 + this.DisplayMerchantDefinedData4.GetHashCode();
                if (this.DisplayMerchantDefinedData5 != null)
                    hash = hash * 59 + this.DisplayMerchantDefinedData5.GetHashCode();
                if (this.MerchantDefinedData1DefaultValue != null)
                    hash = hash * 59 + this.MerchantDefinedData1DefaultValue.GetHashCode();
                if (this.MerchantDefinedData1Label != null)
                    hash = hash * 59 + this.MerchantDefinedData1Label.GetHashCode();
                if (this.RequireMerchantDefinedData1 != null)
                    hash = hash * 59 + this.RequireMerchantDefinedData1.GetHashCode();
                if (this.MerchantDefinedData2DefaultValue != null)
                    hash = hash * 59 + this.MerchantDefinedData2DefaultValue.GetHashCode();
                if (this.MerchantDefinedData2Label != null)
                    hash = hash * 59 + this.MerchantDefinedData2Label.GetHashCode();
                if (this.RequireMerchantDefinedData2 != null)
                    hash = hash * 59 + this.RequireMerchantDefinedData2.GetHashCode();
                if (this.MerchantDefinedData3DefaultValue != null)
                    hash = hash * 59 + this.MerchantDefinedData3DefaultValue.GetHashCode();
                if (this.MerchantDefinedData3Label != null)
                    hash = hash * 59 + this.MerchantDefinedData3Label.GetHashCode();
                if (this.RequireMerchantDefinedData3 != null)
                    hash = hash * 59 + this.RequireMerchantDefinedData3.GetHashCode();
                if (this.MerchantDefinedData4DefaultValue != null)
                    hash = hash * 59 + this.MerchantDefinedData4DefaultValue.GetHashCode();
                if (this.MerchantDefinedData4Label != null)
                    hash = hash * 59 + this.MerchantDefinedData4Label.GetHashCode();
                if (this.RequireMerchantDefinedData4 != null)
                    hash = hash * 59 + this.RequireMerchantDefinedData4.GetHashCode();
                if (this.MerchantDefinedData5DefaultValue != null)
                    hash = hash * 59 + this.MerchantDefinedData5DefaultValue.GetHashCode();
                if (this.MerchantDefinedData5Label != null)
                    hash = hash * 59 + this.MerchantDefinedData5Label.GetHashCode();
                if (this.RequireMerchantDefinedData5 != null)
                    hash = hash * 59 + this.RequireMerchantDefinedData5.GetHashCode();
                if (this.MerchantDefinedData1DisplayOnReceipt != null)
                    hash = hash * 59 + this.MerchantDefinedData1DisplayOnReceipt.GetHashCode();
                if (this.MerchantDefinedData2DisplayOnReceipt != null)
                    hash = hash * 59 + this.MerchantDefinedData2DisplayOnReceipt.GetHashCode();
                if (this.MerchantDefinedData3DisplayOnReceipt != null)
                    hash = hash * 59 + this.MerchantDefinedData3DisplayOnReceipt.GetHashCode();
                if (this.MerchantDefinedData4DisplayOnReceipt != null)
                    hash = hash * 59 + this.MerchantDefinedData4DisplayOnReceipt.GetHashCode();
                if (this.MerchantDefinedData5DisplayOnReceipt != null)
                    hash = hash * 59 + this.MerchantDefinedData5DisplayOnReceipt.GetHashCode();
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
