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
    /// The masked number (PAN), expirationMonth, expirationYear and type of the card used during transaction. 
    /// </summary>
    [DataContract]
    public partial class GetSubscriptionResponse1PaymentInstrumentCard :  IEquatable<GetSubscriptionResponse1PaymentInstrumentCard>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="GetSubscriptionResponse1PaymentInstrumentCard" /> class.
        /// </summary>
        /// <param name="Number">The masked customer&#39;s payment card number, also known as the Primary Account Number (PAN). .</param>
        /// <param name="ExpirationMonth">Two-digit month in which the payment card expires.  Format: &#x60;MM&#x60;.  Possible Values: &#x60;01&#x60; through &#x60;12&#x60;. .</param>
        /// <param name="ExpirationYear">Four-digit year in which the credit card expires.  Format: &#x60;YYYY&#x60;. .</param>
        /// <param name="Type">Value that indicates the card type. Possible Values v2 : v1:   * 001 : visa   * 002 : mastercard - Eurocard—European regional brand of Mastercard   * 003 : american express   * 004 : discover   * 005 : diners club   * 006 : carte blanche   * 007 : jcb   * 008 : optima   * 011 : twinpay credit   * 012 : twinpay debit   * 013 : walmart   * 014 : enRoute   * 015 : lowes consumer   * 016 : home depot consumer   * 017 : mbna   * 018 : dicks sportswear   * 019 : casual corner   * 020 : sears   * 021 : jal   * 023 : disney   * 024 : maestro uk domestic   * 025 : sams club consumer   * 026 : sams club business   * 028 : bill me later   * 029 : bebe   * 030 : restoration hardware   * 031 : delta online — use this value only for Ingenico ePayments. For other processors, use 001 for all Visa card types.   * 032 : solo   * 033 : visa electron   * 034 : dankort   * 035 : laser   * 036 : carte bleue — formerly Cartes Bancaires   * 037 : carta si   * 038 : pinless debit   * 039 : encoded account   * 040 : uatp   * 041 : household   * 042 : maestro international   * 043 : ge money uk   * 044 : korean cards   * 045 : style   * 046 : jcrew   * 047 : payease china processing ewallet   * 048 : payease china processing bank transfer   * 049 : meijer private label   * 050 : hipercard — supported only by the Comercio Latino processor.   * 051 : aura — supported only by the Comercio Latino processor.   * 052 : redecard   * 054 : elo — supported only by the Comercio Latino processor.   * 055 : capital one private label   * 056 : synchrony private label   * 057 : costco private label   * 060 : mada   * 062 : china union pay   * 063 : falabella private label .</param>
        public GetSubscriptionResponse1PaymentInstrumentCard(string Number = default(string), string ExpirationMonth = default(string), string ExpirationYear = default(string), string Type = default(string))
        {
            this.Number = Number;
            this.ExpirationMonth = ExpirationMonth;
            this.ExpirationYear = ExpirationYear;
            this.Type = Type;
        }
        
        /// <summary>
        /// The masked customer&#39;s payment card number, also known as the Primary Account Number (PAN). 
        /// </summary>
        /// <value>The masked customer&#39;s payment card number, also known as the Primary Account Number (PAN). </value>
        [DataMember(Name="number", EmitDefaultValue=false)]
        public string Number { get; set; }

        /// <summary>
        /// Two-digit month in which the payment card expires.  Format: &#x60;MM&#x60;.  Possible Values: &#x60;01&#x60; through &#x60;12&#x60;. 
        /// </summary>
        /// <value>Two-digit month in which the payment card expires.  Format: &#x60;MM&#x60;.  Possible Values: &#x60;01&#x60; through &#x60;12&#x60;. </value>
        [DataMember(Name="expirationMonth", EmitDefaultValue=false)]
        public string ExpirationMonth { get; set; }

        /// <summary>
        /// Four-digit year in which the credit card expires.  Format: &#x60;YYYY&#x60;. 
        /// </summary>
        /// <value>Four-digit year in which the credit card expires.  Format: &#x60;YYYY&#x60;. </value>
        [DataMember(Name="expirationYear", EmitDefaultValue=false)]
        public string ExpirationYear { get; set; }

        /// <summary>
        /// Value that indicates the card type. Possible Values v2 : v1:   * 001 : visa   * 002 : mastercard - Eurocard—European regional brand of Mastercard   * 003 : american express   * 004 : discover   * 005 : diners club   * 006 : carte blanche   * 007 : jcb   * 008 : optima   * 011 : twinpay credit   * 012 : twinpay debit   * 013 : walmart   * 014 : enRoute   * 015 : lowes consumer   * 016 : home depot consumer   * 017 : mbna   * 018 : dicks sportswear   * 019 : casual corner   * 020 : sears   * 021 : jal   * 023 : disney   * 024 : maestro uk domestic   * 025 : sams club consumer   * 026 : sams club business   * 028 : bill me later   * 029 : bebe   * 030 : restoration hardware   * 031 : delta online — use this value only for Ingenico ePayments. For other processors, use 001 for all Visa card types.   * 032 : solo   * 033 : visa electron   * 034 : dankort   * 035 : laser   * 036 : carte bleue — formerly Cartes Bancaires   * 037 : carta si   * 038 : pinless debit   * 039 : encoded account   * 040 : uatp   * 041 : household   * 042 : maestro international   * 043 : ge money uk   * 044 : korean cards   * 045 : style   * 046 : jcrew   * 047 : payease china processing ewallet   * 048 : payease china processing bank transfer   * 049 : meijer private label   * 050 : hipercard — supported only by the Comercio Latino processor.   * 051 : aura — supported only by the Comercio Latino processor.   * 052 : redecard   * 054 : elo — supported only by the Comercio Latino processor.   * 055 : capital one private label   * 056 : synchrony private label   * 057 : costco private label   * 060 : mada   * 062 : china union pay   * 063 : falabella private label 
        /// </summary>
        /// <value>Value that indicates the card type. Possible Values v2 : v1:   * 001 : visa   * 002 : mastercard - Eurocard—European regional brand of Mastercard   * 003 : american express   * 004 : discover   * 005 : diners club   * 006 : carte blanche   * 007 : jcb   * 008 : optima   * 011 : twinpay credit   * 012 : twinpay debit   * 013 : walmart   * 014 : enRoute   * 015 : lowes consumer   * 016 : home depot consumer   * 017 : mbna   * 018 : dicks sportswear   * 019 : casual corner   * 020 : sears   * 021 : jal   * 023 : disney   * 024 : maestro uk domestic   * 025 : sams club consumer   * 026 : sams club business   * 028 : bill me later   * 029 : bebe   * 030 : restoration hardware   * 031 : delta online — use this value only for Ingenico ePayments. For other processors, use 001 for all Visa card types.   * 032 : solo   * 033 : visa electron   * 034 : dankort   * 035 : laser   * 036 : carte bleue — formerly Cartes Bancaires   * 037 : carta si   * 038 : pinless debit   * 039 : encoded account   * 040 : uatp   * 041 : household   * 042 : maestro international   * 043 : ge money uk   * 044 : korean cards   * 045 : style   * 046 : jcrew   * 047 : payease china processing ewallet   * 048 : payease china processing bank transfer   * 049 : meijer private label   * 050 : hipercard — supported only by the Comercio Latino processor.   * 051 : aura — supported only by the Comercio Latino processor.   * 052 : redecard   * 054 : elo — supported only by the Comercio Latino processor.   * 055 : capital one private label   * 056 : synchrony private label   * 057 : costco private label   * 060 : mada   * 062 : china union pay   * 063 : falabella private label </value>
        [DataMember(Name="type", EmitDefaultValue=false)]
        public string Type { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class GetSubscriptionResponse1PaymentInstrumentCard {\n");
            if (Number != null) sb.Append("  Number: ").Append(Number).Append("\n");
            if (ExpirationMonth != null) sb.Append("  ExpirationMonth: ").Append(ExpirationMonth).Append("\n");
            if (ExpirationYear != null) sb.Append("  ExpirationYear: ").Append(ExpirationYear).Append("\n");
            if (Type != null) sb.Append("  Type: ").Append(Type).Append("\n");
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
            return this.Equals(obj as GetSubscriptionResponse1PaymentInstrumentCard);
        }

        /// <summary>
        /// Returns true if GetSubscriptionResponse1PaymentInstrumentCard instances are equal
        /// </summary>
        /// <param name="other">Instance of GetSubscriptionResponse1PaymentInstrumentCard to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(GetSubscriptionResponse1PaymentInstrumentCard other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Number == other.Number ||
                    this.Number != null &&
                    this.Number.Equals(other.Number)
                ) && 
                (
                    this.ExpirationMonth == other.ExpirationMonth ||
                    this.ExpirationMonth != null &&
                    this.ExpirationMonth.Equals(other.ExpirationMonth)
                ) && 
                (
                    this.ExpirationYear == other.ExpirationYear ||
                    this.ExpirationYear != null &&
                    this.ExpirationYear.Equals(other.ExpirationYear)
                ) && 
                (
                    this.Type == other.Type ||
                    this.Type != null &&
                    this.Type.Equals(other.Type)
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
                if (this.Number != null)
                    hash = hash * 59 + this.Number.GetHashCode();
                if (this.ExpirationMonth != null)
                    hash = hash * 59 + this.ExpirationMonth.GetHashCode();
                if (this.ExpirationYear != null)
                    hash = hash * 59 + this.ExpirationYear.GetHashCode();
                if (this.Type != null)
                    hash = hash * 59 + this.Type.GetHashCode();
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
