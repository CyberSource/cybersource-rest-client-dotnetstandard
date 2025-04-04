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
    /// PtsV2PaymentsPost201Response2ProcessorInformation
    /// </summary>
    [DataContract]
    public partial class PtsV2PaymentsPost201Response2ProcessorInformation :  IEquatable<PtsV2PaymentsPost201Response2ProcessorInformation>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PtsV2PaymentsPost201Response2ProcessorInformation" /> class.
        /// </summary>
        /// <param name="TransactionId">Network transaction identifier (TID). You can use this value to identify a specific transaction when you are discussing the transaction with your processor. Not all processors provide this value.  Returned by the authorization service.  #### PIN debit Transaction identifier generated by the processor.  Returned by PIN debit credit.  #### GPX Processor transaction ID.  #### Cielo For Cielo, this value is the non-sequential unit (NSU) and is supported for all transactions. The value is generated by Cielo or the issuing bank.  #### Comercio Latino For Comercio Latino, this value is the proof of sale or non-sequential unit (NSU) number generated by the acquirers Cielo and Rede, or the issuing bank.  #### CyberSource through VisaNet and GPN For details about this value for CyberSource through VisaNet and GPN, see \&quot;processorInformation.networkTransactionId\&quot; in [REST API Fields](https://developer.cybersource.com/content/dam/docs/cybs/en-us/apifields/reference/all/rest/api-fields.pdf)  #### Moneris This value identifies the transaction on a host system. It contains the following information: - Terminal used to process the transaction - Shift during which the transaction took place - Batch number - Transaction number within the batch You must store this value. If you give the customer a receipt, display this value on the receipt.  **Example** For the value 66012345001069003: - Terminal ID &#x3D; 66012345 - Shift number &#x3D; 001 - Batch number &#x3D; 069 - Transaction number &#x3D; 003 .</param>
        /// <param name="PaymentUrl">Direct the customer to this URL to complete the payment..</param>
        /// <param name="ResponseDetails">This field might contain information about a decline. This field is supported only for **CyberSource through VisaNet**. .</param>
        /// <param name="Token">Payment gateway/processor assigned session token. .</param>
        /// <param name="ResponseCode">Transaction status from the processor. .</param>
        public PtsV2PaymentsPost201Response2ProcessorInformation(string TransactionId = default(string), string PaymentUrl = default(string), string ResponseDetails = default(string), string Token = default(string), string ResponseCode = default(string))
        {
            this.TransactionId = TransactionId;
            this.PaymentUrl = PaymentUrl;
            this.ResponseDetails = ResponseDetails;
            this.Token = Token;
            this.ResponseCode = ResponseCode;
        }
        
        /// <summary>
        /// Network transaction identifier (TID). You can use this value to identify a specific transaction when you are discussing the transaction with your processor. Not all processors provide this value.  Returned by the authorization service.  #### PIN debit Transaction identifier generated by the processor.  Returned by PIN debit credit.  #### GPX Processor transaction ID.  #### Cielo For Cielo, this value is the non-sequential unit (NSU) and is supported for all transactions. The value is generated by Cielo or the issuing bank.  #### Comercio Latino For Comercio Latino, this value is the proof of sale or non-sequential unit (NSU) number generated by the acquirers Cielo and Rede, or the issuing bank.  #### CyberSource through VisaNet and GPN For details about this value for CyberSource through VisaNet and GPN, see \&quot;processorInformation.networkTransactionId\&quot; in [REST API Fields](https://developer.cybersource.com/content/dam/docs/cybs/en-us/apifields/reference/all/rest/api-fields.pdf)  #### Moneris This value identifies the transaction on a host system. It contains the following information: - Terminal used to process the transaction - Shift during which the transaction took place - Batch number - Transaction number within the batch You must store this value. If you give the customer a receipt, display this value on the receipt.  **Example** For the value 66012345001069003: - Terminal ID &#x3D; 66012345 - Shift number &#x3D; 001 - Batch number &#x3D; 069 - Transaction number &#x3D; 003 
        /// </summary>
        /// <value>Network transaction identifier (TID). You can use this value to identify a specific transaction when you are discussing the transaction with your processor. Not all processors provide this value.  Returned by the authorization service.  #### PIN debit Transaction identifier generated by the processor.  Returned by PIN debit credit.  #### GPX Processor transaction ID.  #### Cielo For Cielo, this value is the non-sequential unit (NSU) and is supported for all transactions. The value is generated by Cielo or the issuing bank.  #### Comercio Latino For Comercio Latino, this value is the proof of sale or non-sequential unit (NSU) number generated by the acquirers Cielo and Rede, or the issuing bank.  #### CyberSource through VisaNet and GPN For details about this value for CyberSource through VisaNet and GPN, see \&quot;processorInformation.networkTransactionId\&quot; in [REST API Fields](https://developer.cybersource.com/content/dam/docs/cybs/en-us/apifields/reference/all/rest/api-fields.pdf)  #### Moneris This value identifies the transaction on a host system. It contains the following information: - Terminal used to process the transaction - Shift during which the transaction took place - Batch number - Transaction number within the batch You must store this value. If you give the customer a receipt, display this value on the receipt.  **Example** For the value 66012345001069003: - Terminal ID &#x3D; 66012345 - Shift number &#x3D; 001 - Batch number &#x3D; 069 - Transaction number &#x3D; 003 </value>
        [DataMember(Name="transactionId", EmitDefaultValue=false)]
        public string TransactionId { get; set; }

        /// <summary>
        /// Direct the customer to this URL to complete the payment.
        /// </summary>
        /// <value>Direct the customer to this URL to complete the payment.</value>
        [DataMember(Name="paymentUrl", EmitDefaultValue=false)]
        public string PaymentUrl { get; set; }

        /// <summary>
        /// This field might contain information about a decline. This field is supported only for **CyberSource through VisaNet**. 
        /// </summary>
        /// <value>This field might contain information about a decline. This field is supported only for **CyberSource through VisaNet**. </value>
        [DataMember(Name="responseDetails", EmitDefaultValue=false)]
        public string ResponseDetails { get; set; }

        /// <summary>
        /// Payment gateway/processor assigned session token. 
        /// </summary>
        /// <value>Payment gateway/processor assigned session token. </value>
        [DataMember(Name="token", EmitDefaultValue=false)]
        public string Token { get; set; }

        /// <summary>
        /// Transaction status from the processor. 
        /// </summary>
        /// <value>Transaction status from the processor. </value>
        [DataMember(Name="responseCode", EmitDefaultValue=false)]
        public string ResponseCode { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class PtsV2PaymentsPost201Response2ProcessorInformation {\n");
            if (TransactionId != null) sb.Append("  TransactionId: ").Append(TransactionId).Append("\n");
            if (PaymentUrl != null) sb.Append("  PaymentUrl: ").Append(PaymentUrl).Append("\n");
            if (ResponseDetails != null) sb.Append("  ResponseDetails: ").Append(ResponseDetails).Append("\n");
            if (Token != null) sb.Append("  Token: ").Append(Token).Append("\n");
            if (ResponseCode != null) sb.Append("  ResponseCode: ").Append(ResponseCode).Append("\n");
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
            return this.Equals(obj as PtsV2PaymentsPost201Response2ProcessorInformation);
        }

        /// <summary>
        /// Returns true if PtsV2PaymentsPost201Response2ProcessorInformation instances are equal
        /// </summary>
        /// <param name="other">Instance of PtsV2PaymentsPost201Response2ProcessorInformation to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(PtsV2PaymentsPost201Response2ProcessorInformation other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.TransactionId == other.TransactionId ||
                    this.TransactionId != null &&
                    this.TransactionId.Equals(other.TransactionId)
                ) && 
                (
                    this.PaymentUrl == other.PaymentUrl ||
                    this.PaymentUrl != null &&
                    this.PaymentUrl.Equals(other.PaymentUrl)
                ) && 
                (
                    this.ResponseDetails == other.ResponseDetails ||
                    this.ResponseDetails != null &&
                    this.ResponseDetails.Equals(other.ResponseDetails)
                ) && 
                (
                    this.Token == other.Token ||
                    this.Token != null &&
                    this.Token.Equals(other.Token)
                ) && 
                (
                    this.ResponseCode == other.ResponseCode ||
                    this.ResponseCode != null &&
                    this.ResponseCode.Equals(other.ResponseCode)
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
                if (this.TransactionId != null)
                    hash = hash * 59 + this.TransactionId.GetHashCode();
                if (this.PaymentUrl != null)
                    hash = hash * 59 + this.PaymentUrl.GetHashCode();
                if (this.ResponseDetails != null)
                    hash = hash * 59 + this.ResponseDetails.GetHashCode();
                if (this.Token != null)
                    hash = hash * 59 + this.Token.GetHashCode();
                if (this.ResponseCode != null)
                    hash = hash * 59 + this.ResponseCode.GetHashCode();
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
