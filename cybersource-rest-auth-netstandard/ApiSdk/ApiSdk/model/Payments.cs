namespace ApiSdk.model
{
    public class Payments
    {
        public ClientReferenceInformation clientReferenceInformation { get; set; }

        public ProcessingInformation processingInformation { get; set; }

        public AggregatorInformation aggregatorInformation { get; set; }

        public OrderInformation orderInformation { get; set; }

        public PaymentInformation paymentInformation { get; set; }
    }
}