# CyberSource.Model.PtsV2IncrementalAuthorizationPatch201ResponseErrorInformation
## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Reason** | **string** | The reason of the status.  Possible values:   - AVS_FAILED   - CONTACT_PROCESSOR   - EXPIRED_CARD   - PROCESSOR_DECLINED   - INSUFFICIENT_FUND   - STOLEN_LOST_CARD   - ISSUER_UNAVAILABLE   - UNAUTHORIZED_CARD   - CVN_NOT_MATCH   - EXCEEDS_CREDIT_LIMIT   - INVALID_CVN   - BLOCKED_BY_CARDHOLDER   - BLACKLISTED_CUSTOMER   - SUSPENDED_ACCOUNT   - PAYMENT_REFUSED   - CV_FAILED   - INVALID_ACCOUNT   - GENERAL_DECLINE   - INVALID_MERCHANT_CONFIGURATION   - DECISION_PROFILE_REJECT   - SCORE_EXCEEDS_THRESHOLD   - CONSUMER_AUTHENTICATION_REQUIRED   - ALLOWABLE_PIN_RETRIES_EXCEEDED   - PROCESSOR_ERROR  | [optional] 
**Message** | **string** | The detail message related to the status and reason listed above. | [optional] 
**Details** | [**List&lt;PtsV2PaymentsPost201ResponseErrorInformationDetails&gt;**](PtsV2PaymentsPost201ResponseErrorInformationDetails.md) |  | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

