@echo off

rd /s /q ..\Api
rd /s /q ..\Client
rd /s /q ..\Model
rd /s /q ..\docs
rd /s /q ..\..\cybersource-rest-client-netstandard.Test\Api
rd /s /q ..\..\cybersource-rest-client-netstandard.Test\Model

java -jar swagger-codegen-cli-2.2.3.jar generate -t cybersource-csharp-template -i cybersource-rest-spec.json -l csharp -o ..\..\..\ -c cybersource-csharp-config.json

powershell -Command "Get-ChildItem '..\..\..\src\CyberSource\Api\*.cs' -Recurse | ForEach-Object { (Get-Content $_).Replace('Method.POST','Method.Post').Replace('Method.GET','Method.Get').Replace('Method.PATCH','Method.Patch').Replace('Method.DELETE','Method.Delete').Replace('Method.PUT','Method.Put') | Set-Content $_ }"

powershell -Command "(Get-Content ..\..\..\src\CyberSource\Api\SecureFileShareApi.cs) | ForEach-Object { $_ -replace 'null\); \/\/ Return statement', 'localVarResponse.Content); // Return statement' } | Set-Content ..\..\..\src\CyberSource\Api\SecureFileShareApi.cs"

powershell -Command "(Get-Content ..\..\..\src\CyberSource\Api\ReportDownloadsApi.cs) | ForEach-Object { $_ -replace 'null\); \/\/ Return statement', 'localVarResponse.Content); // Return statement' } | Set-Content ..\..\..\src\CyberSource\Api\ReportDownloadsApi.cs"

powershell -Command "(Get-Content ..\..\..\src\CyberSource\Api\TransactionBatchesApi.cs) | ForEach-Object { $_ -replace 'null\); \/\/ Return statement', 'localVarResponse.Content); // Return statement' } | Set-Content ..\..\..\src\CyberSource\Api\TransactionBatchesApi.cs"

powershell -Command " Set-Content ..\..\..\src\CyberSource\Api\SecureFileShareApi.cs ((get-content ..\..\..\src\CyberSource\Api\SecureFileShareApi.cs -raw) -replace '\*_\/_\*;charset=utf-8', '*/*;charset=utf-8') "

REM Loading content of excludeList.txt into a space-separated list in a variable
SETLOCAL EnableDelayedExpansion
SET excludeList=
FOR /f "tokens=* delims=\n" %%a in ('type "excludelist.txt"') do (
    SET excludeList=!excludeList! %%a
)

REM Need to shorten filenames

powershell Rename-Item ..\..\..\src\CyberSource\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptionsInitiatorMerchantInitiatedTransaction.cs Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedMerchantInitiatedTransaction.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptionsInitiatorMerchantInitiatedTransactionTests.cs Tmsv2customersEmbeddedMerchantInitiatedTransactionTests.cs

powershell Rename-Item ..\..\..\docs\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptionsInitiatorMerchantInitiatedTransaction.md Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedMerchantInitiatedTransaction.md

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptionsInitiatorTests.cs Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedAuthorizationOptionsInitiatorTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptionsTests.cs Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedAuthorizationOptionsTests.cs

powershell Rename-Item ..\..\..\src\CyberSource\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptions.cs Tmsv2customersEmbeddedAuthorizationOptions.cs

powershell Rename-Item ..\..\..\docs\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptions.md Tmsv2customersEmbeddedAuthorizationOptions.md

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\RiskV1AddressVerificationsPost201ResponseAddressVerificationInformationStandardAddressAddress1Tests.cs RiskV1AddressVerificationsPost201ResponseStandardAddressAddress1Tests.cs

powershell Rename-Item ..\..\..\src\CyberSource\Model\RiskV1AddressVerificationsPost201ResponseAddressVerificationInformationStandardAddressAddress1.cs RiskV1AddressVerificationsPost201ResponseAddress1.cs

powershell Rename-Item ..\..\..\docs\RiskV1AddressVerificationsPost201ResponseAddressVerificationInformationStandardAddressAddress1.md RiskV1AddressVerificationsPost201ResponseAddress1.md

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierLinksPaymentInstrumentsTests.cs Tmsv2customersEmbeddedPaymentInstrumentsTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationTests.cs Tmsv2customersEmbeddedDefaultProcessingInformationTests.cs

powershell Rename-Item ..\..\..\src\CyberSource\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierLinksPaymentInstruments.cs Tmsv2customersEmbeddedLinksPaymentInstruments.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\Ptsv2paymentsProcessingInformationAuthorizationOptionsInitiatorMerchantInitiatedTransactionTests.cs Ptsv2paymentsMerchantInitiatedTransactionTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\PtsV2PaymentsPost201ResponseConsumerAuthenticationInformationStrongAuthenticationIssuerInformationTests.cs PtsV2PaymentsPost201ResponseStrongAuthenticationIssuerInformationTests.cs

@REM powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\RiskV1ExportComplianceInquiriesPost201ResponseExportComplianceInformationWatchListMatchesTests.cs RiskV1ExportComplianceWatchListMatchesTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierTokenizedCardCardTests.cs Tmsv2customersTokenizedCardCardTests.cs

powershell Rename-Item ..\..\..\src\CyberSource\Model\PtsV2PaymentsPost201ResponseConsumerAuthenticationInformationStrongAuthenticationIssuerInformation.cs PtsV2PaymentsPost201ResponseStrongAuthenticationIssuerInformation.cs

powershell Rename-Item ..\..\..\docs\PtsV2PaymentsPost201ResponseConsumerAuthenticationInformationStrongAuthenticationIssuerInformation.md PtsV2PaymentsPost201ResponseStrongAuthenticationIssuerInformation.md

powershell Rename-Item ..\..\..\src\CyberSource\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptionsInitiator.cs Tmsv2customersEmbeddedAuthorizationOptionsInitiator.cs

powershell Rename-Item ..\..\..\docs\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptionsInitiator.md Tmsv2customersEmbeddedAuthorizationOptionsInitiator.md

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\PaymentProductsCardProcessingConfigurationInformationConfigurationsCommonMerchantDescriptorInformationTests.cs PaymentProductsCardProcessingMerchantDescriptorInformationTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\PaymentProductsCardProcessingConfigurationInformationConfigurationsFeaturesCardNotPresentPayoutsCurrenciesTests.cs PaymentProductsCardProcessingPayoutsCurrenciesTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\PaymentProductsECheckConfigurationInformationConfigurationsFeaturesAccountValidationServiceInternalOnlyTests.cs PaymentProductsECheckServiceInternalOnlyTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\PaymentProductsECheckConfigurationInformationConfigurationsFeaturesAccountValidationServiceProcessorsTests.cs PaymentProductsECheckProcessorsTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\PaymentProductsPayerAuthenticationConfigurationInformationConfigurationsCardTypesVerifiedByVisaCurrenciesTests.cs PaymentProductsPayerAuthVerifiedByVisaCurrenciesTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\PaymentProductsSecureAcceptanceConfigurationInformationConfigurationsNotificationsCustomerNotificationsTests.cs PaymentProductsSecureAcceptanceCustomerNotificationsTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\PaymentProductsSecureAcceptanceConfigurationInformationConfigurationsNotificationsMerchantNotificationsTests.cs PaymentProductsSecureAcceptanceMerchantNotificationsTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentGlobalPaymentInformationBasicInformationTests.cs PaymentProductsVirtualTerminalPaymentInformationBasicInformationTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentGlobalPaymentInformationMerchantDefinedDataFieldsTests.cs PaymentProductsVirtualTerminalMerchantDefinedDataFieldsTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentGlobalPaymentInformationPaymentInformationTests.cs PaymentProductsVirtualTerminalPaymentInformationTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentGlobalPaymentInformationTests.cs PaymentProductsVirtualTerminalCardNotPresentGlobalPaymentInformationTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformationEmailReceiptTests.cs PaymentProductsVirtualTerminalReceiptInformationEmailReceiptTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformationHeaderTests.cs PaymentProductsVirtualTerminalReceiptInformationHeaderTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformationOrderInformationTests.cs PaymentProductsVirtualTerminalReceiptInformationOrderInformationTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\RiskProductsDecisionManagerConfigurationInformationConfigurationsThirdpartyProviderAccurintCredentialsTests.cs RiskProductsDecisionManagerThirdpartyAccurintCredentialsTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\RiskProductsDecisionManagerConfigurationInformationConfigurationsThirdpartyProviderCredilinkCredentialsTests.cs RiskProductsDecisionManagerThirdpartyCredilinkCredentialsTests.cs

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\RiskProductsDecisionManagerConfigurationInformationConfigurationsThirdpartyProviderSignifydCredentialsTests.cs RiskProductsDecisionManagerThirdpartySignifydCredentialsTests.cs

powershell Rename-Item ..\..\..\src\CyberSource\Model\PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentGlobalPaymentInformationBasicInformation.cs PaymentProductsVirtualTerminalPaymentInformationBasicInformation.cs

powershell Rename-Item ..\..\..\src\CyberSource\Model\PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentGlobalPaymentInformationMerchantDefinedDataFields.cs PaymentProductsVirtualTerminalMerchantDefinedDataFields.cs

powershell Rename-Item ..\..\..\src\CyberSource\Model\PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentGlobalPaymentInformationPaymentInformation.cs PaymentProductsVirtualTerminalPaymentInformation.cs

powershell Rename-Item ..\..\..\src\CyberSource\Model\PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformationEmailReceipt.cs PaymentProductsVirtualTerminalReceiptInformationEmailReceipt.cs

powershell Rename-Item ..\..\..\src\CyberSource\Model\PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformationOrderInformation.cs PaymentProductsVirtualTerminalReceiptInformationOrderInformation.cs

powershell Rename-Item ..\..\..\docs\PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentGlobalPaymentInformationBasicInformation.md PaymentProductsVirtualTerminalPaymentInformationBasicInformation.md

powershell Rename-Item ..\..\..\docs\PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentGlobalPaymentInformationMerchantDefinedDataFields.md PaymentProductsVirtualTerminalMerchantDefinedDataFields.md

powershell Rename-Item ..\..\..\docs\PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentGlobalPaymentInformationPaymentInformation.md PaymentProductsVirtualTerminalPaymentInformation.md

powershell Rename-Item ..\..\..\docs\PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformationEmailReceipt.md PaymentProductsVirtualTerminalReceiptInformationEmailReceipt.md

powershell Rename-Item ..\..\..\docs\PaymentProductsVirtualTerminalConfigurationInformationConfigurationsCardNotPresentReceiptInformationOrderInformation.md PaymentProductsVirtualTerminalReceiptInformationOrderInformation.md


robocopy ..\..\..\src\cybersource ..\ /S /XF %excludeList%

robocopy ..\..\..\src\cybersource.test ..\..\cybersource-rest-client-netstandard.Test /S /XF %excludeList%

robocopy ..\..\..\docs ..\docs /S

del ..\..\..\CyberSource.sln
del ..\..\..\*ignore
git checkout ..\..\..\.gitignore
del ..\..\..\.travis.yml
del ..\..\..\build.*
del ..\..\..\git_push.sh
del ..\..\..\mono_nunit_test.sh
del ..\..\..\README.md
git checkout ..\..\..\README.md

rd /s /q ..\..\..\src
rd /s /q ..\..\..\docs
git checkout ..\Api\OAuthApi.cs
git checkout ..\Model\AccessTokenResponse.cs
git checkout ..\Model\CreateAccessTokenRequest.cs

pause
