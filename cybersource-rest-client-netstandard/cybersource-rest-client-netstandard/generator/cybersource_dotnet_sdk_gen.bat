@echo off

rd /s /q ..\Api
rd /s /q ..\Client
rd /s /q ..\Model
rd /s /q ..\docs
rd /s /q ..\..\cybersource-rest-client-netstandard.Test\Api
rd /s /q ..\..\cybersource-rest-client-netstandard.Test\Model

java -jar swagger-codegen-cli-2.2.3.jar generate -t cybersource-csharp-template -i cybersource-rest-spec.json -l csharp -o ../ -c cybersource-csharp-config.json

powershell -Command "(Get-Content ..\src\CyberSource\Api\SecureFileShareApi.cs) | ForEach-Object { $_ -replace 'null\); \/\/ Return statement', 'localVarResponse.Content); // Return statement' } | Set-Content ..\src\CyberSource\Api\SecureFileShareApi.cs"

powershell -Command "(Get-Content ..\src\CyberSource\Api\ReportDownloadsApi.cs) | ForEach-Object { $_ -replace 'null\); \/\/ Return statement', 'localVarResponse.Content); // Return statement' } | Set-Content ..\src\CyberSource\Api\ReportDownloadsApi.cs"

powershell -Command "(Get-Content ..\src\CyberSource\Api\TransactionBatchesApi.cs) | ForEach-Object { $_ -replace 'null\); \/\/ Return statement', 'localVarResponse.Content); // Return statement' } | Set-Content ..\src\CyberSource\Api\TransactionBatchesApi.cs"

powershell -Command " Set-Content ..\src\CyberSource\Api\SecureFileShareApi.cs ((get-content ..\src\CyberSource\Api\SecureFileShareApi.cs -raw) -replace '\*_\/_\*;charset=utf-8', '*/*;charset=utf-8') "

REM Loading content of excludeList.txt into a space-separated list in a variable
SETLOCAL EnableDelayedExpansion
SET excludeList=
FOR /f "tokens=* delims=\n" %%a in ('type "excludelist.txt"') do (
	SET excludeList=!excludeList! %%a
)

REM Need to shorten filenames

powershell Rename-Item ..\src\Cybersource\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptionsInitiatorMerchantInitiatedTransaction.cs Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedMerchantInitiatedTransaction.cs

powershell Rename-Item ..\src\Cybersource.Test\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptionsInitiatorMerchantInitiatedTransactionTests.cs Tmsv2customersEmbeddedMerchantInitiatedTransactionTests.cs

powershell Rename-Item ..\docs\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptionsInitiatorMerchantInitiatedTransaction.md Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedMerchantInitiatedTransaction.md

powershell Rename-Item ..\src\Cybersource.Test\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptionsInitiatorTests.cs Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedAuthorizationOptionsInitiatorTests.cs

powershell Rename-Item ..\src\Cybersource.Test\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptionsTests.cs Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedAuthorizationOptionsTests.cs

powershell Rename-Item ..\src\Cybersource\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptions.cs Tmsv2customersEmbeddedAuthorizationOptions.cs

powershell Rename-Item ..\docs\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptions.md Tmsv2customersEmbeddedAuthorizationOptions.md

powershell Rename-Item ..\src\Cybersource.Test\Model\RiskV1AddressVerificationsPost201ResponseAddressVerificationInformationStandardAddressAddress1Tests.cs RiskV1AddressVerificationsPost201ResponseStandardAddressAddress1Tests.cs

powershell Rename-Item ..\src\Cybersource\Model\RiskV1AddressVerificationsPost201ResponseAddressVerificationInformationStandardAddressAddress1.cs RiskV1AddressVerificationsPost201ResponseAddress1.cs

powershell Rename-Item ..\docs\RiskV1AddressVerificationsPost201ResponseAddressVerificationInformationStandardAddressAddress1.md RiskV1AddressVerificationsPost201ResponseAddress1.md

powershell Rename-Item ..\src\Cybersource.Test\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierLinksPaymentInstrumentsTests.cs Tmsv2customersEmbeddedPaymentInstrumentsTests.cs

powershell Rename-Item ..\src\Cybersource.Test\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationTests.cs Tmsv2customersEmbeddedDefaultProcessingInformationTests.cs

powershell Rename-Item ..\src\Cybersource\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierLinksPaymentInstruments.cs Tmsv2customersEmbeddedLinksPaymentInstruments.cs

powershell Rename-Item ..\src\Cybersource.Test\Model\Ptsv2paymentsProcessingInformationAuthorizationOptionsInitiatorMerchantInitiatedTransactionTests.cs Ptsv2paymentsMerchantInitiatedTransactionTests.cs

powershell Rename-Item ..\src\Cybersource.Test\Model\PtsV2PaymentsPost201ResponseConsumerAuthenticationInformationStrongAuthenticationIssuerInformationTests.cs PtsV2PaymentsPost201ResponseStrongAuthenticationIssuerInformationTests.cs

powershell Rename-Item ..\src\Cybersource.Test\Model\RiskV1ExportComplianceInquiriesPost201ResponseExportComplianceInformationWatchListMatchesTests.cs RiskV1ExportComplianceWatchListMatchesTests.cs

powershell Rename-Item ..\src\Cybersource.Test\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierTokenizedCardCardTests.cs Tmsv2customersTokenizedCardCardTests.cs

powershell Rename-Item ..\src\Cybersource\Model\PtsV2PaymentsPost201ResponseConsumerAuthenticationInformationStrongAuthenticationIssuerInformation.cs PtsV2PaymentsPost201ResponseStrongAuthenticationIssuerInformation.cs

powershell Rename-Item ..\docs\PtsV2PaymentsPost201ResponseConsumerAuthenticationInformationStrongAuthenticationIssuerInformation.md PtsV2PaymentsPost201ResponseStrongAuthenticationIssuerInformation.md

powershell Rename-Item ..\src\Cybersource\Model\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptionsInitiator.cs Tmsv2customersEmbeddedAuthorizationOptionsInitiator.cs

powershell Rename-Item ..\docs\Tmsv2customersEmbeddedDefaultPaymentInstrumentEmbeddedInstrumentIdentifierProcessingInformationAuthorizationOptionsInitiator.md Tmsv2customersEmbeddedAuthorizationOptionsInitiator.md

robocopy ..\src\cybersource ..\ /S /XF %excludeList%

robocopy ..\src\cybersource.test ..\..\cybersource-rest-client-netstandard.Test /S /XF %excludeList%

del ..\CyberSource.sln
del ..\*ignore
del ..\.travis.yml
del ..\build.*
del ..\git_push.sh
del ..\mono_nunit_test.sh
del ..\README.md

rd /s /q ..\src
git checkout ..\Api\OAuthApi.cs
git checkout ..\Model\AccessTokenResponse.cs
git checkout ..\Model\CreateAccessTokenRequest.cs

pause
