@echo off

rd /s /q ..\Api
rd /s /q ..\Client
rd /s /q ..\Model
rd /s /q ..\docs
rd /s /q ..\..\cybersource-rest-client-netstandard.Test\Api
rd /s /q ..\..\cybersource-rest-client-netstandard.Test\Model

setlocal enabledelayedexpansion
python replaceFieldNamesForPaths.py -i cybersource-rest-spec.json -o cybersource-rest-spec-netstandard.json > replaceFieldLogs.log
del replaceFieldLogs.log
endlocal

java -jar swagger-codegen-cli-2.4.38.jar generate -t cybersource-csharp-template -i cybersource-rest-spec-netstandard.json -l csharp -o ..\..\..\ -c cybersource-csharp-config.json

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

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\RiskV1AddressVerificationsPost201ResponseAddressVerificationInformationStandardAddressAddress1Tests.cs RiskV1AddressVerificationsPost201ResponseStandardAddressAddress1Tests.cs

powershell Rename-Item ..\..\..\src\CyberSource\Model\RiskV1AddressVerificationsPost201ResponseAddressVerificationInformationStandardAddressAddress1.cs RiskV1AddressVerificationsPost201ResponseAddress1.cs

powershell Rename-Item ..\..\..\docs\RiskV1AddressVerificationsPost201ResponseAddressVerificationInformationStandardAddressAddress1.md RiskV1AddressVerificationsPost201ResponseAddress1.md

powershell Rename-Item ..\..\..\src\CyberSource.Test\Model\Ptsv2paymentsProcessingInformationAuthorizationOptionsInitiatorMerchantInitiatedTransactionTests.cs Ptsv2paymentsMerchantInitiatedTransactionTests.cs

robocopy ..\..\..\src\cybersource ..\ /S /XF %excludeList%

robocopy ..\..\..\src\cybersource.test ..\..\cybersource-rest-client-netstandard.Test /S /XF %excludeList%

robocopy ..\..\..\docs ..\docs /S

@REM replace sdkLinks fieldName to links for supporting links field name in request/response body
echo "starting of replacing the links keyword in PblPaymentLinksAllGet200Response.cs model"
powershell -Command "Set-Content ..\Model\PblPaymentLinksAllGet200Response.cs ((Get-Content ..\Model\PblPaymentLinksAllGet200Response.cs -Raw) -replace '\[DataMember\(Name=\"sdkLinks\", EmitDefaultValue=false\)\]', '[DataMember(Name=\"links\", EmitDefaultValue=false)]')"
echo "completed the task of replacing the links keyword in PblPaymentLinksAllGet200Response.cs model"

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
del ..\Client\IReadableConfiguration.cs

pause
