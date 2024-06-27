# # sed -i'' -e 's|pattern|replacement|g' filename
# #this script needs to be executed in the $github-workspace working directory

# sed -i'' -e 's|<PackageReference Include="CyberSource.Authentication.NetStandard" Version="[0.0.1.14]" />|<Reference Include="CyberSource.Authentication.NetStandard">\n
#   <HintPath>../../cybersource-rest-auth-netstandard/AuthenticationSdk/AuthenticationSdk/bin/Release/netstandard2.1/Cybersource.Authentication.NetStandard.dll</HintPath>\n
#   <Private>true</Private>\n
# </Reference>|g' cybersource-rest-client-dotnetstandard/cybersource-rest-client-netstandard/cybersource-rest-client-netstandard/cybersource-rest-client-netstandard.csproj


# sed -i'' -e 's|<PackageReference Include="CyberSource.Authentication.NetStandard" Version="0.0.1.13" />|<Reference Include="CyberSource.Authentication.NetStandard">\n
#   <HintPath>../cybersource-rest-client-dotnetstandard/cybersource-rest-auth-netstandard/AuthenticationSdk/AuthenticationSdk/bin/Release/netstandard2.1/Cybersource.Authentication.NetStandard.dll</HintPath>\n
#   <Private>true</Private>\n
# </Reference>|g' cybersource-rest-samples-csharp/cybersource-rest-samples-netcore.csproj

# sed -i'' -e 's|<PackageReference Include="CyberSource.Rest.Client.NetStandard" Version="0.0.1.33" />|<Reference Include="CyberSource.Rest.Client.NetStandard">\n
#   <HintPath>../cybersource-rest-client-dotnetstandard/cybersource-rest-client-netstandard/cybersource-rest-client-netstandard/bin/Release/netstandard2.1/cybersource-rest-client-netstandard.dll</HintPath>\n
#   <Private>true</Private>\n
# </Reference>|g' cybersource-rest-samples-csharp/cybersource-rest-samples-netcore.csproj

sed -i'' -e 's|<PackageReference Include="CyberSource.Authentication.NetStandard" Version="[0.0.1.14]" />|<Reference Include="CyberSource.Authentication.NetStandard">\n  <HintPath>../../cybersource-rest-auth-netstandard/AuthenticationSdk/AuthenticationSdk/bin/Release/netstandard2.1/Cybersource.Authentication.NetStandard.dll</HintPath>\n  <Private>true</Private>\n</Reference>|g' cybersource-rest-client-dotnetstandard/cybersource-rest-client-netstandard/cybersource-rest-client-netstandard/cybersource-rest-client-netstandard.csproj
sed -i'' -e 's|<PackageReference Include="CyberSource.Authentication.NetStandard" Version="0.0.1.13" />|<Reference Include="CyberSource.Authentication.NetStandard">\n  <HintPath>../cybersource-rest-client-dotnetstandard/cybersource-rest-auth-netstandard/AuthenticationSdk/AuthenticationSdk/bin/Release/netstandard2.1/Cybersource.Authentication.NetStandard.dll</HintPath>\n  <Private>true</Private>\n</Reference>|g' cybersource-rest-samples-csharp/cybersource-rest-samples-netcore.csproj
sed -i'' -e 's|<PackageReference Include="CyberSource.Rest.Client.NetStandard" Version="0.0.1.33" />|<Reference Include="CyberSource.Rest.Client.NetStandard">\n  <HintPath>../cybersource-rest-client-dotnetstandard/cybersource-rest-client-netstandard/cybersource-rest-client-netstandard/bin/Release/netstandard2.1/cybersource-rest-client-netstandard.dll</HintPath>\n  <Private>true</Private>\n</Reference>|g' cybersource-rest-samples-csharp/cybersource-rest-samples-netcore.csproj
