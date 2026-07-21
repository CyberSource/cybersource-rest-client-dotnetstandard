# Repository Migration Notice

The packages in this repository have been retired and are no longer actively maintained.

The NuGet packages **<CyberSource.Authentication.NetStandard>** and **<CyberSource.Rest.Client.NetStandard>** will not receive further feature updates, bug fixes, or security patches.

Development has moved to **<CyberSource.Authentication>** and **<CyberSource.Rest.Client>**, which should be used for all new projects and future upgrades.

## Recommended Action

Existing consumers should migrate from:

```xml
<PackageReference Include="<CyberSource.Authentication.NetStandard>" Version="0.0.1.24" />
<PackageReference Include="<CyberSource.Rest.Client.NetStandard>" Version="0.0.1.56" />
```

to

```xml
<PackageReference Include="<CyberSource.Authentication>" Version="1.0.0" />
<PackageReference Include="<CyberSource.Rest.Client>" Version="1.0.0" />
```

### Compatibility Notice

There are **no breaking changes or functional code changes** associated with this migration.

The package versions listed above are intended to be compatible replacements for the retired packages. The version changes reflect updates to the package identity and target framework support, rather than changes to the runtime behavior or public functionality of the code.

This migration is expected to be straightforward for most consumers. However, as with any dependency update, we recommend validating the change in your application or library through your normal build, test, and release process.

### Consumer Guidance

If you maintain a library or application that depends on **<CyberSource.Authentication.NetStandard>** and/or **<CyberSource.Rest.Client.NetStandard>**, we recommend updating your dependency as soon as practical to ensure continued compatibility and support.

## Thank you to everyone who used, contributed to, or provided feedback on this package.

# .NET Standard Client SDK for the CyberSource REST API

The CyberSource .NET Standard client provides convenient access to the [CyberSource REST API](https://developer.cybersource.com/api/reference/api-reference.html) from your .NET application.

This repository also contains the code for the Authentication SDK written in .NET Standard.

For a more detailed explanation of these libraries, refer to

* [CyberSource REST Client SDK README.md](./cybersource-rest-client-netstandard/README.md)

* [CyberSource Authentication SDK README.md](./cybersource-rest-auth-netstandard/README.md)

## Versions

**.NET Standard : v2.1**

**This version of .NET Standard is compatible with applications written in .NET Core 3.1.**

## License

This repository is distributed under a proprietary license.

## Disclaimer

Cybersource may allow Customer to access, use, and/or test a Cybersource product or service that may still be in development or has not been market-tested (“Beta Product”) solely for the purpose of evaluating the functionality or marketability of the Beta Product (a “Beta Evaluation”). Notwithstanding any language to the contrary, the following terms shall apply with respect to Customer’s participation in any Beta Evaluation (and the Beta Product(s)) accessed thereunder): The Parties will enter into a separate form agreement detailing the scope of the Beta Evaluation, requirements, pricing, the length of the beta evaluation period (“Beta Product Form”). Beta Products are not, and may not become, Transaction Services and have not yet been publicly released and are offered for the sole purpose of internal testing and non-commercial evaluation. Customer’s use of the Beta Product shall be solely for the purpose of conducting the Beta Evaluation. Customer accepts all risks arising out of the access and use of the Beta Products. Cybersource may, in its sole discretion, at any time, terminate or discontinue the Beta Evaluation. Customer acknowledges and agrees that any Beta Product may still be in development and that Beta Product is provided “AS IS” and may not perform at the level of a commercially available service, may not operate as expected and may be modified prior to release. CYBERSOURCE SHALL NOT BE RESPONSIBLE OR LIABLE UNDER ANY CONTRACT, TORT (INCLUDING NEGLIGENCE), OR OTHERWISE RELATING TO A BETA PRODUCT OR THE BETA EVALUATION (A) FOR LOSS OR INACCURACY OF DATA OR COST OF PROCUREMENT OF SUBSTITUTE GOODS, SERVICES OR TECHNOLOGY, (B) ANY CLAIM, LOSSES, DAMAGES, OR CAUSE OF ACTION ARISING IN CONNECTION WITH THE BETA PRODUCT; OR (C) FOR ANY INDIRECT, INCIDENTAL OR CONSEQUENTIAL DAMAGES INCLUDING, BUT NOT LIMITED TO, LOSS OF REVENUES AND LOSS OF PROFITS.
