Dks.SimpleToken [![NuGet Version](https://img.shields.io/nuget/v/Dks.SimpleToken.Core.svg?style=flat)](https://www.nuget.org/packages/Dks.SimpleToken.Core/) 
=================
*Simple and lightweight library for stateless token authorization.*

### Installation

```powershell
PM> Install-Package Dks.SimpleToken.Core
```

This library is targeting both .NET Standard 1.3 and .NET 4.5.  
See the [.NET Standard Platform Support Matrix][1] for further details.

### Typical scenario:

This library was primarily born to handle authorization and access-control of uncoupled services that resides on different machines.

The typical scenario is the same of services like Amazon S3 or Azure Blob Storage, in which files and blobs are stored inside a completely different service and authorization must be handled using a secure token. This token is usually generated inside by the main web site or service, it has short lifetime and contains enough information for the resource service to fully authorize the request.

```
+----------+                                   +------------+
|   User   |    requests access to resource    | API Server |
|          |  +----------------------------->  |            |
|          |                                   |            |
|          |                                   | Generates  |
|          |        returns secure token       |   Token    |
|          |  <-----------------------------+  |            |
|          |                                   |            |
|          |                                   +------------+
| Requires |
|  access  |
|   to a   |                                 +-----------------+
| resource |       sends secure token        | Resource Server |
|          |  +--------------------------->  |                 |
|          |                                 |                 |
|          |                                 |    Validates    |
|          |                                 |      Token      |
|          |       returns the resource      |                 |
|          |  <---------------------------+  |                 |
+----------+                                 +-----------------+
```

With this library you may generate a secure encrypted token (by default protected using AES algorithm with a key shared between two services/machines) with custom data embedded inside it.
This will ensure a stateless and freely scalable approach.

### Notes

The core library contains abstractions and default implementations for generating and validating Secure Tokens protected with AES encryption and serialized as JSON.

Other packages extend the functionalities and integrate the library with other frameworks:

 - [`Dks.SimpleToken.Serializers.Protobuf`](https://www.nuget.org/packages/Dks.SimpleToken.Serializers.Protobuf)  
    Google Protobuf token serialization (which greatly reduces token size).

 - [`Dks.SimpleToken.SystemWeb`](https://www.nuget.org/packages/Dks.SimpleToken.SystemWeb)  
    Adds implementations for token encryption and serialization using native `System.Web` methods like `MachineKey` and `FormsAuthenticationTicket`.

 - [`Dks.SimpleToken.Validation.MVC6`](https://www.nuget.org/packages/Dks.SimpleToken.Validation.MVC6)  
    Integrates `Dks.SimpleToken` with ASP .NET Core MVC 6 using `ActionFilters`. Retrives and validates tokens inside an HTTP header or in a query string parameter.

 - [`Dks.SimpleToken.Validation.MVC5`](https://www.nuget.org/packages/Dks.SimpleToken.Validation.MVC5)  
    Integrates `Dks.SimpleToken` with ASP .NET MVC 5 using `ActionFilters`. Retrives and validates tokens inside an HTTP header or in a query string parameter.

 - [`Dks.SimpleToken.Validation.WebAPI`](https://www.nuget.org/packages/Dks.SimpleToken.Validation.WebAPI)  
    Integrates `Dks.SimpleToken` with ASP .NET Web API 2 using `ActionFilters`. Retrives and validates tokens inside an HTTP header or in a query string parameter.

### Example Usage

Create a new default `ISecureTokenProvider` instance:

```csharp
var config = new AESEncryptionConfiguration
{
    // example key DO NOT USE IN PRODUCTION
    EncryptionKey = "3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8="

    // the following are the default values for AES options:
    CipherMode = CipherMode.CBC,
    Padding = PaddingMode.PKCS7,
    KeySize = 256
};

var provider = DefaultTokenProvider.Create(config);
```

Create a new `DefaultTokenProvider` using custom encryption and serialization:

```csharp
// provide to the constructor custom ISecureTokenSerializer and ISecureTokenProtector instances
var provider = new DefaultTokenProvider(serializer, protector);
```

Generate a Secure Token string with 5 minutes expiration and custom user data:

```csharp
var userData =  new Dictionary<string, string> {
    { "Foo", "bar"}
};
var token = provider.GenerateToken(userData, 300);
// or using the extension method that accepts an object
var token = provider.GenerateToken(new { Foo = "bar" }, 300);
```

Validate a Secure Token string and extract custom user data:

```csharp
var validated = provider.ValidateAndGetData(token);
// this will throw SecurityException if invalid or expired

var fooData = validated["Foo"];
// fooData now contains "bar"
```

### How to generate a new AES key:

The default `ISecureTokenProtector` will accept a standard AES key in Base64 format.

Please **DO NOT USE THE KEY PROVIDED IN THE EXAMPLES** as it is no secret at all.

You may generate a new key in C# using the following code:

```csharp
string key;
using(var aes = System.Security.Cryptography.Aes.Create())
{
    // set the following parameters to what you will use inside
    // AESEncryptionConfiguration:
    aes.Mode = CipherMode.CBC; // this is the default mode
    aes.KeySize = 256; // this is the default size

    // generate the key
    aes.GenerateKey();

    // convert to Base 64
    key = Convert.ToBase64String(aes.Key);
}
// now key contains a base 64 formatted key for AESEncryptionConfiguration
```
Store this key in a secure place for both the token generating service and the token validation service.
Typically you would store the key inside the Web.config file (better if in encrypted format), a json configuration file for ASP.NET Core or using Azure Key Vault and similar services.

## License

This library is provided free of charge, under the terms of the MIT license.

Default AES encryption was inspired by [Simple AES][3] available under the MIT license.

Default JSON Serialization is provided by [SimpleJson][4] available under the MIT license.

[1]: https://docs.microsoft.com/en-us/dotnet/articles/standard/library
[2]: https://github.com/mgravell/protobuf-net
[3]: https://github.com/ArtisanCode/SimpleAesEncryption
[4]: https://github.com/facebook-csharp-sdk/simple-json