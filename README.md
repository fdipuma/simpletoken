Dks.SimpleToken [![NuGet Version](https://img.shields.io/nuget/v/Dks.SimpleToken.Core.svg?style=flat)](https://www.nuget.org/packages/Dks.SimpleToken.Core/) 
=================

## Core

Simple and lightweight library for stateless token authorization.

### Installation

```powershell
PM> Install-Package Dks.SimpleToken.Core
```

This library is targeting both .NET Standard 1.3 and .NET 4.5.  
See the [.NET Standard Platform Support Matrix][1] for further details.

### Notes

The core library contains abstractions and default implementations for generating and validating Secure Tokens protected with AES encryption and serialized as JSON.

Other packages extend the functionalities and integrate the library with other frameworks:

 - `Dks.SimpleToken.Serializers.Protobuf`   
    Google Protobuf serialization (which greatly reduces token size).

 - `Dks.SimpleToken.SystemWeb`   
    Adds implementations for token encryption and serialization using native `System.Web` methods.

 - `Dks.SimpleToken.Validation.MVC6`   
    Integrates `Dks.SimpleToken` with ASP .NET Core MVC 6.

 - `Dks.SimpleToken.Validation.MVC5`   
    Integrates `Dks.SimpleToken` with ASP .NET MVC 5.

 - `Dks.SimpleToken.Validation.WebAPI`   
    Integrates `Dks.SimpleToken` with ASP .NET Web API 2.

### Example Usage

Create a new default `ISecureTokenProvider` instance:

```csharp
var config = new AESEncryptionConfiguration
{
    EncryptionKey = "3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8="
};
// using default values for other AES options

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
## License

This library is provided free of charge, under the terms of the MIT license.

Default AES encryption was inspired by [Simple AES][3] available under the MIT license.

Default JSON Serialization is provided by [SimpleJson][4] available under the MIT license.

[1]: https://docs.microsoft.com/en-us/dotnet/articles/standard/library
[2]: https://github.com/mgravell/protobuf-net
[3]: https://github.com/ArtisanCode/SimpleAesEncryption
[4]: https://github.com/facebook-csharp-sdk/simple-json