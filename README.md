# Integrating Kinde Auth with .NET8 Apps (including Blazor)

This library assists with integrating Kinde with .NET applications. It is still in development but usable. There may be breaking changes from version to version for now.

Add the following NuGet package:
```Clinically.Kinde.Authentication```

The following needs to be in your ```appSettings.json``` on the server:

```json
{
  "Kinde": {
    "Domain": "<From Kinde>",
    "ClientId": "<From Kinde>",
    "ClientSecret": "<From Kinde>",
    "ManagementApiAudience": "<From Kinde>", // Optional - only need to set this if using custom domains
    "SignedOutRedirectUri": "https://localhost:5001/signout-callback-oidc",
    "JwtAudience": "<From Kinde - Audience for API, if using JWT Bearer Auth in addition to Identity>"
  },
  "AppConfig": {
    "BaseUrl": "https://localhost:5001"
  }
}
```

Remember to give your app access to the Kinde Management API!

You can omit ```JwtAudience``` if you are not using JWT Bearer Authentication.

If you want users to log in to your MVC / Razor Page / Blazor app, you need to add this to your ```Program.cs```:

```csharp 
builder.Services.AddKindeIdentityAuthentication(opt =>
{
    opt.UseMemoryCacheTicketStore = false; // optional - default to false
}); 
```

If you want to add JwtBearer Authentication to your API, add this to your ```Program.cs``` (remember to add the JwtAudience to your appSettings.json):

```csharp
builder.Services.AddKindeJwtBearerAuthentication();
```

Then add the standard authorization services:
    
```csharp
builder.Services.AddAuthorization();
```

And:
```csharp
app.MapKindeIdentityEndpoints();
```

For Blazor WASM, you also need to add this to ```Program.cs``` on the **client**:
```csharp
builder.Services.AddKindeWebAssemblyClient();
```

## Roles

You can use the standard Authorize attribute:

```csharp
[Authorize(Roles = "Admin")]
```

## Permissions

In order to add authorization policies for your Kinde permissions:

```csharp
builder.Services
    .AddAuthorizationBuilder()
    .AddKindePermissionPolicies<Permissions>();
```

Then create a Permissions class that contains all the Kinde permissions you want to use:

```csharp
public class Permissions
{
    public const string MyPermissionName = "myPermissionNameInKinde";
}
```

Then you can use the permissions in your controllers or Razor pages:

```csharp
[Authorize(Policy = Permissions.MyPermissionName)]
```

## Notes

- You need to go to the Tokens section of your app, and enable the Roles and Email claims in the access token.
- In order to access the management API (e.g. to add users programmatially etc), inject ```KindeManagementClient``` into
  your services. Note you will need a separate M2M app in Kinde for this, with access to the Management API.
- You can also inject ```KindeUserManager``` instead of the standard ```UserManager``` to get access to Kinde-specific
  methods.
- Inject ```BlazorUserAccessor``` to get access to the current user in your Blazor components.

I've only recently worked out how to tie all this together, so some bits may not be entirely required etc. Raise an issue if you notice any problems.

## Example Projects
- [JWT Bearer Authentication with Web API and React Client](https://github.com/clinically-au/KindeJwtExample)
- [Blazor App](https://github.com/clinically-au/BlazorAppWithKindeAuthentication)

## To Do List:

- Feature flags not currently implemented (but will work the same way as Permissions)
- Support more claims/properties in the strongly typed user objects