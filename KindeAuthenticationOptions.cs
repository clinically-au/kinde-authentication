namespace Clinically.Kinde.Authentication;

public class KindeAuthenticationOptions()
{
    /// <summary>
    /// Your Kinde domain, e.g. https://{your-app}.au.kinde.com or whatever custom domain you are using.
    /// <see href="https://kinde.com/docs/connect-to-kinde/getting-app-keys/">Kinde documentation</see>.
    /// </summary>
    public string Domain { get; set; }
    
    /// <summary>
    /// The client ID from your app's Kinde dashboard
    /// <see href="https://kinde.com/docs/connect-to-kinde/getting-app-keys/">Kinde documentation</see>.
    /// </summary>
    public string ClientId { get; set; }
    
    /// <summary>
    /// The client secret from your app's Kinde dashboard
    /// <see href="https://kinde.com/docs/connect-to-kinde/getting-app-keys/">Kinde documentation</see>.
    /// </summary>
    public string ClientSecret { get; set; }
    
    /// <summary>
    /// The audience for your app's API, if required. This is only used by JWT authentication and should
    /// be the same as you set the audience to in your API's configuration.
    /// Remember to give your app access to your API in Kinde!
    /// <see href="https://kinde.com/docs/build/register-an-api/">Kinde documentation</see>.
    /// </summary>
    public string JwtAudience { get; set; }
    
    /// <summary>
    /// The audience for the management API - usually something like https://{your.kinde.domain}.kinde.com/api
    /// Defaults to using the same domain as the main client - but this won't work if you are using a custom
    /// domain as your authority, in which case you need to set the audience here.
    /// Remember to give your app access to the management API in Kinde!
    /// <see href="https://kinde.com/docs/build/about-kinde-apis/">Kinde documentation</see>.
    /// </summary>
    public string ManagementApiAudience { get; set; }

    /// <summary>
    /// The URL to redirect to after a successful logout
    /// <see href="https://kinde.com/docs/connect-to-kinde/callback-urls">Kinde documentation</see>.
    /// </summary>
    public string SignedOutRedirectUri { get; set; }

    /// <summary>
    /// Default is false. Set this to true if you want to store the user's session in memory on the server rather than
    /// on the client. While this uses memory, it is more secure as it doesn't expose any user details client-side
    /// <see href="https://nestenius.se/2024/01/22/improving-asp-net-core-security-by-putting-your-cookies-on-a-diet/">Explanation</see>
    /// </summary>
    public bool UseMemoryCacheTicketStore { get; set; } = false;
    
    /// <summary>
    /// Default is true. Adds support for Blazor authentication state providers. If you are also using a webassembly
    /// client, don't forget to add builder.AddKindeWebAssemblyClient() to your Program.cs
    /// Set this to false if you are not using Blazor (e.g. for MVC or Razor apps)
    /// <see href="https://auth0.com/blog/auth0-authentication-blazor-web-apps/">Explanation and inspirations
    /// </summary>
    public bool UseBlazor { get; set; } = true;

    /// <summary>
    /// Defaults to true. Note that to use Permissions and Roles, users must have an organization
    /// (even if it is the default organization). If you don't want to use organizations, set this to false.
    /// This can be a bit confusing as you can create Kinde users in the Kinde dashboard without an organization,
    /// but you lose a lot of functionality so it doesn't make sense even for single-tenant apps.
    /// <see href=https://kinde.com/docs/build/allow-user-signup-org/#sign-users-up-to-the-default-organization">Kinde documentation</see>
    /// </summary>
    public bool UsersMustHaveOrganization { get; set; } = true;
}