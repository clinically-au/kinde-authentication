namespace Clinically.Kinde.Authentication;

public class KindeAuthenticationOptions()
{
    public string Authority { get; set; }
    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
    public string JwtAudience { get; set; }
    public string ManagementApiClientId { get; set; }
    public string ManagementApiClientSecret { get; set; }
    public string SignedOutRedirectUri { get; set; }

    // For other clients using the API, e.g. mobile apps:
    public bool UseJwtBearerValidation { get; set; } = false;

    // To avoid keeping any user details client-side; has some down-sides if you have many users
    // as it uses server memory
    public bool UseMemoryCacheTicketStore { get; set; } = false;
}