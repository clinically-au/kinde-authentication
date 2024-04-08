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

    // To avoid keeping any user details client-side; has some down-sides if you have many users
    // as it uses server memory
    public bool UseMemoryCacheTicketStore { get; set; } = false;
    public bool UseBlazor { get; set; } = true;
}