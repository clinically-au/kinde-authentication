using System.Security.Claims;
using System.Text.Json;
using Clinically.Kinde.Authentication.Types;

namespace Clinically.Kinde.Authentication.Identity;

public static class ClaimsPrincipalExtensions
{
    public static List<string> GetRolesList(this ClaimsPrincipal? principal) => principal?.Claims
        .Where(x => x.Type == ClaimTypes.Role)
        .Select(x => x.Value).ToList() ?? [];

    public static List<KindeRole> GetRoles(this ClaimsPrincipal? principal) => (principal?.Claims.Where(
        claim => claim.Type == KindeClaimTypes.Roles)
        .Select(claim => JsonSerializer.Deserialize<KindeRole>(claim.Value)).ToList() ?? [])!;

    public static List<string> GetPermissionsList(this ClaimsPrincipal? principal) => principal?.Claims
        .Where(x => x.Type == KindeClaimTypes.Permissions)
        .Select(x => x.Value).ToList() ?? [];

    public static List<string> GetOrganizationsList(this ClaimsPrincipal? principal) => principal?.Claims
        .Where(x => x.Type == KindeClaimTypes.Organizations)
        .Select(x => x.Value).ToList() ?? [];

    public static List<KindeOrganization> GetOrganizations(this ClaimsPrincipal? principal) => (principal?.Claims
            .Where(x => x.Type == KindeClaimTypes.Organizations)
            .Select(x => JsonSerializer.Deserialize<KindeOrganization>(x.Value)).ToList() ?? [])!;
    public static string? GetPicture(this ClaimsPrincipal? principal) =>
        principal?.FindFirstValue(KindeClaimTypes.Picture);

    public static string? GetGivenName(this ClaimsPrincipal? principal) =>
        principal?.FindFirstValue(ClaimTypes.GivenName);

    public static string? GetFamilyName(this ClaimsPrincipal? principal) =>
        principal?.FindFirstValue(ClaimTypes.Surname);    
    
    public static string? GetEmail(this ClaimsPrincipal? principal) =>
        principal?.FindFirstValue(ClaimTypes.Email);

    public static string? GetId(this ClaimsPrincipal? principal) =>
        principal?.FindFirstValue(ClaimTypes.NameIdentifier);

    public static string? GetOrganizationCode(this ClaimsPrincipal? principal) =>
        principal?.FindFirstValue(KindeClaimTypes.OrganizationCode);
}
