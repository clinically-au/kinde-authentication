namespace Clinically.Kinde.Authentication.Types;

public class KindeUserInfo
{
    public required string Id { get; set; }
    public required string Email { get; set; }
    public string? GivenName { get; set; }
    public string? FamilyName { get; set; }
    public string? Picture { get; set; }
    public List<string>? RolesList { get; set; }
    public List<KindeRole>? Roles { get; set; }
    public List<string>? PermissionsList { get; set; }
    public List<string>? OrganizationsList { get; set; }
    public List<KindeOrganization>? Organizations { get; set; }
    public string? OrganizationCode { get; set; }
}