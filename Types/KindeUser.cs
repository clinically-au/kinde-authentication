using System.Text.Json;
using Clinically.Kinde.Authentication.ManagementApi.Model;
using Microsoft.AspNetCore.Identity;

namespace Clinically.Kinde.Authentication.Types;

public class KindeUser : IdentityUser
{
    public string? GivenName { get; private set; }
    public string? FamilyName { get; private set; }
    public string? ProvidedId { get; private set; }
    public bool IsSuspended { get; private set; }
    public string? Picture { get; private set; }
    public int? TotalSignIns { get; private set; }
    public int? FailedSignIns { get; private set; }
    public string? LastSignedIn { get; private set; }
    public string? CreatedOn { get; private set; }
    public List<string>? Organizations { get; private set; }
    
internal static KindeUser FromUserResponse(UsersResponseUsersInner user)
    {
        return new KindeUser()
        {
            Id = user.Id,
            UserName = user.Email,
            Email = user.Email,
            GivenName = user.FirstName,
            FamilyName = user.LastName,
            ProvidedId = user.ProvidedId,
            IsSuspended = user.IsSuspended,
            Picture = user.Picture,
            TotalSignIns = user.TotalSignIns,
            FailedSignIns = user.FailedSignIns,
            LastSignedIn = user.LastSignedIn,
            CreatedOn = user.CreatedOn,
            Organizations = user.Organizations
        };
    }

    internal static KindeUser FromOrganizationUser(OrganizationUser user)
    {
        return new KindeUser()
        {
            Id = user.Id,
            UserName = user.Email,
            Email = user.Email,
            GivenName = user.FirstName,
            FamilyName = user.LastName
        };
    }
}
