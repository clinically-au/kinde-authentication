using Clinically.Kinde.Authentication.Identity;
using Clinically.Kinde.Authentication.Types;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;

namespace Clinically.Kinde.Authentication.Blazor;

public class BlazorUserAccessor(AuthenticationStateProvider authenticationStateProvider, UserManager<KindeUser> userManager)
{
    public async Task<KindeUser?> GetCurrentUserAsync()
    {
        var authState = await authenticationStateProvider.GetAuthenticationStateAsync().ConfigureAwait(false);
        var claimsPrincipal = authState.User;
        return await userManager.GetUserAsync(claimsPrincipal).ConfigureAwait(false);
    }

    public async Task<KindeUserInfo?> GetCurrentUserInfoAsync()
    {
        var principal = (await authenticationStateProvider.GetAuthenticationStateAsync().ConfigureAwait(false))
            .User;

        var id = principal.GetId();
        var email = principal.GetEmail();
        
        if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(email))
        {
            return null;
        }

        return new KindeUserInfo()
        {
            Id = id,
            Email = email,
            GivenName = principal.GetGivenName(),
            FamilyName = principal.GetFamilyName(),
            Picture = principal.GetPicture(),
            RolesList = principal.GetRolesList(),
            Roles = principal.GetRoles(),
            PermissionsList = principal.GetPermissionsList(),
            OrganizationCode = principal.GetOrganizationCode(),
            OrganizationsList = principal.GetOrganizationsList(),
            Organizations = principal.GetOrganizations()
        };
    }
}