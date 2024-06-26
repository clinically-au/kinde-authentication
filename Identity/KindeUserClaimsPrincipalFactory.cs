using System.Security.Claims;
using Clinically.Kinde.Authentication.Types;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Clinically.Kinde.Authentication.Identity;

public class AdditionalUserClaimsPrincipalFactory(
    UserManager<KindeUser> userManager,
    RoleManager<KindeRole> roleManager,
    IOptions<IdentityOptions> optionsAccessor,
    IHttpContextAccessor httpContextAccessor)
    : UserClaimsPrincipalFactory<KindeUser, KindeRole>(userManager, roleManager, optionsAccessor)
{
    public override async Task<ClaimsPrincipal> CreateAsync(KindeUser user)
    {
        var principal = await base.CreateAsync(user);
        var identity = (ClaimsIdentity)principal.Identity!;

        if (httpContextAccessor.HttpContext == null) return principal;
        
        var authResult = await httpContextAccessor.HttpContext.AuthenticateAsync(IdentityConstants.ExternalScheme);
        if (!authResult.Succeeded)
        {
            return principal;
        }

        var claims = new List<Claim>();
        
        // Add additional claims here
        if (user.GivenName != null)
        {
            claims.Add(new Claim(KindeClaimTypes.GivenName, user.GivenName));
        }

        if (user.FamilyName != null)
        {
            claims.Add(new Claim(KindeClaimTypes.FamilyName, user.FamilyName));
        }

        if (user.Picture != null)
        {
            claims.Add(new Claim(KindeClaimTypes.Picture, user.Picture));
        }

        var authClaims = authResult.Principal.Claims;

        var authClaimsList = authClaims.ToList();
        
        if (authClaimsList.Any(c => c.Type == KindeClaimTypes.OrganizationCode))
            claims.Add(authClaimsList.First(x => x.Type == KindeClaimTypes.OrganizationCode));
        
        if (authClaimsList.Any(c => c.Type == KindeClaimTypes.Organizations))
            claims.AddRange(authClaimsList.Where(c => c.Type == KindeClaimTypes.Organizations));
        
        if (authClaimsList.Any(c => c.Type == KindeClaimTypes.Roles))
            claims.AddRange(authClaimsList.Where(c => c.Type == KindeClaimTypes.Roles));
        
        if (authClaimsList.Any(c => c.Type == KindeClaimTypes.Permissions))
            claims.AddRange(authClaimsList.Where(c => c.Type == KindeClaimTypes.Permissions));
        
        if (authClaimsList.Any(c => c.Type == ClaimTypes.Role))
            claims.AddRange(authClaimsList.Where(c => c.Type == ClaimTypes.Role));
        
        if (authClaimsList.Any(c => c.Type == ClaimTypes.Email))
            claims.Add(new Claim(ClaimTypes.Email, authClaimsList.First(x => x.Type == ClaimTypes.Email).Value));
        
        if (authClaimsList.Any(c => c.Type == KindeClaimTypes.DisplayName))
            claims.Add(new Claim(ClaimTypes.Name, authClaimsList.First(x => x.Type == KindeClaimTypes.DisplayName).Value));

        identity.AddClaims(claims);

        return principal;
    }
}