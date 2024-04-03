using System.Security.Claims;
using System.Text.Json;
using Clinically.Kinde.Authentication.Types;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace Clinically.Kinde.Authentication.Blazor;

internal class ClientAuthenticationStateProvider : AuthenticationStateProvider
{
    private static readonly Task<AuthenticationState> DefaultUnauthenticatedTask =
        Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));

    private readonly Task<AuthenticationState> _authenticationStateTask = DefaultUnauthenticatedTask;

    public ClientAuthenticationStateProvider(PersistentComponentState state)
    {
        if (!state.TryTakeFromJson<KindeUserInfo>(nameof(KindeUserInfo), out var userInfo) || userInfo is null)
        {
            return;
        }

        List<Claim> claims = [
            new Claim(ClaimTypes.NameIdentifier, userInfo.Id),
            new Claim(ClaimTypes.Email, userInfo.Email) ,
        ];
        
        if (userInfo.GivenName is not null) claims.Add(
            new Claim(ClaimTypes.GivenName, userInfo.GivenName));
        
        if (userInfo.FamilyName is not null) claims.Add(
            new Claim(ClaimTypes.Surname, userInfo.FamilyName));
        
        if (userInfo.Picture is not null) claims.Add(
            new Claim(KindeClaimTypes.Picture, userInfo.Picture));
        
        if (userInfo.Roles is not null && userInfo.Roles.Count > 0) 
            claims.AddRange(userInfo.Roles.Select(role => 
                new Claim(ClaimTypes.Role, role.Name)));
        
        if (userInfo.PermissionsList?.Any() ?? false) 
            claims.AddRange(userInfo.PermissionsList.Select(permission => 
                new Claim(KindeClaimTypes.Permissions, permission)));
        
        if (userInfo.OrganizationsList?.Any() ?? false) 
            claims.AddRange(userInfo.OrganizationsList.Select(org => 
                new Claim(KindeClaimTypes.Organizations, org)));
        
        if (userInfo.OrganizationCode is not null) 
            claims.Add(new Claim(KindeClaimTypes.OrganizationCode, userInfo.OrganizationCode));
        
        if (userInfo.Roles?.Any() ?? false) 
            claims.AddRange(userInfo.Roles.Select(role => 
                new Claim(KindeClaimTypes.Roles, JsonSerializer.Serialize(role))));
        
        if (userInfo.Organizations?.Any() ?? false) 
            claims.AddRange(userInfo.Organizations.Select(org => 
                new Claim(KindeClaimTypes.Organizations, JsonSerializer.Serialize(org))));
        
        _authenticationStateTask = Task.FromResult(
            new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(claims,
                authenticationType: nameof(ClientAuthenticationStateProvider)))));
    }

    public override Task<AuthenticationState> GetAuthenticationStateAsync() => _authenticationStateTask;
}

