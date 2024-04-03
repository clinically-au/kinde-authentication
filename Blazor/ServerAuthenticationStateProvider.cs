using System.Diagnostics;
using System.Security.Claims;
using Clinically.Kinde.Authentication.Identity;
using Clinically.Kinde.Authentication.Types;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Clinically.Kinde.Authentication.Blazor;

internal sealed class ServerAuthenticationStateProvider
    : RevalidatingServerAuthenticationStateProvider
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly PersistentComponentState _state;
    private readonly IdentityOptions _options;
    private readonly PersistingComponentStateSubscription _subscription;

    private Task<AuthenticationState>? _authenticationStateTask;

    public ServerAuthenticationStateProvider(
        ILoggerFactory loggerFactory,
        IServiceScopeFactory serviceScopeFactory,
        PersistentComponentState persistentComponentState,
        IOptions<IdentityOptions> optionsAccessor)
        : base(loggerFactory)
    {
        _scopeFactory = serviceScopeFactory;
        _state = persistentComponentState;
        _options = optionsAccessor.Value;

        AuthenticationStateChanged += OnAuthenticationStateChanged;
        _subscription = _state.RegisterOnPersisting(OnPersistingAsync, RenderMode.InteractiveWebAssembly);
    }

    // TODO: make this configurable
    protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(30);

    protected override async Task<bool> ValidateAuthenticationStateAsync(
        AuthenticationState authenticationState, CancellationToken cancellationToken)
    {
        // Get the user manager from a new scope to ensure it fetches fresh data
        await using var scope = _scopeFactory.CreateAsyncScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<KindeUser>>();
        return await ValidateSecurityStampAsync(userManager, authenticationState.User);
    }

    private async Task<bool> ValidateSecurityStampAsync(UserManager<KindeUser> userManager, ClaimsPrincipal principal)
    {
        var user = await userManager.GetUserAsync(principal);
        if (user is null)
        {
            return false;
        }
        else if (!userManager.SupportsUserSecurityStamp)
        {
            return true;
        }
        else
        {
            var principalStamp = principal.FindFirstValue(_options.ClaimsIdentity.SecurityStampClaimType);
            var userStamp = await userManager.GetSecurityStampAsync(user);
            return principalStamp == userStamp;
        }
    }

    private void OnAuthenticationStateChanged(Task<AuthenticationState> task)
    {
        _authenticationStateTask = task;
    }

    private async Task OnPersistingAsync()
    {
        if (_authenticationStateTask is null)
        {
            throw new UnreachableException($"Authentication state not set in {nameof(OnPersistingAsync)}().");
        }

        var authenticationState = await _authenticationStateTask;
        var principal = authenticationState.User;

        if (principal.Identity?.IsAuthenticated == true)
        {
            var userId = principal.GetId();
            var email = principal.GetEmail();

            if (userId != null && email != null)
            {
                _state.PersistAsJson(nameof(KindeUserInfo), new KindeUserInfo()
                {
                    Id = userId,
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
                });
            }
        }
    }

    protected override void Dispose(bool disposing)
    {
        _subscription.Dispose();
        AuthenticationStateChanged -= OnAuthenticationStateChanged;
        base.Dispose(disposing);
    }


}



