using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Clinically.Kinde.Authentication.Blazor;
using Clinically.Kinde.Authentication.Identity;
using Clinically.Kinde.Authentication.ManagementApi;
using Clinically.Kinde.Authentication.Types;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Clinically.Kinde.Authentication;

public static class KindeAuthenticationBuilderExtensions
{
    private static string GetRequiredConfiguration(string key, IConfiguration configuration)
    {
        return configuration[key] ??
               throw new ArgumentException($"{key} not found in configuration");
    }

    public static AuthenticationBuilder AddKindeJwtBearerAuthentication(this IServiceCollection services,
        IConfiguration configuration, Action<KindeAuthenticationOptions>? kindeAuthenticationOptions = null)
    {
        kindeAuthenticationOptions ??= _ => { };
        
        services.Configure(kindeAuthenticationOptions);
        var configOptions = new KindeAuthenticationOptions();
        kindeAuthenticationOptions(configOptions);

        if (string.IsNullOrEmpty(configOptions.Domain))
            configOptions.Domain = GetRequiredConfiguration("Kinde:Domain", configuration);
        if (string.IsNullOrEmpty(configOptions.ClientId))
            configOptions.ClientId = GetRequiredConfiguration("Kinde:ClientId", configuration);
        if (string.IsNullOrEmpty(configOptions.ClientSecret))
            configOptions.ClientSecret = GetRequiredConfiguration("Kinde:ClientSecret", configuration);
        if (string.IsNullOrEmpty(configOptions.ManagementApiAudience))
            configOptions.ManagementApiAudience = Path.Combine(configOptions.Domain, "api");
        if (string.IsNullOrEmpty(configOptions.JwtAudience))
            configOptions.JwtAudience = GetRequiredConfiguration("Kinde:JwtAudience", configuration);

        services.AddHttpClient();

        var builder = services.AddAuthentication();

        builder.AddJwtBearer(opt =>
        {
            opt.SaveToken = true;
            opt.Authority = configOptions.Domain;
            opt.Audience = configOptions.JwtAudience;
            opt.TokenValidationParameters = new TokenValidationParameters
            {
                SaveSigninToken = true,
                ValidIssuer = configOptions.Domain,
                ValidAudience = configOptions.JwtAudience,
                IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
                {
                    var client = new HttpClient();
                    var response = client.GetAsync(new Uri(Path.Combine(configOptions.Domain, ".well-known/jwks"))).Result;
                    var responseString = response.Content.ReadAsStringAsync().Result;
                    return JwksHelper.LoadKeysFromJson(responseString);
                }
            };
            opt.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = context =>
                {
                    // place holder method for debugging failures
                    Console.Error.WriteLine($"Authentication failed: {context.Exception.Message}");
                    return Task.CompletedTask;
                },
            OnTokenValidated = async context =>
            {
                var claims = context.Principal?.Claims?.ToList();
                if (claims is null)
                {
                    context.Fail("No claims found in the token");
                    return;
                }

                var userId = claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
                if (userId is null)
                {
                    context.Fail("No user id found in the token");
                    return;
                }
                
                var orgCode = claims
                    .FirstOrDefault(x => x.Type == KindeClaimTypes.OrganizationCode)
                    ?.Value;
                if (configOptions.UsersMustHaveOrganization && orgCode is null)
                {
                    context.Fail("No organization code found in the token");
                    return;
                }

                // The following extracts roles, permissions, and organizations - all of which require
                // the user to be part of an organization
                if (string.IsNullOrEmpty(orgCode)) return;

                var newClaims = new List<Claim>();

                var kindeClient =
                    context.HttpContext.RequestServices.GetRequiredService<KindeManagementClient>();

                // Retrieves the claims from the authToken if they exist, otherwise fetches them using the 
                // Management API. This is done to avoid making unnecessary calls to the Management API.
                // However, if the user does not have roles or permissions, then these calls become 
                // unnecessary.
                // TODO: make this configurable or add caching
                if (configOptions.UsersMustHaveOrganization && claims.All(clm => clm.Type != KindeClaimTypes.Permissions))
                {
                    var permissions =
                        (await kindeClient
                            .Organizations.GetOrganizationUserPermissionsAsync(orgCode!, userId).ConfigureAwait(false))
                        .Permissions ?? [];
                    if (permissions.Count != 0)
                    {
                        var permissionNames = permissions.Select(perm => perm.Name).ToList();
                        newClaims.AddRange(
                            permissionNames.Select(perm => new Claim(KindeClaimTypes.Permissions, perm))
                        );
                    }
                }

                if (claims.All(clm => clm.Type != KindeClaimTypes.Organizations))
                {
                    var organizations = (await kindeClient.Users.GetUsersAsync(userId: userId, expand:"organizations")
                        .ConfigureAwait(false)).Users.First().Organizations;
                    
                    if (organizations.Count != 0)
                    {
                        newClaims.AddRange(
                            organizations.Select(org => new Claim(KindeClaimTypes.Organizations, org))
                        );
                    }
                }

                if (claims.Any(clm => clm.Type == KindeClaimTypes.Roles))
                {
                    var claimRoles = claims.Where(clm => clm.Type == KindeClaimTypes.Roles).Select(
                        clm => JsonSerializer.Deserialize<KindeRole>(clm.Value));
                    newClaims.AddRange(claimRoles.Select(role => new Claim(ClaimTypes.Role, role!.Name)));
                }
                else
                {
                    var roles =
                        (await kindeClient.Organizations.GetOrganizationUserRolesAsync(orgCode!, userId).ConfigureAwait(false))
                        .Roles ?? [];
                    if (roles.Count != 0)
                    {
                        newClaims.AddRange(
                            roles.Select(role => new Claim(
                                KindeClaimTypes.Roles,
                                JsonSerializer.Serialize(role)
                            ))
                        );
                        newClaims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role.Name)));
                    }
                }
                
                context.Principal!.AddIdentity(new ClaimsIdentity(newClaims));
            }
            };
        });

        builder.Services.AddIdentityCore<KindeUser>()
            .AddUserManager<KindeUserManager>()
            .AddUserStore<KindeUserStore>()
            .AddRoles<KindeRole>()
            .AddRoleManager<KindeRoleManager>()
            .AddRoleStore<KindeRoleStore>()
            .AddSignInManager();

        builder.Services.AddScoped<KindeManagementClient>(x => ActivatorUtilities
            .CreateInstance<KindeManagementClient>(x, configOptions));

        builder.Services.AddSingleton<KindeManagementApiAuthenticationHelper>(x => ActivatorUtilities
            .CreateInstance<KindeManagementApiAuthenticationHelper>(x, configOptions));

        return builder;
    }

    public static AuthenticationBuilder AddKindeIdentityAuthentication(this IServiceCollection services,
        IConfiguration configuration, Action<KindeAuthenticationOptions>? kindeAuthenticationOptions = null)
    {
        kindeAuthenticationOptions ??= _ => { };

        services.Configure(kindeAuthenticationOptions);
        var configOptions = new KindeAuthenticationOptions();
        kindeAuthenticationOptions(configOptions);

        if (string.IsNullOrEmpty(configOptions.Domain))
            configOptions.Domain = GetRequiredConfiguration("Kinde:Domain", configuration);
        if (string.IsNullOrEmpty(configOptions.ClientId))
            configOptions.ClientId = GetRequiredConfiguration("Kinde:ClientId", configuration);
        if (string.IsNullOrEmpty(configOptions.ClientSecret))
            configOptions.ClientSecret = GetRequiredConfiguration("Kinde:ClientSecret", configuration);
        if (string.IsNullOrEmpty(configOptions.SignedOutRedirectUri))
            configOptions.SignedOutRedirectUri = GetRequiredConfiguration("Kinde:SignedOutRedirectUri", configuration);
        if (string.IsNullOrEmpty(configOptions.ManagementApiAudience))
            configOptions.ManagementApiAudience = Path.Combine(configOptions.Domain, "api");
        
        services.AddHttpClient();
        services.AddHttpContextAccessor();

        if (configOptions.UseBlazor)
            services.AddScoped<AuthenticationStateProvider, ServerAuthenticationStateProvider>();

        services.AddScoped<IdentityRedirectManager>();


        var builder = services.AddAuthentication();

        builder.Services.Configure<AuthenticationOptions>(options =>
        {
            options.DefaultScheme = IdentityConstants.ApplicationScheme;
            options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
            options.DefaultSignOutScheme = IdentityConstants.ExternalScheme;
        });

        builder.AddOpenIdConnect("OpenIdConnect", options =>
        {
            var authority = configOptions.Domain;
            options.Authority = authority;
            options.ClientId = configOptions.ClientId;
            options.ClientSecret = configOptions.ClientSecret;
            options.SignedOutRedirectUri = configOptions.SignedOutRedirectUri;
            options.ResponseType = OpenIdConnectResponseType.Code;
            options.MapInboundClaims = false;
            options.Scope.Add(OpenIdConnectScope.OpenIdProfile);
            options.Scope.Add(OpenIdConnectScope.Email);
            options.Scope.Add("offline");
            options.SaveTokens = true;
            options.GetClaimsFromUserInfoEndpoint = true;

            options.TokenValidationParameters = new TokenValidationParameters
            {
                IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
                {
                    var client = new HttpClient();
                    var response = client.GetAsync(new Uri($"{authority}/.well-known/jwks")).Result;
                    var responseString = response.Content.ReadAsStringAsync().Result;
                    return JwksHelper.LoadKeysFromJson(responseString);
                }
            };

            options.Events = new OpenIdConnectEvents
            {
                OnTokenValidated = ctx =>
                {
                    var handler = new JwtSecurityTokenHandler();
                    if (ctx.TokenEndpointResponse == null) return Task.CompletedTask;

                    var jsonToken = handler.ReadJwtToken(ctx.TokenEndpointResponse.AccessToken);

                    var newClaims = new List<Claim>();

                    newClaims.AddRange(jsonToken.Claims.Where(c => c.Type == KindeClaimTypes.Permissions));
                    newClaims.AddRange(jsonToken.Claims.Where(c => c.Type == KindeClaimTypes.Roles));
                    newClaims.Add(new Claim(KindeClaimTypes.OrganizationCode,
                        jsonToken.Claims.FirstOrDefault(x => x.Type == KindeClaimTypes.OrganizationCode)?.Value ??
                        string.Empty));
                    newClaims.Add(new Claim(ClaimTypes.Email,
                        jsonToken.Claims.FirstOrDefault(x => x.Type == KindeClaimTypes.Email)?.Value ??
                        string.Empty));

                    // also need to transform the role claims so the AuthorizeAttribute can find them
                    newClaims.AddRange(jsonToken.Claims.Where(c => c.Type == KindeClaimTypes.Roles)
                        .Select(role =>
                            new Claim(ClaimTypes.Role,
                                JsonSerializer.Deserialize<KindeRole>(role.Value)?.Name ?? string.Empty)));

                    ctx.Principal!.AddIdentity(new ClaimsIdentity(newClaims));

                    return Task.CompletedTask;
                }
            };
        });

        builder.Services.AddSingleton<CookieOidcRefresher>();

        if (configOptions.UseMemoryCacheTicketStore)
            builder.AddIdentityCookies(bld =>
            {
                bld.ExternalCookie!.PostConfigure(x =>
                    {
                        x.SessionStore = new MemoryCacheTicketStore();
                        x.ExpireTimeSpan = TimeSpan.FromMinutes(30);
                    })
                    .Configure<CookieOidcRefresher>((cookieOptions, refresher) =>
                    {
                        cookieOptions.Events.OnValidatePrincipal =
                            context => refresher.ValidateOrRefreshCookieAsync(context,
                                IdentityConstants.ExternalScheme);
                    });
            });
        else
            builder.AddIdentityCookies();

        builder.Services.AddIdentityCore<KindeUser>()
            .AddUserManager<KindeUserManager>()
            .AddUserStore<KindeUserStore>()
            .AddRoles<KindeRole>()
            .AddRoleManager<KindeRoleManager>()
            .AddRoleStore<KindeRoleStore>()
            .AddSignInManager();

        builder.Services.AddScoped<IUserClaimsPrincipalFactory<KindeUser>, AdditionalUserClaimsPrincipalFactory>();

        if (configOptions.UseBlazor) builder.Services.AddTransient<BlazorUserAccessor>();

        builder.Services.AddScoped<KindeManagementClient>(x => ActivatorUtilities
            .CreateInstance<KindeManagementClient>(x, configOptions));

        builder.Services.AddSingleton<KindeManagementApiAuthenticationHelper>(x => ActivatorUtilities
            .CreateInstance<KindeManagementApiAuthenticationHelper>(x, configOptions));

        return builder;
    }
}