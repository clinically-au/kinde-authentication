using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Clinically.Kinde.Authentication.Blazor;
using Clinically.Kinde.Authentication.Identity;
using Clinically.Kinde.Authentication.ManagementApi;
using Clinically.Kinde.Authentication.Types;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Clinically.Kinde.Authentication;

public static class KindeAuthenticationBuilderExtension
{
    public static AuthenticationBuilder AddKindeAuthentication(this IServiceCollection services,
        IConfiguration configuration, Action<KindeAuthenticationOptions> kindeAuthenticationOptions)
    {
        services.Configure(kindeAuthenticationOptions);
        var configOptions = new KindeAuthenticationOptions();
        kindeAuthenticationOptions(configOptions);

        if (string.IsNullOrEmpty(configOptions.Authority)) configOptions.Authority = configuration["Kinde:Authority"] ?? throw new ArgumentException("Kinde:Authority not found in configuration");
        if (string.IsNullOrEmpty(configOptions.ClientId)) configOptions.ClientId = configuration["Kinde:ClientId"] ?? throw new ArgumentException("Kinde:ClientId not found in configuration");
        if (string.IsNullOrEmpty(configOptions.ClientSecret)) configOptions.ClientSecret = configuration["Kinde:ClientSecret"] ?? throw new ArgumentException("Kinde:ClientSecret not found in configuration");
        if (string.IsNullOrEmpty(configOptions.SignedOutRedirectUri)) configOptions.SignedOutRedirectUri = configuration["Kinde:SignedOutRedirectUri"] ?? throw new ArgumentException("Kinde:SignedOutRedirectUri not found in configuration");
        if (string.IsNullOrEmpty(configOptions.ManagementApiClientId)) configOptions.ManagementApiClientId = configuration["Kinde:ManagementApiClientId"] ?? throw new ArgumentException("Kinde:ManagementApiClientId not found in configuration");
        if (string.IsNullOrEmpty(configOptions.ManagementApiClientSecret)) configOptions.ManagementApiClientSecret = configuration["Kinde:ManagementApiClientSecret"] ?? throw new ArgumentException("Kinde:ManagementApiClientSecret not found in configuration");
        if (configOptions.UseJwtBearerValidation && string.IsNullOrEmpty(configOptions.JwtAudience)) configOptions.JwtAudience = configuration["Kinde:JwtAudience"] ?? throw new ArgumentException("Kinde:JwtAudience not found in configuration when UseJwtBearerValidation is true");
        
        services.AddHttpClient();
        services.AddHttpContextAccessor();
        services.AddScoped<IdentityRedirectManager>();
        services.AddScoped<AuthenticationStateProvider, ServerAuthenticationStateProvider>();
        
        var builder = services.AddAuthentication();
        
        builder.Services.Configure<AuthenticationOptions>(options =>
        {
            options.DefaultScheme = IdentityConstants.ApplicationScheme;
            options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
            options.DefaultSignOutScheme = IdentityConstants.ExternalScheme;
        });

        builder.AddOpenIdConnect("OpenIdConnect", options =>
        {
            var authority = configOptions.Authority;
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
                },
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
                        jsonToken.Claims.FirstOrDefault(x => x.Type == KindeClaimTypes.Email)?.Value ?? string.Empty));

                    // also need to transform the role claims so the AuthorizeAttribute can find them
                    newClaims.AddRange(jsonToken.Claims.Where(c => c.Type == KindeClaimTypes.Roles)
                        .Select(role =>
                            new Claim(ClaimTypes.Role, JsonSerializer.Deserialize<KindeRole>(role.Value)?.Name ?? string.Empty)));

                    ctx.Principal!.AddIdentity(new ClaimsIdentity(newClaims));

                    return Task.CompletedTask;
                }
            };
        });

        if (configOptions.UseJwtBearerValidation)
        {
            builder.AddJwtBearer(opt =>
            {
                opt.Authority = configOptions.Authority;
                opt.Audience = configOptions.JwtAudience;
                opt.TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidIssuer = configOptions.Authority,
                    ValidAudience = configOptions.JwtAudience,
                    IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
                    {
                        var client = new HttpClient();
                        var response = client.GetAsync(new Uri($"{configOptions.Authority}/.well-known/jwks")).Result;
                        var responseString = response.Content.ReadAsStringAsync().Result;
                        return JwksHelper.LoadKeysFromJson(responseString);
                    }
                };
            });
        }
        
        services.AddSingleton<CookieOidcRefresher>();

        if (configOptions.UseMemoryCacheTicketStore)
        {
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
        }
        else 
        {
            builder.AddIdentityCookies();
        }

        builder.Services.AddIdentityCore<KindeUser>()
            .AddUserManager<KindeUserManager>()
            .AddUserStore<KindeUserStore>()
            .AddRoles<KindeRole>()
            .AddRoleManager<KindeRoleManager>()
            .AddRoleStore<KindeRoleStore>()
            .AddSignInManager();

        services.AddScoped<IUserClaimsPrincipalFactory<KindeUser>, AdditionalUserClaimsPrincipalFactory>();

        services.AddScoped<KindeManagementClient>(x => ActivatorUtilities
            .CreateInstance<KindeManagementClient>(x, configOptions));
        
        services.AddSingleton<KindeManagementApiAuthenticationHelper>(x => ActivatorUtilities
            .CreateInstance<KindeManagementApiAuthenticationHelper>(x, configOptions));

        services.AddTransient<BlazorUserAccessor>();
        
        return builder;
    }
}