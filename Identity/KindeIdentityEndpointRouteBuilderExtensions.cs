using System.Security.Claims;
using Clinically.Kinde.Authentication.Types;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;

namespace Clinically.Kinde.Authentication.Identity;

public static class KindeIdentityEndpointRouteBuilderExtensions
{
    public static IEndpointConventionBuilder MapKindeIdentityEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var accountGroup = endpoints.MapGroup("/Account");

        accountGroup.MapGet("/Login", (
            HttpContext context,
            [FromServices] SignInManager<KindeUser> signInManager,
            [FromQuery] string? returnUrl) =>
        {
            IEnumerable<KeyValuePair<string, StringValues>> query =
            [
                new("ReturnUrl", string.IsNullOrEmpty(returnUrl) ? "/" : returnUrl),
            ];

            var redirectUrl = UriHelper.BuildRelative(
                context.Request.PathBase,
                "/Account/LoginCallback",
                QueryString.Create(query));

            var properties = signInManager.ConfigureExternalAuthenticationProperties("OpenIdConnect", redirectUrl);
            return TypedResults.Challenge(properties, ["OpenIdConnect"]);
        });

        accountGroup.MapGet("/LoginCallback",
            new Func<HttpContext, SignInManager<KindeUser>, string?, string?, Task<RedirectHttpResult>>(async (context,
                [FromServices] signInManager,
                [FromQuery] returnUrl,
                [FromQuery] remoteError) =>
            {
                ArgumentException.ThrowIfNullOrEmpty(returnUrl);
                
                if (remoteError is not null)
                {
                    return TypedResults.Redirect("/Error");
                }

                var info = await signInManager.GetExternalLoginInfoAsync();
                if (info is null)
                {
                    return TypedResults.Redirect("/Error");
                }

                var signinResult =
                    await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey,
                        isPersistent: false);
                if (!signinResult.Succeeded)
                {
                    return TypedResults.Redirect("/Error");
                }

                return TypedResults.Redirect(returnUrl);
            }));

        accountGroup.MapPost("/Logout", async (
            ClaimsPrincipal user,
            SignInManager<KindeUser> signInManager,
            IConfiguration config,
            [FromForm] string returnUrl) =>
        {
            await signInManager.SignOutAsync();
            var authority = config.GetRequiredSection("Kinde:Domain").Value;
            var baseUrl = config.GetRequiredSection("AppConfig:BaseUrl").Value;
            var logoutUri = $"{authority}/logout?redirect={Uri.EscapeDataString(baseUrl!)}";
            return TypedResults.Redirect(logoutUri);
        });

        return accountGroup;
    }

}

