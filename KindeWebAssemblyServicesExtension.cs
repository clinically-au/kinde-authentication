using Clinically.Kinde.Authentication.Blazor;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace Clinically.Kinde.Authentication;

public static class KindeWebAssemblyServicesExtension
{
    public static IServiceCollection AddKindeWebAssemblyClient(this IServiceCollection services)
    {
        services.AddSingleton<AuthenticationStateProvider, ClientAuthenticationStateProvider>();
        return services;
    }
}
