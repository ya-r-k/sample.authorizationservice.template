using AuthorizationServiceExample.Dal.Contexts;
using AuthorizationServiceExample.Di.Configs;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace AuthorizationServiceExample.Di;

public static class ApplicationBuilderExtensions
{
    public static IApplicationBuilder FillAuthorizationServiceDatabase(this IApplicationBuilder builder)
    {
        using var serviceScope = builder.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope();
        var context = serviceScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        context.Database.Migrate();

        var manager = serviceScope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        manager.InitializeOpenIddictApplications().GetAwaiter().GetResult();

        return builder;
    }

    private static async Task InitializeOpenIddictApplications(this IOpenIddictApplicationManager manager)
    {
        foreach (var application in OpenIddictApplications.DevelopmentApplications)
        {
            if (await manager.FindByClientIdAsync(application.ClientId) is null)
            {
                await manager.CreateAsync(application);
            }
        }
    }
}
