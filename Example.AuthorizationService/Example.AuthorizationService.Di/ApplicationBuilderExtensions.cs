using Example.AuthorizationService.Dal.Contexts;
using Example.AuthorizationService.Di.Configs;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace Example.AuthorizationService.Di;

public static class ApplicationBuilderExtensions
{
    public static IApplicationBuilder FillAuthorizationServiceDatabase(this IApplicationBuilder builder)
    {
        using var serviceScope = builder.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope();
        var context = serviceScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        context.Database.Migrate();

        var roleManager = serviceScope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<int>>>();
        var applicationManager = serviceScope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var scopeManager = serviceScope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

        roleManager.InitializeDefaultRolesAsync().GetAwaiter().GetResult();
        applicationManager.InitializeOpenIddictApplications().GetAwaiter().GetResult();
        scopeManager.InitializeOpenIddictScopes().GetAwaiter().GetResult();

        return builder;
    }

    private static async Task InitializeDefaultRolesAsync(this RoleManager<IdentityRole<int>> roleManager)
    {
        foreach (var roleName in OpenIddictConfigs.Roles)
        {
            if (!await roleManager.RoleExistsAsync(roleName))
            {
                await roleManager.CreateAsync(new IdentityRole<int>(roleName));
            }
        }
    }

    private static async Task InitializeOpenIddictApplications(this IOpenIddictApplicationManager manager)
    {
        foreach (var application in OpenIddictConfigs.DevelopmentApplications)
        {
            if (await manager.FindByClientIdAsync(application.ClientId) is null)
            {
                await manager.CreateAsync(application);
            }
        }
    }

    private static async Task InitializeOpenIddictScopes(this IOpenIddictScopeManager manager)
    {
        foreach (var scope in OpenIddictConfigs.Scopes)
        {
            if (await manager.FindByNameAsync(scope.Name) is null)
            {
                await manager.CreateAsync(scope);
            }
        }
    }
}
