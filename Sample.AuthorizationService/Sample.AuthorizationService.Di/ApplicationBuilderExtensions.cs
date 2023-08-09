using Sample.AuthorizationService.Common.Defaults;
using Sample.AuthorizationService.Common.Entities;
using Sample.AuthorizationService.Dal.Contexts;
using Sample.AuthorizationService.Di.Configs;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;

namespace Sample.AuthorizationService.Di;

public static class ApplicationBuilderExtensions
{
    public static IApplicationBuilder FillAuthorizationServiceDatabase(this IApplicationBuilder builder, IWebHostEnvironment environment)
    {
        using var serviceScope = builder.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope();
        var context = serviceScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        context.Database.Migrate();

        var applicationManager = serviceScope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var scopeManager = serviceScope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

        applicationManager.InitializeOpenIddictApplications().GetAwaiter().GetResult();
        scopeManager.InitializeOpenIddictScopes().GetAwaiter().GetResult();

        if (!environment.IsProduction())
        {
            InitializeAspNetIdentityRoles(serviceScope.ServiceProvider).GetAwaiter().GetResult();
            InitializeAspNetIdentityUsers(serviceScope.ServiceProvider).GetAwaiter().GetResult();
        }

        return builder;
    }

    private static async Task InitializeAspNetIdentityRoles(this IServiceProvider serviceProvider)
    {
        var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole<int>>>();

        if (!await roleManager.Roles.AnyAsync())
        {
            foreach (var role in RolesDefaults.Roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                {
                    await roleManager.CreateAsync(new IdentityRole<int>(role));
                }
            }
        }
    }

    private static async Task InitializeAspNetIdentityUsers(this IServiceProvider serviceProvider)
    {
        var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        if (!await userManager.Users.AnyAsync())
        {
            foreach (var userDetails in UsersDefaults.Users)
            {
                if (await userManager.FindByIdAsync(userDetails.Id.ToString()) is not null)
                {
                    continue;
                }

                var user = new ApplicationUser
                {
                    UserName = userDetails.Email,
                    GivenName = userDetails.GivenName,
                    MiddleName = userDetails.MiddleName,
                    PicturePath = userDetails.PicturePath,
                    BackgroundPicturePath = userDetails.BackgroundPicturePath,
                    FamilyName = userDetails.FamilyName,
                    Nickname = userDetails.Nickname,
                    ZoneInfo = userDetails.ZoneInfo,
                    Gender = userDetails.Gender,
                    Locale = userDetails.Locale,
                    Email = userDetails.Email,
                    PhoneNumber = userDetails.PhoneNumber,
                    BirthDate = userDetails.BirthDate,
                };

                var result = await userManager.CreateAsync(user, UsersDefaults.Password);

                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, userDetails.Role.ToString());
                }
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
