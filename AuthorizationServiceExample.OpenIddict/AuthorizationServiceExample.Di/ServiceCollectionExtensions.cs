using AuthorizationServiceExample.Bll.Services;
using AuthorizationServiceExample.Common.Entities;
using AuthorizationServiceExample.Dal.Contexts;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace AuthorizationServiceExample.Di;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection ConfigureAspNetCoreIdentity(this IServiceCollection services)
    {
        services.AddIdentity<ApplicationUser, IdentityRole>(options => options.SignIn.RequireConfirmedAccount = true)
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddSignInManager()
            .AddDefaultTokenProviders();

        return services;
    }

    public static IServiceCollection ConfigureOpenIddict(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<ApplicationDbContext>(options =>
        {
            // Configure the context to use an in-memory store.
            options.UseSqlServer(configuration.GetConnectionString("DefaultConnection"));

            // Register the entity sets needed by OpenIddict.
            options.UseOpenIddict();
        });

        services.AddOpenIddict()
            .AddCore(options =>
            {
                // Configure OpenIddict to use the Entity Framework Core stores and models.
                // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
                options.UseEntityFrameworkCore()
                       .UseDbContext<ApplicationDbContext>();
            })
            .AddServer(options =>
            {
                // Enable the required endpoints
                options.SetAuthorizationEndpointUris("connect/authorize")
                       .SetDeviceEndpointUris("connect/device")
                       .SetIntrospectionEndpointUris("connect/introspect")
                       .SetLogoutEndpointUris("connect/logout")
                       .SetTokenEndpointUris("connect/token")
                       .SetUserinfoEndpointUris("connect/userinfo")
                       .SetVerificationEndpointUris("connect/verify");

                // Add all auth flows you want to support
                // Supported flows are:
                //      - Authorization code flow
                //      - Client credentials flow
                //      - Device code flow
                //      - Implicit flow
                //      - Password flow
                //      - Refresh token flow
                options.AllowAuthorizationCodeFlow()
                       .RequireProofKeyForCodeExchange();

                options.AllowDeviceCodeFlow()
                       .AllowPasswordFlow()
                       .AllowRefreshTokenFlow();

                // Register your scopes - Scopes are a list of identifiers used to specify
                // what access privileges are requested.
                options.RegisterScopes(
                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Roles,
                    "api");

                // Register the signing and encryption credentials.
                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                // Set the lifetime of your tokens
                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(30));
                options.SetRefreshTokenLifetime(TimeSpan.FromDays(7));

                // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                options.UseAspNetCore()
                       .EnableStatusCodePagesIntegration()
                       .EnableAuthorizationEndpointPassthrough()
                       .EnableLogoutEndpointPassthrough()
                       .EnableTokenEndpointPassthrough()
                       .EnableUserinfoEndpointPassthrough()
                       .EnableVerificationEndpointPassthrough();
            })
            .AddValidation(options =>
            {
                // Import the configuration from the local OpenIddict server instance.
                options.UseLocalServer();

                // Register the ASP.NET Core host.
                options.UseAspNetCore();
            });

        return services;
    }

    public static IServiceCollection AddBllServices(this IServiceCollection services)
    {
        services.AddTransient<IEmailSender, AuthMessageSender>();
        services.AddTransient<ISmsSender, AuthMessageSender>();

        return services;
    }
}
