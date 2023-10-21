using Sample.AuthorizationService.Bll.Services;
using Sample.AuthorizationService.Common.Entities;
using Sample.AuthorizationService.Dal.Contexts;
using Sample.AuthorizationService.Dal.Repositories;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sample.AuthorizationService.Di;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection ConfigureAspNetCoreIdentity(this IServiceCollection services)
    {
        services.AddIdentity<ApplicationUser, IdentityRole<int>>(options =>
        {
            options.SignIn.RequireConfirmedAccount = false;
        })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddSignInManager()
            .AddDefaultTokenProviders();

        return services;
    }

    public static IServiceCollection ConfigureOpenIddict(this IServiceCollection services, IConfiguration configuration, IWebHostEnvironment environment, bool isRunningInContainer)
    {
        services.AddDbContextFactory<ApplicationDbContext>(options =>
        {
            options.UseSqlServer(isRunningInContainer
                ? configuration.GetConnectionString("Docker")
                : configuration.GetConnectionString("Default"));

            options.UseOpenIddict();
        });

        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                       .UseDbContext<ApplicationDbContext>();

                options.UseQuartz(builder =>
                {
                    builder.Configure(options => 
                    { 
                        options.MaximumRefireCount = 3;
                    });
                });
            })
            .AddServer(options =>
            {
                options.SetAuthorizationEndpointUris("connect/authorize")
                       .SetTokenEndpointUris("connect/token")
                       .SetUserinfoEndpointUris("connect/userinfo")
                       .SetIntrospectionEndpointUris("connect/introspect")
                       .SetLogoutEndpointUris("connect/logout");

                options.AllowAuthorizationCodeFlow()
                       .RequireProofKeyForCodeExchange();

                options.AllowClientCredentialsFlow()
                       .AllowRefreshTokenFlow();

                // Register your scopes - Scopes are a list of identifiers used to specify
                // what access privileges are requested.
                options.RegisterScopes(
                    OpenIddictConstants.Scopes.Email,
                    OpenIddictConstants.Scopes.Phone,
                    OpenIddictConstants.Scopes.Profile,
                    OpenIddictConstants.Scopes.Roles,
                    "api");

                // Register the signing and encryption credentials.
                if (environment.IsDevelopment())
                {
                    options.AddEphemeralEncryptionKey()
                           .AddEphemeralSigningKey();
                }
                else
                {
                    options.AddEncryptionCertificate(LoadCertificate(
                               configuration["AuthServer:EncryptionCertificatePath"],
                               configuration["AuthServer:CertificatePassword"],
                               configuration["AuthServer:EncryptionCertificateSubject"],
                               X509KeyUsageFlags.KeyEncipherment))
                           .AddSigningCertificate(LoadCertificate(
                               configuration["AuthServer:SigningCertificatePath"],
                               configuration["AuthServer:CertificatePassword"],
                               configuration["AuthServer:SigningCertificateSubject"],
                               X509KeyUsageFlags.DigitalSignature));
                }

                // Set the lifetime of your tokens
                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(30));
                options.SetRefreshTokenLifetime(TimeSpan.FromDays(7));

                //options.DisableAccessTokenEncryption();

                // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                options.UseAspNetCore()
                       .EnableStatusCodePagesIntegration()
                       .EnableAuthorizationEndpointPassthrough()
                       .EnableLogoutEndpointPassthrough()
                       .EnableTokenEndpointPassthrough()
                       .EnableUserinfoEndpointPassthrough();
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();

                options.UseAspNetCore();
            });

        return services;
    }

    public static IServiceCollection AddServices(this IServiceCollection services)
    {
        services.AddScoped<IUserService, UserService>();

        services.AddScoped<IUserRepository, UserRepository>();

        services.AddTransient<IClaimDestinationResolver, ClaimDestinationResolver>();

        services.AddTransient<IEmailSender, AuthMessageSender>();
        services.AddTransient<ISmsSender, AuthMessageSender>();

        return services;
    }

    private static X509Certificate2 LoadCertificate(string path, string password, string distinguishedName, X509KeyUsageFlags keyUsages)
    {
        if (!File.Exists(path))
        {
            GenerateCertificate(path, password, distinguishedName, keyUsages);
        }

        return new X509Certificate2(path, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }

    private static void GenerateCertificate(string path, string password, string distinguishedName, X509KeyUsageFlags keyUsages)
    {
        using var algorithm = RSA.Create(keySizeInBits: 2048);

        var subject = new X500DistinguishedName(distinguishedName);
        var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsages, critical: true));

        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(365));

        File.WriteAllBytes(path, certificate.Export(X509ContentType.Pfx, password));
    }
}
