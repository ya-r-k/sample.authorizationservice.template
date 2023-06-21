using OpenIddict.Abstractions;
using Example.AuthorizationService.Common.Enums;
using System.Data;

namespace Example.AuthorizationService.Di.Configs;

internal static class OpenIddictConfigs
{
    internal static readonly IEnumerable<OpenIddictScopeDescriptor> Scopes = new[]
    {
        new OpenIddictScopeDescriptor
        {
            Description = "Grants access to the health API",
            DisplayName = "Forbairt Health API",
            Name = "forbairt-health-api"
        },
    };

    internal static readonly IEnumerable<OpenIddictApplicationDescriptor> DevelopmentApplications = new[]
    {
        new OpenIddictApplicationDescriptor
        {
            ClientId = "postman",
            ClientSecret = "postman-secret",
            DisplayName = "Postman",
            RedirectUris =
            {
                new Uri("https://oauth.pstmn.io/v1/callback")
            },
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,

                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.GrantTypes.DeviceCode,

                OpenIddictConstants.Permissions.Prefixes.Scope + "api",
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Phone,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Address,

                OpenIddictConstants.Permissions.ResponseTypes.Code
            }
        },
    };

    internal static IEnumerable<string> Roles => Enum.GetValues(typeof(Role))
            .Cast<Role>()
            .Select(x => x.ToString());
}
