using OpenIddict.Abstractions;

namespace Sample.AuthorizationService.Di.Configs;

internal static class OpenIddictConfigs
{
    internal static readonly IEnumerable<OpenIddictScopeDescriptor> Scopes = new[]
    {
        new OpenIddictScopeDescriptor
        {
            Description = "Grants access to the health API",
            DisplayName = "Sample Health API",
            Name = "Sample-health-api"
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
                new Uri("https://oauth.pstmn.io/v1/callback"),
            },
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.Logout,
                OpenIddictConstants.Permissions.Endpoints.Introspection,

                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                OpenIddictConstants.Scopes.OpenId,

                OpenIddictConstants.Permissions.Prefixes.Scope + "api",
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Phone,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Roles,
                OpenIddictConstants.Permissions.Scopes.Address,

                OpenIddictConstants.Permissions.ResponseTypes.Code
            }
        },
    };
}
