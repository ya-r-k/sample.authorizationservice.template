using OpenIddict.Abstractions;

namespace AuthorizationServiceExample.Di.Configs;

internal static class OpenIddictApplications
{
    internal static readonly List<OpenIddictApplicationDescriptor> DevelopmentApplications = new()
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
}
