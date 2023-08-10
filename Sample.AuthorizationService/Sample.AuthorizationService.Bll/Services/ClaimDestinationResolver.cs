using OpenIddict.Abstractions;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sample.AuthorizationService.Bll.Services;

/// <summary>
/// 
/// </summary>
public class ClaimDestinationResolver : IClaimDestinationResolver
{
    /// <inheritdoc />
    public IEnumerable<string> GetDestinations(Claim claim)
    {
        return claim switch
        {
            { Type: Claims.Name } when claim.Subject.HasScope(Scopes.Profile) => new[] { Destinations.AccessToken, Destinations.IdentityToken },
            { Type: Claims.Email } when claim.Subject.HasScope(Scopes.Email) => new[] { Destinations.AccessToken, Destinations.IdentityToken },
            { Type: Claims.Role } when claim.Subject.HasScope(Scopes.Roles) => new[] { Destinations.AccessToken, Destinations.IdentityToken },
            { Type: "AspNet.Identity.SecurityStamp" } => Array.Empty<string>(),
            _ => new[] { Destinations.AccessToken },
        };
    }
}
