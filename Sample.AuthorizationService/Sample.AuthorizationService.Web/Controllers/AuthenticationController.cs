using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Client.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sample.AuthorizationService.Web.Controllers;

/// <summary>
/// Provides endpoints for the external authentication providers.
/// Note: this controller uses the same callback action for all providers
/// but for users who prefer using a different action per provider,
/// the following action can be split into separate actions.
/// </summary>
public class AuthenticationController : Controller
{
    /// <summary>
    /// Log ins in the external provider
    /// </summary>
    /// <exception cref="InvalidOperationException">Throws if the provider is not supported.</exception>
    [HttpGet("~/callback/login/{provider}")]
    [HttpPost("~/callback/login/{provider}")]
    [IgnoreAntiforgeryToken]
    public async Task<ActionResult> LogInCallback()
    {
        var result = await HttpContext.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);

        if (result.Principal is not ClaimsPrincipal { Identity.IsAuthenticated: true })
        {
            throw new InvalidOperationException("The external authorization data cannot be used for authentication.");
        }

        var claims = new List<Claim>(result.Principal.Claims
            .Select(claim => claim switch
            {
                { Type: Claims.Subject } or
                { Type: "id", Issuer: "https://github.com/" or "https://twitter.com/" }
                    => new Claim(ClaimTypes.NameIdentifier, claim.Value, claim.ValueType, claim.Issuer),
                { Type: Claims.Name }
                    => new Claim(ClaimTypes.Name, claim.Value, claim.ValueType, claim.Issuer),
                _ => claim
            })
            .Where(claim => claim switch
            {
                { Type: ClaimTypes.NameIdentifier or ClaimTypes.Name } => true,
                { Type: "bio", Issuer: "https://github.com/" } => true,
                _ => false
            }));

        var identity = new ClaimsIdentity(claims,
            authenticationType: IdentityConstants.ExternalScheme,
            nameType: ClaimTypes.NameIdentifier,
            roleType: ClaimTypes.Role);

        var properties = new AuthenticationProperties(result.Properties.Items);

        properties.StoreTokens(result.Properties.GetTokens().Where(token => token switch
        {
            {
                Name: OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken or
                      OpenIddictClientAspNetCoreConstants.Tokens.RefreshToken
            } => true,
            _ => false
        }));

        return SignIn(new ClaimsPrincipal(identity), properties, IdentityConstants.ExternalScheme);
    }
}
