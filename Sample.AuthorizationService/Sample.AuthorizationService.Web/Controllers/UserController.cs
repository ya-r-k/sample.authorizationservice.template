using Sample.AuthorizationService.Common.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sample.AuthorizationService.Web.Controllers;

/// <summary>
/// Provides endpoints for OpenIdConnect users management.
/// </summary>
public class UserController : Controller
{
    private readonly UserManager<ApplicationUser> userManager;

    /// <summary>
    /// Initializes a new instance of the <see cref="UserController"/> class.
    /// </summary>
    /// <param name="userManager">ASP.NET Identity user manager.</param>
    public UserController(UserManager<ApplicationUser> userManager)
    {
        this.userManager = userManager;
    }

    /// <summary>
    /// OpenIdConnect user info endpoint
    /// </summary>
    [IgnoreAntiforgeryToken]
    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("~/connect/userinfo")]
    [HttpPost("~/connect/userinfo")]
    [Produces("application/json")]
    public async Task<IActionResult> Userinfo()
    {
        var user = await userManager.FindByIdAsync(User.GetClaim(Claims.Subject));

        if (user is null)
        {
            return Challenge(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The specified access token is bound to an account that no longer exists."
                }));
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            // Note: the "sub" claim is a mandatory claim and must be included in the JSON response.
            [Claims.Subject] = await userManager.GetUserIdAsync(user)
        };

        if (User.HasScope(Scopes.Email))
        {
            claims[Claims.Email] = await userManager.GetEmailAsync(user);
            claims[Claims.EmailVerified] = await userManager.IsEmailConfirmedAsync(user);
        }

        if (User.HasScope(Scopes.Phone))
        {
            claims[Claims.PhoneNumber] = await userManager.GetPhoneNumberAsync(user);
            claims[Claims.PhoneNumberVerified] = await userManager.IsPhoneNumberConfirmedAsync(user);
        }

        if (User.HasScope(Scopes.Roles))
        {
            claims[Claims.Role] = await userManager.GetRolesAsync(user);
        }

        if (User.HasScope(Scopes.Profile))
        {
            claims[Claims.GivenName] = user.GivenName;
            claims[Claims.FamilyName] = user.FamilyName;
            claims[Claims.MiddleName] = user.MiddleName;
            claims[Claims.Nickname] = user.Nickname;
            claims[Claims.Birthdate] = user.BirthDate;
            claims[Claims.Gender] = user.Gender.ToString();
            claims[Claims.Locale] = user.Locale;
            claims[Claims.Zoneinfo] = user.ZoneInfo;
            claims[Claims.Picture] = user.PicturePath;
        }

        // Note: the complete list of standard claims supported by the OpenID Connect specification
        // can be found here: http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

        return Ok(claims);
    }
}
