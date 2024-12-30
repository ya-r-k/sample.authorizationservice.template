using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Sample.AuthorizationService.Common.Entities;
using Sample.AuthorizationService.Web.Metrics;
using System.Security.Claims;

namespace Sample.AuthorizationService.Web.Controllers;

/// <summary>
/// Контроллер для обработки OAuth 2.0/OpenID Connect запросов.
/// Обрабатывает основные эндпоинты для аутентификации и выдачи токенов.
/// </summary>
public class AuthenticationController : Controller
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<AuthenticationController> _logger;

    public AuthenticationController(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        ILogger<AuthenticationController> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _logger = logger;
    }

    [HttpPost("~/connect/token")]
    public async Task<IActionResult> Token()
    {
        using (AuthMetrics.MeasureRequestDuration("token_request"))
        {
            var request = HttpContext.GetOpenIddictServerRequest() ?? 
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            // Определяем тип grant и вызываем соответствующий обработчик
            return request switch
            {
                { IsPasswordGrantType: true } => await HandlePasswordGrantType(request),
                { IsAuthorizationCodeGrantType: true } => await HandleAuthorizationCodeGrantType(request),
                { IsRefreshTokenGrantType: true } => await HandleRefreshTokenGrantType(request),
                { IsClientCredentialsGrantType: true } => await HandleClientCredentialsGrantType(request),
                _ => throw new NotImplementedException("The specified grant type is not implemented.")
            };
        }
    }

    private async Task<IActionResult> HandlePasswordGrantType(OpenIddictRequest request)
    {
        var user = await _userManager.FindByNameAsync(request.Username);
        if (user == null || !await ValidatePassword(user, request.Password))
        {
            AuthMetrics.LoginAttempted(false);
            return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        AuthMetrics.LoginAttempted(true);
        return await SignInUser(user);
    }

    private async Task<IActionResult> HandleAuthorizationCodeGrantType(OpenIddictRequest request)
    {
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var user = await _userManager.FindByIdAsync(result.Principal.GetClaim(Claims.Subject));
        
        return user == null ? 
            Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme) : 
            await SignInUser(user);
    }

    private async Task<IActionResult> HandleRefreshTokenGrantType(OpenIddictRequest request)
    {
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var user = await _userManager.FindByIdAsync(result.Principal.GetClaim(Claims.Subject));
        
        return user == null ? 
            Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme) : 
            await SignInUser(user);
    }

    private async Task<IActionResult> HandleClientCredentialsGrantType(OpenIddictRequest request)
    {
        var application = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var identity = new ClaimsIdentity(
            authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.AddClaim(Claims.Subject, application.Principal.GetClaim(Claims.ClientId));
        
        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<bool> ValidatePassword(ApplicationUser user, string password)
    {
        var result = await _signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);
        return result.Succeeded;
    }

    private async Task<IActionResult> SignInUser(ApplicationUser user)
    {
        var claims = await GetUserClaimsAsync(user);
        var identity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        
        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IEnumerable<Claim>> GetUserClaimsAsync(ApplicationUser user)
    {
        var claims = new List<Claim>
        {
            new(Claims.Subject, user.Id),
            new(Claims.Email, user.Email),
            new(Claims.Name, user.UserName)
        };

        var roles = await _userManager.GetRolesAsync(user);
        claims.AddRange(roles.Select(role => new Claim(Claims.Role, role)));

        if (!string.IsNullOrEmpty(user.GivenName))
            claims.Add(new Claim(Claims.GivenName, user.GivenName));
        
        if (!string.IsNullOrEmpty(user.FamilyName))
            claims.Add(new Claim(Claims.FamilyName, user.FamilyName));

        return claims;
    }
}
