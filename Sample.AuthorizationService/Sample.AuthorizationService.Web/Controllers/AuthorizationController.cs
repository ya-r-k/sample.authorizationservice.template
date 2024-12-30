using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Sample.AuthorizationService.Common.Entities;
using Sample.AuthorizationService.Web.ViewModels.Authorization;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sample.AuthorizationService.Web.Controllers;

/// <summary>
/// Контроллер для обработки авторизации OAuth 2.0/OpenID Connect.
/// </summary>
public class AuthorizationController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<AuthorizationController> _logger;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        ILogger<AuthorizationController> logger)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _signInManager = signInManager;
        _userManager = userManager;
        _logger = logger;
    }

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request = await GetOpenIddictServerRequest();
        var result = await HttpContext.AuthenticateAsync();

        // Если пользователь не аутентифицирован или требуется повторный вход
        if (await RequiresAuthentication(result, request))
        {
            return await HandleAuthenticationChallenge(request);
        }

        var user = await _userManager.GetUserAsync(result.Principal);
        var application = await GetClientApplication(request.ClientId);

        // Проверяем необходимость получения согласия пользователя
        if (await RequiresUserConsent(user, application, request))
        {
            return View("Consent", await CreateConsentViewModel(application, request));
        }

        // Создаем и возвращаем токен
        return await CreateAuthorizationResponse(user, application, request);
    }

    [Authorize]
    [HttpPost("~/connect/authorize")]
    [ValidateAntiForgeryToken]
    [FormValueRequired("submit.Accept")]
    public async Task<IActionResult> Accept()
    {
        var request = await GetOpenIddictServerRequest();
        var user = await _userManager.GetUserAsync(User);
        var application = await GetClientApplication(request.ClientId);

        // Проверяем разрешения и создаем токен
        return await CreateAuthorizationResponse(user, application, request);
    }

    [Authorize]
    [HttpPost("~/connect/authorize")]
    [ValidateAntiForgeryToken]
    [FormValueRequired("submit.Deny")]
    public IActionResult Deny()
    {
        return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<bool> RequiresAuthentication(AuthenticateResult result, OpenIddictRequest request)
    {
        return !result.Succeeded || 
               request.HasPrompt(Prompts.Login) ||
               (request.MaxAge != null && result.Properties?.IssuedUtc != null &&
                DateTimeOffset.UtcNow - result.Properties.IssuedUtc > TimeSpan.FromSeconds(request.MaxAge.Value));
    }

    private async Task<IActionResult> HandleAuthenticationChallenge(OpenIddictRequest request)
    {
        if (request.HasPrompt(Prompts.None))
        {
            return CreateLoginRequiredError();
        }

        var parameters = await GetAuthenticationParameters(request);
        
        return Challenge(
            authenticationSchemes: IdentityConstants.ApplicationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = Request.PathBase + Request.Path + QueryString.Create(parameters)
            });
    }

    private async Task<bool> RequiresUserConsent(ApplicationUser user, object application, OpenIddictRequest request)
    {
        if (await _applicationManager.GetConsentTypeAsync(application) != ConsentTypes.Explicit)
        {
            return false;
        }

        var authorizations = await _authorizationManager.FindAsync(
            subject: user.Id,
            client: await _applicationManager.GetIdAsync(application),
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: request.GetScopes()).ToListAsync();

        return !authorizations.Any();
    }

    private async Task<IActionResult> CreateAuthorizationResponse(
        ApplicationUser user, 
        object application, 
        OpenIddictRequest request)
    {
        var identity = await CreateIdentity(user, request);
        var authorization = await CreateOrUpdateAuthorization(user, application, identity);

        identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
        
        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<ClaimsIdentity> CreateIdentity(ApplicationUser user, OpenIddictRequest request)
    {
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        // Добавляем базовые claims
        await AddBasicClaims(identity, user);

        // Добавляем scopes и ресурсы
        var scopes = request.GetScopes();
        identity.SetScopes(scopes);
        identity.SetResources(await _scopeManager.ListResourcesAsync(scopes).ToListAsync());

        return identity;
    }

    private async Task AddBasicClaims(ClaimsIdentity identity, ApplicationUser user)
    {
        identity.SetClaim(Claims.Subject, user.Id)
                .SetClaim(Claims.Email, user.Email)
                .SetClaim(Claims.Name, user.UserName)
                .SetClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray());
    }

    private async Task<OpenIddictRequest> GetOpenIddictServerRequest()
    {
        return HttpContext.GetOpenIddictServerRequest() ?? 
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
    }

    private async Task<object> GetClientApplication(string clientId)
    {
        return await _applicationManager.FindByClientIdAsync(clientId) ?? 
            throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
    }

    private IActionResult CreateLoginRequiredError()
    {
        return Forbid(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties(new Dictionary<string, string>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is not logged in."
            }));
    }

    private async Task<AuthorizeViewModel> CreateConsentViewModel(object application, OpenIddictRequest request)
    {
        return new AuthorizeViewModel
        {
            ApplicationName = await _applicationManager.GetLocalizedDisplayNameAsync(application),
            Scope = request.Scope
        };
    }
}
