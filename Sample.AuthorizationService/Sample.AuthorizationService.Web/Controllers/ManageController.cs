using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Sample.AuthorizationService.Common.Entities;
using Sample.AuthorizationService.Web.ViewModels.Manage;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace Sample.AuthorizationService.Web.Controllers;

/// <summary>
/// Контроллер для управления профилем пользователя
/// </summary>
[Authorize]
public class ManageController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILogger<ManageController> _logger;
    private readonly UrlEncoder _urlEncoder;

    public ManageController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ILogger<ManageController> logger,
        UrlEncoder urlEncoder)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
        _urlEncoder = urlEncoder;
    }

    /// <summary>
    /// Отображает информацию профиля пользователя
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var user = await GetCurrentUserAsync();
        if (user == null)
        {
            return NotFound();
        }

        var model = await CreateProfileViewModel(user);
        return View(model);
    }

    /// <summary>
    /// Обновляет профиль пользователя
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UpdateProfile(ProfileViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View("Index", model);
        }

        var user = await GetCurrentUserAsync();
        if (user == null)
        {
            return NotFound();
        }

        var result = await UpdateUserProfile(user, model);
        if (!result.Succeeded)
        {
            AddErrors(result);
            return View("Index", model);
        }

        _logger.LogInformation("User profile updated successfully");
        return RedirectToAction(nameof(Index));
    }

    /// <summary>
    /// Отображает форму изменения пароля
    /// </summary>
    [HttpGet]
    public IActionResult ChangePassword()
    {
        return View();
    }

    /// <summary>
    /// Обрабатывает изменение пароля
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await GetCurrentUserAsync();
        if (user == null)
        {
            return NotFound();
        }

        var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
        if (!result.Succeeded)
        {
            AddErrors(result);
            return View(model);
        }

        await _signInManager.RefreshSignInAsync(user);
        _logger.LogInformation("User changed their password successfully");
        
        return RedirectToAction(nameof(Index));
    }

    /// <summary>
    /// Отображает форму управления двухфакторной аутентификацией
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> TwoFactorAuthentication()
    {
        var user = await GetCurrentUserAsync();
        if (user == null)
        {
            return NotFound();
        }

        var model = await CreateTwoFactorViewModel(user);
        return View(model);
    }

    /// <summary>
    /// Включает/выключает двухфакторную аутентификацию
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EnableTwoFactor(bool enable)
    {
        var user = await GetCurrentUserAsync();
        if (user == null)
        {
            return NotFound();
        }

        await _userManager.SetTwoFactorEnabledAsync(user, enable);
        await _signInManager.RefreshSignInAsync(user);

        _logger.LogInformation($"User {(enable ? "enabled" : "disabled")} 2FA");
        return RedirectToAction(nameof(TwoFactorAuthentication));
    }

    /// <summary>
    /// Отображает форму настройки аутентификатора
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> EnableAuthenticator()
    {
        var user = await GetCurrentUserAsync();
        if (user == null)
        {
            return NotFound();
        }

        var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(unformattedKey))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        var model = new EnableAuthenticatorViewModel
        {
            SharedKey = FormatKey(unformattedKey),
            AuthenticatorUri = GenerateQrCodeUri(user.Email, unformattedKey)
        };

        return View(model);
    }

    /// <summary>
    /// Обрабатывает настройку аутентификатора
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EnableAuthenticator(EnableAuthenticatorViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await GetCurrentUserAsync();
        if (user == null)
        {
            return NotFound();
        }

        // Verify the code
        var verificationCode = model.Code.Replace(" ", string.Empty).Replace("-", string.Empty);
        var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
            user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

        if (!is2faTokenValid)
        {
            ModelState.AddModelError("Code", "Неверный код подтверждения.");
            return View(model);
        }

        await _userManager.SetTwoFactorEnabledAsync(user, true);
        _logger.LogInformation("User has enabled 2FA with an authenticator app.");

        // Generate recovery codes
        var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
        
        return RedirectToAction(nameof(ShowRecoveryCodes), 
            new { RecoveryCodes = recoveryCodes });
    }

    /// <summary>
    /// Отображает форму отображения кодов восстановления
    /// </summary>
    [HttpGet]
    public IActionResult ShowRecoveryCodes(IEnumerable<string> recoveryCodes)
    {
        if (recoveryCodes == null)
        {
            return RedirectToAction(nameof(TwoFactorAuthentication));
        }

        var model = new ShowRecoveryCodesViewModel { RecoveryCodes = recoveryCodes };
        return View(model);
    }

    #region Helper Methods

    private async Task<ApplicationUser> GetCurrentUserAsync()
    {
        return await _userManager.GetUserAsync(User);
    }

    private async Task<ProfileViewModel> CreateProfileViewModel(ApplicationUser user)
    {
        return new ProfileViewModel
        {
            GivenName = user.GivenName,
            FamilyName = user.FamilyName,
            MiddleName = user.MiddleName,
            Nickname = user.Nickname,
            Gender = user.Gender,
            BirthDate = user.BirthDate,
            Email = user.Email,
            PhoneNumber = user.PhoneNumber,
            IsEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user)
        };
    }

    private async Task<IdentityResult> UpdateUserProfile(ApplicationUser user, ProfileViewModel model)
    {
        user.GivenName = model.GivenName;
        user.FamilyName = model.FamilyName;
        user.MiddleName = model.MiddleName;
        user.Nickname = model.Nickname;
        user.Gender = model.Gender;
        user.BirthDate = model.BirthDate;
        user.PhoneNumber = model.PhoneNumber;

        var result = await _userManager.UpdateAsync(user);
        if (result.Succeeded)
        {
            await _signInManager.RefreshSignInAsync(user);
        }

        return result;
    }

    private async Task<TwoFactorAuthenticationViewModel> CreateTwoFactorViewModel(ApplicationUser user)
    {
        return new TwoFactorAuthenticationViewModel
        {
            HasAuthenticator = await _userManager.GetAuthenticatorKeyAsync(user) != null,
            Is2faEnabled = await _userManager.GetTwoFactorEnabledAsync(user),
            RecoveryCodesLeft = await _userManager.CountRecoveryCodesAsync(user),
        };
    }

    private void AddErrors(IdentityResult result)
    {
        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }
    }

    private string FormatKey(string unformattedKey)
    {
        var result = new StringBuilder();
        int currentPosition = 0;
        while (currentPosition + 4 < unformattedKey.Length)
        {
            result.Append(unformattedKey.Substring(currentPosition, 4)).Append(" ");
            currentPosition += 4;
        }
        if (currentPosition < unformattedKey.Length)
        {
            result.Append(unformattedKey.Substring(currentPosition));
        }

        return result.ToString().ToLowerInvariant();
    }

    private string GenerateQrCodeUri(string email, string unformattedKey)
    {
        const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

        return string.Format(
            AuthenticatorUriFormat,
            _urlEncoder.Encode("Sample.AuthorizationService"),
            _urlEncoder.Encode(email),
            unformattedKey);
    }

    #endregion
}
