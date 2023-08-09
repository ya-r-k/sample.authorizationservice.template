using Sample.AuthorizationService.Bll.Services;
using Sample.AuthorizationService.Common.Entities;
using Sample.AuthorizationService.Web.Enums;
using Sample.AuthorizationService.Web.ViewModels.Manage;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Sample.AuthorizationService.Web.Controllers;

/// <summary>
/// Provides endpoints for manage current user information.
/// </summary>
[Authorize]
public class ManageController : Controller
{
    private readonly UserManager<ApplicationUser> userManager;
    private readonly SignInManager<ApplicationUser> signInManager;
    private readonly IEmailSender emailSender;
    private readonly ISmsSender smsSender;
    private readonly ILogger<ManageController> logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="ManageController"/> class.
    /// </summary>
    /// <param name="userManager">ASP.NET Identity user manager.</param>
    /// <param name="signInManager">ASP.NET Identity sign-in manager.</param>
    /// <param name="emailSender">Email sender.</param>
    /// <param name="smsSender">SMS sender.</param>
    /// <param name="loggerFactory">Logger factory.</param>
    public ManageController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IEmailSender emailSender,
        ISmsSender smsSender,
        ILoggerFactory loggerFactory)
    {
        this.userManager = userManager;
        this.signInManager = signInManager;
        this.emailSender = emailSender;
        this.smsSender = smsSender;

        logger = loggerFactory.CreateLogger<ManageController>();
    }

    /// <summary>
    /// Views the index page.
    /// </summary>
    /// <param name="message">Message.</param>
    [HttpGet]
    public async Task<IActionResult> Index(ManageMessageId? message = null)
    {
        ViewData["StatusMessage"] = message switch
        {
            ManageMessageId.ChangePasswordSuccess => "Your password has been changed.",
            ManageMessageId.SetPasswordSuccess => "Your password has been set.",
            ManageMessageId.SetTwoFactorSuccess => "Your two-factor authentication provider has been set.",
            ManageMessageId.Error => "An error has occurred.",
            ManageMessageId.AddPhoneSuccess => "Your phone number was added.",
            ManageMessageId.RemovePhoneSuccess => "Your phone number was removed.",
            _ => string.Empty,
        };

        var user = await userManager.GetUserAsync(User);
        var model = new IndexViewModel
        {
            HasPassword = await userManager.HasPasswordAsync(user),
            PhoneNumber = await userManager.GetPhoneNumberAsync(user),
            TwoFactor = await userManager.GetTwoFactorEnabledAsync(user),
            Logins = await userManager.GetLoginsAsync(user),
            BrowserRemembered = await signInManager.IsTwoFactorClientRememberedAsync(user)
        };

        return View(model);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="account"></param>
    /// <returns></returns>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RemoveLogin(RemoveLoginViewModel account)
    {
        var message = ManageMessageId.Error;
        var user = await userManager.GetUserAsync(User);

        if (user is not null)
        {
            var result = await userManager.RemoveLoginAsync(user, account.LoginProvider, account.ProviderKey);

            if (result.Succeeded)
            {
                await signInManager.SignInAsync(user, isPersistent: false);

                message = ManageMessageId.RemoveLoginSuccess;
            }
        }

        return RedirectToAction(nameof(ManageLogins), new { Message = message });
    }

    /// <summary>
    /// Views the add phone number page.
    /// </summary>
    public IActionResult AddPhoneNumber()
    {
        return View();
    }

    /// <summary>
    /// Adds the phone number.
    /// </summary>
    /// <param name="model">Add phone number view model.</param>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AddPhoneNumber(AddPhoneNumberViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        // Generate the token and send it
        var user = await userManager.GetUserAsync(User);
        var code = await userManager.GenerateChangePhoneNumberTokenAsync(user, model.PhoneNumber);

        await smsSender.SendSmsAsync(model.PhoneNumber, "Your security code is: " + code);

        return RedirectToAction(nameof(VerifyPhoneNumber), new { model.PhoneNumber });
    }

    /// <summary>
    /// Enables two-factor authentication.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EnableTwoFactorAuthentication()
    {
        var user = await userManager.GetUserAsync(User);

        if (user is not null)
        {
            await userManager.SetTwoFactorEnabledAsync(user, true);
            await signInManager.SignInAsync(user, isPersistent: false);

            logger.LogInformation(1, "User enabled two-factor authentication.");
        }
        return RedirectToAction(nameof(Index), "Manage");
    }

    /// <summary>
    /// Disables two-factor authentication.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DisableTwoFactorAuthentication()
    {
        var user = await userManager.GetUserAsync(User);

        if (user is not null)
        {
            await userManager.SetTwoFactorEnabledAsync(user, false);
            await signInManager.SignInAsync(user, isPersistent: false);

            logger.LogInformation(2, "User disabled two-factor authentication.");
        }

        return RedirectToAction(nameof(Index), "Manage");
    }

    /// <summary>
    /// Views the verify phone number page.
    /// </summary>
    /// <param name="phoneNumber">Phone number.</param>
    [HttpGet]
    public async Task<IActionResult> VerifyPhoneNumber(string phoneNumber)
    {
        var code = await userManager.GenerateChangePhoneNumberTokenAsync(await userManager.GetUserAsync(User), phoneNumber);

        // Send an SMS to verify the phone number
        return phoneNumber is null ? View("Error") : View(new VerifyPhoneNumberViewModel { PhoneNumber = phoneNumber });
    }

    /// <summary>
    /// Verifies the phone number.
    /// </summary>
    /// <param name="model">Verify phone number view model.</param>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyPhoneNumber(VerifyPhoneNumberViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await userManager.GetUserAsync(User);

        if (user is not null)
        {
            var result = await userManager.ChangePhoneNumberAsync(user, model.PhoneNumber, model.Code);

            if (result.Succeeded)
            {
                await signInManager.SignInAsync(user, isPersistent: false);

                return RedirectToAction(nameof(Index), new { Message = ManageMessageId.AddPhoneSuccess });
            }
        }

        // If we got this far, something failed, redisplay the form
        ModelState.AddModelError(string.Empty, "Failed to verify phone number");

        return View(model);
    }

    /// <summary>
    /// Removes the phone number.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RemovePhoneNumber()
    {
        var user = await userManager.GetUserAsync(User);

        if (user is not null)
        {
            var result = await userManager.SetPhoneNumberAsync(user, null);

            if (result.Succeeded)
            {
                await signInManager.SignInAsync(user, isPersistent: false);

                return RedirectToAction(nameof(Index), new { Message = ManageMessageId.RemovePhoneSuccess });
            }
        }

        return RedirectToAction(nameof(Index), new { Message = ManageMessageId.Error });
    }

    /// <summary>
    /// Views the change password page.
    /// </summary>
    [HttpGet]
    public IActionResult ChangePassword()
    {
        return View();
    }

    /// <summary>
    /// Changes the password.
    /// </summary>
    /// <param name="model">Change password view model.</param>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await userManager.GetUserAsync(User);

        if (user is not null)
        {
            var result = await userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);

            if (result.Succeeded)
            {
                await signInManager.SignInAsync(user, isPersistent: false);

                logger.LogInformation(3, "User changed their password successfully.");

                return RedirectToAction(nameof(Index), new { Message = ManageMessageId.ChangePasswordSuccess });
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        return RedirectToAction(nameof(Index), new { Message = ManageMessageId.Error });
    }

    /// <summary>
    /// Views the set password page.
    /// </summary>
    [HttpGet]
    public IActionResult SetPassword()
    {
        return View();
    }

    /// <summary>
    /// Sets the password.
    /// </summary>
    /// <param name="model">Set password view model.</param>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SetPassword(SetPasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await userManager.GetUserAsync(User);

        if (user is not null)
        {
            var result = await userManager.AddPasswordAsync(user, model.NewPassword);

            if (result.Succeeded)
            {
                await signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToAction(nameof(Index), new { Message = ManageMessageId.SetPasswordSuccess });
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);

        }

        return RedirectToAction(nameof(Index), new { Message = ManageMessageId.Error });
    }

    /// <summary>
    /// Views the manage logins page.
    /// </summary>
    /// <param name="message">Message.</param>
    [HttpGet]
    public async Task<IActionResult> ManageLogins(ManageMessageId? message = null)
    {
        ViewData["StatusMessage"] = message switch
        {
            ManageMessageId.RemoveLoginSuccess => "The external login was removed.",
            ManageMessageId.AddLoginSuccess => "The external login was added.",
            ManageMessageId.Error => "An error has occurred.",
            _ => string.Empty,
        };

        var user = await userManager.GetUserAsync(User);

        if (user is null)
        {
            return View("Error");
        }

        var userLogins = await userManager.GetLoginsAsync(user);
        var otherLogins = (await signInManager.GetExternalAuthenticationSchemesAsync()).Where(auth => userLogins.All(ul => auth.Name != ul.LoginProvider)).ToList();

        ViewData["ShowRemoveButton"] = user.PasswordHash is not null || userLogins.Count > 1;

        return View(new ManageLoginsViewModel
        {
            CurrentLogins = userLogins,
            OtherLogins = otherLogins
        });
    }

    /// <summary>
    /// Request a redirect to the external login provider to link a login for the current user.
    /// </summary>
    /// <param name="provider">External login provider.</param>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult LinkLogin(string provider)
    {
        var redirectUrl = Url.Action("LinkLoginCallback", "Manage");
        var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl, userManager.GetUserId(User));

        return Challenge(properties, provider);
    }

    /// <summary>
    /// Gets the callback url for linking a login for the current user.
    /// </summary>
    [HttpGet]
    public async Task<ActionResult> LinkLoginCallback()
    {
        var user = await userManager.GetUserAsync(User);

        if (user is null)
        {
            return View("Error");
        }

        var info = await signInManager.GetExternalLoginInfoAsync(await userManager.GetUserIdAsync(user));

        if (info is null)
        {
            return RedirectToAction(nameof(ManageLogins), new { Message = ManageMessageId.Error });
        }

        var result = await userManager.AddLoginAsync(user, info);
        var message = result.Succeeded ? ManageMessageId.AddLoginSuccess : ManageMessageId.Error;

        return RedirectToAction(nameof(ManageLogins), new { Message = message });
    }
}
