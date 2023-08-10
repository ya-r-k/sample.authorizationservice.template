using System.Security.Claims;
using Sample.AuthorizationService.Bll.Services;
using Sample.AuthorizationService.Common.Entities;
using Sample.AuthorizationService.Common.Enums;
using Sample.AuthorizationService.Web.ViewModels.Account;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace Sample.AuthorizationService.Web.Controllers;

/// <summary>
/// Provides endpoints for the login, logout, register, reset password, confirm email and phone number. 
/// </summary>
[Authorize]
public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> userManager;
    private readonly SignInManager<ApplicationUser> signInManager;
    private readonly IEmailSender emailSender;
    private readonly ISmsSender smsSender;

    /// <summary>
    /// Initializes a new instance of the <see cref="AccountController"/> class.
    /// </summary>
    /// <param name="userManager">ASP.NET Identity user manager</param>
    /// <param name="signInManager">ASP.NET Identity sign-in manager</param>
    /// <param name="emailSender">Email sender</param>
    /// <param name="smsSender">SMS sender</param>
    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IEmailSender emailSender,
        ISmsSender smsSender)
    {
        this.userManager = userManager;
        this.signInManager = signInManager;
        this.emailSender = emailSender;
        this.smsSender = smsSender;
    }

    /// <summary>
    /// Views the login page.
    /// </summary>
    /// <param name="returnUrl">URL to redirect after login.</param>
    [HttpGet]
    [AllowAnonymous]
    public IActionResult Login(string returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;

        return View();
    }

    /// <summary>
    /// Signs in the user according to the specified login model and redirects to the return URL if it is local.
    /// </summary>
    /// <param name="model">Login view model.</param>
    /// <param name="returnUrl">URL to redirect after login.</param>
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;

        if (ModelState.IsValid)
        {
            var result = await signInManager.PasswordSignInAsync(model.Login, model.Password, model.RememberMe, lockoutOnFailure: false);

            if (result.Succeeded)
            {
                return RedirectToLocal(returnUrl);
            }
            if (result.RequiresTwoFactor)
            {
                return RedirectToAction(nameof(SendCode), new { ReturnUrl = returnUrl, model.RememberMe });
            }
            if (result.IsLockedOut)
            {
                return View("Lockout");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");

                return View(model);
            }
        }

        return View(model);
    }

    /// <summary>
    /// Views the register page.
    /// </summary>
    /// <param name="returnUrl">URL to redirect after register.</param>
    [HttpGet]
    [AllowAnonymous]
    public IActionResult Register(string returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;

        return View();
    }

    /// <summary>
    /// Registers the user according to the specified register model and redirects to the return URL if it is local.
    /// </summary>
    /// <param name="model">Register view model.</param>
    /// <param name="returnUrl">URL to redirect after register.</param>
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;

        if (ModelState.IsValid)
        {
            var user = new ApplicationUser
            {
                GivenName = model.GivenName,
                FamilyName = model.FamilyName,
                MiddleName = model.MiddleName,
                Nickname = model.Nickname,
                Gender = model.Gender,
                BirthDate = model.BirthDate,
                Locale = model.Locale,
                UserName = model.Email,
                PhoneNumber = model.PhoneNumber,
                Email = model.Email
            };
            var result = await userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=532713
                // Send an email with this link
                //var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                //var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Context.Request.Scheme);
                //await _emailSender.SendEmailAsync(model.Email, "Confirm your account",
                //    "Please confirm your account by clicking this link: <a href=\"" + callbackUrl + "\">link</a>");

                result = await userManager.AddToRoleAsync(user, Role.Default.ToString());

                if (result.Succeeded)
                {
                    await signInManager.SignInAsync(user, isPersistent: false);

                    return RedirectToLocal(returnUrl);
                }
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        return View(model);
    }

    /// <summary>
    /// Logs out the user and redirects to the home page.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LogOff()
    {
        await signInManager.SignOutAsync();

        return RedirectToAction(nameof(HomeController.Index), "Home");
    }

    /// <summary>
    /// Redirects to the external login provider.
    /// </summary>
    /// <param name="provider">External login provider name.</param>
    /// <param name="returnUrl">URL to redirect after login.</param>
    /// <returns></returns>
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public IActionResult ExternalLogin(string provider, string returnUrl = null)
    {
        // Request a redirect to the external login provider.
        var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl });
        var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);

        return new ChallengeResult(provider, properties);
    }

    /// <summary>
    /// Redirects to the external login provider.
    /// </summary>
    /// <param name="returnUrl">URL to redirect after login.</param>
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null)
    {
        var info = await signInManager.GetExternalLoginInfoAsync();

        if (info is null)
        {
            return RedirectToAction(nameof(Login));
        }

        // Sign in the user with this external login provider if the user already has a login.
        var result = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);

        if (result.Succeeded)
        {
            return RedirectToLocal(returnUrl);
        }

        if (result.RequiresTwoFactor)
        {
            return RedirectToAction(nameof(SendCode), new { ReturnUrl = returnUrl });
        }

        if (result.IsLockedOut)
        {
            return View("Lockout");
        }

        // If the user does not have an account, then ask the user to create an account.
        ViewData["ReturnUrl"] = returnUrl;
        ViewData["LoginProvider"] = info.LoginProvider;
        var email = info.Principal.FindFirstValue(ClaimTypes.Email);

        return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = email });
    }

    /// <summary>
    /// Redirects to the external login provider.
    /// </summary>
    /// <param name="model">External login confirmation view model.</param>
    /// <param name="returnUrl">URL to redirect after login.</param>
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl = null)
    {
        if (ModelState.IsValid)
        {
            // Get the information about the user from the external login provider
            var info = await signInManager.GetExternalLoginInfoAsync();

            if (info is null)
            {
                return View("ExternalLoginFailure");
            }

            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email
            };

            var result = await userManager.CreateAsync(user);

            if (result.Succeeded)
            {
                result = await userManager.AddLoginAsync(user, info);

                if (result.Succeeded)
                {
                    await signInManager.SignInAsync(user, isPersistent: false);

                    return RedirectToLocal(returnUrl);
                }
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        ViewData["ReturnUrl"] = returnUrl;

        return View(model);
    }

    /// <summary>
    /// Confirms the email.
    /// </summary>
    /// <param name="userId">User id.</param>
    /// <param name="code">Confirmation code.</param>
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmEmail(string userId, string code)
    {
        if (userId is null || code is null)
        {
            return View("Error");
        }

        var user = await userManager.FindByIdAsync(userId);

        if (user is null)
        {
            return View("Error");
        }

        var result = await userManager.ConfirmEmailAsync(user, code);

        return View(result.Succeeded ? "ConfirmEmail" : "Error");
    }

    /// <summary>
    /// Views the forgot password page.
    /// </summary>
    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPassword()
    {
        return View();
    }

    /// <summary>
    /// Tries to reset the password for the specified user.
    /// </summary>
    /// <param name="model">Forgot password view model.</param>
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
    {
        if (ModelState.IsValid)
        {
            var user = await userManager.FindByEmailAsync(model.Email);

            if (user is null || !await userManager.IsEmailConfirmedAsync(user))
            {
                // Don't reveal that the user does not exist or is not confirmed
                return View("ForgotPasswordConfirmation");
            }

            // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=532713
            // Send an email with this link
            //var code = await _userManager.GeneratePasswordResetTokenAsync(user);
            //var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Context.Request.Scheme);
            //await _emailSender.SendEmailAsync(model.Email, "Reset Password",
            //   "Please reset your password by clicking here: <a href=\"" + callbackUrl + "\">link</a>");
            //return View("ForgotPasswordConfirmation");
        }

        // If we got this far, something failed, redisplay form
        return View(model);
    }

    /// <summary>
    /// Views the forgot password confirmation page.
    /// </summary>
    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPasswordConfirmation()
    {
        return View();
    }

    /// <summary>
    /// Views the reset password page.
    /// </summary>
    /// <param name="code">Confirmation code.</param>
    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPassword(string code = null)
    {
        return code is null ? View("Error") : View();
    }

    /// <summary>
    /// Resets the password for the specified user.
    /// </summary>
    /// <param name="model">Reset password view model.</param>
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await userManager.FindByNameAsync(model.Email);

        if (user is null)
        {
            // Don't reveal that the user does not exist
            return RedirectToAction(nameof(AccountController.ResetPasswordConfirmation), "Account");
        }

        var result = await userManager.ResetPasswordAsync(user, model.Code, model.Password);

        if (result.Succeeded)
        {
            return RedirectToAction(nameof(AccountController.ResetPasswordConfirmation), "Account");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        return View();
    }

    /// <summary>
    /// Views the reset password confirmation page.
    /// </summary>
    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPasswordConfirmation()
    {
        return View();
    }

    /// <summary>
    /// Views the send code page.
    /// </summary>
    /// <param name="returnUrl">URL to redirect after login.</param>
    /// <param name="rememberMe">Value indicating whether to remember user who tried to log in.</param>
    [HttpGet]
    [AllowAnonymous]
    public async Task<ActionResult> SendCode(string returnUrl = null, bool rememberMe = false)
    {
        var user = await signInManager.GetTwoFactorAuthenticationUserAsync();

        if (user is null)
        {
            return View("Error");
        }

        var userFactors = await userManager.GetValidTwoFactorProvidersAsync(user);
        var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();

        return View(new SendCodeViewModel
        {
            Providers = factorOptions,
            ReturnUrl = returnUrl,
            RememberMe = rememberMe
        });
    }

    /// <summary>
    /// Here user sends the code.
    /// </summary>
    /// <param name="model">Send code view model.</param>
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SendCode(SendCodeViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View();
        }

        var user = await signInManager.GetTwoFactorAuthenticationUserAsync();

        if (user is null)
        {
            return View("Error");
        }

        // Generate the token and send it
        var code = await userManager.GenerateTwoFactorTokenAsync(user, model.SelectedProvider);

        if (string.IsNullOrWhiteSpace(code))
        {
            return View("Error");
        }

        var message = "Your security code is: " + code;

        if (model.SelectedProvider == "Email")
        {
            await emailSender.SendEmailAsync(await userManager.GetEmailAsync(user), "Security Code", message);
        }
        else if (model.SelectedProvider == "Phone")
        {
            await smsSender.SendSmsAsync(await userManager.GetPhoneNumberAsync(user), message);
        }

        return RedirectToAction(nameof(VerifyCode), new { Provider = model.SelectedProvider, model.ReturnUrl, model.RememberMe });
    }

    /// <summary>
    /// Views the verify code page.
    /// </summary>
    /// <param name="provider">Provider name.</param>
    /// <param name="rememberMe">Value indicating whether to remember user who tried to log in.</param>
    /// <param name="returnUrl">URL to redirect after login.</param>
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> VerifyCode(string provider, bool rememberMe, string returnUrl = null)
    {
        // Require that the user has already logged in via username/password or external login
        var user = await signInManager.GetTwoFactorAuthenticationUserAsync();

        if (user is null)
        {
            return View("Error");
        }

        return View(new VerifyCodeViewModel
        {
            Provider = provider,
            ReturnUrl = returnUrl,
            RememberMe = rememberMe
        });
    }

    /// <summary>
    /// Here users verifies the code.
    /// </summary>
    /// <param name="model">Verify code view model.</param>
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyCode(VerifyCodeViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        // The following code protects for brute force attacks against the two factor codes.
        // If a user enters incorrect codes for a specified amount of time then the user account
        // will be locked out for a specified amount of time.
        var result = await signInManager.TwoFactorSignInAsync(model.Provider, model.Code, model.RememberMe, model.RememberBrowser);

        if (result.Succeeded)
        {
            return RedirectToLocal(model.ReturnUrl);
        }

        if (result.IsLockedOut)
        {
            return View("Lockout");
        }
        else
        {
            ModelState.AddModelError("", "Invalid code.");

            return View(model);
        }
    }

    private IActionResult RedirectToLocal(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }
        else
        {
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }
    }
}
