using Sample.AuthorizationService.Web.ViewModels.Common;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;

namespace Sample.AuthorizationService.Web.Controllers;

/// <summary>
/// Provides endpoints for error in OpenIddict.
/// </summary>
public class ErrorController : Controller
{
    /// <summary>
    /// Views the error page.
    /// </summary>
    [HttpGet]
    [HttpPost]
    [Route("~/error")]
    public IActionResult Error()
    {
        // If the error was not caused by an invalid
        // OIDC request, display a generic error page.
        var response = HttpContext.GetOpenIddictServerResponse();

        if (response is null)
        {
            return View(new ErrorViewModel());
        }

        return View(new ErrorViewModel
        {
            Error = response.Error,
            ErrorDescription = response.ErrorDescription
        });
    }
}