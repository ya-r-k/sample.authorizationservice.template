using Example.AuthorizationService.Web.ViewModels.Common;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;

namespace Example.AuthorizationService.Web.Controllers;

public class ErrorController : Controller
{
    [HttpGet, HttpPost, Route("~/error")]
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