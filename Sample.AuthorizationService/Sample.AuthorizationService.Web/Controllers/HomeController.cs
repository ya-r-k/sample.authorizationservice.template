using Microsoft.AspNetCore.Mvc;

namespace Sample.AuthorizationService.Web.Controllers;

/// <summary>
/// Provides home endpoints for the application.
/// </summary>
public class HomeController : Controller
{
    /// <summary>
    /// Views the index page for the application.
    /// </summary>
    /// <returns></returns>
    public IActionResult Index()
    {
        return View();
    }

    /// <summary>
    /// Views the privacy page.
    /// </summary>
    /// <returns></returns>
    public IActionResult Privacy()
    {
        return View();
    }

    /// <summary>
    /// Views the about page.
    /// </summary>
    /// <returns></returns>
    public IActionResult About()
    {
        ViewData["Message"] = "Your application description page.";

        return View();
    }

    /// <summary>
    /// Views the contact page.
    /// </summary>
    /// <returns></returns>
    public IActionResult Contact()
    {
        ViewData["Message"] = "Your contact page.";

        return View();
    }

    /// <summary>
    /// Views the error page.
    /// </summary>
    /// <returns></returns>
    public IActionResult Error()
    {
        return View("~/Views/Shared/Error.cshtml");
    }
}
