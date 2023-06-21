using Example.AuthorizationService.Web.Middlewares.Csp;

namespace Example.AuthorizationService.Web.Middlewares;

public class CspMiddleware
{
    private readonly RequestDelegate next;
    private readonly CspOptions options;

    public CspMiddleware(RequestDelegate next, CspOptions options)
    {
        this.next = next;
        this.options = options;
    }

    public Task InvokeAsync(HttpContext context)
    {
        context.Response.Headers.ContentSecurityPolicy = options.CspHeaderValue;
        context.Response.Headers.ContentSecurityPolicyReportOnly = options.CspReportOnlyHeaderValue;

        return next.Invoke(context);
    }
}
