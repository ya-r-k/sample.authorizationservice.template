using AuthorizationServiceExample.Web.Middlewares.Csp;

namespace AuthorizationServiceExample.Web.Middlewares;

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
