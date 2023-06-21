using Example.AuthorizationService.Web.Middlewares;
using Example.AuthorizationService.Web.Middlewares.Csp;

namespace Example.AuthorizationService.Web.Extensions;

internal static class ApplicationBuilderExtensions
{
    internal static IApplicationBuilder UseContentSecurityPolicy(this IApplicationBuilder app, Action<CspOptions> builder)
    {
        var options = new CspOptions();

        builder.Invoke(options);

        options.ApplyCspConfiguration();

        app.UseMiddleware<CspMiddleware>(options);

        return app;
    }

    internal static IApplicationBuilder UseDefaultContentSecurityPolicy(this IApplicationBuilder app, IWebHostEnvironment env)
    {
        app.UseContentSecurityPolicy(options =>
        {
            options.AddDirective(CspDirectives.FrameFetchDirective, CspSources.NoneSource);
            options.AddDirective(CspDirectives.WorkerFetchDirective, CspSources.NoneSource);
            options.AddDirective(CspDirectives.ObjectFetchDirective, CspSources.NoneSource);
            options.AddDirective(CspDirectives.MediaFetchDirective, CspSources.NoneSource);
            options.AddDirective(CspDirectives.ManifestsFetchDirective, CspSources.NoneSource);
            options.AddDirective(CspDirectives.DefaultsFetchDirective, CspSources.NoneSource);
            options.AddDirective(CspDirectives.ImagesFetchDirective, CspSources.SelfSources);
            options.AddDirective(CspDirectives.ScriptsFetchDirective, CspSources.SelfSources);
            options.AddDirective(CspDirectives.StylesFetchDirective, CspSources.SelfSources);
            options.AddDirective(CspDirectives.ConnectFetchDirective, CspSources.SelfSources, "https");
            options.AddDirective(CspDirectives.FormActionNavigationDirective, CspSources.SelfSources);
            options.AddDirective(CspDirectives.FrameAncestorsNavigationDirective, CspSources.NoneSource);
            options.AddDirective(CspDirectives.BaseUriDocumentDirective, CspSources.SelfSources);
            options.AddDirective(CspDirectives.UpgrateInsecureRequestsDirective);

            if (env.IsDevelopment())
            {
                options.AddDirective(CspDirectives.ConnectFetchDirective, CspSources.AllWebSocketSources);
                options.AddDirective(CspDirectives.FormActionNavigationDirective, "https://oauth.pstmn.io/v1/callback");
            }
        });

        return app;
    }
}
