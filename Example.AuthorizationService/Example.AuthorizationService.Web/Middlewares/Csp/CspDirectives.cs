namespace Example.AuthorizationService.Web.Middlewares.Csp;

internal class CspDirectives
{
    internal const string FrameFetchDirective = "frame-src";

    internal const string WorkerFetchDirective = "worker-src";

    internal const string ObjectFetchDirective = "object-src";

    internal const string DefaultsFetchDirective = "default-src";

    internal const string ScriptsFetchDirective = "script-src";

    internal const string StylesFetchDirective = "style-src";

    internal const string ConnectFetchDirective = "connect-src";

    internal const string ImagesFetchDirective = "img-src";

    internal const string ManifestsFetchDirective = "manifest-src";

    internal const string FontsFetchDirective = "font-src";

    internal const string MediaFetchDirective = "media-src";

    internal const string BaseUriDocumentDirective = "base-uri";

    internal const string FormActionNavigationDirective = "form-action";

    internal const string FrameAncestorsNavigationDirective = "frame-ancestors";

    internal const string ReportDirective = "report-to";

    internal const string UpgrateInsecureRequestsDirective = "upgrade-insecure-requests";
}
