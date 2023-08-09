namespace Sample.AuthorizationService.Web.Middlewares.Csp;

internal class CspSources
{
    internal const string AllHttpsSources = "https:";

    internal const string AllWebSocketSources = "wss:";

    internal const string NoneSource = "'none'";

    internal const string SelfSources = "'self'";

    internal const string StrictDynamicSource = "'strict-dynamic'";

    internal const string ReportSampleSource = "'report-sample'";
}
