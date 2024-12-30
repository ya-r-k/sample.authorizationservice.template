using Prometheus;
using System.Diagnostics;

namespace Sample.AuthorizationService.Web.Middleware
{
    public class HttpMetricsMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly Counter _httpRequestsTotal;
        private readonly Histogram _httpRequestDuration;

        public HttpMetricsMiddleware(RequestDelegate next)
        {
            _next = next;
            _httpRequestsTotal = Metrics.CreateCounter(
                "http_requests_total",
                "Number of HTTP requests processed",
                new CounterConfiguration
                {
                    LabelNames = new[] { "method", "endpoint", "status" }
                });

            _httpRequestDuration = Metrics.CreateHistogram(
                "http_request_duration_seconds",
                "Duration of HTTP requests in seconds",
                new HistogramConfiguration
                {
                    LabelNames = new[] { "method", "endpoint" },
                    Buckets = new[] { .005, .01, .025, .05, .075, .1, .25, .5, .75, 1, 2.5, 5, 7.5, 10 }
                });
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var path = context.Request.Path.Value;
            var method = context.Request.Method;

            using (var timer = _httpRequestDuration.WithLabels(method, path).NewTimer())
            {
                try
                {
                    await _next(context);
                }
                finally
                {
                    _httpRequestsTotal.WithLabels(method, path, context.Response.StatusCode.ToString()).Inc();
                }
            }
        }
    }
}