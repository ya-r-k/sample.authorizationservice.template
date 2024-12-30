using Prometheus;

namespace Sample.AuthorizationService.Web.Metrics
{
    public static class AuthMetrics
    {
        private static readonly Counter LoginAttempts = Metrics
            .CreateCounter("auth_login_attempts_total", "Number of login attempts", 
                new CounterConfiguration
                {
                    LabelNames = new[] { "status" }
                });

        private static readonly Counter RegistrationAttempts = Metrics
            .CreateCounter("auth_registration_attempts_total", "Number of registration attempts",
                new CounterConfiguration
                {
                    LabelNames = new[] { "status" }
                });

        private static readonly Counter PasswordResetAttempts = Metrics
            .CreateCounter("auth_password_reset_attempts_total", "Number of password reset attempts",
                new CounterConfiguration
                {
                    LabelNames = new[] { "status" }
                });

        private static readonly Histogram RequestDuration = Metrics
            .CreateHistogram("auth_request_duration_seconds", "Histogram of authentication request durations",
                new HistogramConfiguration
                {
                    LabelNames = new[] { "action" },
                    Buckets = new[] { .005, .01, .025, .05, .075, .1, .25, .5, .75, 1, 2.5, 5, 7.5, 10 }
                });

        private static readonly Gauge ActiveSessions = Metrics
            .CreateGauge("auth_active_sessions_total", "Number of active user sessions");

        public static void LoginAttempted(bool success)
        {
            LoginAttempts.WithLabels(success ? "success" : "failure").Inc();
        }

        public static void RegistrationAttempted(bool success)
        {
            RegistrationAttempts.WithLabels(success ? "success" : "failure").Inc();
        }

        public static void PasswordResetAttempted(bool success)
        {
            PasswordResetAttempts.WithLabels(success ? "success" : "failure").Inc();
        }

        public static ITimer MeasureRequestDuration(string action)
        {
            return RequestDuration.WithLabels(action).NewTimer();
        }

        public static void SetActiveSessions(int count)
        {
            ActiveSessions.Set(count);
        }
    }
} 