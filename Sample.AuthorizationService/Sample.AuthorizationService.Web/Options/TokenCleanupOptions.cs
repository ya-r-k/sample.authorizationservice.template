namespace Sample.AuthorizationService.Web.Options;

public class TokenCleanupOptions
{
    public TimeSpan Interval { get; set; } = TimeSpan.FromHours(12);
    public TimeSpan AuthorizationLifetime { get; set; } = TimeSpan.FromDays(7);
    public int BatchSize { get; set; } = 1000;
    public int DelayBetweenBatches { get; set; } = 100; // миллисекунды
} 