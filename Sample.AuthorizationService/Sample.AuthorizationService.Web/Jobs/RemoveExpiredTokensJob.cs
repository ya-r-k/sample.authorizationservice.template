using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using Quartz;
using Sample.AuthorizationService.Dal.Contexts;
using Microsoft.Extensions.Options;

namespace Sample.AuthorizationService.Web.Jobs;

[DisallowConcurrentExecution]
public class RemoveExpiredTokensJob : IJob
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<RemoveExpiredTokensJob> _logger;
    private readonly TokenCleanupOptions _options;
    private const int BatchSize = 1000;

    public RemoveExpiredTokensJob(
        IServiceProvider serviceProvider,
        ILogger<RemoveExpiredTokensJob> logger,
        IOptions<TokenCleanupOptions> options)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        _options = options.Value;
    }

    public async Task Execute(IJobExecutionContext context)
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            await RemoveExpiredTokensBatchAsync(dbContext);
            await RemoveExpiredAuthorizationsBatchAsync(dbContext);

            _logger.LogInformation("Successfully completed token cleanup job");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while removing expired tokens");
            throw;
        }
    }

    private async Task RemoveExpiredTokensBatchAsync(ApplicationDbContext dbContext)
    {
        var cutoffDate = DateTime.UtcNow;
        var totalDeleted = 0;

        while (true)
        {
            var expiredTokens = await dbContext.Set<OpenIddictEntityFrameworkCoreToken>()
                .Where(token => token.ExpirationDate < cutoffDate)
                .Take(BatchSize)
                .ToListAsync();

            if (!expiredTokens.Any())
                break;

            dbContext.Set<OpenIddictEntityFrameworkCoreToken>().RemoveRange(expiredTokens);
            var deleted = await dbContext.SaveChangesAsync();
            totalDeleted += deleted;

            _logger.LogInformation("Removed {DeletedCount} expired tokens", deleted);

            // Небольшая пауза между батчами чтобы не перегружать БД
            await Task.Delay(100);
        }

        _logger.LogInformation("Total expired tokens removed: {TotalDeleted}", totalDeleted);
    }

    private async Task RemoveExpiredAuthorizationsBatchAsync(ApplicationDbContext dbContext)
    {
        var cutoffDate = DateTime.UtcNow.Subtract(_options.AuthorizationLifetime);
        var totalDeleted = 0;

        while (true)
        {
            var expiredAuthorizations = await dbContext.Set<OpenIddictEntityFrameworkCoreAuthorization>()
                .Where(auth => auth.CreationDate < cutoffDate)
                .Take(BatchSize)
                .ToListAsync();

            if (!expiredAuthorizations.Any())
                break;

            dbContext.Set<OpenIddictEntityFrameworkCoreAuthorization>().RemoveRange(expiredAuthorizations);
            var deleted = await dbContext.SaveChangesAsync();
            totalDeleted += deleted;

            _logger.LogInformation("Removed {DeletedCount} expired authorizations", deleted);

            // Небольшая пауза между батчами
            await Task.Delay(100);
        }

        _logger.LogInformation("Total expired authorizations removed: {TotalDeleted}", totalDeleted);
    }
} 