
using Microsoft.Extensions.Options;
using multi_auth.Configuration;
using multi_auth.Storages;

namespace multi_auth.Services.Hosted;

public class TokenCleanupService : BackgroundService
{
    private readonly IRefreshTokenStorageCleanup _cleanup;
    private readonly Func<DateTime, DateTime> _getNextCleanupTime;

    public TokenCleanupService(IRefreshTokenStorageCleanup cleanup, IOptions<TimeSettings> timeSettings)
    {
        _cleanup = cleanup;
        _getNextCleanupTime = timeSettings.Value.GetNextCleanupTime;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var now = DateTime.UtcNow;
            var nextRunTime = _getNextCleanupTime(now);
            var delay = nextRunTime - now;

            try
            {
                await Task.Delay(delay, stoppingToken);
            }
            catch (TaskCanceledException)
            {
                break;
            }

            if (!stoppingToken.IsCancellationRequested)
            {
                await _cleanup.CleanupExpiredTokens();
            }
        }
    }
}
