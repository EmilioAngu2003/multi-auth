using multi_auth.Services;
using multi_auth.Services.Hosted;
using multi_auth.Storages;
using multi_auth.Utils;

namespace multi_auth.Configuration;

public static class ServiceSetup
{
    public static IServiceCollection RegisterServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<TimeSettings>(
            configuration.GetSection("TimeSettings")
        );

        services.AddScoped<CookieUtils>()
            .AddScoped<JwtUtils>()
            .AddRefreshTokenStorage()
            .AddSecurityNotificationService(configuration)
            .AddMiddlewares();

        return services;
    }

    public static IServiceCollection AddRefreshTokenStorage(this IServiceCollection services)
    {
        services.AddSingleton<IRefreshTokenStorage, InMemoryRefreshTokenStorage>();
        services.AddSingleton<IRefreshTokenStorageCleanup>(sp => (InMemoryRefreshTokenStorage)sp.GetRequiredService<IRefreshTokenStorage>());
        services.AddSingleton<IHostedService, TokenCleanupService>();

        return services;
    }

    public static IServiceCollection AddSecurityNotificationService(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<SecurityNotificationSettings>(
            configuration.GetSection("SecurityNotificationSettings")
        );

        services.AddScoped<ISecurityNotificationService, EmailSecurityNotificationService>();

        return services;
    }

    public static IServiceCollection AddMiddlewares(this IServiceCollection services)
    {
        return services;
    }
}

