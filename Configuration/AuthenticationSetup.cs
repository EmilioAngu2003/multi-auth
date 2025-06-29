using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.IdentityModel.Tokens;
using multi_auth.Services;
using multi_auth.Storages;
using multi_auth.Utils;
using System.Security.Claims;
using System.Text;

namespace multi_auth.Configuration;

public static class AuthenticationSetup
{
    public static IServiceCollection ConfigureAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        services
            .AddJwt(configuration)
            .AddProviders(configuration);

        return services;
    }

    public static IServiceCollection AddJwt(this IServiceCollection services, IConfiguration configuration)
    {
        var jwtSettings = configuration.GetSection("JwtSettings").Get<JwtSettings>();
        services.AddSingleton(jwtSettings);

        services.AddScoped<JwtEvents>();

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtSettings.Issuer,
                ValidAudience = jwtSettings.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),
                ClockSkew = TimeSpan.Zero
            };
            options.EventsType = typeof(JwtEvents);
        });

        return services;
    }

    public static IServiceCollection AddProviders(this IServiceCollection services, IConfiguration configuration)
    {
        var authSettings = configuration.GetSection("Authentication").Get<AuthSettings>();

        services.AddScoped<AuthEvents>();

        services.AddAuthentication()
            .AddGoogle(options =>
            {
                options.ClientId = authSettings.Google.ClientId;
                options.ClientSecret = authSettings.Google.ClientSecret;
                options.CallbackPath = authSettings.Google.CallbackPath;
                options.EventsType = typeof(AuthEvents);
            })
            .AddFacebook(options =>
            {
                options.AppId = authSettings.Facebook.AppId;
                options.AppSecret = authSettings.Facebook.AppSecret;
                options.CallbackPath = authSettings.Facebook.CallbackPath;
                options.EventsType = typeof(AuthEvents);
            })
            .AddGitHub(options =>
            {
                options.ClientId = authSettings.GitHub.ClientId;
                options.ClientSecret = authSettings.GitHub.ClientSecret;
                options.CallbackPath = authSettings.GitHub.CallbackPath;
                options.EventsType = typeof(AuthEvents);
            });

        return services;
    }
}
public class AuthEvents : OAuthEvents
{
    private readonly IRefreshTokenStorage _refreshTokenStorage;
    private readonly CookieUtils _cookieUtils;
    private readonly JwtUtils _jwtUtils;

    public AuthEvents(
        IRefreshTokenStorage refreshTokenStorage,
        CookieUtils cookieUtils,
        JwtUtils jwtUtils)
    {
        _refreshTokenStorage = refreshTokenStorage;
        _cookieUtils = cookieUtils;
        _jwtUtils = jwtUtils;
    }
    public override async Task CreatingTicket(OAuthCreatingTicketContext context)
    {
        var claims = context.Principal?.Claims.ToList() ?? new List<Claim>();
        context.Properties.Items["access_token"] = _jwtUtils.GenerateToken(claims);

        var userId = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty;
        context.Properties.Items["refresh_token"] = await _refreshTokenStorage.GenerateRefreshTokenAsync(userId);
    }

    public override async Task TicketReceived(TicketReceivedContext context)
    {
        var accessToken = context.Properties?.Items["access_token"];
        _cookieUtils.SetAuthenticationCookie(context.Response, "access_token", accessToken);

        var refreshToken = context.Properties?.Items["refresh_token"];
        _cookieUtils.SetAuthenticationCookie(context.Response, "refresh_token", refreshToken);

        context.HandleResponse();

        context.Response.ContentType = "text/html";
        await context.Response.WriteAsync(@"
        <html>
            <head><script>window.location.href = '/Profile';</script></head>
            <body>Redirigiendo...</body>
        </html>
    ");
    }
}

public class JwtEvents : JwtBearerEvents
{
    private readonly JwtUtils _jwtUtils;
    private readonly CookieUtils _cookieUtils;
    private readonly IRefreshTokenStorage _refreshTokenStorage;
    private readonly ISecurityNotificationService _securityNotificationService;
    public JwtEvents(JwtUtils jwtUtils, CookieUtils cookieUtils, IRefreshTokenStorage refreshTokenStorage, ISecurityNotificationService securityNotificationService)
    {
        _jwtUtils = jwtUtils;
        _refreshTokenStorage = refreshTokenStorage;
        _securityNotificationService = securityNotificationService;
        _cookieUtils = cookieUtils;
    }

    public override async Task MessageReceived(MessageReceivedContext context)
    {
        var accessToken = context.Request.Cookies["access_token"];
        if (!string.IsNullOrEmpty(accessToken))
        {
            context.Token = accessToken;
        }
    }

    public override async Task AuthenticationFailed(AuthenticationFailedContext context)
    {
        if (context.Exception is SecurityTokenExpiredException)
        {
            var (needsTokenUpdate, principal) = await ShouldUpdateToken(context.HttpContext);
            if (needsTokenUpdate && principal != null)
            {
                await UpdateToken(context.HttpContext, principal);
                context.Principal = principal;
                context.Success();
            }
        }
    }

    public override async Task Challenge(JwtBearerChallengeContext context)
    {
        context.HandleResponse();
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Redirect("/");
    }

    private async Task UpdateToken(HttpContext context, ClaimsPrincipal principal)
    {
        var refreshToken = context.Request.Cookies["refresh_token"];
        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        var newRefreshToken = await _refreshTokenStorage.RotateRefreshTokenAsync(userId, refreshToken);
        _cookieUtils.SetAuthenticationCookie(context.Response, "refresh_token", newRefreshToken);

        var newAccessToken = _jwtUtils.GenerateToken(principal.Claims);
        _cookieUtils.SetAuthenticationCookie(context.Response, "access_token", newAccessToken);
        context.User = principal;
    }

    private async Task<(bool NeedsUpdate, ClaimsPrincipal? Principal)> ShouldUpdateToken(HttpContext context)
    {
        var accessToken = context.Request.Cookies["access_token"] ?? string.Empty;
        var refreshToken = context.Request.Cookies["refresh_token"] ?? string.Empty;

        if (string.IsNullOrEmpty(accessToken) && string.IsNullOrEmpty(refreshToken))
            return (false, null);

        var principal = _jwtUtils.ValidateToken(accessToken, validateLifetime: false);
        if (principal == null)
            return (false, null);

        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
            return (false, null);

        var expiredRefreshToken = await _refreshTokenStorage.IsExpiredRefreshTokenAsync(userId, refreshToken);
        if (expiredRefreshToken)
            return (false, null);

        var revokedRefreshToken = await _refreshTokenStorage.IsRevokedRefreshTokenAsync(userId, refreshToken);
        if (revokedRefreshToken)
        {
            context.Response.Cookies.Delete("refresh_token");
            context.Response.Cookies.Delete("access_token");

            var userEmail = principal.FindFirst(ClaimTypes.Email)?.Value;
            var currentIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var userAgent = context.Request.Headers.UserAgent.ToString() ?? "unknown";

            if (!string.IsNullOrEmpty(userEmail))
                await _securityNotificationService.NotifyPossibleTokenTheftAsync(userId, userEmail, currentIp, userAgent);

            return (false, null);
        }

        return (true, principal);
    }
}
