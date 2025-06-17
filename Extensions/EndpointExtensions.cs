using Microsoft.AspNetCore.Authentication;
using multi_auth.Storages;
using System.Security.Claims;

namespace multi_auth.Extensions;

public static class EndpointExtensions
{
    public static void MapAuthEndpoints(this WebApplication app)
    {
        app.MapGet("/auth/login/{provider}", (string provider) =>
        {
            if (!new[] { "Google", "Facebook", "GitHub" }.Contains(provider, StringComparer.OrdinalIgnoreCase))
                return Results.BadRequest("Proveedor no soportado.");

            var redirectUri = $"/Profile";
            var properties = new AuthenticationProperties() { RedirectUri = redirectUri };

            return Results.Challenge(properties, new[] { provider });
        });

        app.MapGet("/auth/logout", async (HttpContext context, IRefreshTokenStorage refreshTokenStorage) =>
        {
            var refreshToken = context.Request.Cookies["refresh_token"];
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(refreshToken) || string.IsNullOrEmpty(userId))
                return Results.Unauthorized();

            await refreshTokenStorage.RevokeRefreshTokenAsync(userId, refreshToken);

            context.Response.Cookies.Delete("refresh_token");
            context.Response.Cookies.Delete("access_token");

            return Results.Redirect("/");
        });

        app.MapGet("/auth/logout/all", async (HttpContext context, IRefreshTokenStorage refreshTokenStorage) =>
        {
            var refreshToken = context.Request.Cookies["refresh_token"];
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(refreshToken) || string.IsNullOrEmpty(userId))
                return Results.Unauthorized();

            await refreshTokenStorage.ExpireAllRefreshTokensAsync(userId);

            context.Response.Cookies.Delete("refresh_token");
            context.Response.Cookies.Delete("access_token");

            return Results.Redirect("/");
        });
    }
}
