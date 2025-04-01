using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using multi_auth.Storages;
using System.Security.Claims;

namespace multi_auth.Middlewares;

public class RefreshCookie
{
    private readonly RequestDelegate _next;
    private readonly RefreshCookieStorage _refreshCookieStorage;

    public RefreshCookie(RequestDelegate next, RefreshCookieStorage refreshCookieStorage)
    {
        _next = next;
        _refreshCookieStorage = refreshCookieStorage;
    }

    public async Task Invoke(HttpContext context)
    {
        if (!context.User.Identity?.IsAuthenticated ?? false)
        {
            var principal = await context.AuthenticateAsync("Refresh-Cookie");

            if (principal?.Principal != null)
            {
                var refreshCookieId = principal?.Principal.FindFirst("refreshCookieId")?.Value;
                var userId = principal?.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (_refreshCookieStorage.IsValidRefreshCookie(userId, refreshCookieId))
                {
                    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal.Principal);
                }
                else
                {
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    await context.SignOutAsync("Refresh-Cookie");
                }
            }
        }

        await _next(context);
    }
}
