using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using multi_auth.Configuration;
using multi_auth.Middlewares;
using multi_auth.Storages;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<RefreshCookieStorage>();

var authSettings = new AuthSettings();
builder.Configuration.GetSection("Authentication").Bind(authSettings);

const int ACCESS_COOKIE_TIME = 30;
const int REFRESH_COOKIE_TIME = 1;

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.Cookie.Name = "Multi-Auth-Access-Cookie";
        options.LoginPath = "/";
        options.ExpireTimeSpan = TimeSpan.FromSeconds(ACCESS_COOKIE_TIME);
        options.SlidingExpiration = false;
        options.Cookie.IsEssential = false;
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    })
    .AddCookie("Refresh-Cookie", options =>
    {
        options.Cookie.Name = "Multi-Auth-Refresh-Cookie";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(REFRESH_COOKIE_TIME);
        options.SlidingExpiration = true;
        options.Cookie.IsEssential = true;
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Events.OnSigningIn = async context =>
        {
            var userId = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var refreshCookieId = Guid.NewGuid().ToString();

            var refreshCookieStorage = context.HttpContext.RequestServices.GetRequiredService<RefreshCookieStorage>();
            refreshCookieStorage.AddRefreshCookie(userId, refreshCookieId);

            var identity = context.Principal?.Identity as ClaimsIdentity;
            if (identity != null)
            {
                identity.AddClaim(new Claim("refreshCookieId", refreshCookieId));
            }
        };
    })
    .AddGoogle(options =>
    {
        options.ClientId = authSettings.Google.ClientId;
        options.ClientSecret = authSettings.Google.ClientSecret;
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.CallbackPath = authSettings.Google.CallbackPath;
        options.Events.OnCreatingTicket = async context =>
        {
            await context.HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, context.Principal);
            await context.HttpContext.SignInAsync("Refresh-Cookie", context.Principal);
        };
    })
    .AddFacebook(options =>
    {
        options.AppId = authSettings.Facebook.AppId;
        options.AppSecret = authSettings.Facebook.AppSecret;
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.CallbackPath = authSettings.Facebook.CallbackPath;
        options.Events.OnCreatingTicket = async context =>
        {
            await context.HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, context.Principal);
            await context.HttpContext.SignInAsync("Refresh-Cookie", context.Principal);
        };
    })
    .AddGitHub(options =>
    {
        options.ClientId = authSettings.GitHub.ClientId;
        options.ClientSecret = authSettings.GitHub.ClientSecret;
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.CallbackPath = authSettings.GitHub.CallbackPath;
        options.Events.OnCreatingTicket = async context =>
        {
            await context.HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, context.Principal);
            await context.HttpContext.SignInAsync("Refresh-Cookie", context.Principal);
        };
    });

builder.Services.AddAuthorization();

builder.Services.AddRazorPages();

var app = builder.Build();

app.UseStaticFiles();

app.UseMiddleware<RefreshCookie>();
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

app.MapGet("/login/{provider}", (string provider, HttpContext context) =>
{
    var redirectUrl = "/Profile";
    var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
    return Results.Challenge(properties, new[] { provider });
});

app.MapGet("/logout", async context =>
{
    var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var refreshCookieId = context.User.FindFirst("refreshCookieId")?.Value;

    var refreshCookieStorage = context.RequestServices.GetRequiredService<RefreshCookieStorage>();
    refreshCookieStorage.RevokeSingleCookie(userId, refreshCookieId);

    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await context.SignOutAsync("Refresh-Cookie");

    context.Response.Redirect("/");
});

app.MapGet("/logout/all", async context =>
{
    var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var refreshCookieStorage = context.RequestServices.GetRequiredService<RefreshCookieStorage>();

    refreshCookieStorage.RevokeAllCookies(userId);

    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await context.SignOutAsync("Refresh-Cookie");

    context.Response.Redirect("/");
});

app.Run();
