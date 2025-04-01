using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using multi_auth.Configuration;

var builder = WebApplication.CreateBuilder(args);


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
    await context.SignOutAsync();
    context.Response.Redirect("/");
});

app.Run();
