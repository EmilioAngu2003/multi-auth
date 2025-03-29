using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = "Cookies";
        options.DefaultChallengeScheme = "Google";
    })
    .AddCookie("Cookies")
    .AddGoogle(options =>
    {
        options.ClientId = builder.Configuration["Authentication:Google:ClientId"];
        options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
        options.SignInScheme = "Cookies";
        options.CallbackPath = builder.Configuration["Authentication:Google:CallbackPath"];
    })
    .AddFacebook(options =>
    {
        options.AppId = builder.Configuration["Authentication:Facebook:AppId"];
        options.AppSecret = builder.Configuration["Authentication:Facebook:AppSecret"];
        options.SignInScheme = "Cookies";
        options.CallbackPath = builder.Configuration["Authentication:Facebook:CallbackPath"];
    })
    .AddGitHub(options =>
    {
        options.ClientId = builder.Configuration["Authentication:GitHub:ClientId"];
        options.ClientSecret = builder.Configuration["Authentication:GitHub:ClientSecret"];
        options.SignInScheme = "Cookies";
        options.CallbackPath = builder.Configuration["Authentication:GitHub:CallbackPath"];
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
    var properties = new Microsoft.AspNetCore.Authentication.AuthenticationProperties { RedirectUri = redirectUrl };
    return Results.Challenge(properties, new[] { provider });
});

app.MapGet("/logout", async context =>
{
    await context.SignOutAsync();
    context.Response.Redirect("/");
});

app.Run();
