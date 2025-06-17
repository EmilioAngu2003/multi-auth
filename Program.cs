using multi_auth.Configuration;
using multi_auth.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.RegisterServices(builder.Configuration)
    .ConfigureAuthentication(builder.Configuration);

builder.Services.AddAuthorization();
builder.Services.AddHttpContextAccessor();
builder.Services.AddRazorPages();

var app = builder.Build();

app.UseCustomMiddlewares();

app.MapRazorPages();
app.MapAuthEndpoints();

app.Run();
