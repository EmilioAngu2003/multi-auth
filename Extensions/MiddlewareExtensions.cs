namespace multi_auth.Extensions;

public static class MiddlewareExtensions
{
    public static void UseCustomMiddlewares(this WebApplication app)
    {
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseStaticFiles();
    }
}
