using Microsoft.Extensions.Options;
using multi_auth.Configuration;

namespace multi_auth.Utils;

public class CookieUtils
{
    private readonly TimeSpan _cookieLifetime;

    public CookieUtils(IOptions<TimeSettings> timeSettings)
    {
        _cookieLifetime = timeSettings.Value.CookieLifetime;
    }

    public void SetAuthenticationCookie(HttpResponse response, string key, string value)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.UtcNow.Add(_cookieLifetime)
        };

        response.Cookies.Append(key, value, cookieOptions);
    }
}
