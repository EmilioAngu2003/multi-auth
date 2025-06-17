namespace multi_auth.Configuration;

public class AuthSettings
{
    public GoogleAuth Google { get; set; }
    public GitHubAuth GitHub { get; set; }
    public FacebookAuth Facebook { get; set; }
}

public class GoogleAuth
{
    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
    public string CallbackPath { get; set; }
}

public class GitHubAuth
{
    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
    public string CallbackPath { get; set; }
}

public class FacebookAuth
{
    public string AppId { get; set; }
    public string AppSecret { get; set; }
    public string CallbackPath { get; set; }
}

public class JwtSettings
{
    public string SecretKey { get; set; }
    public string Issuer { get; set; }
    public string Audience { get; set; }
}

public class SecurityNotificationSettings
{
    public string SmtpServer { get; set; }
    public int SmtpPort { get; set; }
    public string SenderEmail { get; set; }
    public string SenderPassword { get; set; }
    public string SenderName { get; set; }
    public bool EnableSsl { get; set; }
}

public class TimeSettings
{
    public TimeSpan CookieLifetime { get; set; }
    public TimeSpan JwtLifetime { get; set; }
    public TimeSpan TokenLifetime { get; set; }
    public CleanupSettings Cleanup { get; set; }

    public Func<DateTime, DateTime> GetNextCleanupTime
    {
        get
        {
            if (Cleanup.Start.Equals("now", StringComparison.OrdinalIgnoreCase))
            {
                return (currentTime) => currentTime.Add(Cleanup.Interval);
            }
            else if (TimeSpan.TryParse(Cleanup.Start, out TimeSpan start))
            {
                return (currentTime) =>
                {
                    DateTime nextCleanup = currentTime.Date.Add(start);
                    return nextCleanup.Add(Cleanup.Interval);
                };
            }
            else
            {
                throw new InvalidOperationException($"Invalid Cleanup.StartPoint value: {Cleanup.Start}");
            }
        }
    }
}

public class CleanupSettings
{
    public string Start { get; set; }
    public TimeSpan Interval { get; set; }
}
