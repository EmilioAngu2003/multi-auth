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
