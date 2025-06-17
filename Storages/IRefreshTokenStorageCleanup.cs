namespace multi_auth.Storages;

public interface IRefreshTokenStorageCleanup
{
    Task CleanupExpiredTokens();
}
