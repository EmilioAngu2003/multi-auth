namespace multi_auth.Storages;

public interface IRefreshTokenStorage
{
    Task<string> GenerateRefreshTokenAsync(string userId);
    Task StoreRefreshTokenAsync(string userId, string refreshToken);
    Task<bool> ValidateRefreshTokenAsync(string userId, string refreshToken);
    Task RevokeRefreshTokenAsync(string userId, string refreshToken);
    Task ExpireAllRefreshTokensAsync(string userId);
    Task<bool> IsRevokedRefreshTokenAsync(string userId, string refreshToken);
    Task<bool> IsExpiredRefreshTokenAsync(string userId, string refreshToken);
    Task<string> RotateRefreshTokenAsync(string userId, string refreshToken);
}
