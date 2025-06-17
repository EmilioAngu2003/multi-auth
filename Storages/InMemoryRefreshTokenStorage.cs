using Microsoft.Extensions.Options;
using multi_auth.Configuration;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace multi_auth.Storages;

public class InMemoryRefreshTokenStorage : IRefreshTokenStorage, IRefreshTokenStorageCleanup
{
    private class TokenInfo
    {
        public string Token { get; set; }
        public DateTime Created { get; set; }
        public DateTime ExpiryDate { get; set; }
        public bool IsRevoked { get; set; }
    }

    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, TokenInfo>> _userTokens = new();
    private readonly ConcurrentDictionary<string, DateTime> _lastClosingAllSessions = new();

    private readonly TimeSpan _tokenLifetime;

    public InMemoryRefreshTokenStorage(IOptions<TimeSettings> timeSettings)
    {
        _tokenLifetime = timeSettings.Value.TokenLifetime;
    }

    public Task<string> GenerateRefreshTokenAsync(string userId)
    {
        var randomBytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        string token = Convert.ToBase64String(randomBytes);

        StoreRefreshTokenAsync(userId, token);

        return Task.FromResult(token);
    }

    public Task StoreRefreshTokenAsync(string userId, string refreshToken)
    {
        var tokenInfo = new TokenInfo
        {
            Token = refreshToken,
            Created = DateTime.UtcNow,
            ExpiryDate = DateTime.UtcNow.Add(_tokenLifetime),
            IsRevoked = false
        };

        var userTokensDict = _userTokens.GetOrAdd(userId,
            _ => new ConcurrentDictionary<string, TokenInfo>());

        userTokensDict[refreshToken] = tokenInfo;

        return Task.CompletedTask;
    }

    public Task<bool> ValidateRefreshTokenAsync(string userId, string refreshToken)
    {
        if (!_userTokens.TryGetValue(userId, out var userTokensDict))
            return Task.FromResult(false);

        if (!userTokensDict.TryGetValue(refreshToken, out var tokenInfo))
            return Task.FromResult(false);

        if (tokenInfo.IsRevoked)
            return Task.FromResult(false);

        if (_lastClosingAllSessions.TryGetValue(userId, out var lastRevoked))
            if (tokenInfo.Created < lastRevoked)
                return Task.FromResult(false);

        if (tokenInfo.ExpiryDate < DateTime.UtcNow)
            return Task.FromResult(false);

        return Task.FromResult(true);
    }

    public Task RevokeRefreshTokenAsync(string userId, string refreshToken)
    {
        if (_userTokens.TryGetValue(userId, out var userTokensDict))
            if (userTokensDict.TryGetValue(refreshToken, out var tokenInfo))
                tokenInfo.IsRevoked = true;

        return Task.CompletedTask;
    }

    public Task ExpireAllRefreshTokensAsync(string userId)
    {
        _lastClosingAllSessions[userId] = DateTime.UtcNow;
        return Task.CompletedTask;
    }

    public Task<bool> IsRevokedRefreshTokenAsync(string userId, string refreshToken)
    {
        if (!_userTokens.TryGetValue(userId, out var userTokensDict))
            return Task.FromResult(false);

        if (!userTokensDict.TryGetValue(refreshToken, out var tokenInfo))
            return Task.FromResult(false);

        return Task.FromResult(tokenInfo.IsRevoked);
    }

    public Task<bool> IsExpiredRefreshTokenAsync(string userId, string refreshToken)
    {
        if (!_userTokens.TryGetValue(userId, out var userTokensDict))
            return Task.FromResult(true);

        if (!userTokensDict.TryGetValue(refreshToken, out var tokenInfo))
            return Task.FromResult(true);

        if (tokenInfo.ExpiryDate < DateTime.UtcNow)
            return Task.FromResult(true);

        if (!_lastClosingAllSessions.TryGetValue(userId, out var lastClosingAllSessions))
            return Task.FromResult(false);

        return Task.FromResult(tokenInfo.Created < lastClosingAllSessions);
    }

    public async Task<string> RotateRefreshTokenAsync(string userId, string refreshToken)
    {
        await RevokeRefreshTokenAsync(userId, refreshToken);
        return await GenerateRefreshTokenAsync(userId);
    }

    public Task CleanupExpiredTokens()
    {
        var now = DateTime.UtcNow;

        foreach (var userTokenDict in _userTokens)
        {
            _lastClosingAllSessions.TryGetValue(userTokenDict.Key, out var lastClosingAllSessions);

            var tokensToRemove = userTokenDict.Value
                .Where(t => t.Value.ExpiryDate < now || t.Value.IsRevoked || t.Value.Created < lastClosingAllSessions)
                .Select(t => t.Key)
                .ToArray();

            foreach (var token in tokensToRemove)
                userTokenDict.Value.TryRemove(token, out _);

            if (userTokenDict.Value.IsEmpty)
                _userTokens.TryRemove(userTokenDict.Key, out _);
        }

        return Task.CompletedTask;
    }
}
