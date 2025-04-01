namespace multi_auth.Storages;

using System.Collections.Concurrent;

public class RefreshCookieStorage
{
    private readonly ConcurrentDictionary<string, Queue<string>> _userCookies = new();

    private const int MaxSessions = 3;

    public void AddRefreshCookie(string userId, string refreshCookieId)
    {
        var cookieQueue = _userCookies.GetOrAdd(userId, _ => new Queue<string>());

        lock (cookieQueue)
        {
            if (cookieQueue.Count >= MaxSessions)
            {
                cookieQueue.Dequeue();
            }

            cookieQueue.Enqueue(refreshCookieId);
        }
    }

    public bool IsValidRefreshCookie(string userId, string refreshCookieId)
    {
        return _userCookies.TryGetValue(userId, out var cookieQueue) && cookieQueue.Contains(refreshCookieId);
    }

    public void RevokeAllCookies(string userId)
    {
        _userCookies.TryRemove(userId, out _);
    }

    public void RevokeSingleCookie(string userId, string refreshCookieId)
    {
        if (_userCookies.TryGetValue(userId, out var cookieQueue))
        {
            lock (cookieQueue)
            {
                var newQueue = new Queue<string>(cookieQueue.Where(cookie => cookie != refreshCookieId));
                _userCookies[userId] = newQueue;
            }
        }
    }
}

