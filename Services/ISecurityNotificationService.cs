namespace multi_auth.Services;

public interface ISecurityNotificationService
{
    Task NotifyPossibleTokenTheftAsync(string userId, string userEmail, string ipAddress, string userAgent);
}
