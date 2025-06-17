using Microsoft.Extensions.Options;
using multi_auth.Configuration;
using System.Net;
using System.Net.Mail;

namespace multi_auth.Services;

public class EmailSecurityNotificationService : ISecurityNotificationService
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly SecurityNotificationSettings _options;

    public EmailSecurityNotificationService(IOptions<SecurityNotificationSettings> options, IHttpContextAccessor httpContextAccessor)
    {
        _options = options.Value;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task NotifyPossibleTokenTheftAsync(string userId, string userEmail, string ipAddress, string userAgent)
    {
        var request = _httpContextAccessor.HttpContext?.Request;
        string logoutUrl = $"{request?.Scheme}://{request?.Host}/profile";

        var subject = "Alerta de Seguridad - Actividad Sospechosa Detectada";
        var body = $@"<html>
                    <body style='font-family: Arial, sans-serif; padding: 20px;'>
                        <div style='max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px;'>
                            <h2 style='color: #d9534f;'>⚠️ Alerta de Seguridad</h2>
                            <p>Hemos detectado actividad sospechosa en tu cuenta. Es posible que alguien más esté intentando acceder a tu sesión.</p>
        
                            <h3>Detalles:</h3>
                            <ul>
                                <li>Dirección IP: {ipAddress}</li>
                                <li>Dispositivo: {userAgent}</li>
                                <li>Hora: {DateTime.UtcNow}</li>
                            </ul>
        
                            <p>Por precaución, te recomendamos cerrar todas las sesiones desde el tu perfil</p>
        
                            <p style='font-size: 0.9em; color: #777; margin-top: 30px;'>
                                Este es un mensaje automático, por favor no respondas a este correo.
                            </p>
                        </div>
                    </body>
                    </html>";
        try
        {
            using var client = new SmtpClient(_options.SmtpServer, _options.SmtpPort)
            {
                EnableSsl = _options.EnableSsl,
                Credentials = new NetworkCredential(_options.SenderEmail, _options.SenderPassword)
            };

            using var message = new MailMessage
            {
                From = new MailAddress(_options.SenderEmail, _options.SenderName),
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            };

            message.To.Add(userEmail);

            await client.SendMailAsync(message);
        }
        catch (Exception)
        {
            Console.WriteLine($"Error al enviar notificación de seguridad al usuario {userId}");
        }
    }
}
