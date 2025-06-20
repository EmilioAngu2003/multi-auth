# Multi-Auth en .NET 9.0 🔐

Este proyecto implementa autenticación con múltiples proveedores: Google, GitHub y Facebook. Además, incorpora seguridad avanzada con JWT (JSON Web Tokens), notificaciones por correo electrónico para alertar sobre el uso de tokens de actualización revocados, y configuraciones de tiempo personalizables.

1. Clona el repositorio:
   ```sh
   git clone https://github.com/EmilioAngu2003/multi-auth.git
   cd multi-auth
   ```
2. Configura tus credenciales en `appsettings.json`:
    ```json
   {
       "Authentication": {
          "Google": { 
            "ClientId": "your-google-client-id",
            "ClientSecret": "your-google-client-secret",
            "CallbackPath": "/signin-google"
          },
          "GitHub": { 
            "ClientId": "your-github-client-id",
            "ClientSecret": "your-github-client-secret",
            "CallbackPath": "/signin-github"
          },
          "Facebook": { 
            "AppId": "your-facebook-app-id",
            "AppSecret": "your-facebook-app-secret",
            "CallbackPath": "/signin-facebook"
          }
       },
       "JwtSettings": {
          "Secret": "your-super-secret-key-that-is-at-least-32-characters-long",
          "Issuer": "your-issuer",
          "Audience": "your-audience"
       },
       "SecurityNotificationSettings": {
          "SendServer": "your-email-server",
          "Port": 587,
          "SenderEmail": "your-sender-email@example.com",
          "SenderPassword": "your-sender-email-password",
          "RecipientName": "Security Admin",
          "EnabledMail": true
       },
       "TimeSettings": {
          "CookieLifetime": "0.00:07:00",
          "JwtLifetime": "0.00:00:05",
          "TokenLifetime": "0.00:07:00",
          "Cleanup": {
            "Start": "now",
            "Interval": "0.00:01:00"
          }
       }
    }
    ```
    ⚠️ Importante: El CallbackPath debe coincidir con la URL configurada en cada proveedor OAuth para evitar errores de redirección.
    
3. Ejecuta el proyecto:
    ```sh
   dotnet run
   ```
## License

MIT