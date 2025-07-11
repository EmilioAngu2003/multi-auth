# Multi-Auth (.NET 9)

![.NET](https://img.shields.io/badge/.NET-9.0-blue)
![License](https://img.shields.io/github/license/EmilioAngu2003/multi-auth)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

Autenticación con múltiples proveedores (Google, GitHub, Facebook) usando .NET 9, JWT y buenas prácticas de seguridad. Incluye **rotación y revocación de tokens**, **notificaciones por correo**, y **limpieza automática** de tokens expirados.

Además, el proyecto incluye **Razor Pages** para probar fácilmente las funcionalidades del backend directamente desde el navegador.

## 🚀 Tecnologías usadas

- ASP.NET Core 9
- OAuth2 / OpenID Connect
- JWT
- SMTP
- Razor Pages

## 🔐 Características principales

- ✅ Login con Google, GitHub y Facebook
- 🔒 Autenticación segura con JWT
- 🔁 Rotación de refresh tokens
- 📬 Notificaciones por correo electrónico
- ♻️ Limpieza automática de tokens
- ⚙️ Totalmente configurable desde archivo JSON

## 📦 Instalación

```bash
git clone https://github.com/EmilioAngu2003/multi-auth.git
cd multi-auth
dotnet restore
dotnet run
```

## ⚙️ Configuración

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
    "SecretKey": "your-super-secret-key-that-is-at-least-32-characters-long",
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

## 🧪 Cómo probar

El repositorio ya incluye **Razor Pages** para probar las funcionalidades del backend

## License

MIT

## Arquitectura

![Class Diagram](Docs/Diagrams/ClassDiagram.svg)