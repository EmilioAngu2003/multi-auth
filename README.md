# Multi-Auth en .NET 9.0 🔐

Este proyecto implementa autenticación con múltiples proveedores: Google, GitHub y Facebook.

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