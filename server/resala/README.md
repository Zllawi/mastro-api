# Resala Environment

This module is backend-only. Never expose `RESALA_API_TOKEN` in Flutter, web, or
mobile client code.

Create your backend environment file from the template:

```powershell
Copy-Item .env.example .env
```

Fill these values:

```text
RESALA_API_TOKEN=your_real_token
RESALA_BASE_URL=https://dev.resala.ly/api/v1
APP_ENV=development
```

Use `APP_ENV=production` only when you want real SMS delivery. Non-production
environments use Resala `?test` mode automatically.

The Dart code reads process environment variables through
`ResalaConfig.fromEnvironment()`. A `.env` file is not loaded automatically by
Dart unless your backend runner loads it first.
