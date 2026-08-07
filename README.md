# MASTRO API

Backend API for MASTRO / ماسترو.

## Render deployment

This repository is Docker-ready. In Render:

1. Create a new **Web Service** from this GitHub repository.
2. Render will detect `render.yaml`.
3. Add the secret environment variables in Render Dashboard.
4. Deploy.

Render provides `PORT` automatically. The backend binds to `HOST=0.0.0.0`.

## Required environment variables

Do not commit real values. Set them in Render:

- `RESALA_API_TOKEN`
- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`
- `SUPABASE_DATABASE_URL`
- `CLOUDINARY_CLOUD_NAME`
- `CLOUDINARY_API_KEY`
- `CLOUDINARY_API_SECRET`
- `FIREBASE_PROJECT_ID`
- `FIREBASE_SERVICE_ACCOUNT_JSON_BASE64`
- `MAESTRO_ADMIN_PHONE`

Non-secret defaults are included in `render.yaml`.

## Health check

```text
GET /health
```

Expected response:

```json
{"ok":true}
```

## Local run

```powershell
dart pub get
dart run server/http_server.dart
```
