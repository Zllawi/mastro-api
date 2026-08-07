# Supabase PostgreSQL Setup

This folder contains backend-only storage code for Maestro. Keep database
connection strings and service-role keys outside Flutter, web, and mobile code.

## Environment

Start from the root template:

```powershell
Copy-Item .env.example .env
```

Fill these values for your backend process:

```text
SUPABASE_URL=https://your-project-ref.supabase.co
SUPABASE_ANON_KEY=your_public_anon_key
SUPABASE_SERVICE_ROLE_KEY=your_backend_only_service_role_key
SUPABASE_DATABASE_URL=postgresql://postgres.your-project-ref:password@aws-0-region.pooler.supabase.com:5432/postgres?sslmode=require
```

`SUPABASE_DATABASE_URL` is what the Dart backend module uses for PostgreSQL.
Use the Supabase session pooler URL (port `5432`) for this persistent Dart
backend. Transaction pooler port `6543` does not support the prepared
statements used by parameterized queries.

## Migration

Run the SQL file in Supabase SQL Editor:

```text
supabase/migrations/202607271_prepare_maestro_core_schema.sql
```

The migration creates tables for:

- profiles and craftsman profiles
- customer addresses
- service categories
- service requests
- request attachments and status history
- offers
- job messages
- reviews
- notifications
- OTP codes
- Resala delivery logs

RLS is enabled on all tables. The backend should use the service role or direct
PostgreSQL connection. Do not use the service role from Flutter.

## Backend usage

```dart
final database = SupabasePostgresDatabase.fromConfig(
  SupabaseDatabaseConfig.fromEnvironment(),
);

final profiles = ProfilesRepository(database);
final requests = ServiceRequestsRepository(database);
final offers = OffersRepository(database);

final otpService = ResalaOtpService(
  client: ResalaClient(config: ResalaConfig.fromEnvironment()),
  store: SupabaseOtpStore(database),
);
```

Close the database pool when the backend shuts down:

```dart
await database.close();
```
