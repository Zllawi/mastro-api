import 'dart:io';

import '../backend_environment.dart';
import 'maestro_database.dart';
import 'platform_repository.dart';

/// Read-only verification for
/// `20260728193630_admin_services_requests_support_retention.sql`.
///
/// Run this only after the migration has been applied by the release owner.
Future<void> main() async {
  final environment = await loadBackendEnvironment();
  final database = SupabasePostgresDatabase.fromConfig(
    SupabaseDatabaseConfig.fromEnvironment(environment: environment),
  );
  final repository = PlatformRepository(database);
  try {
    final checks = await database.run(
      (session) => session.select('''
        select
          to_regclass('public.support_messages') is not null
            as support_messages_table,
          to_regclass('public.media_cleanup_jobs') is not null
            as media_cleanup_jobs_table,
          to_regclass('public.managed_media_assets') is not null
            as managed_media_assets_table,
          exists (
            select 1
            from information_schema.columns
            where table_schema = 'public'
              and table_name = 'service_categories'
              and column_name = 'icon_url'
          ) as category_icon_url,
          exists (
            select 1
            from information_schema.columns
            where table_schema = 'public'
              and table_name = 'service_categories'
              and column_name = 'availability_status'
          ) as category_availability,
          exists (
            select 1
            from information_schema.columns
            where table_schema = 'public'
              and table_name = 'service_requests'
              and column_name = 'cancellation_mode'
          ) as request_cancellation,
          exists (
            select 1
            from information_schema.columns
            where table_schema = 'public'
              and table_name = 'job_messages'
              and column_name = 'attachment_public_id'
          ) as job_message_public_id,
          exists (
            select 1
            from information_schema.columns
            where table_schema = 'public'
              and table_name = 'managed_media_assets'
              and column_name = 'consumed_at'
          ) as managed_media_consumption,
          (
            select relrowsecurity
            from pg_class
            where oid = 'public.support_messages'::regclass
          ) as support_messages_rls,
          (
            select relrowsecurity
            from pg_class
            where oid = 'public.media_cleanup_jobs'::regclass
          ) as cleanup_jobs_rls,
          (
            select relrowsecurity
            from pg_class
            where oid = 'public.managed_media_assets'::regclass
          ) as managed_media_assets_rls,
          exists (
            select 1
            from public.app_settings
            where key = 'media_retention'
          ) as retention_setting
        '''),
    );
    final row = checks.single;
    final failed = row.entries
        .where((entry) => entry.value != true)
        .map((entry) => entry.key)
        .toList(growable: false);
    if (failed.isNotEmpty) {
      throw StateError(
        'Admin upgrade schema verification failed: ${failed.join(', ')}',
      );
    }

    // These calls compile and execute the production query paths without
    // changing user data.
    await repository.adminRequests(page: 1, perPage: 1);
    final retention = await repository.mediaRetentionSettings();
    if (!retention.containsKey('enabled')) {
      throw StateError('Media-retention settings could not be decoded.');
    }
    stdout.writeln(
      'Admin services, requests, support and media-retention schema verified.',
    );
  } finally {
    await database.close();
  }
}
