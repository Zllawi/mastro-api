import 'dart:io';

import '../backend_environment.dart';
import 'maestro_database.dart';
import 'platform_repository.dart';

/// Read-only verification for
/// `20260803093000_password_dispatch_offer_admin_controls.sql`.
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
          exists (
            select 1
            from information_schema.columns
            where table_schema = 'public'
              and table_name = 'profiles'
              and column_name = 'password_hash'
          ) as profile_password_hash,
          exists (
            select 1
            from information_schema.columns
            where table_schema = 'public'
              and table_name = 'profiles'
              and column_name = 'password_reset_required'
          ) as profile_password_reset_required,
          exists (
            select 1
            from information_schema.columns
            where table_schema = 'public'
              and table_name = 'profiles'
              and column_name = 'warning_count'
          ) as profile_warning_count,
          to_regclass('public.user_warnings') is not null as warnings_table,
          to_regclass('public.request_dispatches') is not null as dispatches_table,
          to_regclass('public.offer_revision_requests') is not null as revisions_table,
          to_regclass('public.customer_reviews') is not null as customer_reviews_table,
          exists (
            select 1
            from public.app_settings
            where key = 'request_automation'
          ) as automation_setting,
          (
            select relrowsecurity
            from pg_class
            where oid = 'public.user_warnings'::regclass
          ) as warnings_rls,
          (
            select relrowsecurity
            from pg_class
            where oid = 'public.request_dispatches'::regclass
          ) as dispatches_rls,
          (
            select relrowsecurity
            from pg_class
            where oid = 'public.offer_revision_requests'::regclass
          ) as revisions_rls,
          (
            select relrowsecurity
            from pg_class
            where oid = 'public.customer_reviews'::regclass
          ) as customer_reviews_rls
        '''),
    );
    final row = checks.single;
    final failed = row.entries
        .where((entry) => entry.value != true)
        .map((entry) => entry.key)
        .toList(growable: false);
    if (failed.isNotEmpty) {
      throw StateError(
        'Password/dispatch schema verification failed: ${failed.join(', ')}',
      );
    }

    final automation = await repository.requestAutomationSettings();
    if (automation['batch_size'] == null ||
        automation['batch_interval_minutes'] == null) {
      throw StateError('Request automation settings could not be decoded.');
    }

    stdout.writeln(
      'Password, warning, fair dispatch, offer revision and customer review schema verified.',
    );
  } finally {
    await database.close();
  }
}
