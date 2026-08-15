import 'dart:io';

import '../backend_environment.dart';
import 'maestro_database.dart';

/// Read-only verification for
/// `20260815122024_request_lifecycle_redispatch_offer_revision.sql`.
///
/// This command reports schema/lifecycle invariants only. It never prints the
/// database URL or any other environment value.
Future<void> main() async {
  final environment = await loadBackendEnvironment();
  final database = SupabasePostgresDatabase.fromConfig(
    SupabaseDatabaseConfig.fromEnvironment(environment: environment),
  );
  try {
    final rows = await database.run(
      (session) => session.select('''
        select
          exists (
            select 1
            from information_schema.columns
            where table_schema = 'public'
              and table_name = 'service_requests'
              and column_name = 'expires_at'
              and is_nullable = 'NO'
          ) as expires_at_column,
          exists (
            select 1
            from information_schema.columns
            where table_schema = 'public'
              and table_name = 'service_requests'
              and column_name = 'last_redispatched_at'
          ) as last_redispatched_at_column,
          exists (
            select 1
            from information_schema.columns
            where table_schema = 'public'
              and table_name = 'service_requests'
              and column_name = 'redispatch_count'
          ) as redispatch_count_column,
          to_regclass(
            'public.idx_service_requests_pending_expiry'
          ) is not null as pending_expiry_index,
          exists (
            select 1
            from pg_index index_definition
            where index_definition.indexrelid =
              to_regclass('public.idx_service_requests_one_active_category')
              and index_definition.indisunique
          ) as unique_active_category_index,
          to_regclass(
            'public.idx_offer_revision_one_pending'
          ) is not null as one_pending_revision_index,
          exists (
            select 1
            from pg_trigger
            where tgrelid = 'public.service_requests'::regclass
              and tgname = 'enforce_one_active_request_per_category'
              and not tgisinternal
          ) as active_category_trigger,
          to_regprocedure(
            'maestro_private.expire_stale_service_requests()'
          ) is not null as private_expiry_function,
          not has_function_privilege(
            'anon',
            'maestro_private.expire_stale_service_requests()',
            'execute'
          ) as expiry_denied_to_anon,
          not has_function_privilege(
            'authenticated',
            'maestro_private.expire_stale_service_requests()',
            'execute'
          ) as expiry_denied_to_authenticated,
          exists (
            select 1
            from cron.job
            where jobname = 'mastro-expire-stale-service-requests'
              and schedule = '*/5 * * * *'
              and command =
                'select maestro_private.expire_stale_service_requests();'
              and active
          ) as expiry_cron_job,
          exists (
            select 1
            from public.app_settings
            where key = 'request_expiry_scheduler'
              and value ->> 'enabled' = 'true'
          ) as expiry_scheduler_setting
        '''),
    );
    final checks = rows.single;
    final failedChecks = checks.entries
        .where((entry) => entry.value != true)
        .map((entry) => entry.key)
        .toList(growable: false);

    final invariantRows = await database.run(
      (session) => session.select('''
        select
          (
            select count(*)::integer
            from (
              select customer_id, category_id
              from public.service_requests
              where status in (
                'submitted',
                'offers_received',
                'accepted',
                'on_the_way',
                'started',
                'disputed'
              )
              group by customer_id, category_id
              having count(*) > 1
            ) duplicates
          ) as active_request_duplicate_groups,
          (
            select count(*)::integer
            from (
              select offer_id
              from public.offer_revision_requests
              where status = 'pending'
              group by offer_id
              having count(*) > 1
            ) duplicates
          ) as pending_revision_duplicate_groups,
          (
            select count(*)::integer
            from public.service_requests
            where status in ('submitted', 'offers_received')
              and accepted_offer_id is null
              and expires_at <= now()
          ) as overdue_unaccepted_requests
        '''),
    );
    final invariants = invariantRows.single;
    final failedInvariants = invariants.entries
        .where((entry) => _integer(entry.value) != 0)
        .map((entry) => '${entry.key}=${entry.value}')
        .toList(growable: false);

    if (failedChecks.isNotEmpty || failedInvariants.isNotEmpty) {
      final failures = [...failedChecks, ...failedInvariants];
      throw StateError(
        'Request lifecycle schema verification failed: ${failures.join(', ')}',
      );
    }

    stdout.writeln(
      'Request lifecycle schema, cron schedule and data invariants verified.',
    );
  } finally {
    await database.close();
  }
}

int _integer(Object? value) => int.tryParse(value?.toString() ?? '') ?? -1;
