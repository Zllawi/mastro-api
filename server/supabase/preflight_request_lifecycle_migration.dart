import 'dart:io';

import '../backend_environment.dart';
import 'maestro_database.dart';

/// Read-only safety check before applying the request lifecycle migration.
/// Prints aggregate counts only and never exposes customer data or secrets.
Future<void> main() async {
  final environment = await loadBackendEnvironment();
  final database = SupabasePostgresDatabase.fromConfig(
    SupabaseDatabaseConfig.fromEnvironment(environment: environment),
  );
  try {
    final rows = await database.run(
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
            ) duplicate_groups
          ) as active_duplicate_groups_before_expiry,
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
                and not (
                  status in ('submitted', 'offers_received')
                  and accepted_offer_id is null
                  and created_at <= now() - interval '48 hours'
                )
              group by customer_id, category_id
              having count(*) > 1
            ) duplicate_groups
          ) as active_duplicate_groups_after_expiry,
          (
            select count(*)::integer
            from public.service_requests
            where status in ('submitted', 'offers_received')
              and accepted_offer_id is null
              and created_at <= now() - interval '48 hours'
          ) as open_requests_due_for_expiry,
          (
            select count(*)::integer
            from (
              select offer_id
              from public.offer_revision_requests
              where status = 'pending'
              group by offer_id
              having count(*) > 1
            ) duplicate_revisions
          ) as pending_revision_duplicate_groups
        '''),
    );
    final result = rows.single;
    final activeDuplicatesBefore = _integer(
      result['active_duplicate_groups_before_expiry'],
    );
    final activeDuplicates = _integer(
      result['active_duplicate_groups_after_expiry'],
    );
    final dueForExpiry = _integer(result['open_requests_due_for_expiry']);
    final revisionDuplicates = _integer(
      result['pending_revision_duplicate_groups'],
    );
    stdout.writeln(
      'Active duplicate groups before expiry: $activeDuplicatesBefore',
    );
    stdout.writeln(
      'Active duplicate groups after planned expiry: $activeDuplicates',
    );
    stdout.writeln('Open requests due for 48-hour expiry: $dueForExpiry');
    stdout.writeln('Pending revision duplicate groups: $revisionDuplicates');
    if (activeDuplicates > 0) {
      final diagnostics = await database.run(
        (session) => session.select('''
          with duplicate_groups as (
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
          )
          select
            request.id,
            request.public_code,
            request.category_id,
            request.status,
            request.accepted_offer_id is not null as has_accepted_offer,
            request.created_at
          from public.service_requests request
          join duplicate_groups duplicates
            on duplicates.customer_id = request.customer_id
           and duplicates.category_id = request.category_id
          where request.status in (
            'submitted',
            'offers_received',
            'accepted',
            'on_the_way',
            'started',
            'disputed'
          )
          order by request.category_id, request.created_at
          '''),
      );
      for (final request in diagnostics) {
        stdout.writeln(
          'Duplicate request: id=${request['id']}, '
          'code=${request['public_code']}, category=${request['category_id']}, '
          'status=${request['status']}, '
          'accepted=${request['has_accepted_offer']}, '
          'created_at=${request['created_at']}',
        );
      }
      throw StateError(
        'Migration blocked: resolve active duplicate request groups first.',
      );
    }
  } finally {
    await database.close();
  }
}

int _integer(Object? value) => int.tryParse(value?.toString() ?? '') ?? 0;
