import 'dart:io';

import '../backend_environment.dart';
import 'maestro_database.dart';

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
              and table_name = 'service_categories'
              and column_name = 'metadata'
          ) as metadata_column,
          exists (
            select 1
            from public.service_categories
            where id = 'driver'
              and is_active = true
              and metadata->>'service_kind' = 'driver'
              and jsonb_array_length(metadata->'driver_vehicle_types') >= 1
              and jsonb_array_length(metadata->'driver_trip_types') >= 2
          ) as driver_category
        '''),
    );
    final row = rows.single;
    final failed = row.entries
        .where((entry) => entry.value != true)
        .map((entry) => entry.key)
        .toList(growable: false);
    if (failed.isNotEmpty) {
      stderr.writeln(
        'Driver service options verification failed: ${failed.join(', ')}',
      );
      exit(1);
    }
    stdout.writeln('Driver service options schema verified.');
  } finally {
    await database.close();
  }
}
