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
              and table_name = 'notification_campaigns'
              and column_name = 'status'
          ) as campaigns_ready,
          exists (
            select 1
            from information_schema.columns
            where table_schema = 'public'
              and table_name = 'notifications'
              and column_name = 'campaign_id'
          ) as notification_links_ready,
          exists (
            select 1
            from information_schema.tables
            where table_schema = 'public'
              and table_name = 'service_categories'
          ) as categories_ready
      '''),
    );
    final result = rows.single;
    if (result['campaigns_ready'] != true ||
        result['notification_links_ready'] != true ||
        result['categories_ready'] != true) {
      throw StateError('Required administration tables are incomplete.');
    }
    stdout.writeln('Admin notification and category schema verified.');
  } finally {
    await database.close();
  }
}
