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
          coalesce(jsonb_array_length(value->'items'), 0) = 12 as method_count,
          exists (
            select 1
            from jsonb_array_elements(value->'items') item
            where item->>'id' = 'coupon'
              and item->>'status' = 'open'
              and item->>'integrated' = 'true'
          ) as coupon_ready,
          not exists (
            select 1
            from jsonb_array_elements(value->'items') item
            where item->>'status' = 'open'
              and item->>'integrated' <> 'true'
          ) as no_unsafe_provider
        from public.app_settings
        where key = 'wallet_topup_methods'
        limit 1
      '''),
    );
    if (rows.isEmpty) {
      stderr.writeln('Wallet top-up methods setting is missing.');
      exit(1);
    }
    final failed = rows.single.entries
        .where((entry) => entry.value != true)
        .map((entry) => entry.key)
        .toList(growable: false);
    if (failed.isNotEmpty) {
      stderr.writeln(
        'Wallet top-up methods verification failed: ${failed.join(', ')}',
      );
      exit(1);
    }
    stdout.writeln(
      'Wallet top-up methods verified: 12 methods, coupon ready, no unsafe provider enabled.',
    );
  } finally {
    await database.close();
  }
}
