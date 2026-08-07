import 'dart:io';

import '../backend_environment.dart';
import 'maestro_database.dart';

Future<void> main() async {
  final environment = await loadBackendEnvironment();
  final database = SupabasePostgresDatabase.fromConfig(
    SupabaseDatabaseConfig.fromEnvironment(environment: environment),
  );
  try {
    final checks = await database.run(
      (session) => session.select('''
        select
          to_regclass('public.wallet_topup_coupons') is not null as coupons_table,
          (
            select relrowsecurity
            from pg_class
            where oid = 'public.wallet_topup_coupons'::regclass
          ) as coupons_rls,
          exists (
            select 1
            from information_schema.columns
            where table_schema = 'public'
              and table_name = 'notifications'
              and column_name = 'push_status'
          ) as push_status_column,
          exists (
            select 1
            from pg_indexes
            where schemaname = 'public'
              and indexname = 'idx_wallet_transactions_coupon_once'
          ) as coupon_once_index
        '''),
    );
    final row = checks.single;
    if (row.values.any((value) => value != true)) {
      throw StateError('Wallet/push schema verification failed: $row');
    }
    stdout.writeln(
      'Wallet coupon and push schema verified with RLS and unique index.',
    );
  } finally {
    await database.close();
  }
}
