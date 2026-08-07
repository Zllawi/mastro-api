import 'dart:io';

import '../backend_environment.dart';
import 'maestro_database.dart';
import 'platform_repository.dart';

Future<void> main() async {
  final environment = await loadBackendEnvironment();
  final database = SupabasePostgresDatabase.fromConfig(
    SupabaseDatabaseConfig.fromEnvironment(environment: environment),
  );
  try {
    final candidates = await database.run(
      (session) => session.select('''
        select
          sr.customer_id,
          sr.id as request_id,
          o.id as offer_id
        from public.service_requests sr
        join public.offers o on o.request_id = sr.id
        where sr.status in ('submitted', 'offers_received')
          and o.status = 'submitted'
        order by sr.created_at desc, o.created_at
        limit 1
        '''),
    );
    if (candidates.isEmpty) {
      stdout.writeln(
        'No pending offer exists; enum query verification is sufficient.',
      );
      return;
    }

    final candidate = candidates.single;
    final rollbackDatabase = _RollbackDatabase(database);
    await PlatformRepository(rollbackDatabase).acceptOffer(
      customerId: candidate['customer_id'].toString(),
      requestId: candidate['request_id'].toString(),
      offerId: candidate['offer_id'].toString(),
    );
    stdout.writeln(
      'Full offer acceptance transaction verified and rolled back.',
    );
  } finally {
    await database.close();
  }
}

class _RollbackDatabase implements MaestroDbExecutor {
  const _RollbackDatabase(this.inner);

  final MaestroDbExecutor inner;

  @override
  Future<R> run<R>(Future<R> Function(MaestroDbSession session) fn) {
    return inner.run(fn);
  }

  @override
  Future<R> runTx<R>(Future<R> Function(MaestroDbSession session) fn) async {
    Object? value;
    try {
      await inner.runTx<void>((session) async {
        value = await fn(session);
        throw const _RollbackSignal();
      });
    } on _RollbackSignal {
      return value as R;
    }
    throw StateError('Verification transaction committed unexpectedly.');
  }

  @override
  Future<void> close() async {}
}

class _RollbackSignal implements Exception {
  const _RollbackSignal();
}
