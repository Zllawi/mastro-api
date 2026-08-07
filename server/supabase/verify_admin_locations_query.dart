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
    final repository = PlatformRepository(database);
    final all = await repository.adminLocations();
    final customers = await repository.adminLocations(role: 'customer');
    final craftsmen = await repository.adminLocations(role: 'craftsman');
    if (all.length < customers.length || all.length < craftsmen.length) {
      throw StateError('Role-filtered location counts exceed all locations.');
    }
    stdout.writeln(
      'Admin locations query verified: all=${all.length}, '
      'customers=${customers.length}, craftsmen=${craftsmen.length}.',
    );
  } finally {
    await database.close();
  }
}
