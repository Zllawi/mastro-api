import 'dart:io';

import '../backend_environment.dart';
import 'maestro_database.dart';

Future<void> main() async {
  final environment = await loadBackendEnvironment();
  final database = SupabasePostgresDatabase.fromConfig(
    SupabaseDatabaseConfig.fromEnvironment(environment: environment),
  );

  try {
    final schema = await database.run(
      (session) => session.select('''
        select column_name
        from information_schema.columns
        where table_schema = 'public'
          and table_name = 'craftsman_profiles'
          and column_name in (
            'last_latitude',
            'last_longitude',
            'location_updated_at'
          )
        order by column_name
        '''),
    );
    if (schema.length != 3) {
      throw StateError('Craftsman location columns are incomplete.');
    }

    final calculation = await database.run(
      (session) => session.select('''
        select
          public.maestro_distance_km(32.1167, 20.0667, 32.1167, 20.0667)
            as same_point_km,
          public.maestro_distance_km(32.1167, 20.0667, 32.1267, 20.0667)
            as nearby_point_km
        '''),
    );
    final row = calculation.single;
    final samePoint = _number(row['same_point_km']);
    final nearbyPoint = _number(row['nearby_point_km']);
    if (samePoint != 0 || nearbyPoint <= 0) {
      throw StateError('Distance calculation returned invalid values.');
    }

    await database.run(
      (session) => session.select('''
        select
          sr.id,
          cp.profile_id,
          public.maestro_distance_km(
            sr.latitude,
            sr.longitude,
            cp.last_latitude,
            cp.last_longitude
          ) as distance_km
        from public.service_requests sr
        join public.craftsman_services cs on cs.category_id = sr.category_id
        join public.craftsman_profiles cp on cp.profile_id = cs.craftsman_id
        limit 1
        '''),
    );

    stdout.writeln(
      'Distance feature verified: same point ${samePoint.toStringAsFixed(1)} km, '
      'nearby point ${nearbyPoint.toStringAsFixed(1)} km.',
    );
  } finally {
    await database.close();
  }
}

double _number(Object? value) {
  if (value is num) return value.toDouble();
  return double.parse(value.toString());
}
