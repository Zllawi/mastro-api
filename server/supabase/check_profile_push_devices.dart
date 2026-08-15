import '../backend_environment.dart';
import 'maestro_database.dart';

Future<void> main(List<String> args) async {
  final phone = _option(args, '--phone');
  if (phone == null || phone.trim().isEmpty) {
    throw ArgumentError('Usage: --phone 2189xxxxxxxx');
  }
  final environment = await loadBackendEnvironment();
  final database = SupabasePostgresDatabase.fromConfig(
    SupabaseDatabaseConfig.fromEnvironment(environment: environment),
  );
  try {
    final rows = await database.run(
      (session) => session.select(
        '''
        select
          p.id,
          p.role,
          p.phone,
          count(d.id) filter (where d.enabled = true)::int as enabled_devices,
          count(d.id)::int as total_devices,
          max(d.last_seen_at) as latest_seen
        from public.profiles p
        left join public.notification_devices d on d.profile_id = p.id
        where p.phone = @phone
        group by p.id, p.role, p.phone
        order by p.role
        ''',
        parameters: {'phone': phone.trim()},
      ),
    );
    if (rows.isEmpty) {
      print('No profile found for phone.');
      return;
    }
    for (final row in rows) {
      print(
        'profile ${row['role']} ${row['phone']}: '
        'enabled=${row['enabled_devices']} '
        'total=${row['total_devices']} '
        'latest=${row['latest_seen']}',
      );
    }
  } finally {
    await database.close();
  }
}

String? _option(List<String> args, String name) {
  for (var index = 0; index < args.length; index++) {
    if (args[index] == name && index + 1 < args.length) {
      return args[index + 1].trim();
    }
    if (args[index].startsWith('$name=')) {
      return args[index].substring(name.length + 1).trim();
    }
  }
  return null;
}
