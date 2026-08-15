import '../backend_environment.dart';
import '../supabase/maestro_database.dart';
import '../supabase/platform_repository.dart';
import 'firebase_push_service.dart';

Future<void> main() async {
  final environment = await loadBackendEnvironment();
  final firebaseConfig = await FirebasePushConfig.fromEnvironment(environment);
  if (firebaseConfig == null) {
    throw StateError('Firebase push is not configured in .env.');
  }
  final database = SupabasePostgresDatabase.fromConfig(
    SupabaseDatabaseConfig.fromEnvironment(environment: environment),
  );
  final push = FirebasePushService(firebaseConfig);
  try {
    final delivered = await NotificationPushDispatcher(
      repository: PlatformRepository(database),
      push: push,
    ).dispatchPending();
    print('Pending push dispatch completed. Delivered notifications: $delivered');
  } finally {
    push.close();
    await database.close();
  }
}
