import 'dart:io';

import '../backend_environment.dart';
import 'firebase_push_service.dart';

Future<void> main() async {
  final environment = await loadBackendEnvironment();
  final config = await FirebasePushConfig.fromEnvironment(environment);
  if (config == null) {
    throw StateError('Firebase push is not configured.');
  }
  final service = FirebasePushService(config);
  try {
    final result = await service.send(
      token: 'maestro-intentionally-invalid-registration-token',
      title: 'MASTRO configuration check',
      body: 'This message must not be delivered.',
      data: const {'verification': true},
    );
    if (result.delivered) {
      throw StateError('Firebase unexpectedly accepted the invalid token.');
    }
    final error = result.error ?? '';
    if (error.contains('401') || error.contains('403')) {
      throw StateError(
        'Firebase credentials or Cloud Messaging API permissions are invalid.',
      );
    }
    if (!error.contains('400') && !error.contains('404')) {
      throw StateError('Unexpected Firebase verification response: $error');
    }
    stdout.writeln(
      'Firebase HTTP v1 authentication and Cloud Messaging API verified.',
    );
  } finally {
    service.close();
  }
}
