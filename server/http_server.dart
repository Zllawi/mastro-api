import 'dart:async';
import 'dart:io';

import 'api/maestro_http_api.dart';
import 'auth/session_service.dart';
import 'backend_environment.dart';
import 'cloudinary/cloudinary_client.dart';
import 'firebase/firebase_push_service.dart';
import 'resala/otp_flow.dart';
import 'resala/resala_client.dart';
import 'supabase/maestro_database.dart';
import 'supabase/platform_repository.dart';
import 'supabase/supabase_otp_store.dart';

Future<void> main() async {
  final environment = await loadBackendEnvironment();
  final port = int.tryParse(environment['PORT'] ?? '') ?? 8080;
  final host = environment['HOST'] ?? '0.0.0.0';
  final databaseUrlError = _validateDatabaseUrlForStartup(
    environment['SUPABASE_DATABASE_URL'] ?? '',
  );
  if (databaseUrlError != null) {
    stderr.writeln(databaseUrlError);
    exit(64);
  }

  final database = SupabasePostgresDatabase.fromConfig(
    SupabaseDatabaseConfig.fromEnvironment(environment: environment),
  );
  final repository = PlatformRepository(database);
  final firebaseConfig = await FirebasePushConfig.fromEnvironment(environment);
  final firebasePush = firebaseConfig == null
      ? null
      : FirebasePushService(firebaseConfig);
  final pushDispatcher = firebasePush == null
      ? null
      : NotificationPushDispatcher(repository: repository, push: firebasePush);
  final cloudinary = CloudinaryClient(
    config: CloudinaryConfig.fromEnvironment(environment),
  );
  final adminPhone = _normalizeLibyanPhone(
    environment['MAESTRO_ADMIN_PHONE'] ?? '',
  );
  if (adminPhone != null) {
    await repository.ensureAdminAccount(adminPhone);
  }
  final api = MaestroHttpApi(
    environment: environment,
    otpService: ResalaOtpService(
      client: ResalaClient(
        config: ResalaConfig.fromEnvironment(environment: environment),
      ),
      store: SupabaseOtpStore(database),
    ),
    repository: repository,
    sessions: SessionService(repository: repository),
    cloudinary: cloudinary,
    pushDispatcher: pushDispatcher,
  );

  late final HttpServer server;
  try {
    server = await HttpServer.bind(host, port);
    server.autoCompress = true;
  } on SocketException catch (error) {
    await database.close();
    if (error.osError?.errorCode == 10048 || error.osError?.errorCode == 98) {
      stderr.writeln(
        'Port $port is already in use. MASTRO backend is probably already running; do not start a second copy.',
      );
      exitCode = 98;
      return;
    }
    rethrow;
  }
  var notificationSchedulerRunning = false;
  final notificationScheduler = Timer.periodic(const Duration(seconds: 10), (
    _,
  ) {
    if (notificationSchedulerRunning) return;
    notificationSchedulerRunning = true;
    unawaited(() async {
      try {
        await repository.dispatchDueRequestBatches();
        await repository.dispatchDueCampaigns();
        await pushDispatcher?.dispatchPending();
      } catch (error) {
        stderr.writeln('Notification scheduler error: $error');
      } finally {
        notificationSchedulerRunning = false;
      }
    }());
  });

  var retentionSchedulerRunning = false;
  final retentionScheduler = Timer.periodic(const Duration(minutes: 1), (_) {
    if (retentionSchedulerRunning) return;
    retentionSchedulerRunning = true;
    unawaited(() async {
      try {
        await repository.queueExpiredMediaCleanup();
      } catch (error) {
        stderr.writeln('Media retention scheduler error: $error');
      } finally {
        retentionSchedulerRunning = false;
      }
    }());
  });

  var cleanupSchedulerRunning = false;
  final cleanupScheduler = Timer.periodic(const Duration(seconds: 10), (_) {
    if (cleanupSchedulerRunning) return;
    cleanupSchedulerRunning = true;
    unawaited(() async {
      try {
        for (var index = 0; index < 10; index++) {
          final job = await repository.claimMediaCleanupJob();
          if (job == null) break;
          try {
            if (job['provider']?.toString() != 'cloudinary') {
              throw StateError(
                'Unsupported cleanup provider: ${job['provider']}',
              );
            }
            await cloudinary.destroy(
              publicId: job['provider_public_id'].toString(),
              resourceType: job['resource_type']?.toString() ?? 'image',
            );
            await repository.completeMediaCleanupJob(job['id'].toString());
          } catch (error) {
            await repository.failMediaCleanupJob(
              jobId: job['id'].toString(),
              error: error,
              attempts: int.tryParse(job['attempts']?.toString() ?? '') ?? 1,
            );
          }
        }
      } catch (error) {
        stderr.writeln('Cloudinary cleanup worker error: $error');
      } finally {
        cleanupSchedulerRunning = false;
      }
    }());
  });

  stdout.writeln('MASTRO backend is running on http://$host:$port');
  stdout.writeln('API: OTP, sessions, profiles, addresses, requests, media,');
  stdout.writeln('     wallets, notifications, chat and web administration.');
  stdout.writeln(
    'Cloudinary: ${api.cloudinary.config.isConfigured ? 'configured' : 'not configured'}',
  );
  stdout.writeln(
    'Admin account: ${adminPhone == null ? 'set MAESTRO_ADMIN_PHONE to enable' : 'configured'}',
  );
  stdout.writeln(
    'Firebase push: ${firebaseConfig == null ? 'not configured' : 'configured'}',
  );
  stdout.writeln(
    'Secrets loaded from environment/.env; tokens will not print.',
  );

  Future<void> shutdown(ProcessSignal signal) async {
    stdout.writeln('Received ${signal.name}; shutting down.');
    notificationScheduler.cancel();
    retentionScheduler.cancel();
    cleanupScheduler.cancel();
    await server.close(force: true);
    firebasePush?.close();
    await database.close();
    exit(0);
  }

  ProcessSignal.sigint.watch().listen(shutdown);
  if (!Platform.isWindows) {
    ProcessSignal.sigterm.watch().listen(shutdown);
  }

  await for (final request in server) {
    unawaited(api.handle(request));
  }
}

String? _validateDatabaseUrlForStartup(String databaseUrl) {
  if (databaseUrl.trim().isEmpty) {
    return 'SUPABASE_DATABASE_URL is missing in .env.';
  }
  final host = _databaseHostForMessage(databaseUrl);
  if (host == null) {
    return 'SUPABASE_DATABASE_URL is invalid. Copy the PostgreSQL connection string from Supabase again.';
  }
  if (host.contains('aws-0-region.pooler.supabase.com')) {
    return 'SUPABASE_DATABASE_URL still contains the placeholder host "$host". Replace "region" with the real Supabase pooler host from Project Settings > Database.';
  }
  return null;
}

String? _databaseHostForMessage(String databaseUrl) {
  final trimmed = databaseUrl.trim();
  final lastAt = trimmed.lastIndexOf('@');
  final authorityAndPath = lastAt >= 0
      ? trimmed.substring(lastAt + 1)
      : trimmed;
  final withoutScheme = authorityAndPath.contains('://')
      ? authorityAndPath.split('://').last
      : authorityAndPath;
  final hostPort = withoutScheme.split('/').first;
  return hostPort.isEmpty ? null : hostPort;
}

String? _normalizeLibyanPhone(String value) {
  final digits = value.replaceAll(RegExp(r'\D'), '');
  final local = digits.startsWith('218')
      ? digits.substring(3)
      : digits.startsWith('0')
      ? digits.substring(1)
      : digits;
  return RegExp(r'^9\d{8}$').hasMatch(local) ? '218$local' : null;
}
