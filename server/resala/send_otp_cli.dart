import 'dart:io';

import '../backend_environment.dart';
import 'otp_flow.dart';
import 'resala_client.dart';

Future<void> main(List<String> args) async {
  final phone = _argValue(args, '--phone');
  if (phone == null || phone.trim().isEmpty) {
    stderr.writeln(
      'Usage: dart run server/resala/send_otp_cli.dart --phone 218910001234',
    );
    exitCode = 64;
    return;
  }

  final environment = await loadBackendEnvironment();
  final config = ResalaConfig.fromEnvironment(environment: environment);
  final appEnv = (environment['APP_ENV'] ?? 'development').toLowerCase();
  final mode = config.useTestMode
      ? 'test mode, no real SMS'
      : 'production, real SMS';

  stdout.writeln('Sending OTP to $phone via Resala ($mode).');
  stdout.writeln('No token will be printed.');

  final client = ResalaClient(config: config);
  final otpService = ResalaOtpService(client: client, store: MemoryOtpStore());
  final receipt = await otpService.requestOtp(
    phone: phone,
    serviceName: 'MASTRO',
  );

  stdout.writeln('Resala accepted OTP request.');
  stdout.writeln('Pin id: ${receipt.resalaPinId}');
  stdout.writeln('Expires at: ${receipt.expiresAt.toIso8601String()}');
  if (appEnv != 'production' && appEnv != 'prod') {
    stdout.writeln('APP_ENV is $appEnv, so Resala test mode was used.');
  }
}

String? _argValue(List<String> args, String name) {
  final index = args.indexOf(name);
  if (index == -1 || index + 1 >= args.length) {
    return null;
  }
  return args[index + 1];
}
