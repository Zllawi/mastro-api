import 'dart:io';

import '../backend_environment.dart';
import 'otp_flow.dart';
import 'resala_client.dart';

Future<void> main() async {
  final environment = await loadBackendEnvironment();
  final config = ResalaConfig.fromEnvironment(environment: environment);
  final client = ResalaClient(config: config);
  final otpService = ResalaOtpService(client: client, store: MemoryOtpStore());

  final receipt = await otpService.requestOtp(
    phone: '218910001234',
    serviceName: 'MASTRO',
  );

  stdout.writeln('OTP sent. Resala pin id: ${receipt.resalaPinId}');
  stdout.writeln('Expires at: ${receipt.expiresAt.toIso8601String()}');

  final result = await otpService.verifyOtp(
    phone: '218910001234',
    input: '123456',
  );

  stdout.writeln('Verified: ${result.verified}');
}
