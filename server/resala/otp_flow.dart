import 'resala_client.dart';

typedef ResalaClock = DateTime Function();

abstract interface class OtpStore {
  Future<StoredOtp?> read(String phone);

  Future<void> write(StoredOtp otp);

  Future<void> delete(String phone);
}

class MemoryOtpStore implements OtpStore {
  final Map<String, StoredOtp> _items = {};

  @override
  Future<StoredOtp?> read(String phone) async => _items[phone];

  @override
  Future<void> write(StoredOtp otp) async {
    _items[otp.phone] = otp;
  }

  @override
  Future<void> delete(String phone) async {
    _items.remove(phone);
  }
}

class StoredOtp {
  const StoredOtp({
    required this.phone,
    required this.pin,
    required this.expiresAt,
    required this.attempts,
    required this.sentAt,
    required this.resalaPinId,
  });

  final String phone;
  final String pin;
  final DateTime expiresAt;
  final int attempts;
  final DateTime sentAt;
  final String resalaPinId;

  StoredOtp copyWith({
    String? phone,
    String? pin,
    DateTime? expiresAt,
    int? attempts,
    DateTime? sentAt,
    String? resalaPinId,
  }) {
    return StoredOtp(
      phone: phone ?? this.phone,
      pin: pin ?? this.pin,
      expiresAt: expiresAt ?? this.expiresAt,
      attempts: attempts ?? this.attempts,
      sentAt: sentAt ?? this.sentAt,
      resalaPinId: resalaPinId ?? this.resalaPinId,
    );
  }
}

class OtpRequestReceipt {
  const OtpRequestReceipt({
    required this.phone,
    required this.resalaPinId,
    required this.expiresAt,
    required this.cooldownUntil,
  });

  final String phone;
  final String resalaPinId;
  final DateTime expiresAt;
  final DateTime cooldownUntil;
}

enum OtpVerificationStatus {
  success,
  notFound,
  expired,
  invalid,
  attemptsExceeded,
}

class OtpVerificationResult {
  const OtpVerificationResult({
    required this.status,
    required this.attemptsRemaining,
  });

  final OtpVerificationStatus status;
  final int attemptsRemaining;

  bool get verified => status == OtpVerificationStatus.success;
}

class OtpCooldownException implements Exception {
  const OtpCooldownException(this.cooldownUntil);

  final DateTime cooldownUntil;

  @override
  String toString() => 'OtpCooldownException: retry after $cooldownUntil';
}

class ResalaOtpService {
  ResalaOtpService({
    required this.client,
    required this.store,
    Duration? expiry,
    Duration? resendCooldown,
    int? maxAttempts,
    ResalaClock? clock,
  }) : expiry = expiry ?? const Duration(minutes: 5),
       resendCooldown = resendCooldown ?? const Duration(seconds: 60),
       maxAttempts = maxAttempts ?? 5,
       _clock = clock ?? DateTime.now;

  final ResalaClient client;
  final OtpStore store;
  final Duration expiry;
  final Duration resendCooldown;
  final int maxAttempts;
  final ResalaClock _clock;

  Future<OtpRequestReceipt> requestOtp({
    required String phone,
    int len = 6,
    String? serviceName,
    String? autofill,
    bool? test,
  }) async {
    final now = _clock();
    final existing = await store.read(phone);
    if (existing != null) {
      final cooldownUntil = existing.sentAt.add(resendCooldown);
      if (now.isBefore(cooldownUntil)) {
        throw OtpCooldownException(cooldownUntil);
      }
    }

    final pin = await client.sendOtp(
      phone: phone,
      len: len,
      serviceName: serviceName,
      autofill: autofill,
      test: test,
    );
    final expiresAt = now.add(expiry);
    final cooldownUntil = now.add(resendCooldown);

    await store.write(
      StoredOtp(
        phone: phone,
        pin: pin.pin,
        expiresAt: expiresAt,
        attempts: 0,
        sentAt: now,
        resalaPinId: pin.id,
      ),
    );

    return OtpRequestReceipt(
      phone: phone,
      resalaPinId: pin.id,
      expiresAt: expiresAt,
      cooldownUntil: cooldownUntil,
    );
  }

  Future<OtpVerificationResult> verifyOtp({
    required String phone,
    required String input,
  }) async {
    final current = await store.read(phone);
    if (current == null) {
      return OtpVerificationResult(
        status: OtpVerificationStatus.notFound,
        attemptsRemaining: maxAttempts,
      );
    }

    if (!_clock().isBefore(current.expiresAt)) {
      await store.delete(phone);
      return const OtpVerificationResult(
        status: OtpVerificationStatus.expired,
        attemptsRemaining: 0,
      );
    }

    if (current.attempts >= maxAttempts) {
      return const OtpVerificationResult(
        status: OtpVerificationStatus.attemptsExceeded,
        attemptsRemaining: 0,
      );
    }

    if (input.trim() == current.pin) {
      await store.delete(phone);
      return OtpVerificationResult(
        status: OtpVerificationStatus.success,
        attemptsRemaining: maxAttempts - current.attempts,
      );
    }

    final attempts = current.attempts + 1;
    await store.write(current.copyWith(attempts: attempts));
    final remaining = maxAttempts - attempts;

    return OtpVerificationResult(
      status: remaining <= 0
          ? OtpVerificationStatus.attemptsExceeded
          : OtpVerificationStatus.invalid,
      attemptsRemaining: remaining < 0 ? 0 : remaining,
    );
  }
}
