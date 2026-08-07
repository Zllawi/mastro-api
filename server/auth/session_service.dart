import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';

import '../supabase/platform_repository.dart';

class SessionService {
  SessionService({required this.repository, Duration? lifetime, Random? random})
    : lifetime = lifetime ?? const Duration(days: 30),
      _random = random ?? Random.secure();

  final PlatformRepository repository;
  final Duration lifetime;
  final Random _random;

  Future<IssuedSession> issue({
    required String profileId,
    String? deviceName,
    String? ipAddress,
  }) async {
    final bytes = List<int>.generate(32, (_) => _random.nextInt(256));
    final token = base64UrlEncode(bytes).replaceAll('=', '');
    final expiresAt = DateTime.now().toUtc().add(lifetime);
    await repository.createSession(
      profileId: profileId,
      tokenHash: hashToken(token),
      expiresAt: expiresAt,
      deviceName: deviceName,
      ipAddress: ipAddress,
    );
    return IssuedSession(token: token, expiresAt: expiresAt);
  }

  Future<Map<String, dynamic>?> authenticate(String? authorization) {
    final token = bearerToken(authorization);
    if (token == null) return Future.value();
    return repository.authenticate(hashToken(token));
  }

  Future<void> revoke(String? authorization) async {
    final token = bearerToken(authorization);
    if (token == null) return;
    await repository.revokeSession(hashToken(token));
  }

  static String? bearerToken(String? authorization) {
    if (authorization == null) return null;
    final match = RegExp(
      r'^Bearer\s+([A-Za-z0-9_-]+)$',
      caseSensitive: false,
    ).firstMatch(authorization.trim());
    return match?.group(1);
  }

  static String hashToken(String token) {
    return sha256.convert(utf8.encode(token)).toString();
  }
}

class IssuedSession {
  const IssuedSession({required this.token, required this.expiresAt});

  final String token;
  final DateTime expiresAt;
}
