import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';

final Random _secureRandom = Random.secure();

class PasswordHasher {
  const PasswordHasher();

  static const _scheme = 'pbkdf2_sha256';
  static const _saltBytes = 24;
  static const _iterations = 120000;
  static const _derivedKeyBytes = 32;

  String hash(String password) {
    final normalized = password.trim();
    if (normalized.length < 4 || normalized.length > 72) {
      throw const PasswordValidationException();
    }
    final salt = List<int>.generate(
      _saltBytes,
      (_) => _secureRandom.nextInt(256),
    );
    final saltText = base64UrlEncode(salt);
    final digest = _pbkdf2(normalized, salt, _iterations);
    return '$_scheme\$$_iterations\$$saltText\$${base64UrlEncode(digest)}';
  }

  bool verify(String password, String storedHash) {
    final parts = storedHash.split(r'$');
    if (parts.length == 3 && parts[0] == 'sha256') {
      final expected = sha256
          .convert(
            utf8.encode('${parts[1]}:${password.trim()}:maestro-auth-v1'),
          )
          .toString();
      return _constantTimeEquals(utf8.encode(expected), utf8.encode(parts[2]));
    }
    if (parts.length != 4 || parts[0] != _scheme) return false;
    final iterations = int.tryParse(parts[1]);
    if (iterations == null || iterations < 10000) return false;
    try {
      final salt = base64Url.decode(base64Url.normalize(parts[2]));
      final expected = _pbkdf2(password.trim(), salt, iterations);
      final provided = base64Url.decode(base64Url.normalize(parts[3]));
      return _constantTimeEquals(expected, provided);
    } on FormatException {
      return false;
    }
  }

  List<int> _pbkdf2(String password, List<int> salt, int iterations) {
    final hmac = Hmac(sha256, utf8.encode(password));
    final blocks = <int>[];
    var blockIndex = 1;
    while (blocks.length < _derivedKeyBytes) {
      final blockSalt = <int>[
        ...salt,
        (blockIndex >> 24) & 0xff,
        (blockIndex >> 16) & 0xff,
        (blockIndex >> 8) & 0xff,
        blockIndex & 0xff,
      ];
      var previous = hmac.convert(blockSalt).bytes;
      final output = List<int>.from(previous);
      for (var iteration = 1; iteration < iterations; iteration++) {
        previous = hmac.convert(previous).bytes;
        for (var index = 0; index < output.length; index++) {
          output[index] ^= previous[index];
        }
      }
      blocks.addAll(output);
      blockIndex++;
    }
    return blocks.take(_derivedKeyBytes).toList(growable: false);
  }

  bool _constantTimeEquals(List<int> a, List<int> b) {
    var diff = a.length ^ b.length;
    final maxLength = max(a.length, b.length);
    for (var index = 0; index < maxLength; index++) {
      final av = index < a.length ? a[index] : 0;
      final bv = index < b.length ? b[index] : 0;
      diff |= av ^ bv;
    }
    return diff == 0;
  }
}

class PasswordValidationException implements Exception {
  const PasswordValidationException();
}
