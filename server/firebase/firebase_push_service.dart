import 'dart:convert';
import 'dart:io';

import 'package:googleapis_auth/auth_io.dart';
import 'package:http/http.dart' as http;

import '../supabase/platform_repository.dart';

const _firebaseMessagingScope =
    'https://www.googleapis.com/auth/firebase.messaging';
const _generalAndroidChannelId = 'maestro_general_v1';
const _orderAndroidChannelId = 'maestro_orders_v2';
const _orderAndroidSound = 'maestro_order_notification';

class FirebasePushConfig {
  const FirebasePushConfig({
    required this.projectId,
    required this.serviceAccount,
  });

  static Future<FirebasePushConfig?> fromEnvironment(
    Map<String, String> environment,
  ) async {
    final path = environment['FIREBASE_SERVICE_ACCOUNT_JSON_PATH']?.trim();
    final encoded = environment['FIREBASE_SERVICE_ACCOUNT_JSON_BASE64']?.trim();
    String? rawJson;
    if (encoded != null && encoded.isNotEmpty) {
      rawJson = utf8.decode(base64Decode(encoded));
    } else if (path != null && path.isNotEmpty) {
      final file = File(path);
      if (!await file.exists()) {
        stderr.writeln(
          'FIREBASE_SERVICE_ACCOUNT_JSON_PATH does not point to an existing file; Firebase push is disabled. '
          'On Render, set FIREBASE_SERVICE_ACCOUNT_JSON_BASE64 instead or leave the path empty.',
        );
        return null;
      }
      rawJson = await file.readAsString();
    } else {
      return null;
    }

    final decoded = jsonDecode(rawJson);
    if (decoded is! Map) {
      throw const FormatException('Firebase service account must be JSON.');
    }
    final serviceAccount = Map<String, dynamic>.from(decoded);
    final projectId =
        environment['FIREBASE_PROJECT_ID']?.trim().isNotEmpty == true
        ? environment['FIREBASE_PROJECT_ID']!.trim()
        : serviceAccount['project_id']?.toString().trim() ?? '';
    if (projectId.isEmpty) {
      throw StateError('FIREBASE_PROJECT_ID is missing.');
    }
    return FirebasePushConfig(
      projectId: projectId,
      serviceAccount: serviceAccount,
    );
  }

  final String projectId;
  final Map<String, dynamic> serviceAccount;
}

class FirebasePushService {
  FirebasePushService(this.config);

  final FirebasePushConfig config;
  http.Client? _client;

  Future<FirebasePushResult> send({
    required String token,
    required String title,
    required String body,
    required Map<String, dynamic> data,
  }) async {
    final client = await _authorizedClient();
    final response = await client.post(
      Uri.https(
        'fcm.googleapis.com',
        '/v1/projects/${config.projectId}/messages:send',
      ),
      headers: {'content-type': 'application/json; charset=utf-8'},
      body: jsonEncode(
        buildFirebaseMessagePayload(
          token: token,
          title: title,
          body: body,
          data: data,
        ),
      ),
    );
    if (response.statusCode >= 200 && response.statusCode < 300) {
      return const FirebasePushResult(delivered: true);
    }

    final errorCode = _firebaseErrorCode(response.body);
    final invalidToken =
        errorCode == 'UNREGISTERED' ||
        (errorCode == 'INVALID_ARGUMENT' && response.statusCode == 400);
    return FirebasePushResult(
      delivered: false,
      invalidToken: invalidToken,
      error:
          'Firebase HTTP ${response.statusCode}'
          '${errorCode == null ? '' : ' ($errorCode)'}',
    );
  }

  Future<http.Client> _authorizedClient() async {
    final current = _client;
    if (current != null) return current;
    final credentials = ServiceAccountCredentials.fromJson(
      config.serviceAccount,
    );
    final created = await clientViaServiceAccount(credentials, const [
      _firebaseMessagingScope,
    ]);
    _client = created;
    return created;
  }

  void close() {
    _client?.close();
    _client = null;
  }
}

Map<String, dynamic> buildFirebaseMessagePayload({
  required String token,
  required String title,
  required String body,
  required Map<String, dynamic> data,
}) {
  final isOrderNotification = data['notification_type'] == 'order';
  return {
    'message': {
      'token': token,
      'notification': {'title': title, 'body': body},
      'data': {
        'notification_id': data['notification_id']?.toString() ?? '',
        for (final entry in data.entries)
          if (entry.key != 'notification_id')
            entry.key: _firebaseDataValue(entry.value),
      },
      'android': {
        'priority': 'high',
        'notification': {
          'channel_id': isOrderNotification
              ? _orderAndroidChannelId
              : _generalAndroidChannelId,
          'sound': isOrderNotification ? _orderAndroidSound : 'default',
        },
      },
      'apns': {
        'payload': {
          'aps': {'sound': 'default'},
        },
      },
    },
  };
}

class FirebasePushResult {
  const FirebasePushResult({
    required this.delivered,
    this.invalidToken = false,
    this.error,
  });

  final bool delivered;
  final bool invalidToken;
  final String? error;
}

class NotificationPushDispatcher {
  const NotificationPushDispatcher({
    required this.repository,
    required this.push,
  });

  final PlatformRepository repository;
  final FirebasePushService push;

  Future<int> dispatchPending() async {
    final notifications = await repository.claimPushNotifications();
    var delivered = 0;
    for (final notification in notifications) {
      final notificationId = notification['id'].toString();
      final devices = _deviceList(notification['devices']);
      if (devices.isEmpty) {
        await repository.completePushNotification(
          notificationId: notificationId,
          status: 'skipped',
          error: 'No enabled push device.',
        );
        continue;
      }

      var anyDelivered = false;
      final errors = <String>[];
      for (final device in devices) {
        final token = device['token']?.toString() ?? '';
        if (token.isEmpty) continue;
        try {
          final result = await push.send(
            token: token,
            title: notification['title']?.toString() ?? 'MASTRO',
            body: notification['body']?.toString() ?? '',
            data: {
              ..._dataMap(notification['data']),
              'notification_id': notificationId,
            },
          );
          anyDelivered = anyDelivered || result.delivered;
          if (result.invalidToken) {
            await repository.disablePushToken(token);
          }
          if (!result.delivered && result.error != null) {
            errors.add(result.error!);
          }
        } catch (error) {
          errors.add(error.toString());
        }
      }
      final errorText = errors.take(3).join('; ');
      await repository.completePushNotification(
        notificationId: notificationId,
        status: anyDelivered ? 'sent' : 'failed',
        error: anyDelivered || errors.isEmpty
            ? null
            : errorText.length <= 500
            ? errorText
            : errorText.substring(0, 500),
      );
      if (anyDelivered) delivered++;
    }
    return delivered;
  }
}

String _firebaseDataValue(Object? value) {
  if (value == null) return '';
  if (value is String) return value;
  if (value is num || value is bool) return value.toString();
  return jsonEncode(value);
}

String? _firebaseErrorCode(String body) {
  try {
    final decoded = jsonDecode(body);
    if (decoded is! Map) return null;
    final error = decoded['error'];
    if (error is! Map) return null;
    final details = error['details'];
    if (details is List) {
      for (final detail in details) {
        if (detail is Map && detail['errorCode'] != null) {
          return detail['errorCode'].toString();
        }
      }
    }
    return error['status']?.toString();
  } catch (_) {
    return null;
  }
}

Map<String, dynamic> _dataMap(Object? value) {
  if (value is Map<String, dynamic>) return value;
  if (value is Map) return Map<String, dynamic>.from(value);
  if (value is String) {
    try {
      final decoded = jsonDecode(value);
      if (decoded is Map) return Map<String, dynamic>.from(decoded);
    } catch (_) {}
  }
  return <String, dynamic>{};
}

List<Map<String, dynamic>> _deviceList(Object? value) {
  Object? decoded = value;
  if (value is String) {
    try {
      decoded = jsonDecode(value);
    } catch (_) {
      return const [];
    }
  }
  if (decoded is! List) return const [];
  return decoded
      .whereType<Map>()
      .map(Map<String, dynamic>.from)
      .toList(growable: false);
}
