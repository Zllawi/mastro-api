import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:googleapis_auth/auth_io.dart';
import 'package:http/http.dart' as http;

const _packageName = 'com.maestro.ly.maestro';
const _scope = 'https://www.googleapis.com/auth/cloud-platform';
const _host = 'firebase.googleapis.com';

Future<void> main(List<String> args) async {
  if (args.isEmpty) {
    stderr.writeln(
      'Usage: dart run server/firebase/configure_android_app.dart '
      '<service-account.json> [--create] [--output <google-services.json>]',
    );
    exitCode = 64;
    return;
  }

  final credentialFile = File(args.first);
  if (!await credentialFile.exists()) {
    throw StateError('Firebase service-account file does not exist.');
  }
  final createIfMissing = args.contains('--create');
  final outputIndex = args.indexOf('--output');
  final outputPath = outputIndex >= 0 && outputIndex + 1 < args.length
      ? args[outputIndex + 1]
      : null;

  final credentialsJson = jsonDecode(await credentialFile.readAsString());
  if (credentialsJson is! Map || credentialsJson['type'] != 'service_account') {
    throw const FormatException('Expected a Firebase service-account JSON.');
  }
  final credentials = Map<String, dynamic>.from(credentialsJson);
  final projectId = credentials['project_id']?.toString().trim() ?? '';
  if (projectId.isEmpty) {
    throw StateError('The service account has no project_id.');
  }

  final client = await clientViaServiceAccount(
    ServiceAccountCredentials.fromJson(credentials),
    const [_scope],
  );
  try {
    var app = await _findAndroidApp(client, projectId);
    if (app == null && !createIfMissing) {
      stdout.writeln(
        'No Firebase Android app is registered for the MASTRO package.',
      );
      return;
    }
    if (app == null) {
      stdout.writeln('Creating the Firebase Android app for MASTRO...');
      final operation = await _requestJson(
        client,
        'POST',
        Uri.https(_host, '/v1beta1/projects/$projectId/androidApps'),
        body: {'displayName': 'MASTRO Android', 'packageName': _packageName},
      );
      final operationName = operation['name']?.toString() ?? '';
      if (operationName.isEmpty) {
        throw StateError('Firebase returned no operation name.');
      }
      await _waitForOperation(client, operationName);
      app = await _findAndroidApp(client, projectId);
      if (app == null) {
        throw StateError(
          'Firebase app creation completed but app was not found.',
        );
      }
      stdout.writeln('Firebase Android app created.');
    } else {
      stdout.writeln('Firebase Android app already exists.');
    }

    if (outputPath == null) return;
    final resourceName = app['name']?.toString() ?? '';
    if (resourceName.isEmpty) {
      throw StateError('Firebase Android app has no resource name.');
    }
    final config = await _requestJson(
      client,
      'GET',
      Uri.https(_host, '/v1beta1/$resourceName/config'),
    );
    final encoded = config['configFileContents']?.toString() ?? '';
    if (encoded.isEmpty) {
      throw StateError('Firebase returned an empty Android configuration.');
    }
    final bytes = base64Decode(encoded);
    final decodedConfig = jsonDecode(utf8.decode(bytes));
    if (decodedConfig is! Map ||
        !utf8.decode(bytes).contains('"$_packageName"')) {
      throw StateError('Downloaded Firebase config has the wrong package.');
    }
    final outputFile = File(outputPath);
    await outputFile.parent.create(recursive: true);
    await outputFile.writeAsBytes(bytes, flush: true);
    stdout.writeln('Android Firebase configuration downloaded successfully.');
  } finally {
    client.close();
  }
}

Future<Map<String, dynamic>?> _findAndroidApp(
  http.Client client,
  String projectId,
) async {
  final response = await _requestJson(
    client,
    'GET',
    Uri.https(_host, '/v1beta1/projects/$projectId/androidApps'),
  );
  final apps = response['apps'];
  if (apps is! List) return null;
  for (final raw in apps.whereType<Map>()) {
    final app = Map<String, dynamic>.from(raw);
    if (app['packageName'] == _packageName && app['state'] != 'DELETED') {
      return app;
    }
  }
  return null;
}

Future<void> _waitForOperation(http.Client client, String operationName) async {
  final deadline = DateTime.now().add(const Duration(minutes: 2));
  while (DateTime.now().isBefore(deadline)) {
    final operation = await _requestJson(
      client,
      'GET',
      Uri.https(_host, '/v1beta1/$operationName'),
    );
    if (operation['done'] == true) {
      if (operation['error'] != null) {
        throw StateError('Firebase Android app creation failed.');
      }
      return;
    }
    await Future<void>.delayed(const Duration(seconds: 2));
  }
  throw TimeoutException('Firebase Android app creation timed out.');
}

Future<Map<String, dynamic>> _requestJson(
  http.Client client,
  String method,
  Uri uri, {
  Map<String, dynamic>? body,
}) async {
  final request = http.Request(method, uri)
    ..headers['accept'] = 'application/json';
  if (body != null) {
    request.headers['content-type'] = 'application/json; charset=utf-8';
    request.body = jsonEncode(body);
  }
  final streamed = await client.send(request);
  final response = await http.Response.fromStream(streamed);
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw HttpException(
      'Firebase Management API returned HTTP ${response.statusCode}.',
      uri: uri,
    );
  }
  final decoded = jsonDecode(response.body);
  if (decoded is! Map) {
    throw const FormatException('Firebase returned a non-object response.');
  }
  return Map<String, dynamic>.from(decoded);
}
