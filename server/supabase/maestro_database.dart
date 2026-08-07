import 'dart:io';

import 'package:postgres/postgres.dart';

abstract interface class MaestroDbExecutor {
  Future<R> run<R>(Future<R> Function(MaestroDbSession session) fn);

  Future<R> runTx<R>(Future<R> Function(MaestroDbSession session) fn);

  Future<void> close();
}

abstract interface class MaestroDbSession {
  Future<List<Map<String, dynamic>>> select(
    String sql, {
    Map<String, Object?> parameters = const {},
  });

  Future<int> execute(String sql, {Map<String, Object?> parameters = const {}});
}

class SupabaseDatabaseConfig {
  const SupabaseDatabaseConfig({
    required this.databaseUrl,
    this.databaseUrlEnvName = 'SUPABASE_DATABASE_URL',
  });

  factory SupabaseDatabaseConfig.fromEnvironment({
    Map<String, String>? environment,
    String databaseUrlEnvName = 'SUPABASE_DATABASE_URL',
  }) {
    final env = environment ?? Platform.environment;
    final databaseUrl = env[databaseUrlEnvName] ?? '';
    if (databaseUrl.trim().isEmpty) {
      throw StateError('Missing $databaseUrlEnvName for Supabase PostgreSQL.');
    }
    return SupabaseDatabaseConfig(
      databaseUrl: databaseUrl,
      databaseUrlEnvName: databaseUrlEnvName,
    );
  }

  final String databaseUrl;
  final String databaseUrlEnvName;
}

class SupabasePostgresDatabase implements MaestroDbExecutor {
  SupabasePostgresDatabase.fromConfig(SupabaseDatabaseConfig config)
    : _pool = Pool.withUrl(
        normalizeDatabaseUrlForPersistentBackend(config.databaseUrl),
      );

  SupabasePostgresDatabase.withPool(Pool<dynamic> pool) : _pool = pool;

  final Pool<dynamic> _pool;

  @override
  Future<R> run<R>(Future<R> Function(MaestroDbSession session) fn) {
    return _pool.run((session) => fn(_PostgresDbSession(session)));
  }

  @override
  Future<R> runTx<R>(Future<R> Function(MaestroDbSession session) fn) {
    return _pool.runTx((session) => fn(_PostgresDbSession(session)));
  }

  @override
  Future<void> close() => _pool.close();
}

class _PostgresDbSession implements MaestroDbSession {
  const _PostgresDbSession(this._session);

  final Session _session;

  @override
  Future<List<Map<String, dynamic>>> select(
    String sql, {
    Map<String, Object?> parameters = const {},
  }) async {
    final result = await _session.execute(
      Sql.named(sql),
      parameters: parameters,
    );
    return result.map((row) {
      return row.toColumnMap().map(
        (key, value) => MapEntry(key, decodePostgresValue(value)),
      );
    }).toList();
  }

  @override
  Future<int> execute(
    String sql, {
    Map<String, Object?> parameters = const {},
  }) async {
    final result = await _session.execute(
      Sql.named(sql),
      parameters: parameters,
      ignoreRows: true,
    );
    return result.affectedRows;
  }
}

/// Converts PostgreSQL extension and custom-enum values that the driver cannot
/// type automatically into their text representation.
///
/// Supabase schemas in Maestro use custom enum types for roles and statuses.
/// The postgres driver intentionally exposes unknown types as [UndecodedBytes]
/// instead of guessing their representation, so they must be decoded before
/// repository code compares or serializes them.
Object? decodePostgresValue(Object? value) {
  if (value is UndecodedBytes) {
    return value.asString;
  }
  if (value is List<Object?>) {
    return value.map(decodePostgresValue).toList(growable: false);
  }
  if (value is Map) {
    return value.map(
      (key, nestedValue) => MapEntry(key, decodePostgresValue(nestedValue)),
    );
  }
  return value;
}

/// Normalizes the PostgreSQL URL for Maestro's persistent HTTP backend.
///
/// Supabase's port 6543 is the transaction pooler, which does not support
/// prepared statements. The Dart postgres driver uses prepared statements for
/// parameterized queries, so a shared Supabase pooler URL must use session mode
/// on port 5432.
String normalizeDatabaseUrlForPersistentBackend(String databaseUrl) {
  var uri = _parsePostgresUri(databaseUrl.trim());
  if (uri.host.endsWith('.pooler.supabase.com') && uri.port == 6543) {
    uri = uri.replace(port: 5432);
  }
  final params = Map<String, String>.from(uri.queryParameters);
  params.putIfAbsent('sslmode', () => 'require');
  params.putIfAbsent('application_name', () => 'maestro_backend');
  params.putIfAbsent('max_connection_count', () => '10');
  return uri.replace(queryParameters: params).toString();
}

Uri _parsePostgresUri(String databaseUrl) {
  try {
    return Uri.parse(databaseUrl);
  } on FormatException {
    final schemeEnd = databaseUrl.indexOf('://');
    final lastAt = databaseUrl.lastIndexOf('@');
    if (schemeEnd < 0 || lastAt <= schemeEnd + 3) {
      rethrow;
    }

    final prefix = databaseUrl.substring(0, schemeEnd + 3);
    final userInfo = databaseUrl.substring(schemeEnd + 3, lastAt);
    final rest = databaseUrl.substring(lastAt + 1);
    final separator = userInfo.indexOf(':');
    if (separator < 0) {
      rethrow;
    }

    final username = _encodeUriUserInfoPart(userInfo.substring(0, separator));
    final password = _encodeUriUserInfoPart(userInfo.substring(separator + 1));
    return Uri.parse('$prefix$username:$password@$rest');
  }
}

String _encodeUriUserInfoPart(String value) {
  try {
    return Uri.encodeComponent(Uri.decodeComponent(value));
  } on FormatException {
    return Uri.encodeComponent(value);
  }
}
