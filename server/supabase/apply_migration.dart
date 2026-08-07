import 'dart:io';

import '../backend_environment.dart';
import 'maestro_database.dart';

Future<void> main(List<String> args) async {
  final migrationPath = args.isEmpty
      ? 'supabase/migrations/202607271_prepare_maestro_core_schema.sql'
      : args.first;
  final file = File(migrationPath);
  if (!await file.exists()) {
    stderr.writeln('Migration file not found: $migrationPath');
    exit(66);
  }

  final environment = await loadBackendEnvironment();
  final database = SupabasePostgresDatabase.fromConfig(
    SupabaseDatabaseConfig.fromEnvironment(environment: environment),
  );

  final sql = await file.readAsString();
  final statements = _splitSqlStatements(sql);
  stdout.writeln('Applying ${statements.length} SQL statements...');

  try {
    await database.runTx((session) async {
      for (var i = 0; i < statements.length; i++) {
        final statement = statements[i].trim();
        if (statement.isEmpty) continue;
        stdout.writeln('Statement ${i + 1}/${statements.length}');
        await session.execute(statement);
      }
    });

    final rows = await database.run(
      (session) => session.select('''
        select table_name
        from information_schema.tables
        where table_schema = 'public'
          and table_name in ('otp_codes', 'profiles', 'service_requests', 'offers')
        order by table_name
        '''),
    );
    stdout.writeln(
      'Verified tables: ${rows.map((row) => row['table_name']).join(', ')}',
    );
  } finally {
    await database.close();
  }
}

List<String> _splitSqlStatements(String sql) {
  final statements = <String>[];
  final buffer = StringBuffer();
  String? dollarQuoteTag;
  var inSingleQuote = false;
  var inDoubleQuote = false;
  var inLineComment = false;
  var inBlockComment = false;

  for (var i = 0; i < sql.length; i++) {
    final char = sql[i];
    final next = i + 1 < sql.length ? sql[i + 1] : '';
    buffer.write(char);

    if (inLineComment) {
      if (char == '\n') inLineComment = false;
      continue;
    }
    if (inBlockComment) {
      if (char == '*' && next == '/') {
        buffer.write(next);
        i++;
        inBlockComment = false;
      }
      continue;
    }
    if (dollarQuoteTag != null) {
      if (sql.startsWith(dollarQuoteTag, i)) {
        for (var j = 1; j < dollarQuoteTag.length; j++) {
          buffer.write(sql[i + j]);
        }
        i += dollarQuoteTag.length - 1;
        dollarQuoteTag = null;
      }
      continue;
    }

    if (!inSingleQuote && !inDoubleQuote) {
      if (char == '-' && next == '-') {
        buffer.write(next);
        i++;
        inLineComment = true;
        continue;
      }
      if (char == '/' && next == '*') {
        buffer.write(next);
        i++;
        inBlockComment = true;
        continue;
      }
      if (char == r'$') {
        final tag = _readDollarQuoteTag(sql, i);
        if (tag != null) {
          for (var j = 1; j < tag.length; j++) {
            buffer.write(sql[i + j]);
          }
          i += tag.length - 1;
          dollarQuoteTag = tag;
          continue;
        }
      }
    }

    if (!inDoubleQuote && char == "'") {
      final escaped = i > 0 && sql[i - 1] == "'";
      if (!escaped) inSingleQuote = !inSingleQuote;
      continue;
    }
    if (!inSingleQuote && char == '"') {
      inDoubleQuote = !inDoubleQuote;
      continue;
    }

    if (!inSingleQuote && !inDoubleQuote && char == ';') {
      final statement = buffer.toString().trim();
      if (statement.isNotEmpty) {
        statements.add(statement);
      }
      buffer.clear();
    }
  }

  final tail = buffer.toString().trim();
  if (tail.isNotEmpty) {
    statements.add(tail);
  }
  return statements;
}

String? _readDollarQuoteTag(String sql, int start) {
  final end = sql.indexOf(r'$', start + 1);
  if (end < 0) return null;
  final tagBody = sql.substring(start + 1, end);
  if (tagBody.isNotEmpty &&
      !RegExp(r'^[A-Za-z_][A-Za-z0-9_]*$').hasMatch(tagBody)) {
    return null;
  }
  return sql.substring(start, end + 1);
}
