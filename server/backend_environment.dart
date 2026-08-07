import 'dart:io';

Future<Map<String, String>> loadBackendEnvironment({
  String path = '.env',
}) async {
  final values = Map<String, String>.from(Platform.environment);
  final file = File(path);
  if (!await file.exists()) {
    return values;
  }

  final lines = await file.readAsLines();
  for (final rawLine in lines) {
    final line = rawLine.trim();
    if (line.isEmpty || line.startsWith('#') || !line.contains('=')) {
      continue;
    }
    final separator = line.indexOf('=');
    final key = line.substring(0, separator).trim();
    final value = _unquote(line.substring(separator + 1).trim());
    final processValue = values[key]?.trim() ?? '';
    if (key.isNotEmpty && processValue.isEmpty) {
      values[key] = value;
    }
  }

  return values;
}

String _unquote(String value) {
  if (value.length < 2) {
    return value;
  }
  final first = value[0];
  final last = value[value.length - 1];
  if ((first == '"' && last == '"') || (first == "'" && last == "'")) {
    return value.substring(1, value.length - 1);
  }
  return value;
}
