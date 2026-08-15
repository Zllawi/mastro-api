import 'dart:async';
import 'dart:io';

import 'package:dio/dio.dart';

typedef ResalaDelay = Future<void> Function(Duration duration);

class ResalaConfig {
  ResalaConfig({
    required this.token,
    Uri? baseUrl,
    bool? useTestMode,
    this.tokenEnvName = 'RESALA_API_TOKEN',
  }) : baseUrl = baseUrl ?? Uri.parse(defaultBaseUrl),
       useTestMode = useTestMode ?? true {
    if (token.trim().isEmpty) {
      throw ResalaAuthException(
        'Resala token is missing. Check $tokenEnvName.',
        statusCode: 401,
      );
    }
  }

  factory ResalaConfig.fromEnvironment({
    Map<String, String>? environment,
    String tokenEnvName = 'RESALA_API_TOKEN',
    String baseUrlEnvName = 'RESALA_BASE_URL',
    String environmentEnvName = 'APP_ENV',
  }) {
    final env = environment ?? Platform.environment;
    final token = env[tokenEnvName] ?? '';
    final baseUrl = env[baseUrlEnvName];
    final appEnv = (env[environmentEnvName] ?? env['DART_ENV'] ?? 'development')
        .toLowerCase();
    final hostedOnRender = (env['RENDER'] ?? '').trim().toLowerCase() == 'true';
    final production =
        hostedOnRender || appEnv == 'production' || appEnv == 'prod';

    return ResalaConfig(
      token: token,
      baseUrl: baseUrl == null || baseUrl.trim().isEmpty
          ? null
          : Uri.parse(baseUrl),
      useTestMode: !production,
      tokenEnvName: tokenEnvName,
    );
  }

  static const defaultBaseUrl = 'https://dev.resala.ly/api/v1';

  final String token;
  final Uri baseUrl;
  final bool useTestMode;
  final String tokenEnvName;
}

class ResalaClient {
  ResalaClient({required this.config, Dio? dio, ResalaDelay? delay})
    : _dio =
          dio ??
          Dio(
            BaseOptions(
              baseUrl: config.baseUrl.toString(),
              connectTimeout: const Duration(seconds: 10),
              receiveTimeout: const Duration(seconds: 20),
              sendTimeout: const Duration(seconds: 10),
            ),
          ),
      _delay = delay ?? Future.delayed {
    _dio.options.baseUrl = config.baseUrl.toString();
  }

  final ResalaConfig config;
  final Dio _dio;
  final ResalaDelay _delay;

  Future<ResalaPin> sendOtp({
    required String phone,
    bool? test,
    int? len,
    String? serviceName,
    String? autofill,
  }) async {
    _validatePhone(phone);
    if (len != null && !{4, 5, 6}.contains(len)) {
      throw ArgumentError.value(
        len,
        'len',
        'Allowed OTP lengths are 4, 5, or 6.',
      );
    }
    if (autofill != null && autofill.length > 32) {
      throw ArgumentError.value(
        autofill,
        'autofill',
        'Android autofill hash must be 32 characters or fewer.',
      );
    }

    final query = <String, String?>{};
    if (test ?? config.useTestMode) {
      query['test'] = null;
    }
    if (len != null) {
      query['len'] = len.toString();
    }
    if (serviceName != null) {
      query['service_name'] = serviceName;
    }
    if (autofill != null) {
      query['autofill'] = autofill;
    }

    final response = await _request(
      'POST',
      _pathWithQuery('/pins', query),
      data: {'phone': phone},
    );

    return ResalaPin.fromJson(_asJsonObject(response.data));
  }

  Future<ResalaTemplateSendResult> sendTemplate({
    required String smsTemplateId,
    required List<ResalaTemplateRecord> records,
  }) async {
    if (smsTemplateId.trim().isEmpty) {
      throw ArgumentError.value(
        smsTemplateId,
        'smsTemplateId',
        'Template ID is required.',
      );
    }
    if (records.isEmpty) {
      throw ArgumentError.value(
        records,
        'records',
        'At least one record is required.',
      );
    }
    for (final record in records) {
      _validatePhone(record.phone);
    }

    final response = await _request(
      'POST',
      _pathWithQuery('/messages/send-template', {
        'sms_template_id': smsTemplateId,
      }),
      data: {'records': records.map((record) => record.toJson()).toList()},
    );

    return ResalaTemplateSendResult(raw: _asJsonObject(response.data));
  }

  Future<ResalaSentViewPage> getSentView({
    ResalaSentSource source = ResalaSentSource.pin,
    int page = 1,
    int paginate = 10,
    String sorts = '-created_at',
  }) async {
    if (page < 1) {
      throw ArgumentError.value(page, 'page', 'Page must be 1 or greater.');
    }
    if (paginate < 1) {
      throw ArgumentError.value(
        paginate,
        'paginate',
        'Paginate must be 1 or greater.',
      );
    }

    final response = await _request(
      'GET',
      '/sent-view',
      queryParameters: {
        'filters': 'source:${source.name}',
        'page': page,
        'paginate': paginate,
        'sorts': sorts,
      },
      retryGet: true,
    );

    return ResalaSentViewPage.fromJson(_asJsonObject(response.data));
  }

  Future<Response<dynamic>> _request(
    String method,
    String path, {
    Object? data,
    Map<String, Object?>? queryParameters,
    bool retryGet = false,
  }) async {
    final maxAttempts = retryGet && method == 'GET' ? 3 : 1;

    for (var attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await _dio.request<dynamic>(
          path,
          data: data,
          queryParameters: queryParameters,
          options: Options(
            method: method,
            headers: {
              HttpHeaders.authorizationHeader: 'Bearer ${config.token}',
              HttpHeaders.acceptHeader: 'application/json',
              HttpHeaders.contentTypeHeader: 'application/json',
            },
          ),
        );
      } on DioException catch (error) {
        final isLastAttempt = attempt == maxAttempts;
        if (method == 'GET' && error.response == null && !isLastAttempt) {
          await _delay(Duration(milliseconds: 200 * (1 << (attempt - 1))));
          continue;
        }
        throw _mapDioException(error, config.tokenEnvName);
      }
    }

    throw StateError('Unreachable Resala retry state.');
  }

  static void _validatePhone(String phone) {
    final normalized = phone.trim();
    if (!RegExp(r'^2189\d{8}$').hasMatch(normalized)) {
      throw ArgumentError.value(
        phone,
        'phone',
        'Phone must be a Libyan number like 218910001234.',
      );
    }
  }
}

class ResalaPin {
  const ResalaPin({
    required this.id,
    required this.pin,
    required this.code,
    required this.number,
    required this.content,
    required this.createdAt,
    required this.raw,
  });

  factory ResalaPin.fromJson(Map<String, dynamic> json) {
    return ResalaPin(
      id: json['id']?.toString() ?? '',
      pin: json['pin']?.toString() ?? '',
      code: json['code']?.toString() ?? '',
      number: json['number']?.toString() ?? '',
      content: json['content']?.toString() ?? '',
      createdAt: DateTime.tryParse(json['created_at']?.toString() ?? ''),
      raw: json,
    );
  }

  final String id;
  final String pin;
  final String code;
  final String number;
  final String content;
  final DateTime? createdAt;
  final Map<String, dynamic> raw;
}

class ResalaTemplateRecord {
  ResalaTemplateRecord({required this.phone, required this.variables});

  final String phone;
  final Map<String, String> variables;

  Map<String, dynamic> toJson() => {'phone': phone, ...variables};
}

class ResalaTemplateSendResult {
  const ResalaTemplateSendResult({required this.raw});

  final Map<String, dynamic> raw;
}

enum ResalaSentSource { pin, message }

enum ResalaDeliveryStatus {
  accepted,
  sent,
  delivered,
  undelivered,
  unknown;

  static ResalaDeliveryStatus fromWire(String? value) {
    return ResalaDeliveryStatus.values.firstWhere(
      (status) => status.name == value,
      orElse: () => ResalaDeliveryStatus.unknown,
    );
  }
}

class ResalaSentViewPage {
  const ResalaSentViewPage({
    required this.data,
    required this.meta,
    required this.raw,
  });

  factory ResalaSentViewPage.fromJson(Map<String, dynamic> json) {
    final rows = json['data'] is List
        ? json['data'] as List<dynamic>
        : const [];
    return ResalaSentViewPage(
      data: rows
          .whereType<Map>()
          .map(
            (row) => ResalaSentMessage.fromJson(Map<String, dynamic>.from(row)),
          )
          .toList(),
      meta: json['meta'] is Map
          ? Map<String, dynamic>.from(json['meta'] as Map)
          : const {},
      raw: json,
    );
  }

  final List<ResalaSentMessage> data;
  final Map<String, dynamic> meta;
  final Map<String, dynamic> raw;
}

class ResalaSentMessage {
  const ResalaSentMessage({required this.status, required this.raw});

  factory ResalaSentMessage.fromJson(Map<String, dynamic> json) {
    return ResalaSentMessage(
      status: ResalaDeliveryStatus.fromWire(json['status']?.toString()),
      raw: json,
    );
  }

  final ResalaDeliveryStatus status;
  final Map<String, dynamic> raw;
}

sealed class ResalaException implements Exception {
  const ResalaException(this.message, {this.statusCode, this.payload});

  final String message;
  final int? statusCode;
  final Object? payload;

  @override
  String toString() => 'ResalaException($statusCode): $message';
}

class ResalaAuthException extends ResalaException {
  const ResalaAuthException(super.message, {super.statusCode, super.payload});
}

class ResalaPermissionException extends ResalaException {
  const ResalaPermissionException(
    super.message, {
    super.statusCode,
    super.payload,
  });
}

class ResalaValidationException extends ResalaException {
  const ResalaValidationException(
    super.message, {
    required this.errors,
    super.statusCode,
    super.payload,
  });

  final Map<String, List<String>> errors;
}

class ResalaInsufficientCreditException extends ResalaException {
  const ResalaInsufficientCreditException(
    super.message, {
    super.statusCode,
    super.payload,
  });
}

class ResalaApiException extends ResalaException {
  const ResalaApiException(super.message, {super.statusCode, super.payload});
}

String _pathWithQuery(String path, Map<String, String?> query) {
  final parts = <String>[];
  for (final entry in query.entries) {
    final key = Uri.encodeQueryComponent(entry.key);
    final value = entry.value;
    parts.add(value == null ? key : '$key=${Uri.encodeQueryComponent(value)}');
  }
  return parts.isEmpty ? path : '$path?${parts.join('&')}';
}

Map<String, dynamic> _asJsonObject(Object? data) {
  if (data is Map<String, dynamic>) {
    return data;
  }
  if (data is Map) {
    return Map<String, dynamic>.from(data);
  }
  return {'data': data};
}

ResalaException _mapDioException(DioException error, String tokenEnvName) {
  final response = error.response;
  if (response == null) {
    return ResalaApiException(
      'Network error while calling Resala: ${error.message ?? error.type.name}.',
    );
  }

  final statusCode = response.statusCode;
  final payload = response.data;
  final message = _extractMessage(payload);

  if (statusCode == 401) {
    return ResalaAuthException(
      'Resala token is missing or invalid. Check $tokenEnvName.',
      statusCode: statusCode,
      payload: payload,
    );
  }
  if (statusCode == 403) {
    return ResalaPermissionException(
      'Resala account lacks permission for this endpoint.',
      statusCode: statusCode,
      payload: payload,
    );
  }
  if (statusCode == 422) {
    final errors = _extractValidationErrors(payload);
    return ResalaValidationException(
      errors.isEmpty
          ? message
          : errors.entries
                .map((entry) => '${entry.key}: ${entry.value.join(', ')}')
                .join('; '),
      errors: errors,
      statusCode: statusCode,
      payload: payload,
    );
  }
  if (statusCode == 400 && _looksLikeCreditError(message)) {
    return ResalaInsufficientCreditException(
      'Resala wallet balance is insufficient. Do not retry automatically.',
      statusCode: statusCode,
      payload: payload,
    );
  }

  return ResalaApiException(message, statusCode: statusCode, payload: payload);
}

String _extractMessage(Object? payload) {
  if (payload is Map) {
    final message = payload['message'] ?? payload['error'];
    if (message != null) {
      return message.toString();
    }
  }
  return payload?.toString() ?? 'Unexpected Resala API error.';
}

Map<String, List<String>> _extractValidationErrors(Object? payload) {
  if (payload is! Map) {
    return const {};
  }
  final source = payload['errors'] is Map ? payload['errors'] as Map : payload;
  final errors = <String, List<String>>{};
  for (final entry in source.entries) {
    final key = entry.key.toString();
    if (key == 'message' || key == 'error') {
      continue;
    }
    final value = entry.value;
    if (value is List) {
      errors[key] = value.map((item) => item.toString()).toList();
    } else if (value != null) {
      errors[key] = [value.toString()];
    }
  }
  return errors;
}

bool _looksLikeCreditError(String message) {
  final normalized = message.toLowerCase();
  return normalized.contains('credit') ||
      normalized.contains('balance') ||
      normalized.contains('wallet') ||
      normalized.contains('رصيد');
}
