import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:dio/dio.dart';

class CloudinaryConfig {
  const CloudinaryConfig({
    required this.cloudName,
    required this.apiKey,
    required this.apiSecret,
    this.baseFolder = 'maestro',
  });

  factory CloudinaryConfig.fromEnvironment(Map<String, String> environment) {
    return CloudinaryConfig(
      cloudName: environment['CLOUDINARY_CLOUD_NAME']?.trim() ?? '',
      apiKey: environment['CLOUDINARY_API_KEY']?.trim() ?? '',
      apiSecret: environment['CLOUDINARY_API_SECRET']?.trim() ?? '',
      baseFolder:
          environment['CLOUDINARY_UPLOAD_FOLDER']?.trim().isNotEmpty == true
          ? environment['CLOUDINARY_UPLOAD_FOLDER']!.trim()
          : 'maestro',
    );
  }

  final String cloudName;
  final String apiKey;
  final String apiSecret;
  final String baseFolder;

  bool get isConfigured =>
      cloudName.isNotEmpty && apiKey.isNotEmpty && apiSecret.isNotEmpty;
}

class CloudinaryClient {
  CloudinaryClient({required this.config, Dio? dio}) : _dio = dio ?? Dio();

  final CloudinaryConfig config;
  final Dio _dio;

  Future<CloudinaryUpload> upload({
    required List<int> bytes,
    required String filename,
    required String mimeType,
    required String ownerId,
    required String purpose,
  }) async {
    if (!config.isConfigured) {
      throw const CloudinaryException(
        'تعذر حفظ الملف الآن. حاول مرة أخرى لاحقًا.',
        statusCode: HttpStatus.serviceUnavailable,
      );
    }
    if (bytes.isEmpty) {
      throw const CloudinaryException('الملف فارغ.', statusCode: 422);
    }
    if (bytes.length > 20 * 1024 * 1024) {
      throw const CloudinaryException(
        'حجم الملف يتجاوز الحد المسموح 20 MB.',
        statusCode: HttpStatus.requestEntityTooLarge,
      );
    }
    final resourceType = mimeType.startsWith('audio/')
        ? 'video'
        : mimeType.startsWith('video/')
        ? 'video'
        : mimeType.startsWith('image/')
        ? 'image'
        : 'raw';
    final safePurpose = purpose.replaceAll(RegExp(r'[^a-zA-Z0-9_-]'), '_');
    final folder = '${config.baseFolder}/$safePurpose/$ownerId';
    final timestamp = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
    final parametersToSign = 'folder=$folder&timestamp=$timestamp';
    final signature = sha1
        .convert(utf8.encode('$parametersToSign${config.apiSecret}'))
        .toString();
    final uri =
        'https://api.cloudinary.com/v1_1/${config.cloudName}/$resourceType/upload';

    try {
      final response = await _dio.post<Map<String, dynamic>>(
        uri,
        data: FormData.fromMap({
          'file': MultipartFile.fromBytes(bytes, filename: filename),
          'api_key': config.apiKey,
          'timestamp': timestamp,
          'folder': folder,
          'signature': signature,
        }),
        options: Options(
          contentType: 'multipart/form-data',
          sendTimeout: const Duration(seconds: 45),
          receiveTimeout: const Duration(seconds: 45),
        ),
      );
      final data = response.data;
      if (data == null ||
          data['secure_url'] == null ||
          data['public_id'] == null) {
        throw const CloudinaryException(
          'تعذر حفظ الملف الآن. حاول مرة أخرى لاحقًا.',
          statusCode: HttpStatus.badGateway,
        );
      }
      return CloudinaryUpload(
        url: data['secure_url'].toString(),
        publicId: data['public_id'].toString(),
        resourceType: data['resource_type']?.toString() ?? resourceType,
        format: data['format']?.toString(),
        bytes: _asInt(data['bytes']) ?? bytes.length,
        contentType: mimeType,
      );
    } on DioException catch (error) {
      throw CloudinaryException(
        _friendlyUploadError(error),
        statusCode: error.response?.statusCode ?? HttpStatus.badGateway,
      );
    }
  }

  /// Permanently removes one server-owned Cloudinary asset.
  ///
  /// This is intentionally exposed only by the backend cleanup worker. The
  /// signature and API secret never leave the server.
  Future<void> destroy({
    required String publicId,
    required String resourceType,
  }) async {
    if (!config.isConfigured) {
      throw const CloudinaryException(
        'Cloudinary غير مهيأ في الخادم. راجع متغيرات CLOUDINARY_*.',
        statusCode: HttpStatus.serviceUnavailable,
      );
    }
    if (publicId.trim().isEmpty) {
      throw const CloudinaryException(
        'معرف ملف Cloudinary مفقود.',
        statusCode: 422,
      );
    }
    if (!const {'image', 'video', 'raw'}.contains(resourceType)) {
      throw const CloudinaryException(
        'نوع ملف Cloudinary غير صالح للحذف.',
        statusCode: 422,
      );
    }

    final timestamp = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
    final parametersToSign =
        'invalidate=true&public_id=$publicId&timestamp=$timestamp';
    final signature = sha1
        .convert(utf8.encode('$parametersToSign${config.apiSecret}'))
        .toString();
    final uri =
        'https://api.cloudinary.com/v1_1/${config.cloudName}/$resourceType/destroy';

    try {
      final response = await _dio.post<Map<String, dynamic>>(
        uri,
        data: FormData.fromMap({
          'public_id': publicId,
          'invalidate': 'true',
          'api_key': config.apiKey,
          'timestamp': timestamp,
          'signature': signature,
        }),
        options: Options(
          contentType: 'multipart/form-data',
          sendTimeout: const Duration(seconds: 30),
          receiveTimeout: const Duration(seconds: 30),
        ),
      );
      final result = response.data?['result']?.toString();
      if (result != 'ok' && result != 'not found') {
        throw CloudinaryException(
          'تعذر حذف ملف Cloudinary: ${result ?? 'استجابة غير متوقعة'}.',
          statusCode: HttpStatus.badGateway,
        );
      }
    } on DioException catch (error) {
      final message = _cloudinaryMessage(error.response?.data);
      throw CloudinaryException(
        message ?? 'تعذر حذف الملف من Cloudinary.',
        statusCode: error.response?.statusCode ?? HttpStatus.badGateway,
      );
    }
  }
}

class CloudinaryUpload {
  const CloudinaryUpload({
    required this.url,
    required this.publicId,
    required this.resourceType,
    required this.bytes,
    required this.contentType,
    this.format,
  });

  final String url;
  final String publicId;
  final String resourceType;
  final String? format;
  final int bytes;
  final String contentType;

  Map<String, dynamic> toJson() => {
    'url': url,
    'public_id': publicId,
    'resource_type': resourceType,
    'format': format,
    'size_bytes': bytes,
    'content_type': contentType,
  };
}

class CloudinaryException implements Exception {
  const CloudinaryException(this.message, {this.statusCode = 400});

  final String message;
  final int statusCode;

  @override
  String toString() => 'CloudinaryException($statusCode): $message';
}

String _friendlyUploadError(DioException error) {
  final statusCode = error.response?.statusCode;
  if (statusCode == HttpStatus.requestEntityTooLarge) {
    return 'حجم الملف أكبر من الحد المسموح.';
  }
  if (statusCode == HttpStatus.badRequest ||
      statusCode == HttpStatus.unprocessableEntity) {
    return 'تعذر حفظ هذا الملف. اختر ملفًا آخر وحاول مجددًا.';
  }
  if (error.type == DioExceptionType.connectionTimeout ||
      error.type == DioExceptionType.sendTimeout ||
      error.type == DioExceptionType.receiveTimeout ||
      error.type == DioExceptionType.connectionError) {
    return 'تعذر رفع الملف. تحقق من الإنترنت وحاول مرة أخرى.';
  }
  return 'تعذر حفظ الملف الآن. حاول مرة أخرى لاحقًا.';
}

String? _cloudinaryMessage(Object? data) {
  if (data is Map) {
    final error = data['error'];
    if (error is Map && error['message'] != null) {
      return error['message'].toString();
    }
    if (data['message'] != null) return data['message'].toString();
  }
  return null;
}

int? _asInt(Object? value) {
  if (value is int) return value;
  return int.tryParse(value?.toString() ?? '');
}
