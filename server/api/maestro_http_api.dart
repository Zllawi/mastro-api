import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../auth/password_hasher.dart';
import '../auth/session_service.dart';
import '../auth/test_login_policy.dart';
import '../cloudinary/cloudinary_client.dart';
import '../firebase/firebase_push_service.dart';
import '../resala/otp_flow.dart';
import '../resala/resala_client.dart';
import '../supabase/platform_repository.dart';

class MaestroHttpApi {
  const MaestroHttpApi({
    required this.environment,
    required this.otpService,
    required this.repository,
    required this.sessions,
    required this.cloudinary,
    this.pushDispatcher,
  });

  final Map<String, String> environment;
  final ResalaOtpService otpService;
  final PlatformRepository repository;
  final SessionService sessions;
  final CloudinaryClient cloudinary;
  final NotificationPushDispatcher? pushDispatcher;

  bool get _isProduction =>
      !TestLoginPolicy.fromEnvironment(environment).environmentAllowsTestLogin;

  Future<void> handle(HttpRequest request) async {
    _addCorsHeaders(request.response);
    if (request.method == 'OPTIONS') {
      request.response.statusCode = HttpStatus.noContent;
      await request.response.close();
      return;
    }

    try {
      final path = request.uri.path;
      if (request.method == 'GET' && path == '/health') {
        await _json(request.response, HttpStatus.ok, {
          'ok': true,
          'environment': _isProduction ? 'production' : 'non-production',
          'cloudinary_configured': cloudinary.config.isConfigured,
          'firebase_push_configured': pushDispatcher != null,
        });
        return;
      }
      if (request.method == 'GET' && path == '/config') {
        final enabled = !_isProduction && await repository.testLoginEnabled();
        await _json(request.response, HttpStatus.ok, {
          'test_login_enabled': enabled,
        });
        return;
      }
      if (request.method == 'POST' && path == '/auth/otp/request') {
        await _requestOtp(request);
        return;
      }
      if (request.method == 'POST' && path == '/auth/otp/verify') {
        await _verifyOtp(request);
        return;
      }
      if (request.method == 'POST' && path == '/auth/test-login') {
        await _testLogin(request);
        return;
      }
      if (request.method == 'POST' && path == '/auth/password/login') {
        await _passwordLogin(request);
        return;
      }

      final auth = await sessions.authenticate(
        request.headers.value(HttpHeaders.authorizationHeader),
      );
      if (auth == null) {
        await _json(request.response, HttpStatus.unauthorized, {
          'message': 'انتهت الجلسة أو لم يتم تسجيل الدخول.',
        });
        return;
      }
      final profileId = auth['profile_id'].toString();
      final role = auth['role'].toString();
      final passwordRequired =
          role != 'admin' && auth['password_reset_required'] == true;

      if (request.method == 'POST' && path == '/auth/logout') {
        await sessions.revoke(
          request.headers.value(HttpHeaders.authorizationHeader),
        );
        await _json(request.response, HttpStatus.ok, {'logged_out': true});
        return;
      }
      if (request.method == 'GET' && path == '/me') {
        await _json(
          request.response,
          HttpStatus.ok,
          await repository.bootstrap(profileId),
        );
        return;
      }
      if (request.method == 'PUT' && path == '/auth/password') {
        await _setPassword(request, profileId);
        return;
      }
      if (passwordRequired) {
        await _json(request.response, HttpStatus.forbidden, {
          'message': 'أنشئ كلمة سر لحسابك قبل متابعة استخدام التطبيق.',
          'password_required': true,
        });
        return;
      }
      if (request.method == 'POST' && path == '/uploads') {
        await _upload(request, profileId, role);
        return;
      }
      if (request.method == 'PUT' && path == '/profile/customer') {
        _requireRole(role, 'customer');
        await _saveCustomer(request, profileId);
        return;
      }
      if (request.method == 'PUT' && path == '/profile/craftsman') {
        _requireRole(role, 'craftsman');
        await _saveCraftsman(request, profileId);
        return;
      }
      if (path == '/addresses' && request.method == 'GET') {
        _requireRole(role, 'customer');
        await _json(request.response, HttpStatus.ok, {
          'data': await repository.listAddresses(profileId),
        });
        return;
      }
      if (path == '/addresses' && request.method == 'POST') {
        _requireRole(role, 'customer');
        final body = await _readJsonObject(request);
        _validateAddress(body);
        await _json(request.response, HttpStatus.created, {
          'address': await repository.addAddress(
            profileId: profileId,
            input: body,
          ),
        });
        return;
      }
      final addressId = _pathId(path, '/addresses/');
      if (addressId != null && request.method == 'PUT') {
        _requireRole(role, 'customer');
        final body = await _readJsonObject(request);
        _validateAddress(body);
        await _json(request.response, HttpStatus.ok, {
          'address': await repository.updateAddress(
            profileId: profileId,
            addressId: addressId,
            input: body,
          ),
        });
        return;
      }
      if (addressId != null && request.method == 'DELETE') {
        _requireRole(role, 'customer');
        await repository.deleteAddress(
          profileId: profileId,
          addressId: addressId,
        );
        await _json(request.response, HttpStatus.ok, {'deleted': true});
        return;
      }
      if (path == '/categories' && request.method == 'GET') {
        await _json(request.response, HttpStatus.ok, {
          'data': await repository.listCategories(),
        });
        return;
      }
      if (path == '/home-banners' && request.method == 'GET') {
        await _json(request.response, HttpStatus.ok, {
          'data': await repository.listHomeBanners(),
        });
        return;
      }
      if (path == '/favorites' && request.method == 'GET') {
        await _json(request.response, HttpStatus.ok, {
          'data': await repository.listFavorites(profileId),
        });
        return;
      }
      final favoriteId = _pathId(path, '/favorites/');
      if (favoriteId != null &&
          (request.method == 'POST' || request.method == 'DELETE')) {
        await repository.setFavorite(
          customerId: profileId,
          craftsmanId: favoriteId,
          favorite: request.method == 'POST',
        );
        await _json(request.response, HttpStatus.ok, {'ok': true});
        return;
      }
      if (path == '/requests' && request.method == 'GET') {
        await _json(request.response, HttpStatus.ok, {
          'data': await repository.requestsForProfile(profileId),
        });
        return;
      }
      if (path == '/requests' && request.method == 'POST') {
        _requireRole(role, 'customer');
        await _createRequest(request, profileId);
        return;
      }
      if (path == '/offers' && request.method == 'POST') {
        _requireRole(role, 'craftsman');
        final body = await _readJsonObject(request);
        _requireText(body, 'request_id', 'معرف الطلب مطلوب.');
        _requirePositiveNumber(
          body,
          'total_amount',
          'قيمة العرض يجب أن تكون أكبر من صفر.',
        );
        final labor = _nonNegativeNumber(
          body['labor_amount'],
          'تكلفة العمل غير صالحة.',
        );
        final materials = _nonNegativeNumber(
          body['materials_amount'],
          'تكلفة المواد غير صالحة.',
        );
        final inspection = _nonNegativeNumber(
          body['inspection_fee'],
          'قيمة الكشف غير صالحة.',
        );
        final total = body['total_amount'] as num;
        if ((labor + materials + inspection - total).abs() > 0.001) {
          throw const PlatformRuleException(
            'إجمالي العرض لا يطابق تفاصيل تكلفة العمل والمواد والكشف.',
            statusCode: 422,
          );
        }
        body
          ..['labor_amount'] = labor
          ..['materials_amount'] = materials
          ..['inspection_fee'] = inspection;
        await _json(request.response, HttpStatus.created, {
          'offer': await repository.submitOffer(
            craftsmanId: profileId,
            input: body,
          ),
        });
        return;
      }
      final requestOffersId = _pathBetween(path, '/requests/', '/offers');
      if (requestOffersId != null && request.method == 'GET') {
        _requireRole(role, 'customer');
        await _json(request.response, HttpStatus.ok, {
          'data': await repository.listOffers(
            customerId: profileId,
            requestId: requestOffersId,
          ),
        });
        return;
      }
      final reviseOfferId = _pathBetween(path, '/offers/', '/revision');
      if (reviseOfferId != null && request.method == 'POST') {
        _requireRole(role, 'customer');
        final body = await _readJsonObject(request);
        _validateOfferAmounts(body);
        await _json(request.response, HttpStatus.created, {
          'revision': await repository.requestOfferRevision(
            customerId: profileId,
            offerId: reviseOfferId,
            input: body,
          ),
        });
        return;
      }
      final revisionResponseId = _pathBetween(
        path,
        '/offer-revisions/',
        '/respond',
      );
      if (revisionResponseId != null && request.method == 'POST') {
        _requireRole(role, 'craftsman');
        final body = await _readJsonObject(request);
        if (body['approved'] is! bool) {
          throw const PlatformRuleException(
            'Revision decision is invalid.',
            statusCode: 422,
          );
        }
        await _json(request.response, HttpStatus.ok, {
          'revision': await repository.respondOfferRevision(
            craftsmanId: profileId,
            revisionId: revisionResponseId,
            approved: body['approved'] == true,
            responseNote: body['response_note']?.toString(),
          ),
        });
        return;
      }
      final acceptRequestId = _pathBetween(path, '/requests/', '/accept-offer');
      if (acceptRequestId != null && request.method == 'POST') {
        _requireRole(role, 'customer');
        final body = await _readJsonObject(request);
        final offerId = _requireText(body, 'offer_id', 'معرف العرض مطلوب.');
        await repository.acceptOffer(
          customerId: profileId,
          requestId: acceptRequestId,
          offerId: offerId,
        );
        await _json(request.response, HttpStatus.ok, {'accepted': true});
        return;
      }
      final statusRequestId = _pathBetween(path, '/requests/', '/status');
      if (statusRequestId != null && request.method == 'POST') {
        _requireRole(role, 'craftsman');
        final body = await _readJsonObject(request);
        await repository.advanceRequestStatus(
          craftsmanId: profileId,
          requestId: statusRequestId,
          nextStatus: _requireText(body, 'status', 'حالة الطلب مطلوبة.'),
          cashReceivedConfirmed: body['cash_received_confirmed'] == true,
        );
        await _json(request.response, HttpStatus.ok, {'updated': true});
        return;
      }
      final reviewRequestId = _pathBetween(path, '/requests/', '/review');
      if (reviewRequestId != null && request.method == 'POST') {
        _requireRole(role, 'customer');
        final body = await _readJsonObject(request);
        for (final key in const [
          'quality_rating',
          'punctuality_rating',
          'price_rating',
          'communication_rating',
          'cleanliness_rating',
        ]) {
          final rating = _nonNegativeInt(body[key], 'قيم التقييم غير صالحة.');
          if (rating < 1 || rating > 5) {
            throw const PlatformRuleException(
              'التقييم يجب أن يكون بين 1 و5.',
              statusCode: 422,
            );
          }
          body[key] = rating;
        }
        await _json(request.response, HttpStatus.created, {
          'review': await repository.submitReview(
            customerId: profileId,
            requestId: reviewRequestId,
            input: body,
          ),
        });
        return;
      }
      final customerReviewRequestId = _pathBetween(
        path,
        '/requests/',
        '/customer-review',
      );
      if (customerReviewRequestId != null && request.method == 'POST') {
        _requireRole(role, 'craftsman');
        final body = await _readJsonObject(request);
        final rating = _nonNegativeInt(body['rating'], 'Rating is invalid.');
        if (rating < 1 || rating > 5) {
          throw const PlatformRuleException(
            'Rating must be between 1 and 5.',
            statusCode: 422,
          );
        }
        await _json(request.response, HttpStatus.created, {
          'review': await repository.submitCustomerReview(
            craftsmanId: profileId,
            requestId: customerReviewRequestId,
            rating: rating,
            comment: body['comment']?.toString(),
          ),
        });
        return;
      }
      final messagesRequestId = _pathBetween(path, '/requests/', '/messages');
      if (messagesRequestId != null && request.method == 'GET') {
        await _json(request.response, HttpStatus.ok, {
          'data': await repository.listMessages(
            profileId: profileId,
            requestId: messagesRequestId,
          ),
        });
        return;
      }
      if (messagesRequestId != null && request.method == 'POST') {
        final body = await _readJsonObject(request);
        _requireText(body, 'body', 'اكتب الرسالة أولًا.');
        _validateManagedAttachment(body);
        await _json(request.response, HttpStatus.created, {
          'message': await repository.sendMessage(
            profileId: profileId,
            role: role,
            requestId: messagesRequestId,
            input: body,
          ),
        });
        return;
      }
      if (path == '/notifications' && request.method == 'GET') {
        await _json(request.response, HttpStatus.ok, {
          'data': await repository.listNotifications(profileId),
        });
        return;
      }
      if (path == '/notifications/read' && request.method == 'POST') {
        final body = await _readJsonObject(request);
        await repository.markNotificationsRead(
          profileId,
          id: body['id']?.toString(),
        );
        await _json(request.response, HttpStatus.ok, {'updated': true});
        return;
      }
      if (path == '/wallet' && request.method == 'GET') {
        await _json(
          request.response,
          HttpStatus.ok,
          await repository.wallet(profileId),
        );
        return;
      }
      if (path == '/wallet/coupons/redeem' && request.method == 'POST') {
        final body = await _readJsonObject(request);
        final code = _requireText(
          body,
          'code',
          'رمز شحن المحفظة مطلوب.',
        ).replaceAll(RegExp(r'\D'), '');
        await _json(request.response, HttpStatus.ok, {
          'result': await repository.redeemWalletCoupon(
            profileId: profileId,
            code: code,
          ),
        });
        return;
      }
      if (path == '/notification-devices' && request.method == 'POST') {
        final body = await _readJsonObject(request);
        await _json(request.response, HttpStatus.ok, {
          'device': await repository.registerNotificationDevice(
            profileId: profileId,
            platform: _requireText(body, 'platform', 'نظام الجهاز مطلوب.'),
            pushToken: _requireText(
              body,
              'push_token',
              'رمز جهاز الإشعارات مطلوب.',
            ),
          ),
        });
        return;
      }
      if (path == '/notification-devices' && request.method == 'DELETE') {
        final body = await _readJsonObject(request);
        await repository.unregisterNotificationDevice(
          profileId: profileId,
          pushToken: _requireText(
            body,
            'push_token',
            'رمز جهاز الإشعارات مطلوب.',
          ),
        );
        await _json(request.response, HttpStatus.ok, {'updated': true});
        return;
      }
      if (path == '/craftsman/availability' && request.method == 'PUT') {
        _requireRole(role, 'craftsman');
        final body = await _readJsonObject(request);
        final available = body['available'];
        if (available is! bool) {
          throw const PlatformRuleException(
            'قيمة التوفر غير صالحة.',
            statusCode: 422,
          );
        }
        await repository.updateAvailability(profileId, available);
        await _json(request.response, HttpStatus.ok, {'available': available});
        return;
      }
      if (path == '/craftsman/location' && request.method == 'PUT') {
        _requireRole(role, 'craftsman');
        final body = await _readJsonObject(request);
        final latitude = _coordinate(
          body['latitude'],
          minimum: -90,
          maximum: 90,
          message: 'خط العرض غير صالح.',
        );
        final longitude = _coordinate(
          body['longitude'],
          minimum: -180,
          maximum: 180,
          message: 'خط الطول غير صالح.',
        );
        await repository.updateCraftsmanLocation(
          profileId: profileId,
          latitude: latitude,
          longitude: longitude,
        );
        await _json(request.response, HttpStatus.ok, {'updated': true});
        return;
      }
      if (path == '/notification-preferences' && request.method == 'PUT') {
        final body = await _readJsonObject(request);
        await _json(request.response, HttpStatus.ok, {
          'preferences': await repository.updateNotificationPreferences(
            profileId: profileId,
            input: body,
          ),
        });
        return;
      }
      if (path == '/support/conversations/current' && request.method == 'GET') {
        await _json(request.response, HttpStatus.ok, {
          'conversation': await repository.currentSupportConversation(
            profileId,
          ),
        });
        return;
      }
      if (path == '/support/conversations' && request.method == 'POST') {
        final body = await _readJsonObject(request);
        await _json(request.response, HttpStatus.created, {
          'conversation': await repository.createOrGetSupportConversation(
            profileId: profileId,
            input: body,
          ),
        });
        return;
      }
      final supportMessagesId = _pathBetween(
        path,
        '/support/conversations/',
        '/messages',
      );
      if (supportMessagesId != null && request.method == 'GET') {
        await _json(request.response, HttpStatus.ok, {
          'data': await repository.supportConversationMessages(
            profileId: profileId,
            role: role,
            conversationId: supportMessagesId,
          ),
        });
        return;
      }
      if (supportMessagesId != null && request.method == 'POST') {
        final body = await _readJsonObject(request);
        _validateSupportMessage(body);
        await _json(request.response, HttpStatus.created, {
          'message': await repository.sendSupportConversationMessage(
            profileId: profileId,
            role: role,
            conversationId: supportMessagesId,
            input: body,
          ),
        });
        return;
      }
      final closeSupportId = _pathBetween(
        path,
        '/support/conversations/',
        '/close',
      );
      if (closeSupportId != null && request.method == 'POST') {
        await repository.closeSupportConversation(
          profileId: profileId,
          role: role,
          conversationId: closeSupportId,
        );
        await _json(request.response, HttpStatus.ok, {'closed': true});
        return;
      }
      if (path == '/support/tickets' && request.method == 'POST') {
        final body = await _readJsonObject(request);
        _requireText(body, 'subject', 'موضوع الطلب مطلوب.');
        _requireText(body, 'body', 'تفاصيل طلب الدعم مطلوبة.');
        await _json(request.response, HttpStatus.created, {
          'ticket': await repository.createSupportTicket(
            profileId: profileId,
            input: body,
          ),
        });
        return;
      }

      if (path.startsWith('/admin/')) {
        _requireRole(role, 'admin');
        if (await _handleAdmin(request, profileId)) return;
      }

      await _json(request.response, HttpStatus.notFound, {
        'message': 'المسار غير موجود.',
      });
    } on PlatformRuleException catch (error) {
      await _safeJson(request.response, error.statusCode, {
        'message': error.message,
      });
    } on CloudinaryException catch (error) {
      await _safeJson(request.response, error.statusCode, {
        'message': error.message,
      });
    } on ResalaException catch (error) {
      await _safeJson(request.response, _statusForResalaError(error), {
        'message': error.message,
      });
    } on OtpCooldownException catch (error) {
      await _safeJson(request.response, HttpStatus.tooManyRequests, {
        'message': 'انتظر قليلًا قبل طلب رمز تحقق جديد.',
        'retry_after': error.cooldownUntil.toUtc().toIso8601String(),
      });
    } on FormatException catch (error) {
      await _safeJson(request.response, HttpStatus.badRequest, {
        'message': error.message,
      });
    } on SocketException catch (error) {
      await _safeJson(request.response, HttpStatus.serviceUnavailable, {
        'message':
            'تعذر الاتصال بالخدمة المطلوبة (${error.address?.host ?? 'network'}).',
      });
    } catch (error, stackTrace) {
      stderr.writeln('Unhandled backend error: $error');
      stderr.writeln(stackTrace);
      await _safeJson(request.response, HttpStatus.internalServerError, {
        'message': 'حدث خطأ غير متوقع في الخادم.',
      });
    }
  }

  Future<void> _requestOtp(HttpRequest request) async {
    final body = await _readJsonObject(request);
    final phone = _normalizeLibyanPhone(body['phone']?.toString() ?? '');
    if (phone == null) {
      throw const PlatformRuleException(
        'أدخل رقمًا ليبيًا صحيحًا يبدأ بـ 9 ويتكون من 9 أرقام.',
        statusCode: 422,
      );
    }
    final len = int.tryParse(body['len']?.toString() ?? '') ?? 6;
    final receipt = await otpService.requestOtp(
      phone: phone,
      len: len,
      serviceName: body['service_name']?.toString().trim().isNotEmpty == true
          ? body['service_name'].toString().trim()
          : 'MASTRO',
      autofill: body['autofill']?.toString(),
    );
    await _json(request.response, HttpStatus.created, {
      'message': 'تم إرسال رمز التحقق.',
      'phone': receipt.phone,
      'expires_at': receipt.expiresAt,
      'cooldown_until': receipt.cooldownUntil,
    });
  }

  Future<void> _verifyOtp(HttpRequest request) async {
    final body = await _readJsonObject(request);
    final phone = _normalizeLibyanPhone(body['phone']?.toString() ?? '');
    final code = (body['code'] ?? body['otp'] ?? body['pin'] ?? '')
        .toString()
        .replaceAll(RegExp(r'\D'), '');
    final role = _validatedRole(body['role']?.toString());
    _enforceAppRole(request, role);
    if (phone == null || code.length < 4) {
      throw const PlatformRuleException(
        'رقم الهاتف أو رمز التحقق غير صحيح.',
        statusCode: 422,
      );
    }
    final result = await otpService.verifyOtp(phone: phone, input: code);
    if (!result.verified) {
      final status = switch (result.status) {
        OtpVerificationStatus.notFound => HttpStatus.notFound,
        OtpVerificationStatus.expired => HttpStatus.gone,
        OtpVerificationStatus.invalid => HttpStatus.badRequest,
        OtpVerificationStatus.attemptsExceeded => HttpStatus.tooManyRequests,
        OtpVerificationStatus.success => HttpStatus.ok,
      };
      final message = switch (result.status) {
        OtpVerificationStatus.notFound => 'اطلب رمز تحقق جديد أولًا.',
        OtpVerificationStatus.expired => 'انتهت صلاحية رمز التحقق.',
        OtpVerificationStatus.invalid => 'رمز التحقق غير صحيح.',
        OtpVerificationStatus.attemptsExceeded =>
          'تم تجاوز عدد محاولات التحقق المسموح.',
        OtpVerificationStatus.success => 'تم التحقق.',
      };
      await _json(request.response, status, {
        'verified': false,
        'message': message,
        'attempts_remaining': result.attemptsRemaining,
      });
      return;
    }
    await _completeLogin(request, phone: phone, role: role);
  }

  Future<void> _testLogin(HttpRequest request) async {
    if (_isProduction || !await repository.testLoginEnabled()) {
      throw const PlatformRuleException(
        'الدخول التجريبي غير مفعّل.',
        statusCode: 403,
      );
    }
    final body = await _readJsonObject(request);
    final phone = _normalizeLibyanPhone(body['phone']?.toString() ?? '');
    if (phone == null) {
      throw const PlatformRuleException(
        'أدخل رقم هاتف ليبي صحيح.',
        statusCode: 422,
      );
    }
    final role = _validatedRole(body['role']?.toString());
    _enforceAppRole(request, role);
    final testLoginPolicy = TestLoginPolicy.fromEnvironment(environment);
    if (!testLoginPolicy.allows(phone: phone, role: role)) {
      throw const PlatformRuleException(
        'استخدم رقم الاختبار المخصص لنوع الحساب الذي اخترته.',
        statusCode: 403,
      );
    }
    await _completeLogin(request, phone: phone, role: role);
  }

  Future<void> _passwordLogin(HttpRequest request) async {
    final body = await _readJsonObject(request);
    final phone = _normalizeLibyanPhone(body['phone']?.toString() ?? '');
    if (phone == null) {
      throw const PlatformRuleException(
        'أدخل رقم هاتف ليبي صحيح.',
        statusCode: 422,
      );
    }
    final role = _validatedRole(body['role']?.toString());
    _enforceAppRole(request, role);
    final password = _requirePassword(body);
    final profile = await repository.passwordLoginProfile(
      phone: phone,
      role: role,
    );
    if (profile == null ||
        profile['status']?.toString() == 'deleted' ||
        profile['status']?.toString() == 'suspended') {
      throw const PlatformRuleException(
        'بيانات الدخول غير صحيحة.',
        statusCode: 403,
      );
    }
    final storedHash = profile['password_hash']?.toString();
    if (storedHash == null || storedHash.isEmpty) {
      throw const PlatformRuleException(
        'هذا الحساب يحتاج تأكيد رقم الهاتف أولًا ثم إنشاء كلمة سر.',
        statusCode: 409,
      );
    }
    if (!const PasswordHasher().verify(password, storedHash)) {
      throw const PlatformRuleException(
        'بيانات الدخول غير صحيحة.',
        statusCode: 403,
      );
    }
    await _issueSessionResponse(request, profile);
  }

  Future<void> _setPassword(HttpRequest request, String profileId) async {
    final body = await _readJsonObject(request);
    final password = _requirePassword(body);
    late final String passwordHash;
    try {
      passwordHash = const PasswordHasher().hash(password);
    } on PasswordValidationException {
      throw const PlatformRuleException(
        'كلمة السر يجب أن تكون من 4 إلى 72 حرفًا أو رقمًا.',
        statusCode: 422,
      );
    }
    final profile = await repository.setPasswordHash(
      profileId: profileId,
      passwordHash: passwordHash,
    );
    await _json(request.response, HttpStatus.ok, {
      'password_set': true,
      'bootstrap': await repository.bootstrap(profile['id'].toString()),
    });
  }

  Future<void> _completeLogin(
    HttpRequest request, {
    required String phone,
    required String role,
  }) async {
    final profile = await repository.ensureVerifiedProfile(
      phone: phone,
      requestedRole: role,
      allowExistingAdmin: role == 'admin',
    );
    await _issueSessionResponse(request, profile);
  }

  Future<void> _issueSessionResponse(
    HttpRequest request,
    Map<String, dynamic> profile,
  ) async {
    final issued = await sessions.issue(
      profileId: profile['id'].toString(),
      deviceName: request.headers.value('X-Device-Name'),
      ipAddress: request.connectionInfo?.remoteAddress.address,
    );
    await _json(request.response, HttpStatus.ok, {
      'verified': true,
      'session': {'token': issued.token, 'expires_at': issued.expiresAt},
      'bootstrap': await repository.bootstrap(profile['id'].toString()),
    });
  }

  Future<void> _upload(
    HttpRequest request,
    String profileId,
    String role,
  ) async {
    final body = await _readJsonObject(request, maxBytes: 30 * 1024 * 1024);
    final rawBase64 = _requireText(body, 'file_base64', 'بيانات الملف مطلوبة.');
    final encoded = rawBase64.contains(',')
        ? rawBase64.substring(rawBase64.indexOf(',') + 1)
        : rawBase64;
    late final List<int> bytes;
    try {
      bytes = base64Decode(encoded);
    } on FormatException {
      throw const PlatformRuleException(
        'بيانات الملف غير صالحة.',
        statusCode: 422,
      );
    }
    final filename = _requireText(body, 'filename', 'اسم الملف مطلوب.');
    final mimeType = _requireText(body, 'mime_type', 'نوع الملف مطلوب.');
    final purpose = _requireText(body, 'purpose', 'الغرض من رفع الملف مطلوب.');
    const generalPurposes = {'avatars', 'chat', 'chat-voice', 'support'};
    final rolePurposes = switch (role) {
      'customer' => const {'service-requests', 'voice-notes'},
      'craftsman' => const {'craftsman-verification'},
      'admin' => const {'category_icons', 'home_banners'},
      _ => const <String>{},
    };
    if (!generalPurposes.contains(purpose) && !rolePurposes.contains(purpose)) {
      throw const PlatformRuleException(
        'الغرض من رفع الملف غير مسموح لهذا الحساب.',
        statusCode: 403,
      );
    }
    const safeImageMimeTypes = {'image/jpeg', 'image/png', 'image/webp'};
    final isImage = safeImageMimeTypes.contains(mimeType.toLowerCase());
    final isAudio = mimeType.startsWith('audio/');
    final mimeAllowed = switch (purpose) {
      'avatars' ||
      'category_icons' ||
      'home_banners' ||
      'craftsman-verification' ||
      'service-requests' ||
      'chat' => isImage,
      'voice-notes' || 'chat-voice' => isAudio,
      'support' => isImage || isAudio || mimeType == 'application/pdf',
      _ => false,
    };
    if (!mimeAllowed) {
      throw const PlatformRuleException(
        'نوع الملف لا يطابق استخدامه داخل التطبيق.',
        statusCode: 422,
      );
    }
    if (isImage && !_matchesImageSignature(bytes, mimeType)) {
      throw const PlatformRuleException(
        'محتوى الصورة لا يطابق نوع الملف المرسل.',
        statusCode: 422,
      );
    }
    if (purpose == 'category_icons') {
      _requireRole(role, 'admin');
      if (!const {'image/png', 'image/jpeg', 'image/webp'}.contains(mimeType)) {
        throw const PlatformRuleException(
          'أيقونة الخدمة يجب أن تكون PNG أو JPEG أو WebP.',
          statusCode: 422,
        );
      }
    }
    if (purpose == 'home_banners') {
      _requireRole(role, 'admin');
      if (!const {'image/png', 'image/jpeg', 'image/webp'}.contains(mimeType)) {
        throw const PlatformRuleException(
          'صورة البانر يجب أن تكون PNG أو JPEG أو WebP.',
          statusCode: 422,
        );
      }
    }
    final upload = await cloudinary.upload(
      bytes: bytes,
      filename: filename,
      mimeType: mimeType,
      ownerId: profileId,
      purpose: purpose,
    );
    try {
      await repository.registerManagedMediaAsset(
        ownerId: profileId,
        providerPublicId: upload.publicId,
        resourceType: upload.resourceType,
        purpose: purpose,
        publicUrl: upload.url,
      );
    } catch (_) {
      // Avoid leaving an unowned asset behind when the ownership registry
      // cannot be persisted.
      try {
        await cloudinary.destroy(
          publicId: upload.publicId,
          resourceType: upload.resourceType,
        );
      } catch (_) {}
      rethrow;
    }
    await _json(request.response, HttpStatus.created, {
      'upload': upload.toJson(),
    });
  }

  Future<void> _saveCustomer(HttpRequest request, String profileId) async {
    final body = await _readJsonObject(request);
    final fullName = _requireText(
      body,
      'full_name',
      'الاسم الكامل مطلوب.',
      minLength: 3,
    );
    final city = _requireText(body, 'city', 'المدينة مطلوبة.');
    final rawAddress = body['initial_address'];
    Map<String, dynamic>? address;
    if (rawAddress is Map) {
      address = Map<String, dynamic>.from(rawAddress);
      _validateAddress(address);
    }
    await repository.saveCustomer(
      profileId: profileId,
      fullName: fullName,
      city: city,
      avatarUrl: body['avatar_url']?.toString(),
      avatarPublicId: body['avatar_public_id']?.toString(),
      avatarResourceType: body['avatar_resource_type']?.toString(),
      initialAddress: address,
    );
    await _json(request.response, HttpStatus.ok, {
      'bootstrap': await repository.bootstrap(profileId),
    });
  }

  Future<void> _saveCraftsman(HttpRequest request, String profileId) async {
    final body = await _readJsonObject(request);
    final rawDocuments = body['documents'];
    if (rawDocuments is! List || rawDocuments.length < 2) {
      throw const PlatformRuleException(
        'صور وجه وخلف إثبات الهوية مطلوبة.',
        statusCode: 422,
      );
    }
    final documents = rawDocuments
        .whereType<Map>()
        .map(Map<String, dynamic>.from)
        .toList();
    final types = documents
        .map((item) => item['document_type']?.toString())
        .toSet();
    if (!types.contains('identity_front') || !types.contains('identity_back')) {
      throw const PlatformRuleException(
        'صور وجه وخلف إثبات الهوية مطلوبة.',
        statusCode: 422,
      );
    }
    final categoryIds = _stringList(body['category_ids']);
    if (categoryIds.isEmpty) {
      throw const PlatformRuleException(
        'اختر حرفة واحدة على الأقل.',
        statusCode: 422,
      );
    }
    await repository.saveCraftsman(
      profileId: profileId,
      fullName: _requireText(
        body,
        'full_name',
        'الاسم الكامل مطلوب.',
        minLength: 3,
      ),
      profession: _requireText(body, 'profession', 'التخصص مطلوب.'),
      yearsExperience: _nonNegativeInt(
        body['years_experience'],
        'سنوات الخبرة غير صالحة.',
      ),
      serviceAreas: _stringList(body['service_areas']),
      categoryIds: categoryIds,
      identityType: _requireText(
        body,
        'identity_type',
        'نوع إثبات الهوية مطلوب.',
      ),
      identityNumber: _requireText(
        body,
        'identity_number',
        'رقم إثبات الهوية مطلوب.',
        minLength: 4,
      ),
      documents: documents,
      bio: body['bio']?.toString(),
      avatarUrl: body['avatar_url']?.toString(),
      avatarPublicId: body['avatar_public_id']?.toString(),
      avatarResourceType: body['avatar_resource_type']?.toString(),
    );
    await _json(request.response, HttpStatus.ok, {
      'bootstrap': await repository.bootstrap(profileId),
    });
  }

  Future<void> _createRequest(HttpRequest request, String profileId) async {
    final body = await _readJsonObject(request);
    _requireText(body, 'category_id', 'اختر نوع الخدمة.');
    _requireText(body, 'title', 'عنوان الطلب مطلوب.', minLength: 3);
    _requireText(body, 'description', 'وصف المشكلة مطلوب.', minLength: 10);
    _requireText(body, 'address_id', 'اختر عنوان الخدمة.');
    final paymentMethod = _requireText(
      body,
      'payment_method',
      'اختر طريقة الدفع.',
    );
    if (!const {'cash', 'wallet'}.contains(paymentMethod)) {
      throw const PlatformRuleException(
        'طريقة الدفع يجب أن تكون كاش أو عبر المحفظة.',
        statusCode: 422,
      );
    }
    body['payment_method'] = paymentMethod;
    final created = await repository.createRequest(
      customerId: profileId,
      input: body,
    );
    await _dispatchDueCampaignsAndPush();
    await _json(request.response, HttpStatus.created, {'request': created});
  }

  Future<bool> _handleAdmin(HttpRequest request, String adminId) async {
    final path = request.uri.path;
    if (path == '/admin/overview' && request.method == 'GET') {
      await _json(
        request.response,
        HttpStatus.ok,
        await repository.adminOverview(),
      );
      return true;
    }
    if (path == '/admin/locations' && request.method == 'GET') {
      final role = request.uri.queryParameters['role']?.trim().toLowerCase();
      if (role != null &&
          role.isNotEmpty &&
          role != 'customer' &&
          role != 'craftsman' &&
          role != 'all') {
        throw const PlatformRuleException(
          'فلتر الخريطة غير صالح.',
          statusCode: 422,
        );
      }
      await _json(request.response, HttpStatus.ok, {
        'data': await repository.adminLocations(
          role: role == null || role.isEmpty || role == 'all' ? null : role,
        ),
      });
      return true;
    }
    if (path == '/admin/requests' && request.method == 'GET') {
      final page = _queryInt(
        request.uri.queryParameters['page'],
        fallback: 1,
        minimum: 1,
        maximum: 100000,
      );
      final perPage = _queryInt(
        request.uri.queryParameters['per_page'],
        fallback: 30,
        minimum: 1,
        maximum: 100,
      );
      await _json(
        request.response,
        HttpStatus.ok,
        await repository.adminRequests(
          status: request.uri.queryParameters['status'],
          categoryId: request.uri.queryParameters['category_id'],
          paymentMethod: request.uri.queryParameters['payment_method'],
          search: request.uri.queryParameters['search'],
          page: page,
          perPage: perPage,
        ),
      );
      return true;
    }
    final cancelRequestId = _pathBetween(path, '/admin/requests/', '/cancel');
    if (cancelRequestId != null && request.method == 'POST') {
      final body = await _readJsonObject(request);
      final reason = _requireText(
        body,
        'reason',
        'سبب إلغاء الطلب مطلوب.',
        minLength: 3,
      );
      await _json(request.response, HttpStatus.ok, {
        'cancellation': await repository.adminCancelRequest(
          adminId: adminId,
          requestId: cancelRequestId,
          mode: _requireText(body, 'mode', 'اختر طريقة احتساب مستحقات الكشف.'),
          reason: reason,
        ),
      });
      return true;
    }
    final eligibleRequestId = _pathBetween(
      path,
      '/admin/requests/',
      '/eligible-craftsmen',
    );
    if (eligibleRequestId != null && request.method == 'GET') {
      await _json(request.response, HttpStatus.ok, {
        'data': await repository.adminEligibleCraftsmenForRequest(
          eligibleRequestId,
        ),
      });
      return true;
    }
    final dispatchRequestId = _pathBetween(
      path,
      '/admin/requests/',
      '/dispatch',
    );
    if (dispatchRequestId != null && request.method == 'POST') {
      final body = await _readJsonObject(request);
      final ids = _stringList(body['craftsman_ids']);
      await _json(request.response, HttpStatus.ok, {
        'dispatched': await repository.adminDispatchRequestToCraftsmen(
          adminId: adminId,
          requestId: dispatchRequestId,
          craftsmanIds: ids,
        ),
      });
      return true;
    }
    if (path == '/admin/users' && request.method == 'GET') {
      await _json(request.response, HttpStatus.ok, {
        'data': await repository.adminUsers(
          role: request.uri.queryParameters['role'],
          status: request.uri.queryParameters['status'],
          search: request.uri.queryParameters['search'],
        ),
      });
      return true;
    }
    final warnUserId = _pathBetween(path, '/admin/users/', '/warnings');
    if (warnUserId != null && request.method == 'POST') {
      final body = await _readJsonObject(request);
      await _json(request.response, HttpStatus.created, {
        'warning': await repository.adminWarnUser(
          adminId: adminId,
          profileId: warnUserId,
          reason: _requireText(
            body,
            'reason',
            'Warning reason is required.',
            minLength: 3,
          ),
        ),
      });
      return true;
    }
    final deleteUserId = _pathId(path, '/admin/users/');
    if (deleteUserId != null && request.method == 'DELETE') {
      final body = await _readJsonObject(request);
      await repository.adminDeleteUser(
        adminId: adminId,
        profileId: deleteUserId,
        reason: body['reason']?.toString(),
      );
      await _json(request.response, HttpStatus.ok, {'deleted': true});
      return true;
    }
    if (path == '/admin/wallet-coupons' && request.method == 'GET') {
      await _json(request.response, HttpStatus.ok, {
        'data': await repository.adminWalletCoupons(
          status: request.uri.queryParameters['status'],
          search: request.uri.queryParameters['search'],
        ),
      });
      return true;
    }
    if (path == '/admin/wallet-coupons' && request.method == 'POST') {
      final body = await _readJsonObject(request);
      _requirePositiveNumber(
        body,
        'amount',
        'قيمة كوبون الشحن مطلوبة ويجب أن تكون أكبر من صفر.',
      );
      final quantity = _nonNegativeInt(
        body['quantity'],
        'عدد الكوبونات غير صالح.',
      );
      await _json(request.response, HttpStatus.created, {
        'data': await repository.adminCreateWalletCoupons(
          adminId: adminId,
          amount: body['amount'] as num,
          quantity: quantity,
          expiresAt: _dateOrNull(body['expires_at']),
        ),
      });
      return true;
    }
    final walletCouponId = _pathId(path, '/admin/wallet-coupons/');
    if (walletCouponId != null && request.method == 'DELETE') {
      await repository.adminDeleteWalletCoupon(
        adminId: adminId,
        couponId: walletCouponId,
      );
      await _json(request.response, HttpStatus.ok, {'deleted': true});
      return true;
    }
    if (path == '/admin/wallets/search' && request.method == 'GET') {
      final phone = _normalizeLibyanPhone(
        request.uri.queryParameters['phone'] ?? '',
      );
      if (phone == null) {
        throw const PlatformRuleException(
          'أدخل رقم هاتف ليبي صحيح.',
          statusCode: 422,
        );
      }
      await _json(request.response, HttpStatus.ok, {
        'profile': await repository.adminFindWalletByPhone(phone),
      });
      return true;
    }
    if (path == '/admin/wallets/top-up' && request.method == 'POST') {
      final body = await _readJsonObject(request);
      final phone = _normalizeLibyanPhone(body['phone']?.toString() ?? '');
      if (phone == null) {
        throw const PlatformRuleException(
          'أدخل رقم هاتف ليبي صحيح.',
          statusCode: 422,
        );
      }
      _requirePositiveNumber(
        body,
        'amount',
        'قيمة الشحن مطلوبة ويجب أن تكون أكبر من صفر.',
      );
      await _json(request.response, HttpStatus.ok, {
        'result': await repository.adminTopUpWallet(
          adminId: adminId,
          phone: phone,
          amount: body['amount'] as num,
          note: body['note']?.toString(),
        ),
      });
      return true;
    }
    final statusUserId = _pathBetween(path, '/admin/users/', '/status');
    if (statusUserId != null && request.method == 'POST') {
      final body = await _readJsonObject(request);
      await repository.adminSetUserStatus(
        adminId: adminId,
        profileId: statusUserId,
        status: _requireText(body, 'status', 'الحالة مطلوبة.'),
        reason: body['reason']?.toString(),
      );
      await _dispatchDueCampaignsAndPush();
      await _json(request.response, HttpStatus.ok, {'updated': true});
      return true;
    }
    final craftsmanId = _pathBetween(path, '/admin/craftsmen/', '/review');
    if (craftsmanId != null && request.method == 'POST') {
      final body = await _readJsonObject(request);
      if (body['approved'] is! bool) {
        throw const PlatformRuleException(
          'قرار التوثيق غير صالح.',
          statusCode: 422,
        );
      }
      await repository.adminReviewCraftsman(
        adminId: adminId,
        profileId: craftsmanId,
        approved: body['approved'] == true,
        reason: body['reason']?.toString(),
      );
      await _json(request.response, HttpStatus.ok, {'updated': true});
      return true;
    }
    if (path == '/admin/notifications' && request.method == 'GET') {
      await _json(request.response, HttpStatus.ok, {
        'data': await repository.adminCampaigns(),
      });
      return true;
    }
    if (path == '/admin/support-tickets' && request.method == 'GET') {
      await _json(request.response, HttpStatus.ok, {
        'data': await repository.adminSupportTickets(),
      });
      return true;
    }
    final adminSupportMessagesId = _pathBetween(
      path,
      '/admin/support-tickets/',
      '/messages',
    );
    if (adminSupportMessagesId != null && request.method == 'GET') {
      await _json(request.response, HttpStatus.ok, {
        'data': await repository.supportConversationMessages(
          profileId: adminId,
          role: 'admin',
          conversationId: adminSupportMessagesId,
        ),
      });
      return true;
    }
    if (adminSupportMessagesId != null && request.method == 'POST') {
      final body = await _readJsonObject(request);
      _validateSupportMessage(body);
      await _json(request.response, HttpStatus.created, {
        'message': await repository.sendSupportConversationMessage(
          profileId: adminId,
          role: 'admin',
          conversationId: adminSupportMessagesId,
          input: body,
        ),
      });
      return true;
    }
    final supportTicketId = _pathBetween(
      path,
      '/admin/support-tickets/',
      '/status',
    );
    if (supportTicketId != null && request.method == 'PUT') {
      final body = await _readJsonObject(request);
      await repository.adminUpdateSupportTicket(
        adminId: adminId,
        ticketId: supportTicketId,
        status: _requireText(body, 'status', 'حالة التذكرة مطلوبة.'),
        priority: _requireText(body, 'priority', 'أولوية التذكرة مطلوبة.'),
      );
      await _json(request.response, HttpStatus.ok, {'ok': true});
      return true;
    }
    if (path == '/admin/notifications' && request.method == 'POST') {
      final body = await _readJsonObject(request);
      _validateNotificationCampaign(body);
      final campaign = await repository.adminCreateCampaign(
        adminId: adminId,
        input: body,
      );
      await _dispatchDueCampaignsAndPush();
      await _json(request.response, HttpStatus.created, {'campaign': campaign});
      return true;
    }
    final resendCampaignId = _pathBetween(
      path,
      '/admin/notifications/',
      '/resend',
    );
    if (resendCampaignId != null && request.method == 'POST') {
      await repository.adminResendCampaign(
        adminId: adminId,
        campaignId: resendCampaignId,
      );
      final delivered = await _dispatchDueCampaignsAndPush();
      await _json(request.response, HttpStatus.ok, {
        'resent': true,
        'delivered': delivered,
      });
      return true;
    }
    final notificationCampaignId = _pathId(path, '/admin/notifications/');
    if (notificationCampaignId != null && request.method == 'PUT') {
      final body = await _readJsonObject(request);
      _validateNotificationCampaign(body);
      await _json(request.response, HttpStatus.ok, {
        'campaign': await repository.adminUpdateCampaign(
          adminId: adminId,
          campaignId: notificationCampaignId,
          input: body,
        ),
      });
      return true;
    }
    if (notificationCampaignId != null && request.method == 'DELETE') {
      await repository.adminDeleteCampaign(
        adminId: adminId,
        campaignId: notificationCampaignId,
      );
      await _json(request.response, HttpStatus.ok, {'deleted': true});
      return true;
    }
    if (path == '/admin/categories' && request.method == 'POST') {
      final body = await _readJsonObject(request);
      _validateCategory(body);
      await _json(request.response, HttpStatus.created, {
        'category': await repository.adminSaveCategory(
          adminId: adminId,
          input: body,
        ),
      });
      return true;
    }
    if (path == '/admin/categories' && request.method == 'GET') {
      await _json(request.response, HttpStatus.ok, {
        'data': await repository.adminCategories(),
      });
      return true;
    }
    if (path == '/admin/home-banners' && request.method == 'GET') {
      await _json(request.response, HttpStatus.ok, {
        'data': await repository.adminHomeBanners(),
      });
      return true;
    }
    if (path == '/admin/home-banners' && request.method == 'POST') {
      final body = await _readJsonObject(request);
      _validateHomeBanner(body);
      await _json(request.response, HttpStatus.created, {
        'banner': await repository.adminSaveHomeBanner(
          adminId: adminId,
          input: body,
        ),
      });
      return true;
    }
    final homeBannerId = _pathId(path, '/admin/home-banners/');
    if (homeBannerId != null && request.method == 'PUT') {
      final body = await _readJsonObject(request);
      _validateHomeBanner(body);
      await _json(request.response, HttpStatus.ok, {
        'banner': await repository.adminSaveHomeBanner(
          adminId: adminId,
          input: body,
          bannerId: homeBannerId,
        ),
      });
      return true;
    }
    if (homeBannerId != null && request.method == 'DELETE') {
      await repository.adminDeleteHomeBanner(
        adminId: adminId,
        bannerId: homeBannerId,
      );
      await _json(request.response, HttpStatus.ok, {'deleted': true});
      return true;
    }
    final categoryId = _pathId(path, '/admin/categories/');
    if (categoryId != null && request.method == 'PUT') {
      final body = await _readJsonObject(request);
      _validateCategory(body);
      await _json(request.response, HttpStatus.ok, {
        'category': await repository.adminSaveCategory(
          adminId: adminId,
          input: body,
          categoryId: categoryId,
        ),
      });
      return true;
    }
    if (categoryId != null && request.method == 'DELETE') {
      await repository.adminDeleteCategory(
        adminId: adminId,
        categoryId: categoryId,
      );
      await _json(request.response, HttpStatus.ok, {'deleted': true});
      return true;
    }
    if (path == '/admin/settings/request-automation' &&
        request.method == 'GET') {
      await _json(request.response, HttpStatus.ok, {
        'settings': await repository.requestAutomationSettings(),
      });
      return true;
    }
    if (path == '/admin/settings/request-automation' &&
        request.method == 'PUT') {
      final body = await _readJsonObject(request);
      if (body['enabled'] is! bool) {
        throw const PlatformRuleException(
          'Automation enabled value is invalid.',
          statusCode: 422,
        );
      }
      await _json(request.response, HttpStatus.ok, {
        'settings': await repository.adminSetRequestAutomation(
          adminId: adminId,
          enabled: body['enabled'] == true,
          batchSize: _queryInt(
            body['batch_size']?.toString(),
            fallback: 5,
            minimum: 1,
            maximum: 5,
          ),
          intervalMinutes: _queryInt(
            body['batch_interval_minutes']?.toString(),
            fallback: 60,
            minimum: 15,
            maximum: 24 * 60,
          ),
        ),
      });
      return true;
    }
    if (path == '/admin/settings/media-retention' && request.method == 'GET') {
      await _json(request.response, HttpStatus.ok, {
        'settings': await repository.mediaRetentionSettings(),
      });
      return true;
    }
    if (path == '/admin/settings/media-retention' && request.method == 'PUT') {
      final body = await _readJsonObject(request);
      if (body['enabled'] is! bool) {
        throw const PlatformRuleException(
          'حالة سياسة الاحتفاظ غير صالحة.',
          statusCode: 422,
        );
      }
      final requestDays = _boundedNonNegativeInt(
        body['completed_request_media_days'],
        'مدة الاحتفاظ بصور الطلب غير صالحة.',
        maximum: 3650,
      );
      final supportDays = _boundedNonNegativeInt(
        body['closed_support_message_days'],
        'مدة الاحتفاظ برسائل الدعم غير صالحة.',
        maximum: 3650,
      );
      await _json(request.response, HttpStatus.ok, {
        'settings': await repository.adminSetMediaRetention(
          adminId: adminId,
          enabled: body['enabled'] == true,
          completedRequestMediaDays: requestDays,
          closedSupportMessageDays: supportDays,
        ),
      });
      return true;
    }
    if (path == '/admin/maintenance/media-cleanup' &&
        request.method == 'POST') {
      await _json(request.response, HttpStatus.ok, {
        'result': await repository.queueExpiredMediaCleanup(),
      });
      return true;
    }
    if (path == '/admin/settings/test-login' && request.method == 'PUT') {
      if (_isProduction) {
        throw const PlatformRuleException(
          'لا يمكن تفعيل الدخول التجريبي في بيئة الإنتاج.',
          statusCode: 403,
        );
      }
      final body = await _readJsonObject(request);
      if (body['enabled'] is! bool) {
        throw const PlatformRuleException(
          'قيمة الإعداد غير صالحة.',
          statusCode: 422,
        );
      }
      await repository.adminSetTestLogin(
        adminId: adminId,
        enabled: body['enabled'] == true,
      );
      await _json(request.response, HttpStatus.ok, {
        'enabled': body['enabled'],
      });
      return true;
    }
    return false;
  }

  Future<int> _dispatchDueCampaignsAndPush() async {
    final delivered = await repository.dispatchDueCampaigns();
    await pushDispatcher?.dispatchPending();
    return delivered;
  }
}

Future<Map<String, dynamic>> _readJsonObject(
  HttpRequest request, {
  int maxBytes = 1024 * 1024,
}) async {
  final buffer = BytesBuilder(copy: false);
  var length = 0;
  await for (final chunk in request) {
    length += chunk.length;
    if (length > maxBytes) {
      throw const PlatformRuleException(
        'حجم الطلب أكبر من الحد المسموح.',
        statusCode: HttpStatus.requestEntityTooLarge,
      );
    }
    buffer.add(chunk);
  }
  if (length == 0) return <String, dynamic>{};
  final decoded = jsonDecode(utf8.decode(buffer.takeBytes()));
  if (decoded is Map<String, dynamic>) return decoded;
  if (decoded is Map) return Map<String, dynamic>.from(decoded);
  throw const FormatException('Expected a JSON object.');
}

Future<void> _json(
  HttpResponse response,
  int statusCode,
  Map<String, dynamic> payload,
) async {
  _addCorsHeaders(response);
  response.statusCode = statusCode;
  response.headers.contentType = ContentType.json;
  response.write(jsonEncode(_jsonSafe(payload)));
  await response.close();
}

Future<void> _safeJson(
  HttpResponse response,
  int statusCode,
  Map<String, dynamic> payload,
) async {
  try {
    await _json(response, statusCode, payload);
  } catch (_) {
    try {
      await response.close();
    } catch (_) {}
  }
}

Object? _jsonSafe(Object? value) {
  if (value == null || value is String || value is num || value is bool) {
    return value;
  }
  if (value is DateTime) return value.toUtc().toIso8601String();
  if (value is List) return value.map(_jsonSafe).toList();
  if (value is Map) {
    return value.map((key, item) => MapEntry(key.toString(), _jsonSafe(item)));
  }
  return value.toString();
}

void _addCorsHeaders(HttpResponse response) {
  response.headers
    ..set(HttpHeaders.accessControlAllowOriginHeader, '*')
    ..set(
      HttpHeaders.accessControlAllowMethodsHeader,
      'GET, POST, PUT, DELETE, OPTIONS',
    )
    ..set(
      HttpHeaders.accessControlAllowHeadersHeader,
      'Content-Type, Authorization, X-Device-Name',
    );
}

String? _normalizeLibyanPhone(String value) {
  final digits = value.replaceAll(RegExp(r'\D'), '');
  final local = digits.startsWith('218')
      ? digits.substring(3)
      : digits.startsWith('0')
      ? digits.substring(1)
      : digits;
  return RegExp(r'^9\d{8}$').hasMatch(local) ? '218$local' : null;
}

String _validatedRole(String? raw) {
  final role = raw?.trim().toLowerCase() ?? '';
  if (!const ['customer', 'craftsman', 'admin'].contains(role)) {
    throw const PlatformRuleException('نوع الحساب غير صالح.', statusCode: 422);
  }
  return role;
}

void _enforceAppRole(HttpRequest request, String role) {
  final appKind = request.headers
      .value('X-Maestro-App-Kind')
      ?.trim()
      .toLowerCase();
  if (appKind == 'craftsman' && role != 'craftsman') {
    throw const PlatformRuleException(
      'تطبيق الفني مخصص لحسابات الفنيين فقط.',
      statusCode: 403,
    );
  }
}

void _requireRole(String actual, String expected) {
  if (actual != expected) {
    throw const PlatformRuleException(
      'لا تملك صلاحية تنفيذ هذه العملية.',
      statusCode: 403,
    );
  }
}

String _requireText(
  Map<String, dynamic> input,
  String key,
  String message, {
  int minLength = 1,
}) {
  final value = input[key]?.toString().trim() ?? '';
  if (value.length < minLength) {
    throw PlatformRuleException(message, statusCode: 422);
  }
  return value;
}

String _requirePassword(Map<String, dynamic> input) {
  final value = input['password']?.toString() ?? '';
  if (value.trim().length < 4 || value.trim().length > 72) {
    throw const PlatformRuleException(
      'Password must be 4 to 72 characters or digits.',
      statusCode: 422,
    );
  }
  return value;
}

void _requirePositiveNumber(
  Map<String, dynamic> input,
  String key,
  String message,
) {
  final value = input[key];
  final number = value is num ? value : num.tryParse(value?.toString() ?? '');
  if (number == null || number <= 0) {
    throw PlatformRuleException(message, statusCode: 422);
  }
  input[key] = number;
}

int _nonNegativeInt(Object? value, String message) {
  final parsed = value is int ? value : int.tryParse(value?.toString() ?? '');
  if (parsed == null || parsed < 0) {
    throw PlatformRuleException(message, statusCode: 422);
  }
  return parsed;
}

int _boundedNonNegativeInt(
  Object? value,
  String message, {
  required int maximum,
}) {
  final parsed = _nonNegativeInt(value, message);
  if (parsed > maximum) {
    throw PlatformRuleException(message, statusCode: 422);
  }
  return parsed;
}

int _queryInt(
  String? value, {
  required int fallback,
  required int minimum,
  required int maximum,
}) {
  final parsed = int.tryParse(value ?? '') ?? fallback;
  return parsed.clamp(minimum, maximum);
}

num _nonNegativeNumber(Object? value, String message) {
  final parsed = value is num ? value : num.tryParse(value?.toString() ?? '');
  if (parsed == null || parsed < 0) {
    throw PlatformRuleException(message, statusCode: 422);
  }
  return parsed;
}

num _coordinate(
  Object? value, {
  required num minimum,
  required num maximum,
  required String message,
}) {
  final parsed = value is num ? value : num.tryParse(value?.toString() ?? '');
  if (parsed == null ||
      !parsed.isFinite ||
      parsed < minimum ||
      parsed > maximum) {
    throw PlatformRuleException(message, statusCode: 422);
  }
  return parsed;
}

DateTime? _dateOrNull(Object? value) {
  if (value == null || value.toString().trim().isEmpty) return null;
  final parsed = DateTime.tryParse(value.toString());
  if (parsed == null) {
    throw const PlatformRuleException(
      'صيغة التاريخ غير صالحة.',
      statusCode: 422,
    );
  }
  return parsed;
}

List<String> _stringList(Object? value) {
  if (value is! List) return [];
  return value
      .map((item) => item.toString().trim())
      .where((item) => item.isNotEmpty)
      .toSet()
      .toList();
}

void _validateAddress(Map<String, dynamic> body) {
  _requireText(body, 'label', 'اسم العنوان مطلوب.');
  _requireText(body, 'city', 'المدينة مطلوبة.');
  _requireText(body, 'area', 'المنطقة مطلوبة.');
  _requireText(body, 'street', 'الشارع أو وصف العنوان مطلوب.', minLength: 3);
  final latitude = body['latitude'];
  final longitude = body['longitude'];
  if ((latitude == null) != (longitude == null)) {
    throw const PlatformRuleException(
      'إحداثيات الموقع غير مكتملة.',
      statusCode: 422,
    );
  }
}

void _validateCategory(Map<String, dynamic> body) {
  _requireText(body, 'name_ar', 'اسم الحرفة بالعربية مطلوب.');
  if (body['id'] != null) {
    _requireText(body, 'id', 'معرف الحرفة مطلوب.');
  }
  final availability = body['availability_status']?.toString().trim() ?? 'open';
  if (!const {'open', 'closed', 'coming_soon'}.contains(availability)) {
    throw const PlatformRuleException(
      'حالة توفر الخدمة غير صالحة.',
      statusCode: 422,
    );
  }
  body['availability_status'] = availability;
  final iconUrl = body['icon_url']?.toString().trim();
  if (iconUrl != null && iconUrl.isNotEmpty) {
    final uri = Uri.tryParse(iconUrl);
    if (uri == null || uri.scheme != 'https' || uri.host.isEmpty) {
      throw const PlatformRuleException(
        'رابط أيقونة الخدمة يجب أن يكون رابط HTTPS صالحًا.',
        statusCode: 422,
      );
    }
    body['icon_url'] = iconUrl;
  } else {
    body['icon_url'] = null;
  }
}

void _validateNotificationCampaign(Map<String, dynamic> body) {
  _requireText(body, 'title', 'عنوان الإشعار مطلوب.');
  _requireText(body, 'body', 'نص الإشعار مطلوب.');
  final audience = _requireText(body, 'audience', 'جمهور الإشعار مطلوب.');
  if (!const {'all', 'customers', 'craftsmen', 'profile'}.contains(audience)) {
    throw const PlatformRuleException(
      'جمهور الإشعار غير صالح.',
      statusCode: 422,
    );
  }
  if (audience == 'profile') {
    _requireText(body, 'target_profile_id', 'اختر المستخدم المستلم للإشعار.');
  } else {
    body['target_profile_id'] = null;
  }
  final scheduledFor = body['scheduled_for'];
  if (scheduledFor != null &&
      scheduledFor.toString().trim().isNotEmpty &&
      DateTime.tryParse(scheduledFor.toString()) == null) {
    throw const PlatformRuleException(
      'موعد إرسال الإشعار غير صالح.',
      statusCode: 422,
    );
  }
}

void _validateOfferAmounts(Map<String, dynamic> body) {
  _requirePositiveNumber(
    body,
    'total_amount',
    'Offer total must be greater than zero.',
  );
  final labor = _nonNegativeNumber(
    body['labor_amount'],
    'Labor amount is invalid.',
  );
  final materials = _nonNegativeNumber(
    body['materials_amount'],
    'Materials amount is invalid.',
  );
  final inspection = _nonNegativeNumber(
    body['inspection_fee'],
    'Inspection fee is invalid.',
  );
  final total = body['total_amount'] as num;
  if ((labor + materials + inspection - total).abs() > 0.001) {
    throw const PlatformRuleException(
      'Offer total must equal labor + materials + inspection.',
      statusCode: 422,
    );
  }
  body
    ..['labor_amount'] = labor
    ..['materials_amount'] = materials
    ..['inspection_fee'] = inspection;
}

void _validateHomeBanner(Map<String, dynamic> body) {
  final imageUrl = _requireText(body, 'image_url', 'صورة البانر مطلوبة.');
  final uri = Uri.tryParse(imageUrl);
  if (uri == null || uri.scheme != 'https' || uri.host.isEmpty) {
    throw const PlatformRuleException(
      'رابط صورة البانر يجب أن يكون HTTPS صالحًا.',
      statusCode: 422,
    );
  }
  body['image_url'] = imageUrl;
  body['display_order'] = _nonNegativeInt(
    body['display_order'],
    'ترتيب البانر غير صالح.',
  );
  body['active'] = body['active'] != false;
  final action = body['click_action']?.toString().trim() ?? 'none';
  final normalizedAction = action.isEmpty ? 'none' : action;
  if (!_isValidHomeBannerAction(normalizedAction)) {
    throw const PlatformRuleException(
      'إجراء البانر غير صالح. استخدم none أو new_request أو wallet أو notifications أو support أو category:service_id فقط.',
      statusCode: 422,
    );
  }
  body['click_action'] = normalizedAction;
}

bool _isValidHomeBannerAction(String action) {
  if (const {
    'none',
    'home',
    'new_request',
    'request:new',
    'wallet',
    'notifications',
    'support',
    '/customer',
    '/request/new',
    '/account/wallet',
    '/notifications',
    '/account/support',
  }.contains(action)) {
    return true;
  }
  if (!action.startsWith('category:')) return false;
  final categoryId = action.substring('category:'.length).trim();
  return RegExp(r'^[A-Za-z0-9_-]{2,80}$').hasMatch(categoryId);
}

void _validateSupportMessage(Map<String, dynamic> body) {
  final message = body['body']?.toString().trim() ?? '';
  final attachmentUrl = body['attachment_url']?.toString().trim() ?? '';
  if (message.isEmpty && attachmentUrl.isEmpty) {
    throw const PlatformRuleException(
      'اكتب رسالة أو أرفق ملفًا.',
      statusCode: 422,
    );
  }
  _validateManagedAttachment(body);
  body['body'] = message;
}

void _validateManagedAttachment(Map<String, dynamic> body) {
  final attachmentUrl = body['attachment_url']?.toString().trim() ?? '';
  final publicId = body['attachment_public_id']?.toString().trim() ?? '';
  if (attachmentUrl.isEmpty) {
    if (publicId.isNotEmpty) {
      throw const PlatformRuleException('رابط المرفق مفقود.', statusCode: 422);
    }
    body['attachment_url'] = null;
    body['attachment_public_id'] = null;
    body['attachment_resource_type'] = null;
    body['attachment_type'] = null;
    return;
  }
  if (publicId.isEmpty) {
    throw const PlatformRuleException(
      'معرف ملكية المرفق مفقود. أعد رفع الملف.',
      statusCode: 422,
    );
  }
  if (attachmentUrl.isNotEmpty) {
    final uri = Uri.tryParse(attachmentUrl);
    if (uri == null || uri.scheme != 'https' || uri.host.isEmpty) {
      throw const PlatformRuleException(
        'رابط مرفق المحادثة غير صالح.',
        statusCode: 422,
      );
    }
    final type = body['attachment_type']?.toString();
    if (!const {'image', 'audio', 'file'}.contains(type)) {
      throw const PlatformRuleException(
        'نوع مرفق المحادثة غير صالح.',
        statusCode: 422,
      );
    }
    final resourceType = body['attachment_resource_type']?.toString();
    final normalizedResourceType =
        resourceType ??
        (type == 'audio'
            ? 'video'
            : type == 'image'
            ? 'image'
            : 'raw');
    if (!const {'image', 'video', 'raw'}.contains(normalizedResourceType)) {
      throw const PlatformRuleException(
        'نوع مورد المرفق غير صالح.',
        statusCode: 422,
      );
    }
    body['attachment_url'] = attachmentUrl;
    body['attachment_public_id'] = publicId;
    body['attachment_resource_type'] = normalizedResourceType;
  }
}

bool _matchesImageSignature(List<int> bytes, String mimeType) {
  bool startsWith(List<int> signature) {
    if (bytes.length < signature.length) return false;
    for (var index = 0; index < signature.length; index++) {
      if (bytes[index] != signature[index]) return false;
    }
    return true;
  }

  switch (mimeType.toLowerCase()) {
    case 'image/jpeg':
      return startsWith(const [0xff, 0xd8, 0xff]);
    case 'image/png':
      return startsWith(const [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    case 'image/webp':
      return bytes.length >= 12 &&
          startsWith(const [0x52, 0x49, 0x46, 0x46]) &&
          bytes[8] == 0x57 &&
          bytes[9] == 0x45 &&
          bytes[10] == 0x42 &&
          bytes[11] == 0x50;
  }
  return false;
}

String? _pathId(String path, String prefix) {
  if (!path.startsWith(prefix)) return null;
  final value = path.substring(prefix.length);
  return value.isNotEmpty && !value.contains('/') ? value : null;
}

String? _pathBetween(String path, String prefix, String suffix) {
  if (!path.startsWith(prefix) || !path.endsWith(suffix)) return null;
  final value = path.substring(prefix.length, path.length - suffix.length);
  return value.isNotEmpty && !value.contains('/') ? value : null;
}

int _statusForResalaError(ResalaException error) {
  if (error is ResalaAuthException) return HttpStatus.unauthorized;
  if (error is ResalaPermissionException) return HttpStatus.forbidden;
  if (error is ResalaValidationException) return HttpStatus.unprocessableEntity;
  if (error is ResalaInsufficientCreditException) return HttpStatus.badRequest;
  return error.statusCode ?? HttpStatus.badGateway;
}
