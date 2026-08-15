class TestLoginPolicy {
  TestLoginPolicy._({
    required this.isProduction,
    required this.environmentAllowsTestLogin,
    required Map<String, Set<String>> phonesByRole,
  }) : _phonesByRole = Map.unmodifiable(
         phonesByRole.map(
           (role, phones) => MapEntry(role, Set.unmodifiable(phones)),
         ),
       );

  factory TestLoginPolicy.fromEnvironment(Map<String, String> environment) {
    final appEnvironment = (environment['APP_ENV'] ?? 'development')
        .trim()
        .toLowerCase();
    final hostedOnRender =
        (environment['RENDER'] ?? '').trim().toLowerCase() == 'true';
    final phonesByRole = <String, Set<String>>{};

    void addPhones(String role, Iterable<String> environmentKeys) {
      final phones = phonesByRole.putIfAbsent(role, () => <String>{});
      for (final key in environmentKeys) {
        final configured = environment[key];
        if (configured == null || configured.trim().isEmpty) continue;
        for (final candidate in configured.split(RegExp(r'[,;\r\n]+'))) {
          final phone = normalizeConfiguredLibyanPhone(candidate);
          if (phone != null) phones.add(phone);
        }
      }
    }

    addPhones('customer', const [
      'MAESTRO_TEST_CUSTOMER_PHONES',
      'MAESTRO_TEST_CUSTOMER_PHONE',
    ]);
    addPhones('craftsman', const [
      'MAESTRO_TEST_CRAFTSMAN_PHONES',
      'MAESTRO_TEST_CRAFTSMAN_PHONE',
    ]);
    addPhones('admin', const [
      'MAESTRO_TEST_ADMIN_PHONES',
      'MAESTRO_TEST_ADMIN_PHONE',
    ]);

    final isProduction =
        hostedOnRender ||
        appEnvironment == 'production' ||
        appEnvironment == 'prod';
    final configuredFlag = environment['TEST_LOGIN_ENABLED']
        ?.trim()
        .toLowerCase();

    return TestLoginPolicy._(
      isProduction: isProduction,
      // Preserve the existing local-development behavior when the flag is
      // omitted. Production/Render is always fail-closed unless the flag is
      // explicitly set to the literal value "true".
      environmentAllowsTestLogin:
          configuredFlag == 'true' || (!isProduction && configuredFlag == null),
      phonesByRole: phonesByRole,
    );
  }

  final bool isProduction;
  final bool environmentAllowsTestLogin;
  final Map<String, Set<String>> _phonesByRole;

  bool get hasAnyAllowlistedPhone =>
      _phonesByRole.values.any((phones) => phones.isNotEmpty);

  bool hasAllowlistedPhoneForRole(String role) =>
      _phonesByRole[role]?.isNotEmpty == true;

  bool allows({required String phone, required String role}) {
    final normalizedPhone = normalizeConfiguredLibyanPhone(phone);
    return environmentAllowsTestLogin &&
        normalizedPhone != null &&
        _phonesByRole[role]?.contains(normalizedPhone) == true;
  }
}

String? normalizeConfiguredLibyanPhone(String value) {
  final digits = value.replaceAll(RegExp(r'\D'), '');
  final national = digits.startsWith('218')
      ? digits.substring(3)
      : digits.startsWith('0')
      ? digits.substring(1)
      : digits;
  return RegExp(r'^9\d{8}$').hasMatch(national) ? '218$national' : null;
}
