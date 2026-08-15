class TestLoginPolicy {
  TestLoginPolicy._({
    required this.environmentAllowsTestLogin,
    required Map<String, String> phonesByRole,
  }) : _phonesByRole = Map.unmodifiable(phonesByRole);

  factory TestLoginPolicy.fromEnvironment(Map<String, String> environment) {
    final appEnvironment = (environment['APP_ENV'] ?? 'development')
        .trim()
        .toLowerCase();
    final hostedOnRender =
        (environment['RENDER'] ?? '').trim().toLowerCase() == 'true';
    final phonesByRole = <String, String>{};

    void addPhone(String role, String environmentKey) {
      final phone = normalizeConfiguredLibyanPhone(
        environment[environmentKey] ?? '',
      );
      if (phone != null) phonesByRole[role] = phone;
    }

    addPhone('customer', 'MAESTRO_TEST_CUSTOMER_PHONE');
    addPhone('craftsman', 'MAESTRO_TEST_CRAFTSMAN_PHONE');
    addPhone('admin', 'MAESTRO_ADMIN_PHONE');

    return TestLoginPolicy._(
      environmentAllowsTestLogin:
          !hostedOnRender &&
          appEnvironment != 'production' &&
          appEnvironment != 'prod',
      phonesByRole: phonesByRole,
    );
  }

  final bool environmentAllowsTestLogin;
  final Map<String, String> _phonesByRole;

  bool allows({required String phone, required String role}) {
    return environmentAllowsTestLogin && _phonesByRole[role] == phone;
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
