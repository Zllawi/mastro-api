import 'dart:io';

import '../backend_environment.dart';
import 'maestro_database.dart';
import 'platform_repository.dart';

Future<void> main() async {
  final environment = await loadBackendEnvironment();
  final database = SupabasePostgresDatabase.fromConfig(
    SupabaseDatabaseConfig.fromEnvironment(environment: environment),
  );

  try {
    await database.runTx((session) async {
      final fixtures = await session.select('''
        select
          p.id as customer_id,
          ca.id as address_id,
          category.id as category_id,
          media.public_url,
          media.provider_public_id,
          media.resource_type
        from public.profiles p
        join lateral (
          select id
          from public.customer_addresses
          where customer_id = p.id
          order by is_default desc, created_at desc
          limit 1
        ) ca on true
        join lateral (
          select id
          from public.service_categories
          where is_active = true
            and availability_status = 'open'
          order by sort_order, created_at
          limit 1
        ) category on true
        left join lateral (
          select public_url, provider_public_id, resource_type, created_at
          from public.managed_media_assets
          where owner_id = p.id
            and purpose = 'service-requests'
            and status = 'active'
            and consumed_at is null
          order by created_at desc
          limit 1
        ) media on true
        where p.role = 'customer'
          and p.status = 'active'
        order by media.created_at desc nulls last, p.created_at desc
        limit 1
      ''');

      if (fixtures.isEmpty) {
        throw StateError(
          'No active customer with an address and an open category is available.',
        );
      }

      final fixture = fixtures.single;
      final attachments = <Map<String, dynamic>>[];
      if (fixture['public_url'] != null) {
        attachments.add({
          'url': fixture['public_url'],
          'public_id': fixture['provider_public_id'],
          'resource_type': fixture['resource_type'],
          'content_type': 'image/jpeg',
          'size_bytes': null,
        });
      }

      final repository = PlatformRepository(_ExistingSessionDatabase(session));
      await repository.createRequest(
        customerId: fixture['customer_id'].toString(),
        input: {
          'category_id': fixture['category_id'],
          'address_id': fixture['address_id'],
          'title': 'اختبار نشر الطلب',
          'description': 'اختبار آمن لمسار نشر الطلب ويتم التراجع عنه بالكامل.',
          'urgency': false,
          'scheduled_for': DateTime.now().toUtc().toIso8601String(),
          'payment_method': 'cash',
          'attachments': attachments,
        },
      );

      throw const _VerifiedRollback();
    });
  } on _VerifiedRollback {
    stdout.writeln(
      'Request creation verified; the test transaction was rolled back.',
    );
  } finally {
    await database.close();
  }
}

class _ExistingSessionDatabase implements MaestroDbExecutor {
  const _ExistingSessionDatabase(this.session);

  final MaestroDbSession session;

  @override
  Future<R> run<R>(Future<R> Function(MaestroDbSession session) fn) =>
      fn(session);

  @override
  Future<R> runTx<R>(Future<R> Function(MaestroDbSession session) fn) =>
      fn(session);

  @override
  Future<void> close() async {}
}

class _VerifiedRollback implements Exception {
  const _VerifiedRollback();
}
