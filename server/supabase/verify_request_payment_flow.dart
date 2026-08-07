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
    try {
      await database.runTx<void>((session) async {
        final ids = await session.select('''
          select
            gen_random_uuid() as customer_id,
            gen_random_uuid() as craftsman_id,
            gen_random_uuid() as request_id,
            gen_random_uuid() as offer_id
          ''');
        final values = ids.single;
        const categoryId = 'codex-payment-flow-verification';
        await session.execute(
          '''
          insert into public.profiles (id, role, status, phone, full_name)
          values
            (@customerId, 'customer', 'active', '218900000091', 'Payment test customer'),
            (@craftsmanId, 'craftsman', 'active', '218900000092', 'Payment test craftsman')
          ''',
          parameters: {
            'customerId': values['customer_id'],
            'craftsmanId': values['craftsman_id'],
          },
        );
        await session.execute(
          '''
          insert into public.craftsman_profiles (
            profile_id,
            profession,
            is_verified,
            is_available
          )
          values (@craftsmanId, 'Payment verification', true, true)
          ''',
          parameters: {'craftsmanId': values['craftsman_id']},
        );
        await session.execute(
          '''
          insert into public.service_categories (id, name_ar, is_active)
          values (@categoryId, 'اختبار الدفع', true)
          on conflict (id) do update set is_active = true
          ''',
          parameters: {'categoryId': categoryId},
        );
        await session.execute(
          '''
          insert into public.wallets (profile_id, available_balance)
          values
            (@customerId, 30),
            (@craftsmanId, 0)
          ''',
          parameters: {
            'customerId': values['customer_id'],
            'craftsmanId': values['craftsman_id'],
          },
        );
        await session.execute(
          '''
          insert into public.service_requests (
            id,
            customer_id,
            category_id,
            status,
            title,
            description,
            payment_method
          )
          values (
            @requestId,
            @customerId,
            @categoryId,
            'offers_received',
            'Payment verification',
            'Temporary request rolled back after verification',
            'wallet'
          )
          ''',
          parameters: {
            'requestId': values['request_id'],
            'customerId': values['customer_id'],
            'categoryId': categoryId,
          },
        );
        await session.execute(
          '''
          insert into public.offers (
            id,
            request_id,
            craftsman_id,
            total_amount,
            labor_amount,
            materials_amount,
            inspection_fee
          )
          values (
            @offerId,
            @requestId,
            @craftsmanId,
            100,
            70,
            10,
            20
          )
          ''',
          parameters: {
            'offerId': values['offer_id'],
            'requestId': values['request_id'],
            'craftsmanId': values['craftsman_id'],
          },
        );

        final repository = PlatformRepository(_SessionDatabase(session));
        await repository.acceptOffer(
          customerId: values['customer_id'].toString(),
          requestId: values['request_id'].toString(),
          offerId: values['offer_id'].toString(),
        );
        await repository.advanceRequestStatus(
          craftsmanId: values['craftsman_id'].toString(),
          requestId: values['request_id'].toString(),
          nextStatus: 'on_the_way',
        );
        await repository.advanceRequestStatus(
          craftsmanId: values['craftsman_id'].toString(),
          requestId: values['request_id'].toString(),
          nextStatus: 'started',
        );

        final started = await session.select(
          '''
          select
            rp.wallet_reserved_amount,
            rp.cash_due_amount,
            w.available_balance
          from public.request_payments rp
          join public.wallets w on w.profile_id = rp.customer_id
          where rp.request_id = @requestId
          ''',
          parameters: {'requestId': values['request_id']},
        );
        final payment = started.single;
        if (payment['wallet_reserved_amount'].toString() != '30.00' ||
            payment['cash_due_amount'].toString() != '70.00' ||
            payment['available_balance'].toString() != '0.00') {
          throw StateError('Unexpected payment reservation: $payment');
        }

        var completionWasBlocked = false;
        try {
          await repository.advanceRequestStatus(
            craftsmanId: values['craftsman_id'].toString(),
            requestId: values['request_id'].toString(),
            nextStatus: 'completed',
          );
        } on PlatformRuleException catch (error) {
          completionWasBlocked = error.statusCode == 422;
        }
        if (!completionWasBlocked) {
          throw StateError(
            'Completion was not blocked before cash confirmation.',
          );
        }
        await repository.advanceRequestStatus(
          craftsmanId: values['craftsman_id'].toString(),
          requestId: values['request_id'].toString(),
          nextStatus: 'completed',
          cashReceivedConfirmed: true,
        );
        final settled = await session.select(
          '''
          select status, cash_received_confirmed
          from public.request_payments
          where request_id = @requestId
          ''',
          parameters: {'requestId': values['request_id']},
        );
        if (settled.single['status']?.toString() != 'settled' ||
            settled.single['cash_received_confirmed'] != true) {
          throw StateError('Payment was not settled correctly.');
        }
        throw const _RollbackSignal();
      });
    } on _RollbackSignal {
      stdout.writeln(
        'Wallet reservation, cash remainder, confirmation, and settlement verified; all test data rolled back.',
      );
    }
  } finally {
    await database.close();
  }
}

class _SessionDatabase implements MaestroDbExecutor {
  const _SessionDatabase(this.session);

  final MaestroDbSession session;

  @override
  Future<R> run<R>(Future<R> Function(MaestroDbSession session) fn) {
    return fn(session);
  }

  @override
  Future<R> runTx<R>(Future<R> Function(MaestroDbSession session) fn) {
    return fn(session);
  }

  @override
  Future<void> close() async {}
}

class _RollbackSignal implements Exception {
  const _RollbackSignal();
}
