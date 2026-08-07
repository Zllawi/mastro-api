import 'dart:io';

import '../backend_environment.dart';
import 'maestro_database.dart';

Future<void> main() async {
  final environment = await loadBackendEnvironment();
  final database = SupabasePostgresDatabase.fromConfig(
    SupabaseDatabaseConfig.fromEnvironment(environment: environment),
  );
  const requestId = '00000000-0000-4000-8000-000000000001';
  const offerId = '00000000-0000-4000-8000-000000000002';
  const actorId = '00000000-0000-4000-8000-000000000003';
  try {
    await database.run((session) async {
      await session.select(
        '''
        explain
        update public.offers
        set status = case
          when id = @offerId then 'accepted'::public.offer_status
          else 'rejected'::public.offer_status
        end
        where request_id = @requestId and status = 'submitted'
        ''',
        parameters: {'requestId': requestId, 'offerId': offerId},
      );
      await session.select(
        '''
        explain
        update public.service_requests
        set status = cast(@nextStatus as public.service_request_status)
        where id = @requestId
        ''',
        parameters: {'requestId': requestId, 'nextStatus': 'on_the_way'},
      );
      await session.select(
        '''
        explain
        insert into public.request_status_events (request_id, status, actor_id)
        values (
          @requestId,
          cast(@nextStatus as public.service_request_status),
          @actorId
        )
        ''',
        parameters: {
          'requestId': requestId,
          'nextStatus': 'on_the_way',
          'actorId': actorId,
        },
      );
    });
    stdout.writeln(
      'Offer acceptance and request status enum queries verified.',
    );
  } finally {
    await database.close();
  }
}
