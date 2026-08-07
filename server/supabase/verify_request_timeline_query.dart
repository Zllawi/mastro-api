import 'dart:io';

import '../backend_environment.dart';
import 'maestro_database.dart';

Future<void> main() async {
  final environment = await loadBackendEnvironment();
  final database = SupabasePostgresDatabase.fromConfig(
    SupabaseDatabaseConfig.fromEnvironment(environment: environment),
  );

  try {
    await database.run(
      (session) => session.select('''
        select
          sr.id,
          timeline.submitted_at,
          timeline.offers_received_at,
          timeline.accepted_at,
          timeline.on_the_way_at,
          timeline.arrived_at,
          timeline.started_at,
          timeline.completed_at
        from public.service_requests sr
        left join public.offers accepted_o on accepted_o.id = sr.accepted_offer_id
        left join lateral (
          select
            coalesce(
              min(rse.created_at) filter (where rse.status = 'submitted'),
              sr.created_at
            ) as submitted_at,
            coalesce(
              min(rse.created_at) filter (where rse.status = 'offers_received'),
              (
                select min(first_offer.created_at)
                from public.offers first_offer
                where first_offer.request_id = sr.id
              )
            ) as offers_received_at,
            coalesce(
              min(rse.created_at) filter (where rse.status = 'accepted'),
              case
                when sr.accepted_offer_id is not null then accepted_o.updated_at
              end
            ) as accepted_at,
            min(rse.created_at) filter (where rse.status = 'on_the_way') as on_the_way_at,
            null::timestamptz as arrived_at,
            min(rse.created_at) filter (where rse.status = 'started') as started_at,
            min(rse.created_at) filter (where rse.status = 'completed') as completed_at
          from public.request_status_events rse
          where rse.request_id = sr.id
        ) timeline on true
        order by sr.created_at desc
        limit 1
        '''),
    );
    stdout.writeln('Request timeline query verified.');
  } finally {
    await database.close();
  }
}
