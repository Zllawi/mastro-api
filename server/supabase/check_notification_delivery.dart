import '../backend_environment.dart';
import 'maestro_database.dart';

Future<void> main(List<String> args) async {
  final campaignId = _option(args, '--campaign') ?? _option(args, '-c');
  final environment = await loadBackendEnvironment();
  final database = SupabasePostgresDatabase.fromConfig(
    SupabaseDatabaseConfig.fromEnvironment(environment: environment),
  );
  try {
    final campaigns = await database.run(
      (session) => session.select(
        '''
        select
          id,
          title,
          audience,
          status,
          scheduled_for,
          sent_at,
          target_profile_id
        from public.notification_campaigns
        ${campaignId == null ? '' : 'where id = @campaignId'}
        order by created_at desc
        limit 5
        ''',
        parameters: {
          if (campaignId != null) 'campaignId': campaignId,
        },
      ),
    );
    if (campaigns.isEmpty) {
      print('No notification campaign found.');
      return;
    }

    for (final campaign in campaigns) {
      final id = campaign['id'].toString();
      print('Campaign: ${campaign['title']}');
      print('  id: $id');
      print('  audience: ${campaign['audience']}');
      print('  status: ${campaign['status']}');
      print('  sent_at: ${campaign['sent_at']}');
      final stats = await database.run(
        (session) => session.select(
          '''
          select
            count(*)::int as notifications,
            count(*) filter (where read_at is null)::int as unread,
            count(*) filter (where push_status = 'pending')::int as pending,
            count(*) filter (where push_status = 'processing')::int as processing,
            count(*) filter (where push_status = 'sent')::int as sent,
            count(*) filter (where push_status = 'failed')::int as failed,
            count(*) filter (where push_status = 'skipped')::int as skipped,
            count(*) filter (where d.enabled = true)::int as enabled_devices
          from public.notifications n
          left join public.notification_devices d on d.profile_id = n.profile_id
          where n.campaign_id = @campaignId
          ''',
          parameters: {'campaignId': id},
        ),
      );
      final row = stats.single;
      print('  notifications: ${row['notifications']}');
      print('  unread: ${row['unread']}');
      print('  push pending: ${row['pending']}');
      print('  push sent: ${row['sent']}');
      print('  push failed: ${row['failed']}');
      print('  push skipped: ${row['skipped']}');
      print('  enabled devices: ${row['enabled_devices']}');

      final errors = await database.run(
        (session) => session.select(
          '''
          select push_status, push_error, count(*)::int as total
          from public.notifications
          where campaign_id = @campaignId
            and push_error is not null
          group by push_status, push_error
          order by total desc
          limit 5
          ''',
          parameters: {'campaignId': id},
        ),
      );
      for (final error in errors) {
        print(
          '  error: ${error['push_status']} x${error['total']}: ${error['push_error']}',
        );
      }
    }
  } finally {
    await database.close();
  }
}

String? _option(List<String> args, String name) {
  for (var index = 0; index < args.length; index++) {
    if (args[index] == name && index + 1 < args.length) {
      return args[index + 1].trim();
    }
    if (args[index].startsWith('$name=')) {
      return args[index].substring(name.length + 1).trim();
    }
  }
  return null;
}
