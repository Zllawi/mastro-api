import '../resala/otp_flow.dart';
import 'maestro_database.dart';

class SupabaseOtpStore implements OtpStore {
  const SupabaseOtpStore(this.db);

  final MaestroDbExecutor db;

  @override
  Future<StoredOtp?> read(String phone) {
    return db.run((session) async {
      final rows = await session.select(
        '''
        select phone, pin, expires_at, attempts, sent_at, resala_pin_id
        from public.otp_codes
        where phone = @phone and verified_at is null
        limit 1
        ''',
        parameters: {'phone': phone},
      );
      if (rows.isEmpty) {
        return null;
      }
      return _storedOtpFromRow(rows.single);
    });
  }

  @override
  Future<void> write(StoredOtp otp) {
    return db.run((session) async {
      await session.execute(
        '''
        insert into public.otp_codes (
          phone,
          pin,
          expires_at,
          attempts,
          sent_at,
          resala_pin_id,
          verified_at
        )
        values (
          @phone,
          @pin,
          @expiresAt,
          @attempts,
          @sentAt,
          @resalaPinId,
          null
        )
        on conflict (phone) do update
        set
          pin = excluded.pin,
          expires_at = excluded.expires_at,
          attempts = excluded.attempts,
          sent_at = excluded.sent_at,
          resala_pin_id = excluded.resala_pin_id,
          verified_at = null,
          updated_at = now()
        ''',
        parameters: {
          'phone': otp.phone,
          'pin': otp.pin,
          'expiresAt': otp.expiresAt,
          'attempts': otp.attempts,
          'sentAt': otp.sentAt,
          'resalaPinId': otp.resalaPinId,
        },
      );
    });
  }

  @override
  Future<void> delete(String phone) {
    return db.run((session) async {
      await session.execute(
        '''
        delete from public.otp_codes
        where phone = @phone
        ''',
        parameters: {'phone': phone},
      );
    });
  }
}

StoredOtp _storedOtpFromRow(Map<String, dynamic> row) {
  return StoredOtp(
    phone: row['phone'].toString(),
    pin: row['pin'].toString(),
    expiresAt: _date(row['expires_at']),
    attempts: _int(row['attempts']),
    sentAt: _date(row['sent_at']),
    resalaPinId: row['resala_pin_id']?.toString() ?? '',
  );
}

DateTime _date(Object? value) {
  if (value is DateTime) {
    return value;
  }
  return DateTime.parse(value.toString());
}

int _int(Object? value) {
  if (value is int) {
    return value;
  }
  return int.parse(value.toString());
}
