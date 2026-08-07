import 'maestro_database.dart';
import 'maestro_records.dart';

class ProfilesRepository {
  const ProfilesRepository(this.db);

  final MaestroDbExecutor db;

  Future<MaestroProfile> upsertProfile(CreateProfileInput input) {
    return db.run((session) async {
      final rows = await session.select(
        '''
        insert into public.profiles (role, phone, full_name, city, status)
        values (@role, @phone, @fullName, @city, 'active')
        on conflict (phone) do update
        set
          role = excluded.role,
          full_name = coalesce(excluded.full_name, public.profiles.full_name),
          city = excluded.city,
          status = 'active',
          updated_at = now()
        returning *
        ''',
        parameters: {
          'role': input.role.name,
          'phone': input.phone,
          'fullName': input.fullName,
          'city': input.city,
        },
      );
      return MaestroProfile.fromMap(rows.single);
    });
  }

  Future<MaestroProfile?> findByPhone(String phone) {
    return db.run((session) async {
      final rows = await session.select(
        '''
        select *
        from public.profiles
        where phone = @phone
        limit 1
        ''',
        parameters: {'phone': phone},
      );
      return rows.isEmpty ? null : MaestroProfile.fromMap(rows.single);
    });
  }

  Future<void> markPhoneVerified(String phone) {
    return db.run((session) async {
      await session.execute(
        '''
        update public.profiles
        set phone_verified_at = now(), status = 'active'
        where phone = @phone
        ''',
        parameters: {'phone': phone},
      );
    });
  }
}

class CustomerAddressesRepository {
  const CustomerAddressesRepository(this.db);

  final MaestroDbExecutor db;

  Future<void> upsertDefaultAddress(UpsertCustomerAddressInput input) {
    return db.runTx((session) async {
      await session.execute(
        '''
        update public.customer_addresses
        set is_default = false
        where customer_id = @customerId
        ''',
        parameters: {'customerId': input.customerId},
      );
      await session.execute(
        '''
        insert into public.customer_addresses (
          customer_id,
          label,
          city,
          area,
          street,
          notes,
          is_default
        )
        values (
          @customerId,
          @label,
          @city,
          @area,
          @address,
          @landmark,
          true
        )
        ''',
        parameters: {
          'customerId': input.customerId,
          'label': input.label,
          'city': input.city,
          'area': input.area,
          'address': input.address,
          'landmark': input.landmark,
        },
      );
    });
  }
}

class CraftsmanProfilesRepository {
  const CraftsmanProfilesRepository(this.db);

  final MaestroDbExecutor db;

  Future<void> upsertProfile(UpsertCraftsmanProfileInput input) {
    return db.run((session) async {
      await session.execute(
        '''
        insert into public.craftsman_profiles (
          profile_id,
          profession,
          bio,
          years_experience,
          service_area,
          identity_type,
          identity_number,
          verification_submitted_at
        )
        values (
          @profileId,
          @profession,
          @bio,
          @yearsExperience,
          @serviceArea,
          @identityType,
          @identityNumber,
          now()
        )
        on conflict (profile_id) do update
        set
          profession = excluded.profession,
          bio = excluded.bio,
          years_experience = excluded.years_experience,
          service_area = excluded.service_area,
          identity_type = excluded.identity_type,
          identity_number = excluded.identity_number,
          verification_submitted_at = now(),
          updated_at = now()
        ''',
        parameters: {
          'profileId': input.profileId,
          'profession': input.profession,
          'bio': input.bio,
          'yearsExperience': input.yearsExperience,
          'serviceArea': {'areas': input.serviceAreas},
          'identityType': input.identityType,
          'identityNumber': input.identityNumber,
        },
      );
    });
  }

  Future<void> addVerificationDocument(
    CraftsmanVerificationDocumentInput input,
  ) {
    return db.run((session) async {
      await session.execute(
        '''
        insert into public.craftsman_verification_documents (
          craftsman_id,
          document_type,
          storage_bucket,
          storage_path,
          content_type
        )
        values (
          @craftsmanId,
          @documentType,
          @storageBucket,
          @storagePath,
          @contentType
        )
        ''',
        parameters: {
          'craftsmanId': input.craftsmanId,
          'documentType': input.documentType,
          'storageBucket': input.storageBucket,
          'storagePath': input.storagePath,
          'contentType': input.contentType,
        },
      );
    });
  }
}

class ServiceRequestsRepository {
  const ServiceRequestsRepository(this.db);

  final MaestroDbExecutor db;

  Future<MaestroServiceRequest> create(CreateServiceRequestInput input) {
    return db.runTx((session) async {
      final rows = await session.select(
        '''
        insert into public.service_requests (
          customer_id,
          category_id,
          title,
          description,
          urgency,
          area,
          address_text,
          scheduled_for,
          status
        )
        values (
          @customerId,
          @categoryId,
          @title,
          @description,
          @urgency,
          @area,
          @addressText,
          @scheduledFor,
          'submitted'
        )
        returning *
        ''',
        parameters: {
          'customerId': input.customerId,
          'categoryId': input.categoryId,
          'title': input.title,
          'description': input.description,
          'urgency': input.urgency,
          'area': input.area,
          'addressText': input.addressText,
          'scheduledFor': input.scheduledFor,
        },
      );
      final request = MaestroServiceRequest.fromMap(rows.single);
      await session.execute(
        '''
        insert into public.request_status_events (request_id, status, actor_id)
        values (@requestId, 'submitted', @actorId)
        ''',
        parameters: {'requestId': request.id, 'actorId': input.customerId},
      );
      return request;
    });
  }

  Future<List<MaestroServiceRequest>> listForCustomer(String customerId) {
    return db.run((session) async {
      final rows = await session.select(
        '''
        select *
        from public.service_requests
        where customer_id = @customerId
        order by created_at desc
        ''',
        parameters: {'customerId': customerId},
      );
      return rows.map(MaestroServiceRequest.fromMap).toList();
    });
  }

  Future<void> updateStatus({
    required String requestId,
    required MaestroRequestStatus status,
    String? actorId,
    String? note,
  }) {
    return db.runTx((session) async {
      await session.execute(
        '''
        update public.service_requests
        set status = @status
        where id = @requestId
        ''',
        parameters: {'requestId': requestId, 'status': status.wire},
      );
      await session.execute(
        '''
        insert into public.request_status_events (request_id, status, actor_id, note)
        values (@requestId, @status, @actorId, @note)
        ''',
        parameters: {
          'requestId': requestId,
          'status': status.wire,
          'actorId': actorId,
          'note': note,
        },
      );
    });
  }
}

class OffersRepository {
  const OffersRepository(this.db);

  final MaestroDbExecutor db;

  Future<MaestroOffer> submit(SubmitOfferInput input) {
    return db.runTx((session) async {
      final rows = await session.select(
        '''
        insert into public.offers (
          request_id,
          craftsman_id,
          total_amount,
          arrival_window,
          estimated_duration,
          warranty_text,
          note
        )
        values (
          @requestId,
          @craftsmanId,
          @totalAmount,
          @arrivalWindow,
          @estimatedDuration,
          @warrantyText,
          @note
        )
        on conflict (request_id, craftsman_id) do update
        set
          total_amount = excluded.total_amount,
          arrival_window = excluded.arrival_window,
          estimated_duration = excluded.estimated_duration,
          warranty_text = excluded.warranty_text,
          note = excluded.note,
          status = 'submitted',
          updated_at = now()
        returning *
        ''',
        parameters: {
          'requestId': input.requestId,
          'craftsmanId': input.craftsmanId,
          'totalAmount': input.totalAmount,
          'arrivalWindow': input.arrivalWindow,
          'estimatedDuration': input.estimatedDuration,
          'warrantyText': input.warrantyText,
          'note': input.note,
        },
      );
      await session.execute(
        '''
        update public.service_requests
        set status = 'offers_received'
        where id = @requestId and status = 'submitted'
        ''',
        parameters: {'requestId': input.requestId},
      );
      await session.execute(
        '''
        insert into public.request_status_events (request_id, status, actor_id, note)
        values (@requestId, 'offers_received', @actorId, 'Offer submitted')
        ''',
        parameters: {
          'requestId': input.requestId,
          'actorId': input.craftsmanId,
        },
      );
      return MaestroOffer.fromMap(rows.single);
    });
  }

  Future<List<MaestroOffer>> listForRequest(String requestId) {
    return db.run((session) async {
      final rows = await session.select(
        '''
        select *
        from public.offers
        where request_id = @requestId
        order by total_amount asc, created_at asc
        ''',
        parameters: {'requestId': requestId},
      );
      return rows.map(MaestroOffer.fromMap).toList();
    });
  }

  Future<void> acceptOffer({
    required String requestId,
    required String offerId,
    required String customerId,
  }) {
    return db.runTx((session) async {
      await session.execute(
        '''
        update public.offers
        set status = case when id = @offerId then 'accepted' else 'rejected' end
        where request_id = @requestId and status = 'submitted'
        ''',
        parameters: {'requestId': requestId, 'offerId': offerId},
      );
      await session.execute(
        '''
        update public.service_requests
        set accepted_offer_id = @offerId, status = 'accepted'
        where id = @requestId and customer_id = @customerId
        ''',
        parameters: {
          'requestId': requestId,
          'offerId': offerId,
          'customerId': customerId,
        },
      );
      await session.execute(
        '''
        insert into public.request_status_events (request_id, status, actor_id)
        values (@requestId, 'accepted', @actorId)
        ''',
        parameters: {'requestId': requestId, 'actorId': customerId},
      );
    });
  }
}
