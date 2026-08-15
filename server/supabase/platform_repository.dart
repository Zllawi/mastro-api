import 'dart:convert';
import 'dart:math';

import 'maestro_database.dart';

final Random _secureRandom = Random.secure();

class PlatformRepository {
  const PlatformRepository(this.db);

  final MaestroDbExecutor db;

  Future<void> ensureAdminAccount(String phone) {
    return db.runTx((session) async {
      final existing = await session.select(
        '''
        select id, role
        from public.profiles
        where phone = @phone
        limit 1
        ''',
        parameters: {'phone': phone},
      );
      final previousRole = existing.isEmpty
          ? null
          : existing.single['role']?.toString();
      final rows = await session.select(
        '''
        insert into public.profiles (
          role,
          status,
          phone,
          full_name,
          phone_verified_at,
          password_reset_required
        )
        values (
          'admin',
          'active',
          @phone,
          'إدارة ماسترو',
          now(),
          false
        )
        on conflict (phone) do update
        set
          role = 'admin',
          status = 'active',
          blocked_reason = null,
          full_name = coalesce(
            nullif(public.profiles.full_name, ''),
            'إدارة ماسترو'
          ),
          phone_verified_at = coalesce(
            public.profiles.phone_verified_at,
            now()
          ),
          password_reset_required = false
        returning id
        ''',
        parameters: {'phone': phone},
      );
      final profileId = rows.single['id'];
      if (previousRole != null && previousRole != 'admin') {
        // A session created for the old role must never inherit admin access.
        await session.execute(
          '''
          update public.app_sessions
          set revoked_at = coalesce(revoked_at, now())
          where profile_id = @profileId
            and revoked_at is null
          ''',
          parameters: {'profileId': profileId},
        );
        await session.execute(
          '''
          insert into public.admin_audit_logs (
            admin_id,
            action,
            entity_type,
            entity_id,
            details
          )
          values (
            @profileId:uuid,
            'account.promote_from_environment',
            'profile',
            cast(@profileId:uuid as text),
            jsonb_build_object(
              'previous_role',
              @previousRole:text
            )
          )
          ''',
          parameters: {'profileId': profileId, 'previousRole': previousRole},
        );
      }
      await session.execute(
        '''
        insert into public.wallets (profile_id)
        values (@profileId)
        on conflict do nothing
        ''',
        parameters: {'profileId': profileId},
      );
      await session.execute(
        '''
        insert into public.notification_preferences (profile_id)
        values (@profileId)
        on conflict do nothing
        ''',
        parameters: {'profileId': profileId},
      );
    });
  }

  Future<Map<String, dynamic>?> findProfileByPhone(String phone) {
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
      return rows.isEmpty ? null : rows.single;
    });
  }

  Future<Map<String, dynamic>> registerManagedMediaAsset({
    required String ownerId,
    required String providerPublicId,
    required String resourceType,
    required String purpose,
    required String publicUrl,
  }) {
    return db.run((session) async {
      final rows = await session.select(
        '''
        insert into public.managed_media_assets (
          owner_id,
          provider,
          provider_public_id,
          resource_type,
          purpose,
          public_url
        )
        values (
          @ownerId,
          'cloudinary',
          @providerPublicId,
          @resourceType,
          @purpose,
          @publicUrl
        )
        on conflict (provider, resource_type, provider_public_id) do update
        set
          purpose = excluded.purpose,
          public_url = excluded.public_url,
          status = 'active'
        where public.managed_media_assets.owner_id = excluded.owner_id
        returning *
        ''',
        parameters: {
          'ownerId': ownerId,
          'providerPublicId': providerPublicId,
          'resourceType': resourceType,
          'purpose': purpose,
          'publicUrl': publicUrl,
        },
      );
      if (rows.isEmpty) {
        throw const PlatformRuleException(
          'تعذر تسجيل ملكية الملف المرفوع.',
          statusCode: 409,
        );
      }
      return rows.single;
    });
  }

  Future<Map<String, dynamic>> ensureVerifiedProfile({
    required String phone,
    required String requestedRole,
    bool allowExistingAdmin = false,
  }) {
    return db.runTx((session) async {
      final existing = await session.select(
        '''
        select *
        from public.profiles
        where phone = @phone
        for update
        ''',
        parameters: {'phone': phone},
      );

      late Map<String, dynamic> profile;
      if (existing.isEmpty) {
        if (requestedRole == 'admin') {
          throw const PlatformRuleException(
            'لا يمكن إنشاء حساب إدارة من شاشة الدخول.',
            statusCode: 403,
          );
        }
        final inserted = await session.select(
          '''
          with profile as (
            insert into public.profiles (
              role,
              status,
              phone,
              phone_verified_at,
              last_login_at,
              password_reset_required
            )
            values (
              @role,
              'active',
              @phone,
              now(),
              now(),
              true
            )
            returning *
          ), wallet as (
            insert into public.wallets (profile_id)
            select id from profile
            on conflict (profile_id) do nothing
          ), preferences as (
            insert into public.notification_preferences (profile_id)
            select id from profile
            on conflict (profile_id) do nothing
          )
          select * from profile
          ''',
          parameters: {'role': requestedRole, 'phone': phone},
        );
        profile = inserted.single;
      } else {
        profile = existing.single;
        final storedRole = profile['role'].toString();
        final status = profile['status'].toString();
        if (status == 'suspended') {
          throw PlatformRuleException(
            profile['blocked_reason']?.toString().trim().isNotEmpty == true
                ? 'الحساب محظور: ${profile['blocked_reason']}'
                : 'هذا الحساب محظور. تواصل مع إدارة ماسترو.',
            statusCode: 403,
          );
        }
        if (status == 'deleted') {
          throw const PlatformRuleException(
            'هذا الحساب غير متاح.',
            statusCode: 403,
          );
        }
        if (storedRole != requestedRole) {
          throw PlatformRuleException(
            'هذا الرقم مسجل كـ ${_roleLabel(storedRole)}. اختر نوع الحساب الصحيح.',
            statusCode: 409,
          );
        }
        if (storedRole == 'admin' && !allowExistingAdmin) {
          throw const PlatformRuleException(
            'دخول الإدارة متاح من لوحة الويب فقط.',
            statusCode: 403,
          );
        }
        final updated = await session.select(
          '''
          with profile as (
            update public.profiles
            set
              phone_verified_at = coalesce(phone_verified_at, now()),
              last_login_at = now(),
              status = case when status = 'pending' then 'active' else status end,
              password_reset_required = case
                when role = 'admin' then false
                else password_hash is null
              end
            where id = @profileId
            returning *
          ), wallet as (
            insert into public.wallets (profile_id)
            select id from profile
            on conflict (profile_id) do nothing
          ), preferences as (
            insert into public.notification_preferences (profile_id)
            select id from profile
            on conflict (profile_id) do nothing
          )
          select * from profile
          ''',
          parameters: {'profileId': profile['id']},
        );
        profile = updated.single;
      }

      return profile;
    });
  }

  Future<void> createSession({
    required String profileId,
    required String tokenHash,
    required DateTime expiresAt,
    String? deviceName,
    String? ipAddress,
  }) {
    return db.run((session) async {
      await session.execute(
        '''
        insert into public.app_sessions (
          profile_id,
          token_hash,
          device_name,
          ip_address,
          expires_at
        )
        values (
          @profileId,
          @tokenHash,
          @deviceName,
          cast(@ipAddress as inet),
          @expiresAt
        )
        ''',
        parameters: {
          'profileId': profileId,
          'tokenHash': tokenHash,
          'deviceName': deviceName,
          'ipAddress': ipAddress,
          'expiresAt': expiresAt,
        },
      );
    });
  }

  Future<Map<String, dynamic>?> authenticate(String tokenHash) {
    return db.run((session) async {
      final rows = await session.select(
        '''
        update public.app_sessions s
        set last_seen_at = now()
        from public.profiles p
        where s.token_hash = @tokenHash
          and s.revoked_at is null
          and s.expires_at > now()
          and p.id = s.profile_id
          and p.status <> 'suspended'
        returning
          s.id as session_id,
          s.profile_id,
          s.expires_at,
          p.role,
          p.status,
          p.phone,
          p.full_name,
          p.blocked_reason,
          case
            when p.role = 'admin' then false
            else p.password_reset_required
          end as password_reset_required,
          (p.password_hash is not null) as has_password
        ''',
        parameters: {'tokenHash': tokenHash},
      );
      if (rows.isNotEmpty) return rows.single;
      final suspended = await session.select(
        '''
        update public.app_sessions s
        set revoked_at = now()
        from public.profiles p
        where s.token_hash = @tokenHash
          and s.revoked_at is null
          and s.expires_at > now()
          and p.id = s.profile_id
          and p.status = 'suspended'
        returning p.blocked_reason
        ''',
        parameters: {'tokenHash': tokenHash},
      );
      if (suspended.isEmpty) return null;
      final blockedReason = suspended.single['blocked_reason']?.toString();
      throw PlatformRuleException(
        blockedReason?.trim().isNotEmpty == true
            ? 'الحساب محظور: $blockedReason'
            : 'هذا الحساب محظور.',
        statusCode: 403,
      );
    });
  }

  Future<void> revokeSession(String tokenHash) {
    return db.run((session) async {
      await session.execute(
        '''
        update public.app_sessions
        set revoked_at = now()
        where token_hash = @tokenHash and revoked_at is null
        ''',
        parameters: {'tokenHash': tokenHash},
      );
    });
  }

  Future<Map<String, dynamic>?> passwordLoginProfile({
    required String phone,
    required String role,
  }) {
    return db.run((session) async {
      final rows = await session.select(
        '''
        select *
        from public.profiles
        where phone = @phone
          and role = cast(@role as public.user_role)
        limit 1
        ''',
        parameters: {'phone': phone, 'role': role},
      );
      return rows.isEmpty ? null : rows.single;
    });
  }

  Future<Map<String, dynamic>> setPasswordHash({
    required String profileId,
    required String passwordHash,
  }) {
    return db.runTx((session) async {
      final rows = await session.select(
        '''
        update public.profiles
        set
          password_hash = @passwordHash,
          password_set_at = now(),
          password_reset_required = false
        where id = @profileId
          and status <> 'deleted'
        returning *
        ''',
        parameters: {'profileId': profileId, 'passwordHash': passwordHash},
      );
      if (rows.isEmpty) {
        throw const PlatformRuleException('الحساب غير متاح.', statusCode: 404);
      }
      await session.execute(
        '''
        insert into public.admin_audit_logs (
          admin_id,
          action,
          entity_type,
          entity_id,
          details
        )
        select
          case when role = 'admin' then id else null end,
          'account.password_set',
          'profile',
          cast(id as text),
          '{}'::jsonb
        from public.profiles
        where id = @profileId
        ''',
        parameters: {'profileId': profileId},
      );
      return rows.single;
    });
  }

  Future<Map<String, dynamic>> bootstrap(String profileId) {
    return db.run((session) async {
      final profileRows = await session.select(
        '''
        with expiry_sweep as (
          select maestro_private.expire_stale_service_requests()
            as expired_count
        )
        select
          jsonb_build_object(
            'id', p.id,
            'phone', p.phone,
            'role', p.role,
            'status', p.status,
            'full_name', p.full_name,
            'avatar_url', p.avatar_url,
            'city', p.city,
            'blocked_reason', p.blocked_reason,
            'password_reset_required', case
              when p.role = 'admin' then false
              else p.password_reset_required
            end,
            'warning_count', p.warning_count,
            'last_warning_at', p.last_warning_at,
            'created_at', p.created_at,
            'updated_at', p.updated_at
          ) as profile,
          case when p.role = 'customer' then (
            select coalesce(
              jsonb_agg(to_jsonb(a) order by a.is_default desc, a.created_at desc),
              '[]'::jsonb
            )
            from public.customer_addresses a
            where a.customer_id = p.id
          ) else '[]'::jsonb end as addresses,
          case when p.role = 'craftsman' then (
            select to_jsonb(cp) || jsonb_build_object(
              'category_ids', coalesce(
                (
                  select jsonb_agg(cs.category_id order by cs.category_id)
                  from public.craftsman_services cs
                  where cs.craftsman_id = cp.profile_id
                ),
                '[]'::jsonb
              ),
              'documents', coalesce(
                (
                  select jsonb_agg(
                    jsonb_build_object(
                      'id', d.id,
                      'document_type', d.document_type,
                      'public_url', d.public_url,
                      'status', d.status,
                      'rejection_reason', d.rejection_reason
                    )
                    order by d.created_at
                  )
                  from public.craftsman_verification_documents d
                  where d.craftsman_id = cp.profile_id
                ),
                '[]'::jsonb
              )
            )
            from public.craftsman_profiles cp
            where cp.profile_id = p.id
          ) end as craftsman_profile,
          (
            select to_jsonb(w)
            from public.wallets w
            where w.profile_id = p.id
          ) as wallet,
          (
            select to_jsonb(np)
            from public.notification_preferences np
            where np.profile_id = p.id
          ) as notification_preferences,
          (
            select coalesce(
              jsonb_agg(to_jsonb(sc) order by sc.sort_order, sc.name_ar),
              '[]'::jsonb
            )
            from public.service_categories sc
            where sc.is_active = true
          ) as categories,
          (
            select aps.value
            from public.app_settings aps
            where aps.key = 'home_banners'
          ) as home_banners,
          case when p.role = 'customer' then (
            select coalesce(
              jsonb_agg(
                jsonb_build_object(
                  'id', favorite_profile.id,
                  'full_name', favorite_profile.full_name,
                  'avatar_url', favorite_profile.avatar_url,
                  'profession', favorite_cp.profession,
                  'rating', favorite_cp.rating,
                  'completed_jobs', favorite_cp.completed_jobs,
                  'on_time_percent', favorite_cp.on_time_percent,
                  'is_verified', favorite_cp.is_verified,
                  'saved_at', fc.created_at
                )
                order by fc.created_at desc
              ),
              '[]'::jsonb
            )
            from public.favorite_craftsmen fc
            join public.profiles favorite_profile
              on favorite_profile.id = fc.craftsman_id
            join public.craftsman_profiles favorite_cp
              on favorite_cp.profile_id = fc.craftsman_id
            where fc.customer_id = p.id
              and favorite_profile.status = 'active'
          ) else '[]'::jsonb end as favorites,
          (
            select count(*)::int
            from public.notifications n
            where n.profile_id = p.id and n.read_at is null
          ) as unread_notifications
        from public.profiles p
        cross join expiry_sweep
        where p.id = @profileId
        limit 1
        ''',
        parameters: {'profileId': profileId},
      );
      if (profileRows.isEmpty) {
        throw const PlatformRuleException('الحساب غير موجود.', statusCode: 404);
      }
      final summary = profileRows.single;
      final profile = _jsonObject(summary['profile'])!;
      final requests = await _requestsForProfile(
        session,
        profileId,
        knownRole: profile['role']?.toString() ?? '',
      );
      return {
        'profile': profile,
        'addresses': _jsonObjectList(summary['addresses']),
        'craftsman_profile': _jsonObject(summary['craftsman_profile']),
        'wallet': _jsonObject(summary['wallet']),
        'notification_preferences': _jsonObject(
          summary['notification_preferences'],
        ),
        'requests': requests,
        'categories': _jsonObjectList(summary['categories']),
        'home_banners': _homeBanners(summary['home_banners']),
        'favorites': _jsonObjectList(summary['favorites']),
        'unread_notifications': _intValue(summary['unread_notifications']),
      };
    });
  }

  Future<List<Map<String, dynamic>>> listFavorites(String customerId) {
    return db.run((session) => _favoritesForCustomer(session, customerId));
  }

  Future<void> setFavorite({
    required String customerId,
    required String craftsmanId,
    required bool favorite,
  }) {
    return db.runTx((session) async {
      if (!favorite) {
        await session.execute(
          '''
          delete from public.favorite_craftsmen
          where customer_id = @customerId and craftsman_id = @craftsmanId
          ''',
          parameters: {'customerId': customerId, 'craftsmanId': craftsmanId},
        );
        return;
      }
      final rows = await session.select(
        '''
        insert into public.favorite_craftsmen (customer_id, craftsman_id)
        select @customerId, @craftsmanId
        where exists (
          select 1 from public.profiles
          where id = @customerId and role = 'customer'
        )
        and exists (
          select 1
          from public.profiles p
          join public.craftsman_profiles cp on cp.profile_id = p.id
          where p.id = @craftsmanId
            and p.status = 'active'
            and cp.is_verified = true
        )
        on conflict (customer_id, craftsman_id) do update
        set created_at = public.favorite_craftsmen.created_at
        returning craftsman_id
        ''',
        parameters: {'customerId': customerId, 'craftsmanId': craftsmanId},
      );
      if (rows.isEmpty) {
        throw const PlatformRuleException(
          'لا يمكن حفظ هذا الحرفي.',
          statusCode: 404,
        );
      }
    });
  }

  Future<Map<String, dynamic>> saveCustomer({
    required String profileId,
    required String fullName,
    required String city,
    String? avatarUrl,
    String? avatarPublicId,
    String? avatarResourceType,
    Map<String, dynamic>? initialAddress,
  }) {
    return db.runTx((session) async {
      await _assertOwnedAvatar(
        session,
        ownerId: profileId,
        publicUrl: avatarUrl,
        providerPublicId: avatarPublicId,
        resourceType: avatarResourceType,
      );
      await session.execute(
        '''
        update public.profiles
        set
          full_name = @fullName,
          city = @city,
          avatar_url = coalesce(@avatarUrl, avatar_url),
          status = 'active'
        where id = @profileId and role = 'customer'
        ''',
        parameters: {
          'profileId': profileId,
          'fullName': fullName,
          'city': city,
          'avatarUrl': avatarUrl,
        },
      );
      if (initialAddress != null) {
        await _insertAddress(
          session,
          profileId: profileId,
          input: initialAddress,
          makeDefault: true,
        );
      }
      final rows = await session.select(
        '''
        select
          id,
          phone,
          role,
          status,
          full_name,
          avatar_url,
          city,
          blocked_reason,
          case
            when role = 'admin' then false
            else password_reset_required
          end as password_reset_required,
          warning_count,
          last_warning_at,
          created_at,
          updated_at
        from public.profiles
        where id = @profileId
        ''',
        parameters: {'profileId': profileId},
      );
      return rows.single;
    });
  }

  Future<Map<String, dynamic>> saveCraftsman({
    required String profileId,
    required String fullName,
    required String profession,
    required int yearsExperience,
    required List<String> serviceAreas,
    required List<String> categoryIds,
    required String identityType,
    required String identityNumber,
    required List<Map<String, dynamic>> documents,
    String? bio,
    String? avatarUrl,
    String? avatarPublicId,
    String? avatarResourceType,
  }) {
    return db.runTx((session) async {
      await _assertOwnedAvatar(
        session,
        ownerId: profileId,
        publicUrl: avatarUrl,
        providerPublicId: avatarPublicId,
        resourceType: avatarResourceType,
      );
      for (final document in documents) {
        await _assertOwnedManagedAttachment(
          session,
          ownerId: profileId,
          publicUrl: document['url'],
          providerPublicId: document['public_id'],
          resourceType: document['resource_type'],
          expectedPurpose: 'craftsman-verification',
        );
      }
      await session.execute(
        '''
        update public.profiles
        set
          full_name = @fullName,
          avatar_url = coalesce(@avatarUrl, avatar_url),
          status = 'active'
        where id = @profileId and role = 'craftsman'
        ''',
        parameters: {
          'profileId': profileId,
          'fullName': fullName,
          'avatarUrl': avatarUrl,
        },
      );
      await session.execute(
        '''
        insert into public.craftsman_profiles (
          profile_id,
          profession,
          bio,
          identity_type,
          identity_number,
          years_experience,
          service_area,
          is_verified,
          verification_submitted_at
        )
        values (
          @profileId,
          @profession,
          @bio,
          @identityType,
          @identityNumber,
          @yearsExperience,
          cast(@serviceArea as jsonb),
          false,
          now()
        )
        on conflict (profile_id) do update
        set
          profession = excluded.profession,
          bio = excluded.bio,
          identity_type = excluded.identity_type,
          identity_number = excluded.identity_number,
          years_experience = excluded.years_experience,
          service_area = excluded.service_area,
          is_verified = false,
          verification_submitted_at = now(),
          verification_reviewed_at = null
        ''',
        parameters: {
          'profileId': profileId,
          'profession': profession,
          'bio': bio,
          'identityType': identityType,
          'identityNumber': identityNumber,
          'yearsExperience': yearsExperience,
          'serviceArea': _jsonText({'areas': serviceAreas}),
        },
      );
      await session.execute(
        'delete from public.craftsman_services where craftsman_id = @profileId',
        parameters: {'profileId': profileId},
      );
      for (final categoryId in categoryIds.toSet()) {
        await session.execute(
          '''
          insert into public.craftsman_services (craftsman_id, category_id)
          values (@profileId, @categoryId)
          on conflict do nothing
          ''',
          parameters: {'profileId': profileId, 'categoryId': categoryId},
        );
      }
      for (final document in documents) {
        final documentRows = await session.select(
          '''
          insert into public.craftsman_verification_documents (
            craftsman_id,
            document_type,
            storage_bucket,
            storage_path,
            content_type,
            provider,
            public_url,
            provider_public_id,
            status
          )
          values (
            @profileId,
            @documentType,
            'cloudinary',
            @providerPublicId,
            @contentType,
            'cloudinary',
            @publicUrl,
            @providerPublicId,
            'pending'
          )
          returning id
          ''',
          parameters: {
            'profileId': profileId,
            'documentType': document['document_type'],
            'providerPublicId': document['public_id'],
            'contentType': document['content_type'],
            'publicUrl': document['url'],
          },
        );
        await _consumeOwnedManagedAttachment(
          session,
          ownerId: profileId,
          publicUrl: document['url'],
          providerPublicId: document['public_id'],
          resourceType: document['resource_type'],
          expectedPurpose: 'craftsman-verification',
          consumedByType: 'craftsman_verification_document',
          consumedById: documentRows.single['id'],
        );
      }
      final rows = await session.select(
        'select * from public.craftsman_profiles where profile_id = @profileId',
        parameters: {'profileId': profileId},
      );
      return rows.single;
    });
  }

  Future<List<Map<String, dynamic>>> listAddresses(String profileId) {
    return db.run(
      (session) => session.select(
        '''
        select *
        from public.customer_addresses
        where customer_id = @profileId
        order by is_default desc, created_at desc
        ''',
        parameters: {'profileId': profileId},
      ),
    );
  }

  Future<Map<String, dynamic>> addAddress({
    required String profileId,
    required Map<String, dynamic> input,
  }) {
    return db.runTx((session) async {
      return _insertAddress(
        session,
        profileId: profileId,
        input: input,
        makeDefault: input['is_default'] == true,
      );
    });
  }

  Future<Map<String, dynamic>> updateAddress({
    required String profileId,
    required String addressId,
    required Map<String, dynamic> input,
  }) {
    return db.runTx((session) async {
      if (input['is_default'] == true) {
        await session.execute(
          '''
          update public.customer_addresses
          set is_default = false
          where customer_id = @profileId
          ''',
          parameters: {'profileId': profileId},
        );
      }
      final rows = await session.select(
        '''
        update public.customer_addresses
        set
          label = @label,
          city = @city,
          area = @area,
          street = @street,
          building = @building,
          floor = @floor,
          notes = @notes,
          latitude = @latitude,
          longitude = @longitude,
          is_default = case
            when @makeDefault = true then true
            else is_default
          end
        where id = @addressId and customer_id = @profileId
        returning *
        ''',
        parameters: {
          'profileId': profileId,
          'addressId': addressId,
          'label': input['label'],
          'city': input['city'],
          'area': input['area'],
          'street': input['street'],
          'building': input['building'],
          'floor': input['floor'],
          'notes': input['notes'],
          'latitude': input['latitude'],
          'longitude': input['longitude'],
          'makeDefault': input['is_default'] == true,
        },
      );
      if (rows.isEmpty) {
        throw const PlatformRuleException(
          'العنوان غير موجود.',
          statusCode: 404,
        );
      }
      return rows.single;
    });
  }

  Future<void> deleteAddress({
    required String profileId,
    required String addressId,
  }) {
    return db.runTx((session) async {
      final rows = await session.select(
        '''
        delete from public.customer_addresses
        where id = @addressId and customer_id = @profileId
        returning is_default
        ''',
        parameters: {'profileId': profileId, 'addressId': addressId},
      );
      if (rows.isEmpty) {
        throw const PlatformRuleException(
          'العنوان غير موجود.',
          statusCode: 404,
        );
      }
      if (rows.single['is_default'] == true) {
        await session.execute(
          '''
          update public.customer_addresses
          set is_default = true
          where id = (
            select id
            from public.customer_addresses
            where customer_id = @profileId
            order by created_at desc
            limit 1
          )
          ''',
          parameters: {'profileId': profileId},
        );
      }
    });
  }

  Future<List<Map<String, dynamic>>> listCategories() {
    return db.run(_listCategories);
  }

  Future<List<Map<String, dynamic>>> listHomeBanners() {
    return db.run(_listHomeBanners);
  }

  Future<List<Map<String, dynamic>>> adminCategories() {
    return db.run(
      (session) => session.select('''
        select *
        from public.service_categories
        order by sort_order, name_ar
        '''),
    );
  }

  Future<List<Map<String, dynamic>>> adminHomeBanners() {
    return db.run((session) => _listHomeBanners(session, activeOnly: false));
  }

  Future<Map<String, dynamic>> adminSaveHomeBanner({
    required String adminId,
    required Map<String, dynamic> input,
    String? bannerId,
  }) {
    return db.runTx((session) async {
      final existing = await _listHomeBanners(session, activeOnly: false);
      final now = DateTime.now().toUtc().toIso8601String();
      final id = bannerId ?? await _newUuid(session);
      final currentIndex = existing.indexWhere((item) => item['id'] == id);
      final previous = currentIndex == -1
          ? const <String, dynamic>{}
          : existing[currentIndex];
      final imageUrl = input['image_url']?.toString().trim();
      if (imageUrl == null || imageUrl.isEmpty) {
        throw const PlatformRuleException(
          'صورة البانر مطلوبة.',
          statusCode: 422,
        );
      }
      final banner = <String, dynamic>{
        'id': id,
        'image_url': imageUrl,
        'title': _blankToNull(input['title']),
        'subtitle': _blankToNull(input['subtitle']),
        'display_order': _intValue(input['display_order']),
        'active': input['active'] != false,
        'click_action': _clickAction(input['click_action']),
        'created_at': previous['created_at']?.toString() ?? now,
      };
      if (currentIndex == -1) {
        existing.add(banner);
      } else {
        existing[currentIndex] = banner;
      }
      existing.sort(_compareHomeBannerMaps);
      await _storeHomeBanners(session, adminId: adminId, banners: existing);
      await _audit(
        session,
        adminId: adminId,
        action: bannerId == null ? 'home_banner.create' : 'home_banner.update',
        entityType: 'home_banner',
        entityId: id,
        details: banner,
      );
      return banner;
    });
  }

  Future<void> adminDeleteHomeBanner({
    required String adminId,
    required String bannerId,
  }) {
    return db.runTx((session) async {
      final existing = await _listHomeBanners(session, activeOnly: false);
      final removed = existing.where((item) => item['id'] == bannerId).toList();
      if (removed.isEmpty) {
        throw const PlatformRuleException('البانر غير موجود.', statusCode: 404);
      }
      existing.removeWhere((item) => item['id'] == bannerId);
      existing.sort(_compareHomeBannerMaps);
      await _storeHomeBanners(session, adminId: adminId, banners: existing);
      await _audit(
        session,
        adminId: adminId,
        action: 'home_banner.delete',
        entityType: 'home_banner',
        entityId: bannerId,
        details: removed.single,
      );
    });
  }

  Future<Map<String, dynamic>> createRequest({
    required String customerId,
    required Map<String, dynamic> input,
  }) {
    return db.runTx((session) async {
      await _assertOwnedManagedAttachment(
        session,
        ownerId: customerId,
        publicUrl: input['voice_note_url'],
        providerPublicId: input['voice_note_public_id'],
        resourceType: input['voice_note_resource_type'],
        expectedPurpose: 'voice-notes',
      );
      final rawAttachments = input['attachments'];
      if (rawAttachments is List) {
        for (final raw in rawAttachments.whereType<Map>()) {
          final attachment = Map<String, dynamic>.from(raw);
          await _assertOwnedManagedAttachment(
            session,
            ownerId: customerId,
            publicUrl: attachment['url'],
            providerPublicId: attachment['public_id'],
            resourceType: attachment['resource_type'],
            expectedPurpose: 'service-requests',
          );
        }
      }
      final categoryRows = await session.select(
        '''
        with expiry_sweep as (
          select maestro_private.expire_stale_service_requests()
            as expired_count
        )
        select id, availability_status
        from public.service_categories
        cross join expiry_sweep
        where id = @categoryId
          and is_active = true
        limit 1
        ''',
        parameters: {'categoryId': input['category_id']},
      );
      if (categoryRows.isEmpty) {
        throw const PlatformRuleException(
          'الخدمة المختارة غير موجودة أو مخفية.',
          statusCode: 422,
        );
      }
      final categoryStatus =
          categoryRows.single['availability_status']?.toString() ?? 'open';
      if (categoryStatus != 'open') {
        throw PlatformRuleException(
          categoryStatus == 'coming_soon'
              ? 'هذه الخدمة ستتوفر قريبًا ولا تستقبل طلبات الآن.'
              : 'هذه الخدمة مغلقة مؤقتًا.',
          statusCode: 409,
        );
      }
      await _lockAndAssertNoDuplicateActiveRequest(
        session,
        customerId: customerId,
        categoryId: input['category_id'].toString(),
      );
      final addressRows = await session.select(
        '''
        select *
        from public.customer_addresses
        where id = @addressId and customer_id = @customerId
        limit 1
        ''',
        parameters: {
          'addressId': input['address_id'],
          'customerId': customerId,
        },
      );
      if (addressRows.isEmpty) {
        throw const PlatformRuleException(
          'اختر عنوانًا صالحًا للطلب.',
          statusCode: 422,
        );
      }
      if (input['payment_method'] == 'wallet') {
        final walletRows = await session.select(
          '''
          select available_balance
          from public.wallets
          where profile_id = @customerId
          limit 1
          ''',
          parameters: {'customerId': customerId},
        );
        final balance = walletRows.isEmpty
            ? 0
            : num.tryParse(
                    walletRows.single['available_balance']?.toString() ?? '',
                  ) ??
                  0;
        if (balance <= 0) {
          throw const PlatformRuleException(
            'رصيد المحفظة غير كافٍ لاختيار الدفع بالمحفظة. اشحن المحفظة أو اختر الدفع كاش.',
            statusCode: 409,
          );
        }
      }
      final address = addressRows.single;
      final rows = await session.select(
        '''
        insert into public.service_requests (
          customer_id,
          category_id,
          address_id,
          title,
          description,
          urgency,
          scheduled_for,
          city,
          area,
          address_text,
          latitude,
          longitude,
          voice_note_url,
          payment_method,
          metadata,
          status
        )
        values (
          @customerId,
          @categoryId,
          @addressId,
          @title,
          @description,
          @urgency,
          @scheduledFor,
          @city,
          @area,
          @addressText,
          @latitude,
          @longitude,
          @voiceNoteUrl,
          @paymentMethod,
          @metadata::jsonb,
          'submitted'
        )
        returning *
        ''',
        parameters: {
          'customerId': customerId,
          'categoryId': input['category_id'],
          'addressId': input['address_id'],
          'title': input['title'],
          'description': input['description'],
          'urgency': input['urgency'] == true,
          'scheduledFor': _dateOrNull(input['scheduled_for']),
          'city': address['city'],
          'area': address['area'],
          'addressText': _addressText(address),
          'latitude': address['latitude'],
          'longitude': address['longitude'],
          'voiceNoteUrl': input['voice_note_url'],
          'paymentMethod': input['payment_method'],
          'metadata': _jsonText(
            input['metadata'] is Map ? input['metadata'] : <String, dynamic>{},
          ),
        },
      );
      final request = rows.single;
      await _consumeOwnedManagedAttachment(
        session,
        ownerId: customerId,
        publicUrl: input['voice_note_url'],
        providerPublicId: input['voice_note_public_id'],
        resourceType: input['voice_note_resource_type'],
        expectedPurpose: 'voice-notes',
        consumedByType: 'service_request_voice',
        consumedById: request['id'],
      );
      await session.execute(
        '''
        insert into public.request_status_events (request_id, status, actor_id)
        values (@requestId, 'submitted', @customerId)
        ''',
        parameters: {'requestId': request['id'], 'customerId': customerId},
      );
      if (rawAttachments is List) {
        for (final raw in rawAttachments.whereType<Map>()) {
          final attachment = Map<String, dynamic>.from(raw);
          final attachmentRows = await session.select(
            '''
            insert into public.request_attachments (
              request_id,
              storage_bucket,
              storage_path,
              content_type,
              size_bytes,
              provider,
              public_url,
              provider_public_id,
              resource_type
            )
            values (
              @requestId,
              'cloudinary',
              @publicId,
              @contentType,
              @sizeBytes,
              'cloudinary',
              @publicUrl,
              @publicId,
              @resourceType
            )
            returning id
            ''',
            parameters: {
              'requestId': request['id'],
              'publicId': attachment['public_id'],
              'contentType': attachment['content_type'],
              'sizeBytes': attachment['size_bytes'],
              'publicUrl': attachment['url'],
              'resourceType': attachment['resource_type'] ?? 'image',
            },
          );
          await _consumeOwnedManagedAttachment(
            session,
            ownerId: customerId,
            publicUrl: attachment['url'],
            providerPublicId: attachment['public_id'],
            resourceType: attachment['resource_type'],
            expectedPurpose: 'service-requests',
            consumedByType: 'request_attachment',
            consumedById: attachmentRows.single['id'],
          );
        }
      }
      final automation = await _requestAutomationSettings(session);
      if (automation.enabled) {
        await _createRequestDispatchRows(
          session,
          requestId: request['id'].toString(),
          categoryId: input['category_id'].toString(),
          batchSize: automation.batchSize,
          intervalMinutes: automation.intervalMinutes,
        );
      } else {
        await _notifyAdminsAboutManualRequest(
          session,
          requestId: request['id'].toString(),
          publicCode: request['public_code']?.toString() ?? '',
        );
        return request;
      }
      await session.execute(
        '''
        insert into public.notifications (profile_id, title, body, data)
        select
          cs.craftsman_id,
          'طلب خدمة جديد',
          @notificationBody:text,
          jsonb_build_object(
            'request_id', @requestId:uuid,
            'notification_type', 'order',
            'dispatch_notification', true,
            'actionable', true
          )
        from public.craftsman_services cs
        join public.request_dispatches rd
          on rd.request_id = @requestId:uuid
         and rd.craftsman_id = cs.craftsman_id
        join public.craftsman_profiles cp on cp.profile_id = cs.craftsman_id
        join public.profiles p on p.id = cs.craftsman_id
        where cs.category_id = @categoryId:text
          and cp.is_available = true
          and cp.is_verified = true
          and p.status = 'active'
          and p.notifications_enabled = true
        ''',
        parameters: {
          'notificationBody': input['urgency'] == true
              ? 'يوجد طلب عاجل جديد ضمن تخصصك.'
              : 'يوجد طلب جديد ضمن تخصصك.',
          'requestId': request['id'],
          'categoryId': input['category_id'],
        },
      );
      return request;
    });
  }

  Future<List<Map<String, dynamic>>> requestsForProfile(String profileId) {
    return db.run((session) => _requestsForProfile(session, profileId));
  }

  Future<Map<String, dynamic>> cancelRequestByCustomer({
    required String customerId,
    required String requestId,
    String? reason,
  }) {
    return db.runTx((session) async {
      await _expireStaleRequests(session);
      final requests = await session.select(
        '''
        select id, customer_id, status, accepted_offer_id
        from public.service_requests
        where id = @requestId
          and customer_id = @customerId
        limit 1
        for update
        ''',
        parameters: {'requestId': requestId, 'customerId': customerId},
      );
      if (requests.isEmpty) {
        throw const PlatformRuleException('الطلب غير موجود.', statusCode: 404);
      }
      final request = requests.single;
      if (!{
            'submitted',
            'offers_received',
          }.contains(request['status']?.toString()) ||
          request['accepted_offer_id'] != null) {
        throw const PlatformRuleException(
          'لا يمكن إلغاء الطلب بعد قبول عرض أو بدء العمل.',
          statusCode: 409,
        );
      }
      final cancellationReason = reason?.trim().isNotEmpty == true
          ? reason!.trim()
          : 'ألغى العميل الطلب.';
      final updated = await session.select(
        '''
        update public.service_requests
        set
          status = 'cancelled',
          cancellation_mode = 'no_entitlement',
          cancellation_reason = @reason,
          cancelled_by = @customerId,
          cancelled_at = now(),
          inspection_due_amount = 0,
          updated_at = now()
        where id = @requestId
        returning
          id as request_id,
          status,
          cancellation_mode,
          cancellation_reason,
          cancelled_at
        ''',
        parameters: {
          'requestId': requestId,
          'customerId': customerId,
          'reason': cancellationReason,
        },
      );
      await session.execute(
        '''
        update public.offers
        set status = 'withdrawn', updated_at = now()
        where request_id = @requestId
          and status = 'submitted'
        ''',
        parameters: {'requestId': requestId},
      );
      await session.execute(
        '''
        with cancelled_revisions as (
          update public.offer_revision_requests
          set
            status = 'cancelled',
            response_note = coalesce(response_note, 'أُلغي الطلب من العميل.'),
            responded_at = coalesce(responded_at, now())
          where request_id = @requestId
            and status = 'pending'
          returning id
        )
        update public.notifications notification
        set
          read_at = coalesce(notification.read_at, now()),
          data = notification.data || jsonb_build_object(
            'revision_status', 'cancelled',
            'actionable', false
          ),
          push_status = case
            when notification.push_status in ('pending', 'failed')
              then 'skipped'
            else notification.push_status
          end,
          push_error = case
            when notification.push_status in ('pending', 'failed')
              then 'Offer revision is no longer actionable.'
            else notification.push_error
          end
        from cancelled_revisions revision
        where notification.data ->> 'revision_id' = revision.id::text
        ''',
        parameters: {'requestId': requestId},
      );
      await session.execute(
        '''
        update public.request_dispatches
        set expires_at = least(expires_at, now())
        where request_id = @requestId
          and expires_at > now()
        ''',
        parameters: {'requestId': requestId},
      );
      await _closeRequestDispatchNotifications(
        session,
        requestId: requestId,
        status: 'cancelled',
      );
      await _closeOfferNotifications(
        session,
        requestId: requestId,
        status: 'cancelled',
      );
      await session.execute(
        '''
        insert into public.request_status_events (
          request_id,
          status,
          actor_id,
          note
        )
        values (@requestId, 'cancelled', @customerId, @reason)
        ''',
        parameters: {
          'requestId': requestId,
          'customerId': customerId,
          'reason': cancellationReason,
        },
      );
      await session.execute(
        '''
        insert into public.notifications (profile_id, title, body, data)
        select distinct
          recipients.craftsman_id,
          'تم إلغاء الطلب',
          'ألغى العميل الطلب قبل قبول أي عرض.',
          jsonb_build_object(
            'request_id', @requestId:uuid,
            'notification_type', 'order',
            'status', 'cancelled'
          )
        from (
          select offer.craftsman_id
          from public.offers offer
          where offer.request_id = @requestId
          union
          select dispatch.craftsman_id
          from public.request_dispatches dispatch
          where dispatch.request_id = @requestId
        ) recipients
        ''',
        parameters: {'requestId': requestId},
      );
      return updated.single;
    });
  }

  Future<Map<String, dynamic>> redispatchRequest({
    required String customerId,
    required String requestId,
  }) {
    return db.runTx((session) async {
      await _expireStaleRequests(session);
      await session.select(
        '''
        select pg_advisory_xact_lock(
          hashtextextended(cast(@requestId as text), 904029)
        )
        ''',
        parameters: {'requestId': requestId},
      );
      final rows = await session.select(
        '''
        select
          sr.*,
          coalesce(dispatch_summary.last_notified_at, sr.created_at)
            as last_distribution_at
        from public.service_requests sr
        left join lateral (
          select max(rd.notified_at) as last_notified_at
          from public.request_dispatches rd
          where rd.request_id = sr.id
        ) dispatch_summary on true
        where sr.id = @requestId
          and sr.customer_id = @customerId
        limit 1
        for update of sr
        ''',
        parameters: {'requestId': requestId, 'customerId': customerId},
      );
      if (rows.isEmpty) {
        throw const PlatformRuleException('الطلب غير موجود.', statusCode: 404);
      }
      final request = rows.single;
      if (!{
            'submitted',
            'offers_received',
          }.contains(request['status']?.toString()) ||
          request['accepted_offer_id'] != null ||
          !(_dateOrNull(
                request['expires_at'],
              )?.isAfter(DateTime.now().toUtc()) ??
              false)) {
        throw const PlatformRuleException(
          'لا يمكن إعادة إرسال طلب منتهٍ أو بعد قبول عرض.',
          statusCode: 409,
        );
      }
      final lastDistributionAt =
          [
            _dateOrNull(request['created_at']),
            _dateOrNull(request['last_distribution_at']),
            _dateOrNull(request['last_redispatched_at']),
          ].whereType<DateTime>().reduce(
            (latest, item) => item.isAfter(latest) ? item : latest,
          );
      final now = DateTime.now().toUtc();
      final retryAt = lastDistributionAt.toUtc().add(const Duration(hours: 1));
      if (now.isBefore(retryAt)) {
        throw RequestRedispatchCooldownException(retryAt);
      }

      final settings = await _requestAutomationSettings(session);
      var dispatched = 0;
      if (settings.enabled) {
        dispatched = await _createRequestDispatchRows(
          session,
          requestId: requestId,
          categoryId: request['category_id'].toString(),
          batchSize: settings.batchSize,
          intervalMinutes: settings.intervalMinutes,
          onlyIfDue: true,
        );
        if (dispatched > 0) {
          await _notifyCurrentRequestDispatchBatch(
            session,
            requestId: requestId,
            urgent: request['urgency'] == true,
            redispatched: true,
          );
        } else {
          dispatched = await _renotifyLatestUnansweredDispatchBatch(
            session,
            requestId: requestId,
            urgent: request['urgency'] == true,
            intervalMinutes: settings.intervalMinutes,
          );
        }
      } else {
        dispatched = await _notifyAdminsAboutManualRequest(
          session,
          requestId: requestId,
          publicCode: request['public_code']?.toString() ?? '',
          redispatched: true,
        );
      }
      if (dispatched <= 0) {
        throw const PlatformRuleException(
          'لا يوجد مستلمون جدد لإعادة إرسال الطلب إليهم حاليًا.',
          statusCode: 409,
        );
      }
      final updated = await session.select(
        '''
        update public.service_requests
        set
          last_redispatched_at = now(),
          redispatch_count = redispatch_count + 1,
          updated_at = now()
        where id = @requestId
        returning last_redispatched_at, expires_at
        ''',
        parameters: {'requestId': requestId},
      );
      final lastRedispatchedAt = _dateOrNull(
        updated.single['last_redispatched_at'],
      )!;
      return {
        'redispatched': true,
        'dispatched_count': dispatched,
        'last_redispatched_at': lastRedispatchedAt,
        'next_redispatch_at': lastRedispatchedAt.add(const Duration(hours: 1)),
        'expires_at': updated.single['expires_at'],
      };
    });
  }

  Future<int> dispatchDueRequestBatches() {
    return db.runTx(_dispatchDueRequestBatches);
  }

  Future<Map<String, dynamic>> submitOffer({
    required String craftsmanId,
    required Map<String, dynamic> input,
  }) {
    return db.runTx((session) async {
      await _expireStaleRequests(session);
      await session.select(
        '''
        select pg_advisory_xact_lock(
          hashtextextended(
            cast(@requestId as text) || ':' || cast(@craftsmanId as text),
            904028
          )
        )
        ''',
        parameters: {
          'requestId': input['request_id'],
          'craftsmanId': craftsmanId,
        },
      );
      final previousOffers = await session.select(
        '''
        select id
        from public.offers
        where request_id = @requestId
          and craftsman_id = @craftsmanId
        limit 1
        ''',
        parameters: {
          'requestId': input['request_id'],
          'craftsmanId': craftsmanId,
        },
      );
      if (previousOffers.isNotEmpty) {
        throw const PlatformRuleException(
          'لقد أرسلت عرضًا لهذا الطلب بالفعل، ولا يمكن إرسال عرض ثانٍ.',
          statusCode: 409,
        );
      }
      final eligible = await session.select(
        '''
        select sr.id
        from public.service_requests sr
        join public.craftsman_services cs
          on cs.category_id = sr.category_id
         and cs.craftsman_id = @craftsmanId
        join public.craftsman_profiles cp on cp.profile_id = @craftsmanId
        where sr.id = @requestId
          and sr.status in ('submitted', 'offers_received')
          and sr.accepted_offer_id is null
          and sr.expires_at > now()
          and cp.is_verified = true
          and exists (
            select 1
            from public.request_dispatches rd
            where rd.request_id = sr.id
              and rd.craftsman_id = @craftsmanId
              and (
                rd.expires_at > now()
                or exists (
                  select 1
                  from public.offers existing_offer
                  where existing_offer.request_id = sr.id
                    and existing_offer.craftsman_id = @craftsmanId
                )
              )
          )
        limit 1
        for update of sr
        ''',
        parameters: {
          'craftsmanId': craftsmanId,
          'requestId': input['request_id'],
        },
      );
      if (eligible.isEmpty) {
        throw const PlatformRuleException(
          'لا يمكنك تقديم عرض لهذا الطلب.',
          statusCode: 403,
        );
      }
      final rows = await session.select(
        '''
        insert into public.offers (
          request_id,
          craftsman_id,
          total_amount,
          labor_amount,
          materials_amount,
          inspection_fee,
          arrival_window,
          estimated_duration,
          warranty_text,
          note
        )
        values (
          @requestId,
          @craftsmanId,
          @totalAmount,
          @laborAmount,
          @materialsAmount,
          @inspectionFee,
          @arrivalWindow,
          @estimatedDuration,
          @warrantyText,
          @note
        )
        returning *
        ''',
        parameters: {
          'requestId': input['request_id'],
          'craftsmanId': craftsmanId,
          'totalAmount': input['total_amount'],
          'laborAmount': input['labor_amount'],
          'materialsAmount': input['materials_amount'],
          'inspectionFee': input['inspection_fee'],
          'arrivalWindow': input['arrival_window'],
          'estimatedDuration': input['estimated_duration'],
          'warrantyText': input['warranty_text'],
          'note': input['note'],
        },
      );
      await session.execute(
        '''
        update public.request_dispatches
        set offered_at = coalesce(offered_at, now())
        where request_id = @requestId
          and craftsman_id = @craftsmanId
        ''',
        parameters: {
          'requestId': input['request_id'],
          'craftsmanId': craftsmanId,
        },
      );
      await _closeRequestDispatchNotifications(
        session,
        requestId: input['request_id'].toString(),
        status: 'offer_sent',
        craftsmanId: craftsmanId,
      );
      final transitionedRequests = await session.execute(
        '''
        update public.service_requests
        set status = 'offers_received'
        where id = @requestId
          and status in ('submitted', 'offers_received')
          and accepted_offer_id is null
          and expires_at > now()
        ''',
        parameters: {'requestId': input['request_id']},
      );
      if (transitionedRequests != 1) {
        throw const PlatformRuleException(
          'تغيرت حالة الطلب قبل إرسال العرض. حدّث الطلب وحاول مرة أخرى.',
          statusCode: 409,
        );
      }
      await session.execute(
        '''
        insert into public.request_status_events (request_id, status, actor_id, note)
        select
          @requestId,
          'offers_received'::public.service_request_status,
          @craftsmanId,
          'Offer submitted'
        where not exists (
          select 1
          from public.request_status_events existing_event
          where existing_event.request_id = @requestId
            and existing_event.status = 'offers_received'
        )
        ''',
        parameters: {
          'requestId': input['request_id'],
          'craftsmanId': craftsmanId,
        },
      );
      await session.execute(
        '''
        insert into public.notifications (profile_id, title, body, data)
        select
          sr.customer_id,
          'عرض جديد لطلبك',
          'قدم حرفي عرضًا جديدًا بقيمة ' || @totalAmount || ' د.ل',
          jsonb_build_object(
            'request_id', sr.id,
            'offer_id', @offerId:uuid,
            'notification_type', 'offer'
          )
        from public.service_requests sr
        where sr.id = @requestId
        ''',
        parameters: {
          'requestId': input['request_id'],
          'offerId': rows.single['id'],
          'totalAmount': input['total_amount'].toString(),
        },
      );
      return rows.single;
    });
  }

  Future<List<Map<String, dynamic>>> listOffers({
    required String customerId,
    required String requestId,
  }) {
    return db.runTx((session) async {
      await _expireStaleRequests(session);
      return session.select(
        '''
        select
          o.*,
          p.full_name as craftsman_name,
          p.avatar_url,
          cp.profession,
          cp.rating,
          cp.completed_jobs,
          cp.on_time_percent,
          cp.is_verified,
          latest_revision.id as revision_id,
          latest_revision.status as revision_status,
          latest_revision.total_amount as revision_total_amount,
          latest_revision.labor_amount as revision_labor_amount,
          latest_revision.materials_amount as revision_materials_amount,
          latest_revision.inspection_fee as revision_inspection_fee,
          latest_revision.note as revision_note,
          latest_revision.response_note as revision_response_note,
          latest_revision.created_at as revision_created_at,
          latest_revision.responded_at as revision_responded_at,
          public.maestro_distance_km(
            sr.latitude,
            sr.longitude,
            cp.last_latitude,
            cp.last_longitude
          ) as distance_km
        from public.offers o
        join public.service_requests sr on sr.id = o.request_id
        join public.profiles p on p.id = o.craftsman_id
        join public.craftsman_profiles cp on cp.profile_id = o.craftsman_id
        left join lateral (
          select revision.*
          from public.offer_revision_requests revision
          where revision.offer_id = o.id
          order by revision.created_at desc, revision.id desc
          limit 1
        ) latest_revision on true
        where o.request_id = @requestId
          and sr.customer_id = @customerId
          and o.status in ('submitted', 'accepted')
        order by o.total_amount, o.created_at
        ''',
        parameters: {'requestId': requestId, 'customerId': customerId},
      );
    });
  }

  Future<Map<String, dynamic>> requestOfferRevision({
    required String customerId,
    required String offerId,
    required Map<String, dynamic> input,
  }) {
    return db.runTx((session) async {
      await _expireStaleRequests(session);
      final offerIdentityRows = await session.select(
        '''
        select offer.request_id
        from public.offers offer
        join public.service_requests request on request.id = offer.request_id
        where offer.id = @offerId
          and request.customer_id = @customerId
        limit 1
        ''',
        parameters: {'offerId': offerId, 'customerId': customerId},
      );
      if (offerIdentityRows.isEmpty) {
        throw const PlatformRuleException(
          'لا يمكن تعديل هذا العرض الآن. قد يكون الطلب مقبولًا أو العرض لم يعد متاحًا.',
          statusCode: 409,
        );
      }
      final requestId = offerIdentityRows.single['request_id'];
      final requestRows = await session.select(
        '''
        select id
        from public.service_requests
        where id = @requestId
          and customer_id = @customerId
          and status in ('submitted', 'offers_received')
          and accepted_offer_id is null
          and expires_at > now()
        limit 1
        for update
        ''',
        parameters: {'requestId': requestId, 'customerId': customerId},
      );
      if (requestRows.isEmpty) {
        throw const PlatformRuleException(
          'لا يمكن تعديل هذا العرض الآن. قد يكون الطلب مقبولًا أو العرض لم يعد متاحًا.',
          statusCode: 409,
        );
      }
      final offerRows = await session.select(
        '''
        select offer.*
        from public.offers offer
        where offer.id = @offerId
          and offer.request_id = @requestId
          and offer.status = 'submitted'
        limit 1
        for update
        ''',
        parameters: {'offerId': offerId, 'requestId': requestId},
      );
      if (offerRows.isEmpty) {
        throw const PlatformRuleException(
          'لا يمكن تعديل هذا العرض الآن. قد يكون الطلب مقبولًا أو العرض لم يعد متاحًا.',
          statusCode: 409,
        );
      }
      final offer = offerRows.single;
      await session.execute(
        '''
        with cancelled_revisions as (
          update public.offer_revision_requests
          set
            status = 'cancelled',
            response_note = coalesce(
              response_note,
              'أُلغي بعد إنشاء طلب تعديل أحدث.'
            ),
            responded_at = coalesce(responded_at, now())
          where offer_id = @offerId
            and status = 'pending'
          returning id
        )
        update public.notifications notification
        set
          read_at = coalesce(notification.read_at, now()),
          data = notification.data || jsonb_build_object(
            'revision_status', 'cancelled',
            'actionable', false
          ),
          push_status = case
            when notification.push_status in ('pending', 'failed')
              then 'skipped'
            else notification.push_status
          end,
          push_error = case
            when notification.push_status in ('pending', 'failed')
              then 'Offer revision is no longer actionable.'
            else notification.push_error
          end
        from cancelled_revisions revision
        where notification.data ->> 'revision_id' = revision.id::text
        ''',
        parameters: {'offerId': offerId},
      );
      final rows = await session.select(
        '''
        insert into public.offer_revision_requests (
          offer_id,
          request_id,
          customer_id,
          craftsman_id,
          total_amount,
          labor_amount,
          materials_amount,
          inspection_fee,
          note
        )
        values (
          @offerId,
          @requestId,
          @customerId,
          @craftsmanId,
          @totalAmount,
          @laborAmount,
          @materialsAmount,
          @inspectionFee,
          @note
        )
        returning *
        ''',
        parameters: {
          'offerId': offerId,
          'requestId': offer['request_id'],
          'customerId': customerId,
          'craftsmanId': offer['craftsman_id'],
          'totalAmount': input['total_amount'],
          'laborAmount': input['labor_amount'],
          'materialsAmount': input['materials_amount'],
          'inspectionFee': input['inspection_fee'],
          'note': input['note'],
        },
      );
      await session.execute(
        '''
        insert into public.notifications (profile_id, title, body, data)
        values (
          @craftsmanId,
          'طلب تعديل عرض',
          'اقترح العميل تعديل قيمة أو تفاصيل العرض.',
          jsonb_build_object(
            'request_id', @requestId:uuid,
            'offer_id', @offerId:uuid,
            'revision_id', @revisionId:uuid,
            'notification_type', 'offer_revision',
            'revision_status', 'pending',
            'actionable', true,
            'total_amount', @totalAmount,
            'labor_amount', @laborAmount,
            'materials_amount', @materialsAmount,
            'inspection_fee', @inspectionFee
          )
        )
        ''',
        parameters: {
          'craftsmanId': offer['craftsman_id'],
          'requestId': offer['request_id'],
          'offerId': offerId,
          'revisionId': rows.single['id'],
          'totalAmount': rows.single['total_amount'],
          'laborAmount': rows.single['labor_amount'],
          'materialsAmount': rows.single['materials_amount'],
          'inspectionFee': rows.single['inspection_fee'],
        },
      );
      return rows.single;
    });
  }

  Future<Map<String, dynamic>> respondOfferRevision({
    required String craftsmanId,
    required String revisionId,
    required bool approved,
    String? responseNote,
  }) {
    return db.runTx((session) async {
      await _expireStaleRequests(session);
      final revisionOfferRows = await session.select(
        '''
        select request_id, offer_id
        from public.offer_revision_requests
        where id = @revisionId
          and craftsman_id = @craftsmanId
        limit 1
        ''',
        parameters: {'revisionId': revisionId, 'craftsmanId': craftsmanId},
      );
      if (revisionOfferRows.isEmpty) {
        throw const PlatformRuleException(
          'طلب تعديل العرض غير متاح أو تمت معالجته بالفعل.',
          statusCode: 409,
        );
      }
      final revisionIdentity = revisionOfferRows.single;
      final requestRows = await session.select(
        '''
        select id
        from public.service_requests
        where id = @requestId
          and status in ('submitted', 'offers_received')
          and accepted_offer_id is null
          and expires_at > now()
        limit 1
        for update
        ''',
        parameters: {'requestId': revisionIdentity['request_id']},
      );
      if (requestRows.isEmpty) {
        throw const PlatformRuleException(
          'طلب تعديل العرض غير متاح أو تمت معالجته بالفعل.',
          statusCode: 409,
        );
      }
      final offerRows = await session.select(
        '''
        select id
        from public.offers
        where id = @offerId
          and request_id = @requestId
          and status = 'submitted'
        limit 1
        for update
        ''',
        parameters: {
          'offerId': revisionIdentity['offer_id'],
          'requestId': revisionIdentity['request_id'],
        },
      );
      if (offerRows.isEmpty) {
        throw const PlatformRuleException(
          'طلب تعديل العرض غير متاح أو تمت معالجته بالفعل.',
          statusCode: 409,
        );
      }
      final revisionRows = await session.select(
        '''
        select revision.*
        from public.offer_revision_requests revision
        where revision.id = @revisionId
          and revision.craftsman_id = @craftsmanId
          and revision.request_id = @requestId
          and revision.offer_id = @offerId
          and revision.status = 'pending'
        limit 1
        for update
        ''',
        parameters: {
          'revisionId': revisionId,
          'craftsmanId': craftsmanId,
          'requestId': revisionIdentity['request_id'],
          'offerId': revisionIdentity['offer_id'],
        },
      );
      if (revisionRows.isEmpty) {
        throw const PlatformRuleException(
          'طلب تعديل العرض غير متاح أو تمت معالجته بالفعل.',
          statusCode: 409,
        );
      }
      final revision = revisionRows.single;
      final rows = await session.select(
        '''
        update public.offer_revision_requests
        set
          status = @status,
          response_note = @responseNote,
          responded_at = now()
        where id = @revisionId
        returning *
        ''',
        parameters: {
          'revisionId': revisionId,
          'status': approved ? 'approved' : 'rejected',
          'responseNote': responseNote,
        },
      );
      if (approved) {
        final changedOffers = await session.execute(
          '''
          update public.offers
          set
            total_amount = @totalAmount,
            labor_amount = @laborAmount,
            materials_amount = @materialsAmount,
            inspection_fee = @inspectionFee,
            note = coalesce(@note, note),
            status = 'submitted'
          where id = @offerId
            and status = 'submitted'
          ''',
          parameters: {
            'offerId': revision['offer_id'],
            'totalAmount': revision['total_amount'],
            'laborAmount': revision['labor_amount'],
            'materialsAmount': revision['materials_amount'],
            'inspectionFee': revision['inspection_fee'],
            'note': revision['note'],
          },
        );
        if (changedOffers != 1) {
          throw const PlatformRuleException(
            'تعذر تطبيق تعديل العرض لأن حالة الطلب تغيرت.',
            statusCode: 409,
          );
        }
      }
      await session.execute(
        '''
        update public.notifications notification
        set
          read_at = coalesce(notification.read_at, now()),
          data = notification.data || jsonb_build_object(
            'revision_status', @status,
            'actionable', false
          ),
          push_status = case
            when notification.push_status in ('pending', 'failed')
              then 'skipped'
            else notification.push_status
          end,
          push_error = case
            when notification.push_status in ('pending', 'failed')
              then 'Offer revision is no longer actionable.'
            else notification.push_error
          end
        where notification.profile_id = @craftsmanId
          and notification.data ->> 'notification_type' = 'offer_revision'
          and notification.data ->> 'revision_id' = @revisionId
        ''',
        parameters: {
          'craftsmanId': craftsmanId,
          'revisionId': revisionId,
          'status': approved ? 'approved' : 'rejected',
        },
      );
      await session.execute(
        '''
        insert into public.notifications (profile_id, title, body, data)
        values (
          @customerId,
          @title,
          @body,
          jsonb_build_object(
            'request_id', @requestId:uuid,
            'offer_id', @offerId:uuid,
            'revision_id', @revisionId:uuid,
            'notification_type', 'offer_revision'
          )
        )
        ''',
        parameters: {
          'customerId': revision['customer_id'],
          'requestId': revision['request_id'],
          'offerId': revision['offer_id'],
          'revisionId': revisionId,
          'title': approved
              ? 'تمت الموافقة على تعديل العرض'
              : 'تم رفض تعديل العرض',
          'body': approved
              ? 'وافق الفني على تعديل العرض. يمكنك قبول العرض أو انتظار عروض أخرى.'
              : (responseNote?.trim().isNotEmpty == true
                    ? responseNote
                    : 'رفض الفني تعديل العرض المقترح.'),
        },
      );
      return rows.single;
    });
  }

  Future<void> acceptOffer({
    required String customerId,
    required String requestId,
    required String offerId,
  }) {
    return db.runTx((session) async {
      await _expireStaleRequests(session);
      final requestRows = await session.select(
        '''
        select id, customer_id, status, payment_method
        from public.service_requests
        where id = @requestId
          and customer_id = @customerId
          and expires_at > now()
        for update
        ''',
        parameters: {'customerId': customerId, 'requestId': requestId},
      );
      if (requestRows.isEmpty ||
          !{
            'submitted',
            'offers_received',
          }.contains(requestRows.single['status']?.toString())) {
        throw const PlatformRuleException('تعذر قبول العرض.', statusCode: 409);
      }
      final offerRows = await session.select(
        '''
        select *
        from public.offers
        where id = @offerId
          and request_id = @requestId
          and status = 'submitted'
          and not exists (
            select 1
            from public.offer_revision_requests pending_revision
            where pending_revision.offer_id = @offerId
              and pending_revision.status = 'pending'
          )
        for update
        ''',
        parameters: {'offerId': offerId, 'requestId': requestId},
      );
      if (offerRows.isEmpty) {
        throw const PlatformRuleException(
          'العرض غير متاح للقبول.',
          statusCode: 409,
        );
      }
      final request = requestRows.single;
      final offer = offerRows.single;
      final paymentMethod = request['payment_method']?.toString() ?? 'cash';
      final inspectionAmount = _money(offer['inspection_fee']);
      var walletReserved = 0.0;

      if (paymentMethod == 'wallet') {
        await session.execute(
          '''
          insert into public.wallets (profile_id)
          values (@customerId)
          on conflict do nothing
          ''',
          parameters: {'customerId': customerId},
        );
        final wallets = await session.select(
          '''
          select available_balance
          from public.wallets
          where profile_id = @customerId
          for update
          ''',
          parameters: {'customerId': customerId},
        );
        final available = _money(wallets.single['available_balance']);
        if (available < inspectionAmount) {
          throw PlatformRuleException(
            'رصيد المحفظة لا يكفي لحجز قيمة الكشف. المطلوب ${inspectionAmount.toStringAsFixed(2)} د.ل والمتاح ${available.toStringAsFixed(2)} د.ل.',
            statusCode: 409,
          );
        }
        walletReserved = inspectionAmount;
        if (inspectionAmount > 0) {
          await session.execute(
            '''
            update public.wallets
            set available_balance = available_balance - @amount
            where profile_id = @customerId
            ''',
            parameters: {'customerId': customerId, 'amount': inspectionAmount},
          );
          await session.execute(
            '''
            insert into public.wallet_transactions (
              profile_id,
              request_id,
              kind,
              status,
              amount,
              description,
              metadata
            )
            values (
              @customerId,
              @requestId,
              'payment',
              'pending',
              -cast(@amount as numeric),
              'حجز قيمة الكشف',
              jsonb_build_object('stage', 'inspection')
            )
            ''',
            parameters: {
              'customerId': customerId,
              'requestId': requestId,
              'amount': inspectionAmount,
            },
          );
        }
      }
      await session.execute(
        '''
        insert into public.request_payments (
          request_id,
          offer_id,
          customer_id,
          craftsman_id,
          payment_method,
          status,
          total_amount,
          inspection_amount,
          wallet_reserved_amount,
          cash_due_amount
        )
        values (
          @requestId,
          @offerId,
          @customerId,
          @craftsmanId,
          @paymentMethod,
          @paymentStatus,
          @totalAmount,
          @inspectionAmount,
          @walletReserved,
          0
        )
        ''',
        parameters: {
          'requestId': requestId,
          'offerId': offerId,
          'customerId': customerId,
          'craftsmanId': offer['craftsman_id'],
          'paymentMethod': paymentMethod,
          'paymentStatus': paymentMethod == 'wallet'
              ? 'inspection_reserved'
              : 'accepted',
          'totalAmount': offer['total_amount'],
          'inspectionAmount': inspectionAmount,
          'walletReserved': walletReserved,
        },
      );
      await session.execute(
        '''
        update public.service_requests
        set accepted_offer_id = @offerId, status = 'accepted'
        where id = @requestId
        ''',
        parameters: {'requestId': requestId, 'offerId': offerId},
      );
      await session.execute(
        '''
        update public.request_dispatches
        set expires_at = least(expires_at, now())
        where request_id = @requestId
          and expires_at > now()
        ''',
        parameters: {'requestId': requestId},
      );
      await _closeRequestDispatchNotifications(
        session,
        requestId: requestId,
        status: 'accepted',
      );
      await _closeOfferNotifications(
        session,
        requestId: requestId,
        status: 'accepted',
      );
      await session.execute(
        '''
        update public.offers
        set status = case
          when id = @offerId then 'accepted'::public.offer_status
          else 'rejected'::public.offer_status
        end
        where request_id = @requestId and status = 'submitted'
        ''',
        parameters: {'requestId': requestId, 'offerId': offerId},
      );
      await session.execute(
        '''
        with cancelled_revisions as (
          update public.offer_revision_requests
          set
            status = 'cancelled',
            response_note = coalesce(
              response_note,
              'أُلغي بعد قبول عرض آخر للطلب.'
            ),
            responded_at = coalesce(responded_at, now())
          where request_id = @requestId
            and status = 'pending'
          returning id
        )
        update public.notifications notification
        set
          read_at = coalesce(notification.read_at, now()),
          data = notification.data || jsonb_build_object(
            'revision_status', 'cancelled',
            'actionable', false
          ),
          push_status = case
            when notification.push_status in ('pending', 'failed')
              then 'skipped'
            else notification.push_status
          end,
          push_error = case
            when notification.push_status in ('pending', 'failed')
              then 'Offer revision is no longer actionable.'
            else notification.push_error
          end
        from cancelled_revisions revision
        where notification.data ->> 'revision_id' = revision.id::text
        ''',
        parameters: {'requestId': requestId},
      );
      await session.execute(
        '''
        insert into public.request_status_events (request_id, status, actor_id)
        values (@requestId, 'accepted', @customerId)
        ''',
        parameters: {'requestId': requestId, 'customerId': customerId},
      );
      await session.execute(
        '''
        insert into public.notifications (profile_id, title, body, data)
        select
          o.craftsman_id,
          'تم قبول عرضك',
          'قبل العميل عرضك. يمكنك الآن التواصل ومتابعة العمل.',
          jsonb_build_object(
            'request_id', @requestId:uuid,
            'offer_id', @offerId:uuid,
            'notification_type', 'order'
          )
        from public.offers o
        where o.id = @offerId
        ''',
        parameters: {'requestId': requestId, 'offerId': offerId},
      );
    });
  }

  Future<void> advanceRequestStatus({
    required String craftsmanId,
    required String requestId,
    required String nextStatus,
    bool cashReceivedConfirmed = false,
  }) {
    const allowed = {
      'on_the_way': 'accepted',
      'started': 'on_the_way',
      'completed': 'started',
    };
    final expectedStatus = allowed[nextStatus];
    if (expectedStatus == null) {
      throw const PlatformRuleException(
        'حالة الطلب المطلوبة غير صالحة.',
        statusCode: 422,
      );
    }
    return db.runTx((session) async {
      final rows = await session.select(
        '''
        select
          sr.*,
          o.total_amount,
          rp.payment_method,
          rp.wallet_reserved_amount,
          rp.cash_due_amount,
          rp.status as payment_status
        from public.service_requests sr
        join public.offers o on o.id = sr.accepted_offer_id
        join public.request_payments rp on rp.request_id = sr.id
        where sr.id = @requestId
          and o.craftsman_id = @craftsmanId
        for update of sr, rp
        ''',
        parameters: {'requestId': requestId, 'craftsmanId': craftsmanId},
      );
      if (rows.isEmpty || rows.single['status']?.toString() != expectedStatus) {
        throw const PlatformRuleException(
          'تعذر تحديث الطلب؛ ربما تغيرت حالته.',
          statusCode: 409,
        );
      }
      final request = rows.single;
      final totalAmount = _money(request['total_amount']);
      var walletReserved = _money(request['wallet_reserved_amount']);
      var cashDue = _money(request['cash_due_amount']);

      if (nextStatus == 'started') {
        if (request['payment_method']?.toString() == 'wallet') {
          await session.execute(
            '''
            insert into public.wallets (profile_id)
            values (@customerId)
            on conflict do nothing
            ''',
            parameters: {'customerId': request['customer_id']},
          );
          final wallets = await session.select(
            '''
            select available_balance
            from public.wallets
            where profile_id = @customerId
            for update
            ''',
            parameters: {'customerId': request['customer_id']},
          );
          final available = _money(wallets.single['available_balance']);
          final remaining = (totalAmount - walletReserved).clamp(
            0.0,
            totalAmount,
          );
          final additionalReserved = available < remaining
              ? available
              : remaining;
          cashDue = remaining - additionalReserved;
          walletReserved += additionalReserved;
          if (additionalReserved > 0) {
            await session.execute(
              '''
              update public.wallets
              set available_balance = available_balance - @amount
              where profile_id = @customerId
              ''',
              parameters: {
                'customerId': request['customer_id'],
                'amount': additionalReserved,
              },
            );
            await session.execute(
              '''
              insert into public.wallet_transactions (
                profile_id,
                request_id,
                kind,
                status,
                amount,
                description,
                metadata
              )
              values (
                @customerId,
                @requestId,
                'payment',
                'pending',
                -cast(@amount as numeric),
                'حجز باقي قيمة الخدمة',
                jsonb_build_object('stage', 'work_started')
              )
              ''',
              parameters: {
                'customerId': request['customer_id'],
                'requestId': requestId,
                'amount': additionalReserved,
              },
            );
          }
        } else {
          walletReserved = 0;
          cashDue = totalAmount;
        }
        await session.execute(
          '''
          update public.request_payments
          set
            wallet_reserved_amount = @walletReserved,
            cash_due_amount = @cashDue,
            status = @paymentStatus,
            started_at = now()
          where request_id = @requestId
          ''',
          parameters: {
            'requestId': requestId,
            'walletReserved': walletReserved,
            'cashDue': cashDue,
            'paymentStatus': cashDue > 0
                ? 'awaiting_cash_confirmation'
                : 'fully_reserved',
          },
        );
        if (cashDue > 0) {
          await session.execute(
            '''
            insert into public.notifications (profile_id, title, body, data)
            values (
              @craftsmanId,
              'مبلغ كاش مطلوب عند الإكمال',
              @body,
              jsonb_build_object(
                'request_id', @requestId:uuid,
                'cash_due_amount', @cashDue:numeric,
                'notification_type', 'order'
              )
            )
            ''',
            parameters: {
              'craftsmanId': craftsmanId,
              'requestId': requestId,
              'cashDue': cashDue,
              'body':
                  'يرجى استلام ${cashDue.toStringAsFixed(2)} د.ل من العميل وتأكيد الاستلام قبل إكمال الطلب.',
            },
          );
        }
      }

      if (nextStatus == 'completed') {
        if (cashDue > 0 && !cashReceivedConfirmed) {
          throw PlatformRuleException(
            'أكد استلام مبلغ ${cashDue.toStringAsFixed(2)} د.ل كاش قبل إكمال الطلب.',
            statusCode: 422,
          );
        }
        await session.execute(
          '''
          update public.request_payments
          set
            status = 'settled',
            cash_received_confirmed = @cashConfirmed,
            cash_received_at = case
              when cast(@cashConfirmed as boolean) then now()
              else cash_received_at
            end,
            cash_received_by = case
              when cast(@cashConfirmed as boolean) then @craftsmanId
              else cash_received_by
            end,
            settled_at = now()
          where request_id = @requestId
          ''',
          parameters: {
            'requestId': requestId,
            'cashConfirmed': cashDue > 0 && cashReceivedConfirmed,
            'craftsmanId': craftsmanId,
          },
        );
      }

      await session.execute(
        '''
        update public.service_requests
        set status = cast(@nextStatus as public.service_request_status)
        where id = @requestId
        ''',
        parameters: {'requestId': requestId, 'nextStatus': nextStatus},
      );
      await session.execute(
        '''
        insert into public.request_status_events (request_id, status, actor_id)
        values (
          @requestId,
          cast(@nextStatus as public.service_request_status),
          @craftsmanId
        )
        ''',
        parameters: {
          'requestId': requestId,
          'nextStatus': nextStatus,
          'craftsmanId': craftsmanId,
        },
      );
      await session.execute(
        '''
        insert into public.notifications (profile_id, title, body, data)
        values (
          @customerId,
          @title,
          @body,
          jsonb_build_object(
            'request_id', @requestId:uuid,
            'notification_type', 'order'
          )
        )
        ''',
        parameters: {
          'customerId': request['customer_id'],
          'title': switch (nextStatus) {
            'on_the_way' => 'الحرفي في الطريق',
            'started' => 'بدأ تنفيذ الخدمة',
            _ => 'اكتملت الخدمة',
          },
          'body': switch (nextStatus) {
            'on_the_way' => 'الحرفي متجه الآن إلى عنوان الخدمة.',
            'started' =>
              cashDue > 0
                  ? 'بدأ العمل. تم حجز المتاح من المحفظة، والمتبقي كاش ${cashDue.toStringAsFixed(2)} د.ل.'
                  : 'تم تسجيل بدء العمل وحجز كامل قيمة الخدمة.',
            _ => 'تم تسجيل اكتمال الخدمة. يمكنك الآن إضافة تقييمك.',
          },
          'requestId': requestId,
        },
      );
      if (nextStatus == 'completed') {
        await session.execute(
          '''
          insert into public.wallets (profile_id)
          values (@craftsmanId)
          on conflict do nothing
          ''',
          parameters: {'craftsmanId': craftsmanId},
        );
        await session.execute(
          '''
          update public.wallets
          set
            pending_balance = pending_balance + @walletAmount,
            total_earned = total_earned + @totalAmount
          where profile_id = @craftsmanId
          ''',
          parameters: {
            'craftsmanId': craftsmanId,
            'walletAmount': walletReserved,
            'totalAmount': totalAmount,
          },
        );
        if (walletReserved > 0) {
          await session.execute(
            '''
            insert into public.wallet_transactions (
              profile_id,
              request_id,
              kind,
              status,
              amount,
              description,
              metadata
            )
            values (
              @craftsmanId,
              @requestId,
              'earning',
              'pending',
              @amount,
              'أرباح خدمة مدفوعة من المحفظة',
              jsonb_build_object('cash_received', @cashDue:numeric)
            )
            ''',
            parameters: {
              'craftsmanId': craftsmanId,
              'requestId': requestId,
              'amount': walletReserved,
              'cashDue': cashDue,
            },
          );
        }
        await session.execute(
          '''
          update public.wallet_transactions
          set status = 'completed'
          where profile_id = @customerId
            and request_id = @requestId
            and kind = 'payment'
            and status = 'pending'
          ''',
          parameters: {
            'customerId': request['customer_id'],
            'requestId': requestId,
          },
        );
        await session.execute(
          '''
          update public.craftsman_profiles
          set completed_jobs = completed_jobs + 1
          where profile_id = @craftsmanId
          ''',
          parameters: {'craftsmanId': craftsmanId},
        );
      }
    });
  }

  Future<Map<String, dynamic>> submitReview({
    required String customerId,
    required String requestId,
    required Map<String, dynamic> input,
  }) {
    return db.runTx((session) async {
      final requestRows = await session.select(
        '''
        select sr.id, o.craftsman_id
        from public.service_requests sr
        join public.offers o on o.id = sr.accepted_offer_id
        where sr.id = @requestId
          and sr.customer_id = @customerId
          and sr.status = 'completed'
        limit 1
        ''',
        parameters: {'requestId': requestId, 'customerId': customerId},
      );
      if (requestRows.isEmpty) {
        throw const PlatformRuleException(
          'لا يمكن تقييم هذا الطلب الآن.',
          statusCode: 409,
        );
      }
      final craftsmanId = requestRows.single['craftsman_id'];
      final rows = await session.select(
        '''
        insert into public.reviews (
          request_id,
          customer_id,
          craftsman_id,
          quality_rating,
          punctuality_rating,
          price_rating,
          communication_rating,
          cleanliness_rating,
          comment,
          complaint
        )
        values (
          @requestId,
          @customerId,
          @craftsmanId,
          @quality,
          @punctuality,
          @price,
          @communication,
          @cleanliness,
          @comment,
          @complaint
        )
        on conflict (request_id) do update
        set
          quality_rating = excluded.quality_rating,
          punctuality_rating = excluded.punctuality_rating,
          price_rating = excluded.price_rating,
          communication_rating = excluded.communication_rating,
          cleanliness_rating = excluded.cleanliness_rating,
          comment = excluded.comment,
          complaint = excluded.complaint
        returning *
        ''',
        parameters: {
          'requestId': requestId,
          'customerId': customerId,
          'craftsmanId': craftsmanId,
          'quality': input['quality_rating'],
          'punctuality': input['punctuality_rating'],
          'price': input['price_rating'],
          'communication': input['communication_rating'],
          'cleanliness': input['cleanliness_rating'],
          'comment': input['comment'],
          'complaint': input['complaint'],
        },
      );
      await session.execute(
        '''
        update public.craftsman_profiles cp
        set rating = ratings.average_rating
        from (
          select
            craftsman_id,
            round(
              avg(
                (
                  quality_rating +
                  punctuality_rating +
                  price_rating +
                  communication_rating +
                  cleanliness_rating
                )::numeric / 5
              ),
              2
            ) as average_rating
          from public.reviews
          where craftsman_id = @craftsmanId
          group by craftsman_id
        ) ratings
        where cp.profile_id = ratings.craftsman_id
        ''',
        parameters: {'craftsmanId': craftsmanId},
      );
      await session.execute(
        '''
        insert into public.notifications (profile_id, title, body, data)
        values (
          @craftsmanId,
          'تقييم جديد',
          'أضاف العميل تقييمًا لخدمتك المكتملة.',
          jsonb_build_object('request_id', @requestId:uuid)
        )
        ''',
        parameters: {'craftsmanId': craftsmanId, 'requestId': requestId},
      );
      return rows.single;
    });
  }

  Future<Map<String, dynamic>> submitCustomerReview({
    required String craftsmanId,
    required String requestId,
    required int rating,
    String? comment,
  }) {
    return db.runTx((session) async {
      final requestRows = await session.select(
        '''
        select sr.customer_id
        from public.service_requests sr
        join public.offers o on o.id = sr.accepted_offer_id
        where sr.id = @requestId
          and o.craftsman_id = @craftsmanId
          and sr.status = 'completed'
        limit 1
        ''',
        parameters: {'requestId': requestId, 'craftsmanId': craftsmanId},
      );
      if (requestRows.isEmpty) {
        throw const PlatformRuleException(
          'Cannot review this customer now.',
          statusCode: 409,
        );
      }
      final customerId = requestRows.single['customer_id'];
      final rows = await session.select(
        '''
        insert into public.customer_reviews (
          request_id,
          customer_id,
          craftsman_id,
          rating,
          comment
        )
        values (
          @requestId,
          @customerId,
          @craftsmanId,
          @rating,
          @comment
        )
        on conflict (request_id) do update
        set rating = excluded.rating,
            comment = excluded.comment
        returning *
        ''',
        parameters: {
          'requestId': requestId,
          'customerId': customerId,
          'craftsmanId': craftsmanId,
          'rating': rating,
          'comment': comment,
        },
      );
      return rows.single;
    });
  }

  Future<List<Map<String, dynamic>>> listNotifications(String profileId) {
    return db.run((session) async {
      await _deleteExpiredReadNotifications(session, profileId);
      return session.select(
        '''
        select *
        from public.notifications
        where profile_id = @profileId
        order by created_at desc
        limit 100
        ''',
        parameters: {'profileId': profileId},
      );
    });
  }

  Future<void> markNotificationsRead(String profileId, {String? id}) {
    return db.run((session) async {
      await session.execute(
        '''
        update public.notifications
        set read_at = coalesce(read_at, now())
        where profile_id = @profileId
          and (
            @notificationId:uuid is null
            or id = @notificationId:uuid
          )
        ''',
        parameters: {'profileId': profileId, 'notificationId': id},
      );
      await _deleteExpiredReadNotifications(session, profileId);
    });
  }

  Future<void> _deleteExpiredReadNotifications(
    MaestroDbSession session,
    String profileId,
  ) async {
    await session.execute(
      '''
      delete from public.notifications
      where profile_id = @profileId
        and read_at is not null
        and read_at <= now() - interval '30 seconds'
      ''',
      parameters: {'profileId': profileId},
    );
  }

  Future<Map<String, dynamic>> wallet(String profileId) {
    return db.run((session) async {
      final walletRows = await session.select(
        'select * from public.wallets where profile_id = @profileId',
        parameters: {'profileId': profileId},
      );
      final transactions = await session.select(
        '''
        select *
        from public.wallet_transactions
        where profile_id = @profileId
        order by created_at desc
        limit 100
        ''',
        parameters: {'profileId': profileId},
      );
      final topupMethods = await _loadWalletTopupMethods(session);
      return {
        'wallet': walletRows.isEmpty ? null : walletRows.single,
        'transactions': transactions,
        'topup_methods': topupMethods
            .where((method) => method.status != 'closed')
            .map((method) => method.toMap())
            .toList(growable: false),
      };
    });
  }

  Future<List<Map<String, dynamic>>> walletTopupMethods() {
    return db.run((session) async {
      final methods = await _loadWalletTopupMethods(session);
      return methods
          .where((method) => method.status != 'closed')
          .map((method) => method.toMap())
          .toList(growable: false);
    });
  }

  Future<List<Map<String, dynamic>>> adminWalletTopupMethods() {
    return db.run((session) async {
      final methods = await _loadWalletTopupMethods(session);
      return methods.map((method) => method.toMap()).toList(growable: false);
    });
  }

  Future<List<Map<String, dynamic>>> adminSetWalletTopupMethods({
    required String adminId,
    required List<Map<String, dynamic>> items,
  }) {
    if (items.isEmpty) {
      throw const PlatformRuleException(
        'أرسل طريقة شحن واحدة على الأقل.',
        statusCode: 422,
      );
    }
    return db.runTx((session) async {
      final rows = await session.select('''
        select value
        from public.app_settings
        where key = 'wallet_topup_methods'
        limit 1
        for update
        ''');
      final current = _walletTopupMethodsFromRaw(
        rows.isEmpty ? null : rows.single['value'],
      );
      final byId = {for (final method in current) method.id: method};
      final seenIds = <String>{};
      final changed = <Map<String, dynamic>>[];

      for (final input in items) {
        final id = input['id']?.toString().trim() ?? '';
        if (id.isEmpty || !byId.containsKey(id)) {
          throw PlatformRuleException(
            'طريقة الشحن "${id.isEmpty ? 'غير محددة' : id}" غير معروفة.',
            statusCode: 422,
          );
        }
        if (!seenIds.add(id)) {
          throw PlatformRuleException(
            'تكررت طريقة الشحن "$id" في الطلب.',
            statusCode: 422,
          );
        }

        final previous = byId[id]!;
        _validateWalletTopupImmutableFields(input, previous);
        var status = previous.status;
        if (input.containsKey('status')) {
          final candidate = input['status']?.toString().trim() ?? '';
          if (!_walletTopupStatuses.contains(candidate)) {
            throw const PlatformRuleException(
              'حالة طريقة الشحن يجب أن تكون open أو coming_soon أو closed.',
              statusCode: 422,
            );
          }
          status = candidate;
        }
        if (status == 'open' && !previous.integrated) {
          throw PlatformRuleException(
            'طريقة الشحن «${previous.titleAr}» غير مربوطة بالخادم بعد، لذلك يمكن ضبطها على قريبًا أو مغلقة فقط.',
            statusCode: 422,
          );
        }

        var sortOrder = previous.sortOrder;
        if (input.containsKey('sort_order')) {
          final candidate = input['sort_order'];
          final parsed = candidate is int
              ? candidate
              : candidate is num && candidate == candidate.roundToDouble()
              ? candidate.toInt()
              : int.tryParse(candidate?.toString() ?? '');
          if (parsed == null || parsed < -100000 || parsed > 100000) {
            throw const PlatformRuleException(
              'ترتيب طريقة الشحن غير صالح.',
              statusCode: 422,
            );
          }
          sortOrder = parsed;
        }

        final updated = previous.copyWith(status: status, sortOrder: sortOrder);
        byId[id] = updated;
        changed.add(updated.toMap());
      }

      final updated =
          _walletTopupMethodDefaults
              .map((method) => byId[method.id] ?? method)
              .toList(growable: false)
            ..sort(_compareWalletTopupMethods);
      await _storeWalletTopupMethods(
        session,
        adminId: adminId,
        methods: updated,
      );
      await _audit(
        session,
        adminId: adminId,
        action: 'settings.wallet_topup_methods.update',
        entityType: 'app_setting',
        entityId: 'wallet_topup_methods',
        details: {'items': changed},
      );
      return updated.map((method) => method.toMap()).toList(growable: false);
    });
  }

  Future<Map<String, dynamic>> redeemWalletCoupon({
    required String profileId,
    required String code,
  }) {
    if (!RegExp(r'^\d{13}$').hasMatch(code)) {
      throw const PlatformRuleException(
        'رمز الشحن يجب أن يتكون من 13 رقمًا.',
        statusCode: 422,
      );
    }
    return db.runTx((session) async {
      final coupons = await session.select(
        '''
        select *
        from public.wallet_topup_coupons
        where code = @code
        for update
        ''',
        parameters: {'code': code},
      );
      if (coupons.isEmpty) {
        throw const PlatformRuleException(
          'رمز شحن المحفظة غير صحيح.',
          statusCode: 404,
        );
      }
      final coupon = coupons.single;
      if (coupon['status'] != 'active') {
        throw const PlatformRuleException(
          'رمز الشحن مستخدم أو غير متاح.',
          statusCode: 409,
        );
      }
      final expiresAt = _dateOrNull(coupon['expires_at']);
      if (expiresAt != null && expiresAt.isBefore(DateTime.now().toUtc())) {
        throw const PlatformRuleException(
          'انتهت صلاحية رمز الشحن.',
          statusCode: 409,
        );
      }

      await session.execute(
        '''
        insert into public.wallets (profile_id)
        values (@profileId)
        on conflict (profile_id) do nothing
        ''',
        parameters: {'profileId': profileId},
      );
      await session.select(
        '''
        select profile_id
        from public.wallets
        where profile_id = @profileId
        for update
        ''',
        parameters: {'profileId': profileId},
      );
      await session.execute(
        '''
        update public.wallet_topup_coupons
        set
          status = 'redeemed',
          redeemed_by = @profileId,
          redeemed_at = now()
        where id = @couponId
        ''',
        parameters: {'couponId': coupon['id'], 'profileId': profileId},
      );
      final wallets = await session.select(
        '''
        update public.wallets
        set available_balance = available_balance + @amount
        where profile_id = @profileId
        returning *
        ''',
        parameters: {'profileId': profileId, 'amount': coupon['amount']},
      );
      final transactions = await session.select(
        '''
        insert into public.wallet_transactions (
          profile_id,
          coupon_id,
          kind,
          status,
          amount,
          description,
          metadata
        )
        values (
          @profileId,
          @couponId,
          'deposit',
          'completed',
          @amount,
          'شحن المحفظة بواسطة كوبون',
          jsonb_build_object('source', 'coupon')
        )
        returning *
        ''',
        parameters: {
          'profileId': profileId,
          'couponId': coupon['id'],
          'amount': coupon['amount'],
        },
      );
      await session.execute(
        '''
        insert into public.notifications (profile_id, title, body, data)
        values (
          @profileId,
          'تم شحن محفظتك',
          @body,
          jsonb_build_object(
            'type', 'wallet_topup',
            'transaction_id', @transactionId:uuid
          )
        )
        ''',
        parameters: {
          'profileId': profileId,
          'body': 'تمت إضافة ${coupon['amount']} د.ل إلى رصيد محفظتك.',
          'transactionId': transactions.single['id'],
        },
      );
      return {
        'wallet': wallets.single,
        'transaction': transactions.single,
        'amount': coupon['amount'],
      };
    });
  }

  Future<Map<String, dynamic>> registerNotificationDevice({
    required String profileId,
    required String platform,
    required String pushToken,
  }) {
    if (!{'android', 'ios', 'web'}.contains(platform)) {
      throw const PlatformRuleException(
        'نظام الجهاز غير مدعوم.',
        statusCode: 422,
      );
    }
    final token = pushToken.trim();
    if (token.length < 20 || token.length > 4096) {
      throw const PlatformRuleException(
        'رمز جهاز الإشعارات غير صالح.',
        statusCode: 422,
      );
    }
    return db.runTx((session) async {
      await session.execute(
        '''
        update public.notification_devices
        set enabled = false, last_seen_at = now()
        where profile_id = @profileId
          and platform = @platform
          and push_token <> @pushToken
        ''',
        parameters: {
          'profileId': profileId,
          'platform': platform,
          'pushToken': token,
        },
      );
      final rows = await session.select(
        '''
        insert into public.notification_devices (
          profile_id,
          platform,
          push_token,
          enabled,
          last_seen_at
        )
        values (
          @profileId,
          @platform,
          @pushToken,
          true,
          now()
        )
        on conflict (push_token) do update
        set
          profile_id = excluded.profile_id,
          platform = excluded.platform,
          enabled = true,
          last_seen_at = now()
        returning id, platform, enabled, last_seen_at
        ''',
        parameters: {
          'profileId': profileId,
          'platform': platform,
          'pushToken': token,
        },
      );
      return rows.single;
    });
  }

  Future<void> unregisterNotificationDevice({
    required String profileId,
    required String pushToken,
  }) {
    return db.run((session) async {
      await session.execute(
        '''
        update public.notification_devices
        set enabled = false, last_seen_at = now()
        where profile_id = @profileId
          and push_token = @pushToken
        ''',
        parameters: {'profileId': profileId, 'pushToken': pushToken.trim()},
      );
    });
  }

  Future<List<Map<String, dynamic>>> claimPushNotifications({int limit = 50}) {
    final safeLimit = limit.clamp(1, 100);
    return db.runTx(
      (session) => session.select(
        '''
        with claimed as (
          select n.id
          from public.notifications n
          join public.profiles p on p.id = n.profile_id
          left join public.notification_preferences np
            on np.profile_id = n.profile_id
          where n.push_attempts < 3
            and (
              p.status = 'active'
              or n.data ->> 'notification_type' = 'account_status'
            )
            and (
              p.notifications_enabled = true
              or n.data ->> 'notification_type' = 'account_status'
            )
            and (
              n.push_status = 'pending'
              or (
                n.push_status = 'failed'
                and coalesce(n.push_claimed_at, n.created_at)
                  <= now() - interval '30 seconds'
              )
              or (
                n.push_status = 'processing'
                and n.push_claimed_at
                  <= now() - interval '10 minutes'
              )
            )
            and (
              case
                when n.data ->> 'notification_type' = 'account_status'
                  then true
                when n.campaign_id is not null
                  or n.data ->> 'notification_type' = 'promotion'
                  then coalesce(np.promotions, true)
                when n.data ->> 'notification_type' = 'offer'
                  then coalesce(np.offers, true)
                when n.data ->> 'notification_type'
                  in ('message', 'chat', 'support')
                  then coalesce(np.messages, true)
                else coalesce(np.request_updates, true)
              end
            )
            and (
              (
                coalesce(n.data ->> 'dispatch_notification', 'false') <> 'true'
                and not (
                  n.data ->> 'notification_type' = 'order'
                  and n.title in (
                    'طلب خدمة جديد',
                    'إعادة إرسال طلب خدمة'
                  )
                )
              )
              or exists (
                select 1
                from public.service_requests active_request
                join public.request_dispatches active_dispatch
                  on active_dispatch.request_id = active_request.id
                 and active_dispatch.craftsman_id = n.profile_id
                where active_request.id::text = n.data ->> 'request_id'
                  and active_request.status in ('submitted', 'offers_received')
                  and active_request.accepted_offer_id is null
                  and active_request.expires_at > now()
                  and active_dispatch.offered_at is null
                  and active_dispatch.expires_at > now()
              )
            )
            and (
              coalesce(n.data ->> 'notification_type', '') <> 'offer'
              or exists (
                select 1
                from public.offers active_offer
                join public.service_requests active_request
                  on active_request.id = active_offer.request_id
                where active_offer.id::text = n.data ->> 'offer_id'
                  and active_request.id::text = n.data ->> 'request_id'
                  and active_offer.status = 'submitted'
                  and active_request.status in ('submitted', 'offers_received')
                  and active_request.accepted_offer_id is null
                  and active_request.expires_at > now()
              )
            )
          order by n.created_at
          limit @limit
          for update of n skip locked
        )
        update public.notifications n
        set
          push_status = 'processing',
          push_attempts = push_attempts + 1,
          push_claimed_at = now(),
          push_error = null
        from claimed
        where n.id = claimed.id
        returning
          n.id,
          n.profile_id,
          n.title,
          n.body,
          n.data,
          n.push_attempts,
          coalesce(
            (
              select jsonb_agg(
                jsonb_build_object(
                  'token', d.push_token,
                  'platform', d.platform
                )
              )
              from public.notification_devices d
              where d.profile_id = n.profile_id
                and d.enabled = true
            ),
            '[]'::jsonb
          ) as devices
        ''',
        parameters: {'limit': safeLimit},
      ),
    );
  }

  Future<void> completePushNotification({
    required String notificationId,
    required String status,
    String? error,
  }) {
    if (!{'sent', 'failed', 'skipped'}.contains(status)) {
      throw ArgumentError.value(status, 'status');
    }
    return db.run((session) async {
      await session.execute(
        '''
        update public.notifications
        set
          push_status = @status,
          push_sent_at = case when @status = 'sent' then now() else null end,
          push_error = @error
        where id = @notificationId
          and push_status = 'processing'
        ''',
        parameters: {
          'notificationId': notificationId,
          'status': status,
          'error': error,
        },
      );
    });
  }

  Future<void> disablePushToken(String token) {
    return db.run((session) async {
      await session.execute(
        '''
        update public.notification_devices
        set enabled = false, last_seen_at = now()
        where push_token = @pushToken
        ''',
        parameters: {'pushToken': token},
      );
    });
  }

  Future<void> updateAvailability(String profileId, bool available) {
    return db.run((session) async {
      await session.execute(
        '''
        update public.craftsman_profiles
        set is_available = @available
        where profile_id = @profileId
        ''',
        parameters: {'profileId': profileId, 'available': available},
      );
    });
  }

  Future<void> updateCraftsmanLocation({
    required String profileId,
    required num latitude,
    required num longitude,
  }) {
    return db.run((session) async {
      final updated = await session.execute(
        '''
        update public.craftsman_profiles
        set
          last_latitude = @latitude,
          last_longitude = @longitude,
          location_updated_at = now()
        where profile_id = @profileId
        ''',
        parameters: {
          'profileId': profileId,
          'latitude': latitude,
          'longitude': longitude,
        },
      );
      if (updated == 0) {
        throw const PlatformRuleException(
          'أكمل ملف الحرفي قبل تحديث الموقع.',
          statusCode: 409,
        );
      }
    });
  }

  Future<Map<String, dynamic>> updateNotificationPreferences({
    required String profileId,
    required Map<String, dynamic> input,
  }) {
    return db.run((session) async {
      final rows = await session.select(
        '''
        update public.notification_preferences
        set
          offers = coalesce(@offers, offers),
          request_updates = coalesce(@requestUpdates, request_updates),
          messages = coalesce(@messages, messages),
          promotions = coalesce(@promotions, promotions)
        where profile_id = @profileId
        returning *
        ''',
        parameters: {
          'profileId': profileId,
          'offers': input['offers'],
          'requestUpdates': input['request_updates'],
          'messages': input['messages'],
          'promotions': input['promotions'],
        },
      );
      return rows.single;
    });
  }

  Future<Map<String, dynamic>> createSupportTicket({
    required String profileId,
    required Map<String, dynamic> input,
  }) {
    return createOrGetSupportConversation(
      profileId: profileId,
      input: {...input, 'message': input['message'] ?? input['body']},
    );
  }

  Future<Map<String, dynamic>?> currentSupportConversation(String profileId) {
    return db.run((session) async {
      final rows = await session.select(
        '''
        select
          st.*,
          (
            select sm.body
            from public.support_messages sm
            where sm.conversation_id = st.id
            order by sm.created_at desc
            limit 1
          ) as last_message
        from public.support_tickets st
        where st.profile_id = @profileId
          and st.status in ('open', 'in_progress')
        order by st.last_message_at desc nulls last, st.created_at desc
        limit 1
        ''',
        parameters: {'profileId': profileId},
      );
      return rows.isEmpty ? null : rows.single;
    });
  }

  Future<Map<String, dynamic>> createOrGetSupportConversation({
    required String profileId,
    required Map<String, dynamic> input,
  }) {
    return db.runTx((session) async {
      // Serializes the "one current conversation per profile" decision without
      // forcing a destructive cleanup of legacy duplicate tickets.
      await session.select(
        '''
        select pg_advisory_xact_lock(
          hashtextextended(cast(@profileId as text), 0)
        )
        ''',
        parameters: {'profileId': profileId},
      );

      final requestId = input['request_id']?.toString().trim();
      if (requestId != null && requestId.isNotEmpty) {
        final participant = await session.select(
          '''
          select sr.id
          from public.service_requests sr
          left join public.offers o on o.id = sr.accepted_offer_id
          where sr.id = @requestId
            and (
              sr.customer_id = @profileId
              or o.craftsman_id = @profileId
            )
          limit 1
          ''',
          parameters: {'requestId': requestId, 'profileId': profileId},
        );
        if (participant.isEmpty) {
          throw const PlatformRuleException(
            'لا يمكنك ربط محادثة الدعم بهذا الطلب.',
            statusCode: 403,
          );
        }
      }

      var conversations = await session.select(
        '''
        select *
        from public.support_tickets
        where profile_id = @profileId
          and status in ('open', 'in_progress')
        order by last_message_at desc nulls last, created_at desc
        limit 1
        for update
        ''',
        parameters: {'profileId': profileId},
      );
      final created = conversations.isEmpty;
      if (created) {
        conversations = await session.select(
          '''
          insert into public.support_tickets (
            profile_id,
            request_id,
            subject,
            body,
            priority,
            last_message_at
          )
          values (
            @profileId,
            cast(@requestId as uuid),
            @subject,
            @body,
            @priority,
            now()
          )
          returning *
          ''',
          parameters: {
            'profileId': profileId,
            'requestId': requestId?.isEmpty == true ? null : requestId,
            'subject': input['subject']?.toString().trim().isNotEmpty == true
                ? input['subject'].toString().trim()
                : 'محادثة الدعم',
            'body': input['message']?.toString().trim() ?? '',
            'priority': input['priority'] ?? 'normal',
          },
        );
      }

      final conversation = conversations.single;
      final conversationId = conversation['id'].toString();
      final message = input['message']?.toString().trim() ?? '';
      if (message.isNotEmpty) {
        await session.execute(
          '''
          insert into public.support_messages (
            conversation_id,
            sender_id,
            sender_type,
            body
          )
          values (@conversationId, @profileId, 'user', @body)
          ''',
          parameters: {
            'conversationId': conversationId,
            'profileId': profileId,
            'body': message,
          },
        );
      }
      if (created) {
        await session.execute(
          '''
          insert into public.support_messages (
            conversation_id,
            sender_type,
            body
          )
          values (
            @conversationId,
            'system',
            'وعليكم السلام، كيف نقدروا نساعدوك؟ 💛'
          )
          ''',
          parameters: {'conversationId': conversationId},
        );
      }
      await session.execute(
        '''
        update public.support_tickets
        set last_message_at = now()
        where id = @conversationId
        ''',
        parameters: {'conversationId': conversationId},
      );
      if (created || message.isNotEmpty) {
        await session.execute(
          '''
          insert into public.notifications (profile_id, title, body, data)
          select
            p.id,
            'محادثة دعم جديدة',
            @body,
            jsonb_build_object(
              'support_conversation_id', @conversationId:uuid,
              'notification_type', 'support'
            )
          from public.profiles p
          where p.role = 'admin'
            and p.status = 'active'
          ''',
          parameters: {
            'conversationId': conversationId,
            'body': message.isNotEmpty
                ? message
                : 'فتح مستخدم محادثة دعم جديدة.',
          },
        );
      }
      return conversation;
    });
  }

  Future<List<Map<String, dynamic>>> supportConversationMessages({
    required String profileId,
    required String role,
    required String conversationId,
  }) {
    return db.run((session) async {
      await _assertSupportConversationAccess(
        session,
        profileId: profileId,
        role: role,
        conversationId: conversationId,
      );
      await session.execute(
        '''
        update public.support_messages
        set read_at = coalesce(read_at, now())
        where conversation_id = @conversationId
          and sender_type <> @readerType
        ''',
        parameters: {
          'conversationId': conversationId,
          'readerType': role == 'admin' ? 'admin' : 'user',
        },
      );
      return session.select(
        '''
        select
          sm.*,
          p.full_name as sender_name,
          p.avatar_url as sender_avatar,
          p.role as sender_role
        from public.support_messages sm
        left join public.profiles p on p.id = sm.sender_id
        where sm.conversation_id = @conversationId
        order by sm.created_at, sm.id
        ''',
        parameters: {'conversationId': conversationId},
      );
    });
  }

  Future<Map<String, dynamic>> sendSupportConversationMessage({
    required String profileId,
    required String role,
    required String conversationId,
    required Map<String, dynamic> input,
  }) {
    return db.runTx((session) async {
      final conversation = await _assertSupportConversationAccess(
        session,
        profileId: profileId,
        role: role,
        conversationId: conversationId,
        lock: true,
      );
      if (!{'open', 'in_progress'}.contains(conversation['status'])) {
        throw const PlatformRuleException(
          'تم إغلاق محادثة الدعم ولا يمكن إرسال رسائل جديدة.',
          statusCode: 409,
        );
      }
      await _assertOwnedManagedAttachment(
        session,
        ownerId: profileId,
        publicUrl: input['attachment_url'],
        providerPublicId: input['attachment_public_id'],
        resourceType: input['attachment_resource_type'],
        expectedPurpose: 'support',
      );
      final senderType = role == 'admin' ? 'admin' : 'user';
      final rows = await session.select(
        '''
        insert into public.support_messages (
          conversation_id,
          sender_id,
          sender_type,
          body,
          attachment_url,
          attachment_type,
          attachment_public_id,
          attachment_resource_type
        )
        values (
          @conversationId,
          @profileId,
          @senderType,
          @body,
          @attachmentUrl,
          @attachmentType,
          @attachmentPublicId,
          @attachmentResourceType
        )
        returning *
        ''',
        parameters: {
          'conversationId': conversationId,
          'profileId': profileId,
          'senderType': senderType,
          'body': input['body']?.toString().trim() ?? '',
          'attachmentUrl': input['attachment_url'],
          'attachmentType': input['attachment_type'],
          'attachmentPublicId': input['attachment_public_id'],
          'attachmentResourceType':
              input['attachment_resource_type'] ??
              (input['attachment_type'] == 'audio'
                  ? 'video'
                  : input['attachment_url'] != null
                  ? 'image'
                  : null),
        },
      );
      await _consumeOwnedManagedAttachment(
        session,
        ownerId: profileId,
        publicUrl: input['attachment_url'],
        providerPublicId: input['attachment_public_id'],
        resourceType: input['attachment_resource_type'],
        expectedPurpose: 'support',
        consumedByType: 'support_message',
        consumedById: rows.single['id'],
      );
      await session.execute(
        '''
        update public.support_tickets
        set
          status = case
            when cast(@senderType as text) = 'admin' then 'in_progress'
            else status
          end,
          assigned_admin_id = case
            when cast(@senderType as text) = 'admin' then @profileId
            else assigned_admin_id
          end,
          last_message_at = now()
        where id = @conversationId
        ''',
        parameters: {
          'senderType': senderType,
          'profileId': profileId,
          'conversationId': conversationId,
        },
      );

      if (role == 'admin') {
        await session.execute(
          '''
          insert into public.notifications (profile_id, title, body, data)
          values (
            @recipientId,
            'رد جديد من الدعم',
            @body,
            jsonb_build_object(
              'support_conversation_id', @conversationId:uuid,
              'notification_type', 'support'
            )
          )
          ''',
          parameters: {
            'recipientId': conversation['profile_id'],
            'conversationId': conversationId,
            'body': input['body']?.toString().trim().isNotEmpty == true
                ? input['body'].toString().trim()
                : 'أرسل فريق الدعم مرفقًا جديدًا.',
          },
        );
        await _audit(
          session,
          adminId: profileId,
          action: 'support_conversation.reply',
          entityType: 'support_conversation',
          entityId: conversationId,
        );
      } else {
        await session.execute(
          '''
          insert into public.notifications (profile_id, title, body, data)
          select
            p.id,
            'رسالة دعم جديدة',
            @body,
            jsonb_build_object(
              'support_conversation_id', @conversationId:uuid,
              'notification_type', 'support'
            )
          from public.profiles p
          where p.role = 'admin'
            and p.status = 'active'
            and (
              @assignedAdminId:uuid is null
              or p.id = @assignedAdminId:uuid
            )
          ''',
          parameters: {
            'conversationId': conversationId,
            'assignedAdminId': conversation['assigned_admin_id'],
            'body': input['body']?.toString().trim().isNotEmpty == true
                ? input['body'].toString().trim()
                : 'أرسل المستخدم مرفقًا جديدًا.',
          },
        );
      }
      return rows.single;
    });
  }

  Future<void> closeSupportConversation({
    required String profileId,
    required String role,
    required String conversationId,
  }) {
    return db.runTx((session) async {
      final conversation = await _assertSupportConversationAccess(
        session,
        profileId: profileId,
        role: role,
        conversationId: conversationId,
        lock: true,
      );
      await session.execute(
        '''
        update public.support_tickets
        set
          status = 'closed',
          closed_at = coalesce(closed_at, now()),
          assigned_admin_id = case
            when cast(@isAdmin as boolean) then @profileId
            else assigned_admin_id
          end
        where id = @conversationId
        ''',
        parameters: {
          'conversationId': conversationId,
          'profileId': profileId,
          'isAdmin': role == 'admin',
        },
      );
      if (role == 'admin') {
        await _audit(
          session,
          adminId: profileId,
          action: 'support_conversation.close',
          entityType: 'support_conversation',
          entityId: conversationId,
          details: {'owner_id': conversation['profile_id']},
        );
      }
    });
  }

  Future<List<Map<String, dynamic>>> adminSupportTickets() {
    return db.run(
      (session) => session.select('''
        select
          st.*,
          p.full_name,
          p.phone,
          p.role,
          (
            select sm.body
            from public.support_messages sm
            where sm.conversation_id = st.id
            order by sm.created_at desc
            limit 1
          ) as last_message,
          (
            select count(*)::int
            from public.support_messages sm
            where sm.conversation_id = st.id
              and sm.sender_type = 'user'
              and sm.read_at is null
          ) as unread_count
        from public.support_tickets st
        join public.profiles p on p.id = st.profile_id
        order by
          case st.priority
            when 'urgent' then 1
            when 'high' then 2
            when 'normal' then 3
            else 4
          end,
          st.last_message_at desc nulls last,
          st.created_at desc
        limit 500
        '''),
    );
  }

  Future<void> adminUpdateSupportTicket({
    required String adminId,
    required String ticketId,
    required String status,
    required String priority,
  }) {
    const statuses = {'open', 'in_progress', 'resolved', 'closed'};
    const priorities = {'low', 'normal', 'high', 'urgent'};
    if (!statuses.contains(status) || !priorities.contains(priority)) {
      throw const PlatformRuleException(
        'حالة تذكرة الدعم غير صحيحة.',
        statusCode: 422,
      );
    }
    return db.runTx((session) async {
      final rows = await session.select(
        '''
        update public.support_tickets
        set
          status = @status,
          priority = @priority,
          assigned_admin_id = @adminId,
          closed_at = case
            when @status in ('resolved', 'closed')
              then coalesce(closed_at, now())
            else null
          end
        where id = @ticketId
        returning id, profile_id, public_code
        ''',
        parameters: {
          'adminId': adminId,
          'ticketId': ticketId,
          'status': status,
          'priority': priority,
        },
      );
      if (rows.isEmpty) {
        throw const PlatformRuleException(
          'تذكرة الدعم غير موجودة.',
          statusCode: 404,
        );
      }
      await session.execute(
        '''
        insert into public.notifications (profile_id, title, body, data)
        values (
          @profileId,
          'تحديث تذكرة الدعم',
          @body,
          jsonb_build_object('support_ticket_id', @ticketId:uuid)
        )
        ''',
        parameters: {
          'profileId': rows.single['profile_id'],
          'ticketId': ticketId,
          'body':
              'تم تحديث التذكرة ${rows.single['public_code']} إلى الحالة $status.',
        },
      );
      await _audit(
        session,
        adminId: adminId,
        action: 'support_ticket.update',
        entityType: 'support_ticket',
        entityId: ticketId,
        details: {'status': status, 'priority': priority},
      );
    });
  }

  Future<List<Map<String, dynamic>>> listMessages({
    required String profileId,
    required String requestId,
  }) {
    return db.run((session) async {
      await _assertRequestParticipant(session, profileId, requestId);
      return session.select(
        '''
        select
          m.*,
          p.full_name as sender_name,
          p.avatar_url as sender_avatar
        from public.job_messages m
        left join public.profiles p on p.id = m.sender_id
        where m.request_id = @requestId
        order by m.created_at
        ''',
        parameters: {'requestId': requestId},
      );
    });
  }

  Future<Map<String, dynamic>> sendMessage({
    required String profileId,
    required String role,
    required String requestId,
    required Map<String, dynamic> input,
  }) {
    return db.runTx((session) async {
      final participant = await _assertRequestParticipant(
        session,
        profileId,
        requestId,
      );
      if ({'completed', 'cancelled'}.contains(participant['status'])) {
        throw const PlatformRuleException(
          'انتهى هذا الطلب، لذلك لا يمكن إرسال رسائل أو مرفقات جديدة.',
          statusCode: 409,
        );
      }
      await _assertOwnedManagedAttachment(
        session,
        ownerId: profileId,
        publicUrl: input['attachment_url'],
        providerPublicId: input['attachment_public_id'],
        resourceType: input['attachment_resource_type'],
        expectedPurpose: input['attachment_type'] == 'audio'
            ? 'chat-voice'
            : 'chat',
      );
      final rows = await session.select(
        '''
        insert into public.job_messages (
          request_id,
          sender_id,
          sender_type,
          body,
          attachment_url,
          attachment_type,
          attachment_public_id,
          attachment_resource_type
        )
        values (
          @requestId,
          @profileId,
          @senderType,
          @body,
          @attachmentUrl,
          @attachmentType,
          @attachmentPublicId,
          @attachmentResourceType
        )
        returning *
        ''',
        parameters: {
          'requestId': requestId,
          'profileId': profileId,
          'senderType': role,
          'body': input['body'],
          'attachmentUrl': input['attachment_url'],
          'attachmentType': input['attachment_type'],
          'attachmentPublicId': input['attachment_public_id'],
          'attachmentResourceType':
              input['attachment_resource_type'] ??
              (input['attachment_type'] == 'audio'
                  ? 'video'
                  : input['attachment_url'] != null
                  ? 'image'
                  : null),
        },
      );
      await _consumeOwnedManagedAttachment(
        session,
        ownerId: profileId,
        publicUrl: input['attachment_url'],
        providerPublicId: input['attachment_public_id'],
        resourceType: input['attachment_resource_type'],
        expectedPurpose: input['attachment_type'] == 'audio'
            ? 'chat-voice'
            : 'chat',
        consumedByType: 'job_message',
        consumedById: rows.single['id'],
      );
      final targetId = role == 'customer'
          ? participant['craftsman_id']
          : participant['customer_id'];
      if (targetId != null) {
        await session.execute(
          '''
          insert into public.notifications (profile_id, title, body, data)
          values (
            @targetId,
            'رسالة جديدة',
            @body,
            jsonb_build_object(
              'request_id', @requestId:uuid,
              'notification_type', 'message'
            )
          )
          ''',
          parameters: {
            'targetId': targetId,
            'body': input['body'],
            'requestId': requestId,
          },
        );
      }
      return rows.single;
    });
  }

  Future<List<Map<String, dynamic>>> adminWalletCoupons({
    String? status,
    String? search,
  }) {
    final normalizedStatus = status?.trim().toLowerCase();
    if (normalizedStatus != null &&
        normalizedStatus.isNotEmpty &&
        !{'active', 'redeemed', 'disabled'}.contains(normalizedStatus)) {
      throw const PlatformRuleException(
        'حالة الكوبون غير صالحة.',
        statusCode: 422,
      );
    }
    return db.run(
      (session) => session.select(
        '''
        select
          c.*,
          creator.full_name as created_by_name,
          redeemer.full_name as redeemed_by_name,
          redeemer.phone as redeemed_by_phone
        from public.wallet_topup_coupons c
        left join public.profiles creator on creator.id = c.created_by
        left join public.profiles redeemer on redeemer.id = c.redeemed_by
        where (
          cast(@status as text) is null
          or cast(@status as text) = ''
          or c.status = cast(@status as text)
        )
          and (
            cast(@search as text) is null
            or cast(@search as text) = ''
            or c.code like '%' || cast(@search as text) || '%'
            or redeemer.phone like '%' || cast(@search as text) || '%'
          )
        order by c.created_at desc
        limit 500
        ''',
        parameters: {'status': normalizedStatus, 'search': search?.trim()},
      ),
    );
  }

  Future<List<Map<String, dynamic>>> adminCreateWalletCoupons({
    required String adminId,
    required num amount,
    required int quantity,
    DateTime? expiresAt,
  }) {
    if (amount <= 0 || amount > 1000000) {
      throw const PlatformRuleException(
        'قيمة الكوبون يجب أن تكون أكبر من صفر.',
        statusCode: 422,
      );
    }
    if (quantity < 1 || quantity > 100) {
      throw const PlatformRuleException(
        'يمكن إنشاء من 1 إلى 100 كوبون في المرة الواحدة.',
        statusCode: 422,
      );
    }
    if (expiresAt != null &&
        !expiresAt.toUtc().isAfter(DateTime.now().toUtc())) {
      throw const PlatformRuleException(
        'تاريخ انتهاء الكوبون يجب أن يكون في المستقبل.',
        statusCode: 422,
      );
    }
    return db.runTx((session) async {
      final created = <Map<String, dynamic>>[];
      var remainingAttempts = quantity * 10;
      while (created.length < quantity && remainingAttempts > 0) {
        remainingAttempts--;
        final rows = await session.select(
          '''
          insert into public.wallet_topup_coupons (
            code,
            amount,
            created_by,
            expires_at
          )
          values (
            @code,
            @amount,
            @adminId,
            @expiresAt
          )
          on conflict (code) do nothing
          returning *
          ''',
          parameters: {
            'code': _newCouponCode(),
            'amount': amount,
            'adminId': adminId,
            'expiresAt': expiresAt?.toUtc(),
          },
        );
        if (rows.isNotEmpty) created.add(rows.single);
      }
      if (created.length != quantity) {
        throw const PlatformRuleException(
          'تعذر إنشاء رموز فريدة. حاول مرة أخرى.',
          statusCode: 503,
        );
      }
      await _audit(
        session,
        adminId: adminId,
        action: 'wallet_coupon.create',
        entityType: 'wallet_topup_coupon',
        details: {
          'amount': amount,
          'quantity': quantity,
          'expires_at': expiresAt?.toUtc().toIso8601String(),
        },
      );
      return created;
    });
  }

  Future<void> adminDeleteWalletCoupon({
    required String adminId,
    required String couponId,
  }) {
    return db.runTx((session) async {
      final rows = await session.select(
        '''
        delete from public.wallet_topup_coupons
        where id = @couponId
          and status = 'active'
          and redeemed_at is null
        returning id, code, amount
        ''',
        parameters: {'couponId': couponId},
      );
      if (rows.isEmpty) {
        throw const PlatformRuleException(
          'الكوبون غير موجود أو تم استخدامه ولا يمكن حذفه.',
          statusCode: 409,
        );
      }
      await _audit(
        session,
        adminId: adminId,
        action: 'wallet_coupon.delete',
        entityType: 'wallet_topup_coupon',
        entityId: couponId,
        details: {'code': rows.single['code'], 'amount': rows.single['amount']},
      );
    });
  }

  Future<Map<String, dynamic>> adminFindWalletByPhone(String phone) {
    return db.run((session) async {
      final rows = await session.select(
        '''
        select
          p.id,
          p.phone,
          p.full_name,
          p.role,
          p.status,
          coalesce(w.available_balance, 0) as available_balance,
          coalesce(w.pending_balance, 0) as pending_balance,
          coalesce(w.total_earned, 0) as total_earned,
          coalesce(w.currency, 'LYD') as currency
        from public.profiles p
        left join public.wallets w on w.profile_id = p.id
        where p.phone = @phone
          and p.role in ('customer', 'craftsman')
          and p.status <> 'deleted'
        limit 1
        ''',
        parameters: {'phone': phone},
      );
      if (rows.isEmpty) {
        throw const PlatformRuleException(
          'لا يوجد مستخدم أو حرفي بهذا الرقم.',
          statusCode: 404,
        );
      }
      return rows.single;
    });
  }

  Future<Map<String, dynamic>> adminTopUpWallet({
    required String adminId,
    required String phone,
    required num amount,
    String? note,
  }) {
    if (amount <= 0 || amount > 1000000) {
      throw const PlatformRuleException(
        'قيمة الشحن يجب أن تكون أكبر من صفر.',
        statusCode: 422,
      );
    }
    return db.runTx((session) async {
      final profiles = await session.select(
        '''
        select id, phone, full_name, role, status
        from public.profiles
        where phone = @phone
          and role in ('customer', 'craftsman')
          and status <> 'deleted'
        limit 1
        ''',
        parameters: {'phone': phone},
      );
      if (profiles.isEmpty) {
        throw const PlatformRuleException(
          'لا يوجد مستخدم أو حرفي بهذا الرقم.',
          statusCode: 404,
        );
      }
      final profile = profiles.single;
      if (profile['status'] != 'active') {
        throw const PlatformRuleException(
          'لا يمكن شحن محفظة حساب غير نشط.',
          statusCode: 409,
        );
      }
      final profileId = profile['id'].toString();
      await session.execute(
        '''
        insert into public.wallets (profile_id)
        values (@profileId)
        on conflict (profile_id) do nothing
        ''',
        parameters: {'profileId': profileId},
      );
      await session.select(
        '''
        select profile_id
        from public.wallets
        where profile_id = @profileId
        for update
        ''',
        parameters: {'profileId': profileId},
      );
      final wallets = await session.select(
        '''
        update public.wallets
        set available_balance = available_balance + @amount
        where profile_id = @profileId
        returning *
        ''',
        parameters: {'profileId': profileId, 'amount': amount},
      );
      final transactions = await session.select(
        '''
        insert into public.wallet_transactions (
          profile_id,
          kind,
          status,
          amount,
          description,
          metadata
        )
        values (
          @profileId,
          'deposit',
          'completed',
          @amount,
          @description,
          jsonb_build_object(
            'source', 'admin',
            'admin_id', @adminId:text
          )
        )
        returning *
        ''',
        parameters: {
          'profileId': profileId,
          'amount': amount,
          'description': note?.trim().isNotEmpty == true
              ? note!.trim()
              : 'شحن المحفظة من الإدارة',
          'adminId': adminId,
        },
      );
      await session.execute(
        '''
        insert into public.notifications (profile_id, title, body, data)
        values (
          @profileId,
          'تم شحن محفظتك',
          @body,
          jsonb_build_object(
            'type', 'wallet_topup',
            'transaction_id', @transactionId:uuid
          )
        )
        ''',
        parameters: {
          'profileId': profileId,
          'body': 'أضافت الإدارة $amount د.ل إلى رصيد محفظتك.',
          'transactionId': transactions.single['id'],
        },
      );
      await _audit(
        session,
        adminId: adminId,
        action: 'wallet.top_up',
        entityType: 'profile',
        entityId: profileId,
        details: {'amount': amount, 'note': note},
      );
      return {
        'profile': profile,
        'wallet': wallets.single,
        'transaction': transactions.single,
      };
    });
  }

  Future<Map<String, dynamic>> adminRequests({
    String? status,
    String? categoryId,
    String? paymentMethod,
    String? search,
    int page = 1,
    int perPage = 30,
  }) {
    final offset = (page - 1) * perPage;
    return db.run((session) async {
      final rows = await session.select(
        '''
        select
          sr.*,
          sc.name_ar as category_name,
          customer.full_name as customer_name,
          customer.phone as customer_phone,
          craftsman.full_name as craftsman_name,
          craftsman.phone as craftsman_phone,
          o.total_amount as offer_total_amount,
          o.inspection_fee,
          rp.status as payment_status,
          rp.wallet_reserved_amount,
          rp.cash_due_amount,
          count(*) over()::int as total_count
        from public.service_requests sr
        join public.service_categories sc on sc.id = sr.category_id
        join public.profiles customer on customer.id = sr.customer_id
        left join public.offers o on o.id = sr.accepted_offer_id
        left join public.profiles craftsman on craftsman.id = o.craftsman_id
        left join public.request_payments rp on rp.request_id = sr.id
        where (
          cast(@status as text) is null
          or sr.status::text = cast(@status as text)
        )
          and (
            cast(@categoryId as text) is null
            or sr.category_id = cast(@categoryId as text)
          )
          and (
            cast(@paymentMethod as text) is null
            or sr.payment_method = cast(@paymentMethod as text)
          )
          and (
            cast(@search as text) is null
            or sr.public_code ilike '%' || cast(@search as text) || '%'
            or sr.title ilike '%' || cast(@search as text) || '%'
            or customer.phone ilike '%' || cast(@search as text) || '%'
            or coalesce(customer.full_name, '') ilike
              '%' || cast(@search as text) || '%'
            or coalesce(craftsman.phone, '') ilike
              '%' || cast(@search as text) || '%'
            or coalesce(craftsman.full_name, '') ilike
              '%' || cast(@search as text) || '%'
          )
        order by sr.created_at desc
        limit @limit offset @offset
        ''',
        parameters: {
          'status': status?.trim().isEmpty == true ? null : status?.trim(),
          'categoryId': categoryId?.trim().isEmpty == true
              ? null
              : categoryId?.trim(),
          'paymentMethod': paymentMethod?.trim().isEmpty == true
              ? null
              : paymentMethod?.trim(),
          'search': search?.trim().isEmpty == true ? null : search?.trim(),
          'limit': perPage,
          'offset': offset,
        },
      );
      final total = rows.isEmpty ? 0 : (rows.first['total_count'] as int? ?? 0);
      final data = rows
          .map((row) => Map<String, dynamic>.from(row)..remove('total_count'))
          .toList(growable: false);
      return {
        'data': data,
        'meta': {
          'page': page,
          'per_page': perPage,
          'total': total,
          'total_pages': total == 0 ? 0 : (total / perPage).ceil(),
        },
      };
    });
  }

  Future<Map<String, dynamic>> adminCancelRequest({
    required String adminId,
    required String requestId,
    required String mode,
    required String reason,
  }) {
    if (!const {'inspection_due', 'no_entitlement'}.contains(mode)) {
      throw const PlatformRuleException(
        'طريقة إلغاء الطلب غير صحيحة.',
        statusCode: 422,
      );
    }
    return db.runTx((session) async {
      final requestRows = await session.select(
        '''
        select *
        from public.service_requests
        where id = @requestId
        for update
        ''',
        parameters: {'requestId': requestId},
      );
      if (requestRows.isEmpty) {
        throw const PlatformRuleException('الطلب غير موجود.', statusCode: 404);
      }
      final serviceRequest = requestRows.single;
      final previousStatus = serviceRequest['status']?.toString();
      if (previousStatus == 'cancelled') {
        throw const PlatformRuleException(
          'الطلب ملغى بالفعل.',
          statusCode: 409,
        );
      }
      if (previousStatus == 'completed') {
        throw const PlatformRuleException(
          'لا يمكن إلغاء طلب مكتمل. استخدم إجراء تسوية منفصل.',
          statusCode: 409,
        );
      }

      Map<String, dynamic>? offer;
      if (serviceRequest['accepted_offer_id'] != null) {
        final offerRows = await session.select(
          '''
          select *
          from public.offers
          where id = @offerId
          for update
          ''',
          parameters: {'offerId': serviceRequest['accepted_offer_id']},
        );
        if (offerRows.isNotEmpty) offer = offerRows.single;
      }
      Map<String, dynamic>? payment;
      final paymentRows = await session.select(
        '''
        select *
        from public.request_payments
        where request_id = @requestId
        for update
        ''',
        parameters: {'requestId': requestId},
      );
      if (paymentRows.isNotEmpty) payment = paymentRows.single;

      final inspectionDue = mode == 'inspection_due' && offer != null
          ? _money(offer['inspection_fee'])
          : 0.0;
      final walletReserved = payment == null
          ? 0.0
          : _money(payment['wallet_reserved_amount']);
      final walletEntitlement = walletReserved < inspectionDue
          ? walletReserved
          : inspectionDue;
      final walletRefund = walletReserved - walletEntitlement;
      final cashDue = inspectionDue - walletEntitlement;
      final customerId = serviceRequest['customer_id'].toString();
      final craftsmanId = offer?['craftsman_id']?.toString();

      if (walletRefund > 0) {
        await session.execute(
          '''
          update public.wallets
          set available_balance = available_balance + @amount
          where profile_id = @customerId
          ''',
          parameters: {'customerId': customerId, 'amount': walletRefund},
        );
      }
      if (payment != null && walletReserved > 0) {
        await session.execute(
          '''
          update public.wallet_transactions
          set status = 'completed'
          where profile_id = @customerId
            and request_id = @requestId
            and kind = 'payment'
            and status = 'pending'
          ''',
          parameters: {'customerId': customerId, 'requestId': requestId},
        );
        if (walletRefund > 0) {
          await session.execute(
            '''
            insert into public.wallet_transactions (
              profile_id,
              request_id,
              kind,
              status,
              amount,
              description,
              metadata
            )
            values (
              @customerId,
              @requestId,
              'refund',
              'completed',
              @amount,
              'استرداد بعد إلغاء الطلب من الإدارة',
              jsonb_build_object(
                'cancellation_mode', @mode:text,
                'admin_id', @adminId:uuid
              )
            )
            ''',
            parameters: {
              'customerId': customerId,
              'requestId': requestId,
              'amount': walletRefund,
              'mode': mode,
              'adminId': adminId,
            },
          );
        }
      }

      if (walletEntitlement > 0 && craftsmanId != null) {
        await session.execute(
          '''
          insert into public.wallets (profile_id)
          values (@craftsmanId)
          on conflict do nothing
          ''',
          parameters: {'craftsmanId': craftsmanId},
        );
        await session.execute(
          '''
          update public.wallets
          set
            pending_balance = pending_balance + @amount,
            total_earned = total_earned + @amount
          where profile_id = @craftsmanId
          ''',
          parameters: {'craftsmanId': craftsmanId, 'amount': walletEntitlement},
        );
        await session.execute(
          '''
          insert into public.wallet_transactions (
            profile_id,
            request_id,
            kind,
            status,
            amount,
            description,
            metadata
          )
          values (
            @craftsmanId,
            @requestId,
            'earning',
            'pending',
            @amount,
            'استحقاق كشف بعد إلغاء الطلب',
            jsonb_build_object('admin_id', @adminId:uuid)
          )
          ''',
          parameters: {
            'craftsmanId': craftsmanId,
            'requestId': requestId,
            'amount': walletEntitlement,
            'adminId': adminId,
          },
        );
      }

      if (payment != null) {
        await session.execute(
          '''
          update public.request_payments
          set
            status = @paymentStatus,
            wallet_reserved_amount = @walletEntitlement,
            cash_due_amount = @cashDue,
            settled_at = case
              when @paymentStatus in ('settled', 'refunded') then now()
              else null
            end
          where request_id = @requestId
          ''',
          parameters: {
            'requestId': requestId,
            'paymentStatus': mode == 'no_entitlement'
                ? 'refunded'
                : cashDue > 0
                ? 'awaiting_cash_confirmation'
                : 'settled',
            'walletEntitlement': walletEntitlement,
            'cashDue': cashDue,
          },
        );
      }

      await session.execute(
        '''
        update public.service_requests
        set
          status = 'cancelled',
          cancellation_mode = @mode,
          cancellation_reason = @reason,
          cancelled_by = @adminId,
          cancelled_at = now(),
          inspection_due_amount = @inspectionDue
        where id = @requestId
        ''',
        parameters: {
          'requestId': requestId,
          'mode': mode,
          'reason': reason,
          'adminId': adminId,
          'inspectionDue': inspectionDue,
        },
      );
      await session.execute(
        '''
        update public.offers
        set status = 'withdrawn', updated_at = now()
        where request_id = @requestId
          and status = 'submitted'
        ''',
        parameters: {'requestId': requestId},
      );
      await session.execute(
        '''
        with cancelled_revisions as (
          update public.offer_revision_requests
          set
            status = 'cancelled',
            response_note = coalesce(
              response_note,
              'أُلغي بعد إلغاء الطلب من الإدارة.'
            ),
            responded_at = coalesce(responded_at, now())
          where request_id = @requestId
            and status = 'pending'
          returning id
        )
        update public.notifications notification
        set
          read_at = coalesce(notification.read_at, now()),
          data = notification.data || jsonb_build_object(
            'revision_status', 'cancelled',
            'actionable', false
          ),
          push_status = case
            when notification.push_status in ('pending', 'failed')
              then 'skipped'
            else notification.push_status
          end,
          push_error = case
            when notification.push_status in ('pending', 'failed')
              then 'Offer revision is no longer actionable.'
            else notification.push_error
          end
        from cancelled_revisions revision
        where notification.data ->> 'revision_id' = revision.id::text
        ''',
        parameters: {'requestId': requestId},
      );
      await session.execute(
        '''
        update public.request_dispatches
        set expires_at = least(expires_at, now())
        where request_id = @requestId
          and expires_at > now()
        ''',
        parameters: {'requestId': requestId},
      );
      await _closeRequestDispatchNotifications(
        session,
        requestId: requestId,
        status: 'cancelled',
      );
      await _closeOfferNotifications(
        session,
        requestId: requestId,
        status: 'cancelled',
      );
      await session.execute(
        '''
        insert into public.request_status_events (
          request_id,
          status,
          actor_id,
          note
        )
        values (@requestId, 'cancelled', @adminId, @note)
        ''',
        parameters: {
          'requestId': requestId,
          'adminId': adminId,
          'note': '$mode: $reason',
        },
      );

      await session.execute(
        '''
        insert into public.notifications (profile_id, title, body, data)
        values (
          @customerId,
          'تم إلغاء الطلب',
          @customerBody,
            jsonb_build_object(
              'request_id', @requestId:uuid,
              'notification_type', 'order',
              'cancellation_mode', @mode:text
          )
        )
        ''',
        parameters: {
          'customerId': customerId,
          'requestId': requestId,
          'mode': mode,
          'customerBody': walletRefund > 0
              ? 'ألغت الإدارة الطلب وأعيد ${walletRefund.toStringAsFixed(2)} د.ل إلى محفظتك.'
              : 'ألغت الإدارة الطلب. السبب: $reason',
        },
      );
      if (craftsmanId != null) {
        await session.execute(
          '''
          insert into public.notifications (profile_id, title, body, data)
          values (
            @craftsmanId,
            'تم إلغاء الطلب',
            @body,
            jsonb_build_object(
              'request_id', @requestId:uuid,
              'notification_type', 'order',
              'cancellation_mode', @mode:text,
              'inspection_due_amount', @inspectionDue:numeric
            )
          )
          ''',
          parameters: {
            'craftsmanId': craftsmanId,
            'requestId': requestId,
            'mode': mode,
            'inspectionDue': inspectionDue,
            'body': inspectionDue > 0
                ? 'ألغت الإدارة الطلب مع استحقاق كشف بقيمة ${inspectionDue.toStringAsFixed(2)} د.ل.'
                : 'ألغت الإدارة الطلب بلا مستحقات. السبب: $reason',
          },
        );
      }
      await _audit(
        session,
        adminId: adminId,
        action: 'service_request.cancel',
        entityType: 'service_request',
        entityId: requestId,
        details: {
          'previous_status': previousStatus,
          'mode': mode,
          'reason': reason,
          'inspection_due_amount': inspectionDue,
          'wallet_refund_amount': walletRefund,
          'wallet_entitlement_amount': walletEntitlement,
          'cash_due_amount': cashDue,
        },
      );
      return {
        'request_id': requestId,
        'status': 'cancelled',
        'cancellation_mode': mode,
        'inspection_due_amount': inspectionDue,
        'wallet_refund_amount': walletRefund,
        'wallet_entitlement_amount': walletEntitlement,
        'cash_due_amount': cashDue,
      };
    });
  }

  Future<Map<String, dynamic>> adminOverview() {
    return db.run((session) async {
      final stats = await session.select('''
        select
          (select count(*)::int from public.profiles where status <> 'deleted') as total_users,
          (select count(*)::int from public.profiles where role = 'customer' and status <> 'deleted') as customers,
          (select count(*)::int from public.profiles where role = 'craftsman' and status <> 'deleted') as craftsmen,
          (select count(*)::int from public.craftsman_profiles where is_verified) as verified_craftsmen,
          (select count(*)::int from public.craftsman_profiles where not is_verified and verification_submitted_at is not null) as pending_verifications,
          (select count(*)::int from public.service_requests) as total_requests,
          (select count(*)::int from public.service_requests where status in ('submitted', 'offers_received')) as open_requests,
          (select count(*)::int from public.support_tickets where status in ('open', 'in_progress')) as open_tickets,
          (select coalesce(sum(total_earned), 0) from public.wallets) as total_earnings
        ''');
      final recentRequests = await session.select('''
        select
          sr.*,
          p.full_name as customer_name,
          sc.name_ar as category_name
        from public.service_requests sr
        join public.profiles p on p.id = sr.customer_id
        join public.service_categories sc on sc.id = sr.category_id
        order by sr.created_at desc
        limit 20
        ''');
      return {'stats': stats.single, 'recent_requests': recentRequests};
    });
  }

  Future<List<Map<String, dynamic>>> adminLocations({String? role}) {
    final normalizedRole = role?.trim().toLowerCase();
    return db.run(
      (session) => session.select(
        '''
        select *
        from (
          select
            p.id,
            p.role::text as role,
            p.status::text as status,
            p.full_name,
            p.phone,
            p.city,
            ca.label as location_label,
            ca.area,
            ca.street,
            ca.latitude::double precision as latitude,
            ca.longitude::double precision as longitude,
            ca.updated_at as location_updated_at,
            null::text as profession,
            ca.is_default
          from public.profiles p
          join lateral (
            select *
            from public.customer_addresses ca
            where ca.customer_id = p.id
              and ca.latitude is not null
              and ca.longitude is not null
            order by ca.is_default desc, ca.updated_at desc
            limit 1
          ) ca on true
          where p.role = 'customer'
            and p.status <> 'deleted'

          union all

          select
            p.id,
            p.role::text as role,
            p.status::text as status,
            p.full_name,
            p.phone,
            p.city,
            'موقع الحرفي الحالي'::text as location_label,
            null::text as area,
            null::text as street,
            cp.last_latitude::double precision as latitude,
            cp.last_longitude::double precision as longitude,
            cp.location_updated_at,
            cp.profession,
            false as is_default
          from public.profiles p
          join public.craftsman_profiles cp on cp.profile_id = p.id
          where p.role = 'craftsman'
            and p.status <> 'deleted'
            and cp.last_latitude is not null
            and cp.last_longitude is not null
        ) locations
        where cast(@role as text) is null
          or locations.role = cast(@role as text)
        order by location_updated_at desc nulls last, full_name nulls last
        limit 500
        ''',
        parameters: {'role': normalizedRole},
      ),
    );
  }

  Future<List<Map<String, dynamic>>> adminUsers({
    String? role,
    String? status,
    String? search,
  }) {
    return db.run(
      (session) => session.select(
        '''
        select
          p.id,
          p.phone,
          p.role,
          p.status,
          p.full_name,
          p.avatar_url,
          p.city,
          p.blocked_reason,
          case
            when p.role = 'admin' then false
            else p.password_reset_required
          end as password_reset_required,
          p.warning_count,
          p.last_warning_at,
          p.created_at,
          p.updated_at,
          cp.profession,
          cp.is_verified,
          cp.verification_submitted_at,
          coalesce(
            (
              select jsonb_agg(
                jsonb_build_object(
                  'document_type', d.document_type,
                  'public_url', d.public_url,
                  'status', d.status,
                  'rejection_reason', d.rejection_reason
                )
                order by d.created_at
              )
              from public.craftsman_verification_documents d
              where d.craftsman_id = p.id
            ),
            '[]'::jsonb
          ) as documents,
          w.available_balance,
          w.pending_balance,
          w.total_earned
        from public.profiles p
        left join public.craftsman_profiles cp on cp.profile_id = p.id
        left join public.wallets w on w.profile_id = p.id
        where (@role:text is null or p.role::text = @role:text)
          and (@status:text is null or p.status::text = @status:text)
          and (
            @search:text is null
            or p.phone ilike '%' || @search:text || '%'
            or coalesce(p.full_name, '') ilike '%' || @search:text || '%'
          )
        order by p.created_at desc
        limit 200
        ''',
        parameters: {'role': role, 'status': status, 'search': search},
      ),
    );
  }

  Future<void> adminSetUserStatus({
    required String adminId,
    required String profileId,
    required String status,
    String? reason,
  }) {
    return db.runTx((session) async {
      if (!const ['active', 'suspended'].contains(status)) {
        throw const PlatformRuleException(
          'حالة الحساب غير صالحة.',
          statusCode: 422,
        );
      }
      final changed = await session.execute(
        '''
        update public.profiles
        set
          status = cast(@status as public.account_status),
          blocked_reason = case
            when cast(@status as public.account_status) = 'suspended'::public.account_status
              then @reason
            else null
          end
        where id = @profileId and role <> 'admin'
        ''',
        parameters: {
          'profileId': profileId,
          'status': status,
          'reason': reason,
        },
      );
      if (changed == 0) {
        throw const PlatformRuleException(
          'المستخدم غير موجود أو لا يمكن تعديل حساب إدارة.',
          statusCode: 404,
        );
      }
      final cleanReason = reason?.trim();
      await session.execute(
        '''
        insert into public.notifications (profile_id, title, body, data)
        values (
          @profileId,
          @title,
          @body,
          jsonb_build_object(
            'notification_type', 'account_status',
            'account_status', cast(@status as text),
            'reason', cast(@reason as text)
          )
        )
        ''',
        parameters: {
          'profileId': profileId,
          'status': status,
          'reason': cleanReason?.isEmpty == true ? null : cleanReason,
          'title': status == 'suspended'
              ? 'تم إيقاف حسابك مؤقتًا'
              : 'تم إعادة تفعيل حسابك',
          'body': status == 'suspended'
              ? (cleanReason?.isNotEmpty == true
                    ? 'سبب الإيقاف: $cleanReason'
                    : 'تم إيقاف الحساب من الإدارة. تواصل مع الدعم للمراجعة.')
              : 'تم إعادة تفعيل حسابك ويمكنك استخدام MASTRO الآن.',
        },
      );
      if (status == 'suspended') {
        await session.execute(
          '''
          update public.app_sessions
          set revoked_at = now()
          where profile_id = @profileId and revoked_at is null
          ''',
          parameters: {'profileId': profileId},
        );
      }
      await _audit(
        session,
        adminId: adminId,
        action: status == 'suspended' ? 'user.suspend' : 'user.activate',
        entityType: 'profile',
        entityId: profileId,
        details: {'reason': reason},
      );
    });
  }

  Future<void> adminDeleteUser({
    required String adminId,
    required String profileId,
    String? reason,
  }) {
    return db.runTx((session) async {
      final changed = await session.execute(
        '''
        update public.profiles
        set
          status = 'deleted',
          blocked_reason = @reason,
          notifications_enabled = false
        where id = @profileId
          and role <> 'admin'
        ''',
        parameters: {'profileId': profileId, 'reason': reason},
      );
      if (changed == 0) {
        throw const PlatformRuleException(
          'User not found or cannot delete an admin account.',
          statusCode: 404,
        );
      }
      await session.execute(
        '''
        update public.app_sessions
        set revoked_at = now()
        where profile_id = @profileId and revoked_at is null
        ''',
        parameters: {'profileId': profileId},
      );
      await _audit(
        session,
        adminId: adminId,
        action: 'user.delete',
        entityType: 'profile',
        entityId: profileId,
        details: {'reason': reason},
      );
    });
  }

  Future<Map<String, dynamic>> adminWarnUser({
    required String adminId,
    required String profileId,
    required String reason,
  }) {
    return db.runTx((session) async {
      final rows = await session.select(
        '''
        insert into public.user_warnings (
          profile_id,
          admin_id,
          reason
        )
        select
          @profileId,
          @adminId,
          @reason
        where exists (
          select 1
          from public.profiles
          where id = @profileId
            and role <> 'admin'
            and status <> 'deleted'
        )
        returning *
        ''',
        parameters: {
          'profileId': profileId,
          'adminId': adminId,
          'reason': reason,
        },
      );
      if (rows.isEmpty) {
        throw const PlatformRuleException(
          'User not found or cannot warn an admin account.',
          statusCode: 404,
        );
      }
      await session.execute(
        '''
        update public.profiles
        set
          warning_count = warning_count + 1,
          last_warning_at = now()
        where id = @profileId
        ''',
        parameters: {'profileId': profileId},
      );
      await session.execute(
        '''
        insert into public.notifications (profile_id, title, body, data)
        values (
          @profileId,
          'تنبيه من إدارة ماسترو',
          @reason,
          jsonb_build_object('notification_type', 'warning')
        )
        ''',
        parameters: {'profileId': profileId, 'reason': reason},
      );
      await _audit(
        session,
        adminId: adminId,
        action: 'user.warn',
        entityType: 'profile',
        entityId: profileId,
        details: {'reason': reason},
      );
      return rows.single;
    });
  }

  Future<void> adminReviewCraftsman({
    required String adminId,
    required String profileId,
    required bool approved,
    String? reason,
  }) {
    return db.runTx((session) async {
      final changed = await session.execute(
        '''
        update public.craftsman_profiles
        set
          is_verified = @approved,
          verification_reviewed_at = now()
        where profile_id = @profileId
        ''',
        parameters: {'profileId': profileId, 'approved': approved},
      );
      if (changed == 0) {
        throw const PlatformRuleException(
          'ملف الحرفي غير موجود.',
          statusCode: 404,
        );
      }
      await session.execute(
        '''
        update public.craftsman_verification_documents
        set
          status = @documentStatus,
          rejection_reason = @reason,
          reviewed_at = now()
        where craftsman_id = @profileId and status = 'pending'
        ''',
        parameters: {
          'profileId': profileId,
          'documentStatus': approved ? 'approved' : 'rejected',
          'reason': reason,
        },
      );
      await session.execute(
        '''
        insert into public.notifications (profile_id, title, body)
        values (@profileId, @title, @body)
        ''',
        parameters: {
          'profileId': profileId,
          'title': approved ? 'تم توثيق حسابك' : 'يحتاج التوثيق إلى تعديل',
          'body': approved
              ? 'تمت مراجعة مستنداتك وتوثيق حساب الحرفي.'
              : (reason?.trim().isNotEmpty == true
                    ? reason
                    : 'راجع بيانات ومستندات التوثيق وأعد إرسالها.'),
        },
      );
      await _audit(
        session,
        adminId: adminId,
        action: approved ? 'craftsman.approve' : 'craftsman.reject',
        entityType: 'profile',
        entityId: profileId,
        details: {'reason': reason},
      );
    });
  }

  Future<Map<String, dynamic>> adminCreateCampaign({
    required String adminId,
    required Map<String, dynamic> input,
  }) {
    return db.runTx((session) async {
      final rows = await session.select(
        '''
        insert into public.notification_campaigns (
          title,
          body,
          audience,
          target_profile_id,
          data,
          scheduled_for,
          created_by
        )
        values (
          @title,
          @body,
          @audience,
          cast(@targetProfileId as uuid),
          cast(@data as jsonb),
          @scheduledFor,
          @adminId
        )
        returning *
        ''',
        parameters: {
          'title': input['title'],
          'body': input['body'],
          'audience': input['audience'],
          'targetProfileId': input['target_profile_id'],
          'data': _jsonText(input['data'] ?? <String, dynamic>{}),
          'scheduledFor':
              _dateOrNull(input['scheduled_for']) ?? DateTime.now().toUtc(),
          'adminId': adminId,
        },
      );
      await _audit(
        session,
        adminId: adminId,
        action: 'notification.schedule',
        entityType: 'notification_campaign',
        entityId: rows.single['id'].toString(),
        details: {
          'audience': input['audience'],
          'scheduled_for': input['scheduled_for'],
        },
      );
      return rows.single;
    });
  }

  Future<List<Map<String, dynamic>>> adminCampaigns() {
    return db.run(
      (session) => session.select('''
        select *
        from public.notification_campaigns
        order by created_at desc
        limit 100
        '''),
    );
  }

  Future<Map<String, dynamic>> adminUpdateCampaign({
    required String adminId,
    required String campaignId,
    required Map<String, dynamic> input,
  }) {
    return db.runTx((session) async {
      final existingRows = await session.select(
        '''
        select
          c.*,
          (
            select count(*)::int
            from public.notifications n
            where n.campaign_id = c.id
          ) as delivered_notifications
        from public.notification_campaigns c
        where c.id = @campaignId
        for update
        ''',
        parameters: {'campaignId': campaignId},
      );
      if (existingRows.isEmpty) {
        throw const PlatformRuleException(
          'الإشعار غير موجود.',
          statusCode: 404,
        );
      }
      final existing = existingRows.single;
      final previousTargetProfileId = existing['target_profile_id']?.toString();
      final nextTargetProfileId = input['target_profile_id']?.toString();
      final recipientsChanged =
          existing['audience']?.toString() != input['audience']?.toString() ||
          (previousTargetProfileId ?? '') != (nextTargetProfileId ?? '');
      final deliveredNotifications =
          int.tryParse(existing['delivered_notifications']?.toString() ?? '') ??
          0;
      final rows = await session.select(
        '''
        update public.notification_campaigns
        set
          title = @title,
          body = @body,
          audience = @audience,
          target_profile_id = cast(@targetProfileId as uuid),
          data = coalesce(cast(@data as jsonb), data),
          scheduled_for = @scheduledFor
        where id = @campaignId
        returning *
        ''',
        parameters: {
          'campaignId': campaignId,
          'title': input['title'],
          'body': input['body'],
          'audience': input['audience'],
          'targetProfileId': input['target_profile_id'],
          'data': input.containsKey('data') ? _jsonText(input['data']) : null,
          'scheduledFor':
              _dateOrNull(input['scheduled_for']) ?? DateTime.now().toUtc(),
        },
      );
      if (rows.isEmpty) {
        throw const PlatformRuleException(
          'الإشعار غير موجود.',
          statusCode: 404,
        );
      }
      if (deliveredNotifications > 0 && recipientsChanged) {
        await session.execute(
          '''
          delete from public.notifications
          where campaign_id = @campaignId
          ''',
          parameters: {'campaignId': campaignId},
        );
        await session.execute(
          '''
          insert into public.notifications (
            profile_id,
            campaign_id,
            title,
            body,
            data,
            push_status
          )
          select
            p.id,
            @campaignId,
            @title,
            @body,
            cast(@data as jsonb),
            'skipped'
          from public.profiles p
          left join public.notification_preferences np on np.profile_id = p.id
          where p.status = 'active'
            and p.notifications_enabled = true
            and coalesce(np.promotions, true) = true
            and (
              @audience = 'all'
              or (@audience = 'customers' and p.role = 'customer')
              or (@audience = 'craftsmen' and p.role = 'craftsman')
              or (@audience = 'profile' and p.id = cast(@targetProfileId as uuid))
            )
          ''',
          parameters: {
            'campaignId': campaignId,
            'title': input['title'],
            'body': input['body'],
            'data': input.containsKey('data')
                ? _jsonText(input['data'])
                : _jsonText(existing['data'] ?? <String, dynamic>{}),
            'audience': input['audience'],
            'targetProfileId': input['target_profile_id'],
          },
        );
      } else {
        await session.execute(
          '''
          update public.notifications
          set
            title = @title,
            body = @body,
            data = coalesce(cast(@data as jsonb), data)
          where campaign_id = @campaignId
          ''',
          parameters: {
            'campaignId': campaignId,
            'title': input['title'],
            'body': input['body'],
            'data': input.containsKey('data') ? _jsonText(input['data']) : null,
          },
        );
      }
      await _audit(
        session,
        adminId: adminId,
        action: 'notification.update',
        entityType: 'notification_campaign',
        entityId: campaignId,
        details: {
          'audience': input['audience'],
          'recipients_changed': recipientsChanged,
        },
      );
      return rows.single;
    });
  }

  Future<Map<String, dynamic>> adminResendCampaign({
    required String adminId,
    required String campaignId,
  }) {
    return db.runTx((session) async {
      final rows = await session.select(
        '''
        select *
        from public.notification_campaigns
        where id = @campaignId
        for update
        ''',
        parameters: {'campaignId': campaignId},
      );
      if (rows.isEmpty) {
        throw const PlatformRuleException(
          'الإشعار غير موجود.',
          statusCode: 404,
        );
      }
      await session.execute(
        '''
        with ranked as (
          select
            id,
            row_number() over (
              partition by profile_id
              order by created_at desc, id desc
            ) as row_number
          from public.notifications
          where campaign_id = @campaignId
        )
        delete from public.notifications n
        using ranked r
        where n.id = r.id
          and r.row_number > 1
        ''',
        parameters: {'campaignId': campaignId},
      );
      final queued = await session.execute(
        '''
        update public.notifications
        set
          push_status = 'pending',
          push_attempts = 0,
          push_claimed_at = null,
          push_sent_at = null,
          push_error = null
        where campaign_id = @campaignId
        ''',
        parameters: {'campaignId': campaignId},
      );
      final updatedRows = queued == 0
          ? await session.select(
              '''
              update public.notification_campaigns
              set
                status = 'scheduled',
                scheduled_for = now(),
                sent_at = null,
                error_message = null
              where id = @campaignId
              returning *
              ''',
              parameters: {'campaignId': campaignId},
            )
          : await session.select(
              '''
              update public.notification_campaigns
              set
                status = 'sent',
                sent_at = now(),
                error_message = null
              where id = @campaignId
              returning *
              ''',
              parameters: {'campaignId': campaignId},
            );
      await _audit(
        session,
        adminId: adminId,
        action: 'notification.resend',
        entityType: 'notification_campaign',
        entityId: campaignId,
        details: {'queued_push_notifications': queued},
      );
      return updatedRows.single;
    });
  }

  Future<void> adminDeleteCampaign({
    required String adminId,
    required String campaignId,
  }) {
    return db.runTx((session) async {
      await session.execute(
        '''
        delete from public.notifications
        where campaign_id = @campaignId
        ''',
        parameters: {'campaignId': campaignId},
      );
      final changed = await session.execute(
        '''
        delete from public.notification_campaigns
        where id = @campaignId
        ''',
        parameters: {'campaignId': campaignId},
      );
      if (changed == 0) {
        throw const PlatformRuleException(
          'الإشعار غير موجود.',
          statusCode: 404,
        );
      }
      await _audit(
        session,
        adminId: adminId,
        action: 'notification.delete',
        entityType: 'notification_campaign',
        entityId: campaignId,
      );
    });
  }

  Future<int> dispatchDueCampaigns() {
    return db.runTx((session) async {
      final campaigns = await session.select('''
        select *
        from public.notification_campaigns
        where status = 'scheduled' and scheduled_for <= now()
        order by scheduled_for
        limit 20
        for update skip locked
        ''');
      var delivered = 0;
      for (final campaign in campaigns) {
        await session.execute(
          '''
          update public.notification_campaigns
          set status = 'processing'
          where id = @campaignId
          ''',
          parameters: {'campaignId': campaign['id']},
        );
        final affected = await session.execute(
          '''
          insert into public.notifications (
            profile_id,
            campaign_id,
            title,
            body,
            data
          )
          select
            p.id,
            @campaignId,
            @title,
            @body,
            cast(@data as jsonb)
          from public.profiles p
          left join public.notification_preferences np on np.profile_id = p.id
          where p.status = 'active'
            and p.notifications_enabled = true
            and coalesce(np.promotions, true) = true
            and (
              @audience = 'all'
              or (@audience = 'customers' and p.role = 'customer')
              or (@audience = 'craftsmen' and p.role = 'craftsman')
              or (@audience = 'profile' and p.id = cast(@targetProfileId as uuid))
            )
          ''',
          parameters: {
            'campaignId': campaign['id'],
            'title': campaign['title'],
            'body': campaign['body'],
            'data': _jsonText(campaign['data'] ?? <String, dynamic>{}),
            'audience': campaign['audience'],
            'targetProfileId': campaign['target_profile_id']?.toString(),
          },
        );
        delivered += affected;
        await session.execute(
          '''
          update public.notification_campaigns
          set status = 'sent', sent_at = now()
          where id = @campaignId
          ''',
          parameters: {'campaignId': campaign['id']},
        );
      }
      return delivered;
    });
  }

  Future<Map<String, dynamic>> adminSaveCategory({
    required String adminId,
    required Map<String, dynamic> input,
    String? categoryId,
  }) {
    return db.runTx((session) async {
      final id = categoryId ?? input['id']?.toString();
      if (id == null || !RegExp(r'^[a-z0-9_-]{2,40}$').hasMatch(id)) {
        throw const PlatformRuleException(
          'معرف الحرفة يجب أن يكون أحرفًا إنجليزية صغيرة.',
          statusCode: 422,
        );
      }
      final rows = await session.select(
        '''
        insert into public.service_categories (
          id,
          name_ar,
          name_en,
          description_ar,
          icon_key,
          icon_url,
          availability_status,
          is_active,
          sort_order,
          metadata
        )
        values (
          @id,
          @nameAr,
          @nameEn,
          @descriptionAr,
          @iconKey,
          @iconUrl,
          @availabilityStatus,
          @isActive,
          @sortOrder,
          coalesce(@metadata::jsonb, '{}'::jsonb)
        )
        on conflict (id) do update
        set
          name_ar = excluded.name_ar,
          name_en = excluded.name_en,
          description_ar = excluded.description_ar,
          icon_key = excluded.icon_key,
          icon_url = excluded.icon_url,
          availability_status = excluded.availability_status,
          is_active = excluded.is_active,
          sort_order = excluded.sort_order,
          metadata = coalesce(@metadata::jsonb, service_categories.metadata)
        returning *
        ''',
        parameters: {
          'id': id,
          'nameAr': input['name_ar'],
          'nameEn': input['name_en'],
          'descriptionAr': input['description_ar'],
          'iconKey': input['icon_key'] ?? 'handyman',
          'iconUrl': input['icon_url'],
          'availabilityStatus': input['availability_status'] ?? 'open',
          'isActive': input['is_active'] != false,
          'sortOrder': input['sort_order'] ?? 0,
          'metadata': input.containsKey('metadata')
              ? _jsonText(
                  input['metadata'] is Map
                      ? input['metadata']
                      : <String, dynamic>{},
                )
              : null,
        },
      );
      await _audit(
        session,
        adminId: adminId,
        action: categoryId == null ? 'category.create' : 'category.update',
        entityType: 'service_category',
        entityId: id,
      );
      return rows.single;
    });
  }

  Future<void> adminDeleteCategory({
    required String adminId,
    required String categoryId,
  }) {
    return db.runTx((session) async {
      final requestCountRows = await session.select(
        '''
        select count(*)::int as count
        from public.service_requests
        where category_id = @categoryId
        ''',
        parameters: {'categoryId': categoryId},
      );
      final requestCount = requestCountRows.isEmpty
          ? 0
          : (requestCountRows.single['count'] as num?)?.toInt() ?? 0;
      if (requestCount > 0) {
        throw const PlatformRuleException(
          'لا يمكن حذف الحرفة نهائيًا لأنها مرتبطة بطلبات سابقة. يمكنك تعطيلها من زر التعديل للحفاظ على سجل الطلبات.',
          statusCode: 409,
        );
      }
      final changed = await session.execute(
        '''
        delete from public.service_categories
        where id = @categoryId
        ''',
        parameters: {'categoryId': categoryId},
      );
      if (changed == 0) {
        throw const PlatformRuleException(
          'الحرفة غير موجودة.',
          statusCode: 404,
        );
      }
      await _audit(
        session,
        adminId: adminId,
        action: 'category.delete',
        entityType: 'service_category',
        entityId: categoryId,
      );
    });
  }

  Future<Map<String, dynamic>> mediaRetentionSettings() {
    return db.run((session) async {
      final rows = await session.select('''
        select value
        from public.app_settings
        where key = 'media_retention'
        limit 1
        ''');
      return _retentionSettings(rows.isEmpty ? null : rows.single['value']);
    });
  }

  Future<Map<String, dynamic>> adminSetMediaRetention({
    required String adminId,
    required bool enabled,
    required int completedRequestMediaDays,
    required int closedSupportMessageDays,
  }) {
    final value = {
      'enabled': enabled,
      'completed_request_media_days': completedRequestMediaDays,
      'closed_support_message_days': closedSupportMessageDays,
    };
    return db.runTx((session) async {
      await session.execute(
        '''
        insert into public.app_settings (
          key,
          value,
          is_public,
          description,
          updated_by
        )
        values (
          'media_retention',
          cast(@value as jsonb),
          false,
          'Retention in days before completed-request media and closed support messages are removed.',
          @adminId
        )
        on conflict (key) do update
        set
          value = excluded.value,
          is_public = false,
          updated_by = excluded.updated_by
        ''',
        parameters: {'value': _jsonText(value), 'adminId': adminId},
      );
      await _audit(
        session,
        adminId: adminId,
        action: 'settings.media_retention.update',
        entityType: 'app_setting',
        entityId: 'media_retention',
        details: value,
      );
      return value;
    });
  }

  /// Removes expired database references atomically and records a durable
  /// outbox job for each Cloudinary asset that can be deleted remotely.
  Future<Map<String, dynamic>> queueExpiredMediaCleanup() {
    return db.runTx((session) async {
      final settingRows = await session.select('''
        select value
        from public.app_settings
        where key = 'media_retention'
        limit 1
        ''');
      final settings = _retentionSettings(
        settingRows.isEmpty ? null : settingRows.single['value'],
      );
      if (settings['enabled'] != true) {
        return {
          'enabled': false,
          'request_attachments_removed': 0,
          'chat_images_removed': 0,
          'support_messages_removed': 0,
          'legacy_support_bodies_cleared': 0,
        };
      }
      final now = DateTime.now().toUtc();
      final requestCutoff = now.subtract(
        Duration(days: settings['completed_request_media_days'] as int),
      );
      final supportCutoff = now.subtract(
        Duration(days: settings['closed_support_message_days'] as int),
      );

      await session.execute(
        '''
        insert into public.media_cleanup_jobs (
          provider,
          provider_public_id,
          resource_type,
          source_type,
          source_id
        )
        select
          mma.provider,
          mma.provider_public_id,
          mma.resource_type,
          'request_attachment',
          ra.id::text
        from public.request_attachments ra
        join public.service_requests sr on sr.id = ra.request_id
        join public.managed_media_assets mma
          on mma.owner_id = sr.customer_id
         and mma.provider = coalesce(ra.provider, 'cloudinary')
         and mma.provider_public_id = ra.provider_public_id
         and mma.resource_type = case
           when ra.resource_type in ('image', 'video', 'raw')
             then ra.resource_type
           else 'image'
         end
         and mma.purpose = 'service-requests'
         and mma.consumed_by_type = 'request_attachment'
         and mma.consumed_by_id = ra.id::text
         and mma.status = 'active'
        where sr.status = 'completed'
          and sr.updated_at <= @cutoff
          and (
            ra.resource_type = 'image'
            or ra.content_type like 'image/%'
          )
          and ra.provider_public_id is not null
          and not exists (
            select 1
            from public.request_attachments other_ra
            where other_ra.id <> ra.id
              and coalesce(other_ra.provider, 'cloudinary')
                = coalesce(ra.provider, 'cloudinary')
              and other_ra.provider_public_id = ra.provider_public_id
              and coalesce(other_ra.resource_type, 'image')
                = coalesce(ra.resource_type, 'image')
          )
        on conflict (provider, resource_type, provider_public_id) do nothing
        ''',
        parameters: {'cutoff': requestCutoff},
      );
      final requestAttachmentsRemoved = await session.execute(
        '''
        delete from public.request_attachments ra
        using public.service_requests sr
        where sr.id = ra.request_id
          and sr.status = 'completed'
          and sr.updated_at <= @cutoff
          and (
            ra.resource_type = 'image'
            or ra.content_type like 'image/%'
          )
        ''',
        parameters: {'cutoff': requestCutoff},
      );

      await session.execute(
        '''
        insert into public.media_cleanup_jobs (
          provider,
          provider_public_id,
          resource_type,
          source_type,
          source_id
        )
        select
          mma.provider,
          mma.provider_public_id,
          mma.resource_type,
          'job_message_attachment',
          jm.id::text
        from public.job_messages jm
        join public.service_requests sr on sr.id = jm.request_id
        join public.managed_media_assets mma
          on mma.owner_id = jm.sender_id
         and mma.provider = 'cloudinary'
         and mma.provider_public_id = jm.attachment_public_id
         and mma.resource_type =
           coalesce(jm.attachment_resource_type, 'image')
         and mma.purpose = 'chat'
         and mma.consumed_by_type = 'job_message'
         and mma.consumed_by_id = jm.id::text
         and mma.status = 'active'
        where sr.status = 'completed'
          and sr.updated_at <= @cutoff
          and jm.attachment_type = 'image'
          and jm.attachment_public_id is not null
        on conflict (provider, resource_type, provider_public_id) do nothing
        ''',
        parameters: {'cutoff': requestCutoff},
      );
      final chatImagesRemoved = await session.execute(
        '''
        update public.job_messages jm
        set
          attachment_url = null,
          attachment_type = null,
          attachment_public_id = null,
          attachment_resource_type = null
        from public.service_requests sr
        where sr.id = jm.request_id
          and sr.status = 'completed'
          and sr.updated_at <= @cutoff
          and jm.attachment_type = 'image'
        ''',
        parameters: {'cutoff': requestCutoff},
      );

      await session.execute(
        '''
        insert into public.media_cleanup_jobs (
          provider,
          provider_public_id,
          resource_type,
          source_type,
          source_id
        )
        select
          mma.provider,
          mma.provider_public_id,
          mma.resource_type,
          'support_message_attachment',
          sm.id::text
        from public.support_messages sm
        join public.support_tickets st on st.id = sm.conversation_id
        join public.managed_media_assets mma
          on mma.owner_id = sm.sender_id
         and mma.provider = 'cloudinary'
         and mma.provider_public_id = sm.attachment_public_id
         and mma.resource_type = coalesce(
           sm.attachment_resource_type,
           case
             when sm.attachment_type = 'audio' then 'video'
             else 'image'
           end
         )
         and mma.purpose = 'support'
         and mma.consumed_by_type = 'support_message'
         and mma.consumed_by_id = sm.id::text
         and mma.status = 'active'
        where st.status in ('resolved', 'closed')
          and st.closed_at <= @cutoff
          and sm.attachment_public_id is not null
        on conflict (provider, resource_type, provider_public_id) do nothing
        ''',
        parameters: {'cutoff': supportCutoff},
      );
      final supportMessagesRemoved = await session.execute(
        '''
        delete from public.support_messages sm
        using public.support_tickets st
        where st.id = sm.conversation_id
          and st.status in ('resolved', 'closed')
          and st.closed_at <= @cutoff
        ''',
        parameters: {'cutoff': supportCutoff},
      );
      final legacySupportBodiesCleared = await session.execute(
        '''
        update public.support_tickets
        set body = ''
        where status in ('resolved', 'closed')
          and closed_at <= @cutoff
          and body <> ''
        ''',
        parameters: {'cutoff': supportCutoff},
      );
      await session.execute('''
        update public.managed_media_assets mma
        set status = 'delete_pending'
        where mma.status = 'active'
          and exists (
            select 1
            from public.media_cleanup_jobs mcj
            where mcj.provider = mma.provider
              and mcj.resource_type = mma.resource_type
              and mcj.provider_public_id = mma.provider_public_id
              and mcj.status in ('pending', 'processing', 'failed')
          )
        ''');
      return {
        'enabled': true,
        'request_attachments_removed': requestAttachmentsRemoved,
        'chat_images_removed': chatImagesRemoved,
        'support_messages_removed': supportMessagesRemoved,
        'legacy_support_bodies_cleared': legacySupportBodiesCleared,
      };
    });
  }

  Future<Map<String, dynamic>?> claimMediaCleanupJob() {
    return db.runTx((session) async {
      final rows = await session.select('''
        select *
        from public.media_cleanup_jobs
        where (
          (
            status in ('pending', 'failed')
            and next_attempt_at <= now()
          )
          or (
            status = 'processing'
            and updated_at <= now() - interval '10 minutes'
          )
        )
          and attempts < 8
        order by next_attempt_at, created_at
        limit 1
        for update skip locked
        ''');
      if (rows.isEmpty) return null;
      final job = rows.single;
      final claimed = await session.select(
        '''
        update public.media_cleanup_jobs
        set
          status = 'processing',
          attempts = attempts + 1,
          last_error = null
        where id = @id
        returning *
        ''',
        parameters: {'id': job['id']},
      );
      return claimed.single;
    });
  }

  Future<void> completeMediaCleanupJob(String jobId) {
    return db.runTx((session) async {
      await session.execute(
        '''
        update public.managed_media_assets mma
        set status = 'deleted'
        from public.media_cleanup_jobs mcj
        where mcj.id = @id
          and mma.provider = mcj.provider
          and mma.resource_type = mcj.resource_type
          and mma.provider_public_id = mcj.provider_public_id
        ''',
        parameters: {'id': jobId},
      );
      await session.execute(
        '''
        update public.media_cleanup_jobs
        set
          status = 'deleted',
          processed_at = now(),
          last_error = null
        where id = @id
        ''',
        parameters: {'id': jobId},
      );
    });
  }

  Future<void> failMediaCleanupJob({
    required String jobId,
    required Object error,
    required int attempts,
  }) {
    final exponent = attempts.clamp(1, 8);
    final delayMinutes = min(24 * 60, pow(2, exponent).toInt());
    final nextAttempt = DateTime.now().toUtc().add(
      Duration(minutes: delayMinutes),
    );
    return db.run((session) async {
      await session.execute(
        '''
        update public.media_cleanup_jobs
        set
          status = 'failed',
          last_error = @error,
          next_attempt_at = @nextAttempt
        where id = @id
        ''',
        parameters: {
          'id': jobId,
          'error': error.toString(),
          'nextAttempt': nextAttempt,
        },
      );
    });
  }

  Future<bool> testLoginEnabled() {
    return db.run((session) async {
      final rows = await session.select('''
        select value
        from public.app_settings
        where key = 'test_login_enabled'
        limit 1
        ''');
      if (rows.isEmpty) return false;
      final value = rows.single['value'];
      return value == true || value.toString() == 'true';
    });
  }

  Future<Map<String, dynamic>> requestAutomationSettings() {
    return db.run((session) async {
      final settings = await _requestAutomationSettings(session);
      return {
        'enabled': settings.enabled,
        'batch_size': settings.batchSize,
        'batch_interval_minutes': settings.intervalMinutes,
      };
    });
  }

  Future<Map<String, dynamic>> adminSetRequestAutomation({
    required String adminId,
    required bool enabled,
    required int batchSize,
    required int intervalMinutes,
  }) {
    final value = {
      'enabled': enabled,
      'batch_size': batchSize.clamp(1, 5),
      'batch_interval_minutes': intervalMinutes.clamp(60, 24 * 60),
    };
    return db.runTx((session) async {
      await session.execute(
        '''
        insert into public.app_settings (key, value, is_public, updated_by)
        values (
          'request_automation',
          cast(@value as jsonb),
          false,
          @adminId
        )
        on conflict (key) do update
        set value = excluded.value, updated_by = excluded.updated_by
        ''',
        parameters: {'value': _jsonText(value), 'adminId': adminId},
      );
      await _audit(
        session,
        adminId: adminId,
        action: 'settings.request_automation',
        entityType: 'app_setting',
        entityId: 'request_automation',
        details: value,
      );
      return value;
    });
  }

  Future<List<Map<String, dynamic>>> adminEligibleCraftsmenForRequest(
    String requestId,
  ) {
    return db.run(
      (session) => session.select(
        '''
        select
          p.id,
          p.full_name,
          p.phone,
          p.avatar_url,
          p.status,
          cp.profession,
          cp.rating,
          cp.completed_jobs,
          cp.is_available,
          cp.is_verified,
          exists (
            select 1
            from public.request_dispatches rd
            where rd.request_id = sr.id
              and rd.craftsman_id = p.id
          ) as already_dispatched,
          public.maestro_distance_km(
            sr.latitude,
            sr.longitude,
            cp.last_latitude,
            cp.last_longitude
          ) as distance_km
        from public.service_requests sr
        join public.craftsman_services cs on cs.category_id = sr.category_id
        join public.profiles p on p.id = cs.craftsman_id
        join public.craftsman_profiles cp on cp.profile_id = p.id
        where sr.id = @requestId
          and p.status = 'active'
          and cp.is_verified = true
        order by already_dispatched, cp.is_available desc, distance_km nulls last, cp.completed_jobs
        limit 100
        ''',
        parameters: {'requestId': requestId},
      ),
    );
  }

  Future<int> adminDispatchRequestToCraftsmen({
    required String adminId,
    required String requestId,
    required List<String> craftsmanIds,
  }) {
    final uniqueIds = craftsmanIds
        .map((id) => id.trim())
        .where((id) => id.isNotEmpty)
        .toSet()
        .take(5)
        .toList();
    if (uniqueIds.isEmpty) {
      throw const PlatformRuleException(
        'Choose at least one craftsman.',
        statusCode: 422,
      );
    }
    return db.runTx((session) async {
      await _expireStaleRequests(session);
      await session.select(
        '''
        select pg_advisory_xact_lock(
          hashtextextended(cast(@requestId as text), 904029)
        )
        ''',
        parameters: {'requestId': requestId},
      );
      final requestRows = await session.select(
        '''
        select id, category_id, urgency, expires_at
        from public.service_requests
        where id = @requestId
          and status in ('submitted', 'offers_received')
          and accepted_offer_id is null
          and expires_at > now()
        limit 1
        for update
        ''',
        parameters: {'requestId': requestId},
      );
      if (requestRows.isEmpty) {
        throw const PlatformRuleException(
          'Request is not available for dispatch.',
          statusCode: 409,
        );
      }
      final request = requestRows.single;
      final activeDispatchRows = await session.select(
        '''
        select count(*)::integer as active_count
        from public.request_dispatches
        where request_id = @requestId
          and expires_at > now()
        ''',
        parameters: {'requestId': requestId},
      );
      final activeDispatchCount = activeDispatchRows.isEmpty
          ? 0
          : _intValue(activeDispatchRows.single['active_count']);
      final remainingCapacity = 5 - activeDispatchCount;
      if (remainingCapacity <= 0) {
        throw const PlatformRuleException(
          'الطلب موزّع حاليًا على خمسة فنيين. انتظر انتهاء الدفعة الحالية.',
          statusCode: 409,
        );
      }
      final dispatchIds = uniqueIds.take(remainingCapacity).toList();
      final batchRows = await session.select(
        '''
        select coalesce(max(batch_no), 0)::int + 1 as next_batch
        from public.request_dispatches
        where request_id = @requestId
        ''',
        parameters: {'requestId': requestId},
      );
      final batchNo = batchRows.isEmpty ? 1 : batchRows.single['next_batch'];
      var inserted = 0;
      for (final craftsmanId in dispatchIds) {
        final rows = await session.select(
          '''
          insert into public.request_dispatches (
            request_id,
            craftsman_id,
            batch_no,
            source,
            expires_at,
            created_by
          )
          select
            @requestId,
            @craftsmanId,
            @batchNo,
            'admin',
            least(active_request.expires_at, now() + interval '1 hour'),
            @adminId
          from public.service_requests active_request
          where active_request.id = @requestId
            and active_request.category_id = @categoryId
            and active_request.status in ('submitted', 'offers_received')
            and active_request.accepted_offer_id is null
            and active_request.expires_at > now()
            and (
              select count(*)
              from public.request_dispatches active_dispatch
              where active_dispatch.request_id = active_request.id
                and active_dispatch.expires_at > now()
            ) < 5
            and exists (
            select 1
            from public.craftsman_services cs
            join public.craftsman_profiles cp on cp.profile_id = cs.craftsman_id
            join public.profiles p on p.id = cs.craftsman_id
            where cs.craftsman_id = @craftsmanId
              and cs.category_id = @categoryId
              and cp.is_verified = true
              and p.status = 'active'
            )
          on conflict (request_id, craftsman_id) do nothing
          returning id
          ''',
          parameters: {
            'requestId': requestId,
            'craftsmanId': craftsmanId,
            'batchNo': batchNo,
            'adminId': adminId,
            'categoryId': request['category_id'],
          },
        );
        inserted += rows.length;
      }
      if (inserted > 0) {
        await _notifyCurrentRequestDispatchBatch(
          session,
          requestId: requestId,
          urgent: request['urgency'] == true,
        );
      }
      await _audit(
        session,
        adminId: adminId,
        action: 'request.dispatch_manual',
        entityType: 'service_request',
        entityId: requestId,
        details: {'craftsman_ids': uniqueIds, 'inserted': inserted},
      );
      return inserted;
    });
  }

  Future<void> adminSetTestLogin({
    required String adminId,
    required bool enabled,
  }) {
    return db.runTx((session) async {
      await session.execute(
        '''
        insert into public.app_settings (key, value, is_public, updated_by)
        values (
          'test_login_enabled',
          cast(@value as jsonb),
          true,
          @adminId
        )
        on conflict (key) do update
        set value = excluded.value, updated_by = excluded.updated_by
        ''',
        parameters: {'value': enabled ? 'true' : 'false', 'adminId': adminId},
      );
      await _audit(
        session,
        adminId: adminId,
        action: 'settings.test_login',
        entityType: 'app_setting',
        entityId: 'test_login_enabled',
        details: {'enabled': enabled},
      );
    });
  }

  Future<Map<String, dynamic>> _insertAddress(
    MaestroDbSession session, {
    required String profileId,
    required Map<String, dynamic> input,
    required bool makeDefault,
  }) async {
    final countRows = await session.select(
      '''
      select count(*)::int as count
      from public.customer_addresses
      where customer_id = @profileId
      ''',
      parameters: {'profileId': profileId},
    );
    final shouldDefault = makeDefault || countRows.single['count'] == 0;
    if (shouldDefault) {
      await session.execute(
        '''
        update public.customer_addresses
        set is_default = false
        where customer_id = @profileId
        ''',
        parameters: {'profileId': profileId},
      );
    }
    final rows = await session.select(
      '''
      insert into public.customer_addresses (
        customer_id,
        label,
        city,
        area,
        street,
        building,
        floor,
        notes,
        latitude,
        longitude,
        is_default
      )
      values (
        @profileId,
        @label,
        @city,
        @area,
        @street,
        @building,
        @floor,
        @notes,
        @latitude,
        @longitude,
        @isDefault
      )
      returning *
      ''',
      parameters: {
        'profileId': profileId,
        'label': input['label'] ?? 'المنزل',
        'city': input['city'],
        'area': input['area'],
        'street': input['street'],
        'building': input['building'],
        'floor': input['floor'],
        'notes': input['notes'],
        'latitude': input['latitude'],
        'longitude': input['longitude'],
        'isDefault': shouldDefault,
      },
    );
    return rows.single;
  }

  Future<List<Map<String, dynamic>>> _listCategories(MaestroDbSession session) {
    return session.select('''
      select *
      from public.service_categories
      where is_active = true
      order by sort_order, name_ar
      ''');
  }

  Future<List<_WalletTopupMethod>> _loadWalletTopupMethods(
    MaestroDbSession session,
  ) async {
    final rows = await session.select('''
      select value
      from public.app_settings
      where key = 'wallet_topup_methods'
      limit 1
      ''');
    return _walletTopupMethodsFromRaw(
      rows.isEmpty ? null : rows.single['value'],
    );
  }

  Future<void> _storeWalletTopupMethods(
    MaestroDbSession session, {
    required String adminId,
    required List<_WalletTopupMethod> methods,
  }) {
    return session.execute(
      '''
      insert into public.app_settings (
        key,
        value,
        is_public,
        description,
        updated_by
      )
      values (
        'wallet_topup_methods',
        cast(@value as jsonb),
        true,
        'Wallet top-up methods shown in the customer and craftsman apps.',
        @adminId
      )
      on conflict (key) do update
      set
        value = excluded.value,
        is_public = true,
        description = excluded.description,
        updated_by = excluded.updated_by
      ''',
      parameters: {
        'value': _jsonText({
          'version': 1,
          'items': methods.map((method) => method.toMap()).toList(),
        }),
        'adminId': adminId,
      },
    );
  }

  Future<List<Map<String, dynamic>>> _listHomeBanners(
    MaestroDbSession session, {
    bool activeOnly = true,
  }) async {
    final rows = await session.select('''
      select value
      from public.app_settings
      where key = 'home_banners'
      limit 1
      ''');
    return _homeBanners(
      rows.isEmpty ? null : rows.single['value'],
      activeOnly: activeOnly,
    );
  }

  Future<String> _newUuid(MaestroDbSession session) async {
    final rows = await session.select('select gen_random_uuid() as id');
    return rows.single['id'].toString();
  }

  Future<void> _storeHomeBanners(
    MaestroDbSession session, {
    required String adminId,
    required List<Map<String, dynamic>> banners,
  }) {
    return session.execute(
      '''
      insert into public.app_settings (
        key,
        value,
        is_public,
        description,
        updated_by
      )
      values (
        'home_banners',
        cast(@value as jsonb),
        true,
        'Home hero banner carousel items shown in the customer app.',
        @adminId
      )
      on conflict (key) do update
      set
        value = excluded.value,
        is_public = true,
        updated_by = excluded.updated_by
      ''',
      parameters: {'value': _jsonText(banners), 'adminId': adminId},
    );
  }

  Future<_RequestAutomationSettings> _requestAutomationSettings(
    MaestroDbSession session,
  ) async {
    final rows = await session.select('''
      select value
      from public.app_settings
      where key = 'request_automation'
      limit 1
      ''');
    Object? raw = rows.isEmpty ? null : rows.single['value'];
    if (raw is String) {
      try {
        raw = jsonDecode(raw);
      } on FormatException {
        raw = null;
      }
    }
    final value = raw is Map
        ? Map<String, dynamic>.from(raw)
        : const <String, dynamic>{};
    return _RequestAutomationSettings(
      enabled: value['enabled'] != false,
      batchSize: _intValue(value['batch_size']).clamp(1, 5),
      intervalMinutes: _intValue(
        value['batch_interval_minutes'],
      ).clamp(60, 24 * 60),
    );
  }

  Future<void> _lockAndAssertNoDuplicateActiveRequest(
    MaestroDbSession session, {
    required String customerId,
    required String categoryId,
  }) async {
    await session.select(
      '''
      select pg_advisory_xact_lock(
        hashtextextended(
          cast(@customerId as text) || ':' || cast(@categoryId as text),
          904027
        )
      )
      ''',
      parameters: {'customerId': customerId, 'categoryId': categoryId},
    );
    final active = await session.select(
      '''
      select id, public_code
      from public.service_requests
      where customer_id = @customerId
        and category_id = @categoryId
        and status in (
          'submitted',
          'offers_received',
          'accepted',
          'on_the_way',
          'started',
          'disputed'
        )
      order by created_at desc
      limit 1
      ''',
      parameters: {'customerId': customerId, 'categoryId': categoryId},
    );
    if (active.isNotEmpty) {
      final code = active.single['public_code']?.toString();
      throw PlatformRuleException(
        code == null || code.isEmpty
            ? 'يوجد طلب فعال سابق لنفس الخدمة. ألغِه أو أكمله أولًا.'
            : 'يوجد طلب فعال سابق لنفس الخدمة برقم $code. ألغِه أو أكمله أولًا.',
        statusCode: 409,
      );
    }
  }

  Future<int> _expireStaleRequests(MaestroDbSession session) async {
    final rows = await session.select('''
      select maestro_private.expire_stale_service_requests()
        as expired_count
      ''');
    return rows.isEmpty ? 0 : _intValue(rows.single['expired_count']);
  }

  Future<int> _createRequestDispatchRows(
    MaestroDbSession session, {
    required String requestId,
    required String categoryId,
    required int batchSize,
    required int intervalMinutes,
    String source = 'automation',
    String? adminId,
    bool onlyIfDue = false,
  }) async {
    await session.select(
      '''
      select pg_advisory_xact_lock(
        hashtextextended(cast(@requestId as text), 904029)
      )
      ''',
      parameters: {'requestId': requestId},
    );
    final activeRequests = await session.select(
      '''
      select id
      from public.service_requests
      where id = @requestId
        and status in ('submitted', 'offers_received')
        and accepted_offer_id is null
        and expires_at > now()
      limit 1
      for update
      ''',
      parameters: {'requestId': requestId},
    );
    if (activeRequests.isEmpty) return 0;
    if (onlyIfDue) {
      final dueRows = await session.select(
        '''
        select
          count(rd.id) = 0
          or coalesce(max(rd.expires_at), request.created_at) <= now() as due
        from public.service_requests request
        left join public.request_dispatches rd on rd.request_id = request.id
        where request.id = @requestId
        group by request.id
        ''',
        parameters: {'requestId': requestId},
      );
      if (dueRows.isEmpty || dueRows.single['due'] != true) return 0;
    }
    final batchRows = await session.select(
      '''
      select coalesce(max(batch_no), 0)::int + 1 as next_batch
      from public.request_dispatches
      where request_id = @requestId
      ''',
      parameters: {'requestId': requestId},
    );
    final batchNo = batchRows.isEmpty ? 1 : batchRows.single['next_batch'];
    return session.execute(
      '''
      insert into public.request_dispatches (
        request_id,
        craftsman_id,
        batch_no,
        source,
        expires_at,
        created_by
      )
      select
        @requestId,
        candidates.craftsman_id,
        @batchNo,
        @source,
        least(
          active_request.expires_at,
          now() + cast(@intervalMinutes as integer) * interval '1 minute'
        ),
        cast(@adminId as uuid)
      from public.service_requests active_request
      cross join lateral (
        select
          cs.craftsman_id,
          (
            select count(*)::int
            from public.request_dispatches rd
            where rd.craftsman_id = cs.craftsman_id
              and rd.created_at >= now() - interval '24 hours'
          ) as daily_dispatches,
          cp.completed_jobs
        from public.craftsman_services cs
        join public.craftsman_profiles cp on cp.profile_id = cs.craftsman_id
        join public.profiles p on p.id = cs.craftsman_id
        where cs.category_id = @categoryId
          and cp.is_available = true
          and cp.is_verified = true
          and p.status = 'active'
          and p.notifications_enabled = true
          and not exists (
            select 1
            from public.request_dispatches old
            where old.request_id = @requestId
              and old.craftsman_id = cs.craftsman_id
          )
        order by daily_dispatches asc, cp.completed_jobs asc, random()
        limit @batchSize
      ) candidates
      where active_request.id = @requestId
        and active_request.category_id = @categoryId
        and active_request.status in ('submitted', 'offers_received')
        and active_request.accepted_offer_id is null
        and active_request.expires_at > now()
      on conflict (request_id, craftsman_id) do nothing
      ''',
      parameters: {
        'requestId': requestId,
        'categoryId': categoryId,
        'batchNo': batchNo,
        'source': source,
        'intervalMinutes': intervalMinutes,
        'adminId': adminId,
        'batchSize': batchSize,
      },
    );
  }

  Future<int> _dispatchDueRequestBatches(MaestroDbSession session) async {
    await _expireStaleRequests(session);
    final settings = await _requestAutomationSettings(session);
    if (!settings.enabled) return 0;
    final dueRequests = await session.select('''
      select
        sr.id,
        sr.category_id,
        sr.urgency,
        coalesce(max(rd.expires_at), sr.created_at) as last_expires_at
      from public.service_requests sr
      left join public.request_dispatches rd on rd.request_id = sr.id
      where sr.status in ('submitted', 'offers_received')
        and sr.accepted_offer_id is null
        and sr.expires_at > now()
      group by sr.id
      having count(rd.id) = 0
        or coalesce(max(rd.expires_at), sr.created_at) <= now()
      order by sr.created_at
      limit 20
      ''');
    var sent = 0;
    for (final request in dueRequests) {
      final inserted = await _createRequestDispatchRows(
        session,
        requestId: request['id'].toString(),
        categoryId: request['category_id'].toString(),
        batchSize: settings.batchSize,
        intervalMinutes: settings.intervalMinutes,
        onlyIfDue: true,
      );
      if (inserted <= 0) continue;
      await _notifyCurrentRequestDispatchBatch(
        session,
        requestId: request['id'].toString(),
        urgent: request['urgency'] == true,
      );
      sent += inserted;
    }
    return sent;
  }

  Future<void> _notifyCurrentRequestDispatchBatch(
    MaestroDbSession session, {
    required String requestId,
    required bool urgent,
    bool redispatched = false,
  }) {
    return session.execute(
      '''
      insert into public.notifications (profile_id, title, body, data)
      select
        rd.craftsman_id,
        'طلب خدمة جديد',
        @body,
        jsonb_build_object(
          'request_id', @requestId:uuid,
          'notification_type', 'order',
          'redispatched', @redispatched:boolean,
          'dispatch_notification', true,
          'actionable', true
        )
      from public.request_dispatches rd
      where rd.request_id = @requestId
        and rd.batch_no = (
          select max(batch_no)
          from public.request_dispatches
          where request_id = @requestId
        )
      ''',
      parameters: {
        'requestId': requestId,
        'redispatched': redispatched,
        'body': urgent
            ? 'يوجد طلب عاجل جديد ضمن تخصصك.'
            : 'يوجد طلب جديد ضمن تخصصك.',
      },
    );
  }

  Future<int> _renotifyLatestUnansweredDispatchBatch(
    MaestroDbSession session, {
    required String requestId,
    required bool urgent,
    required int intervalMinutes,
  }) async {
    final rows = await session.select(
      '''
      with refreshed as (
        update public.request_dispatches dispatch
        set
          notified_at = now(),
          expires_at = least(
            request.expires_at,
            now() + cast(@intervalMinutes as integer) * interval '1 minute'
          )
        from public.service_requests request
        where dispatch.request_id = @requestId
          and request.id = dispatch.request_id
          and dispatch.batch_no = (
            select max(latest.batch_no)
            from public.request_dispatches latest
            where latest.request_id = @requestId
          )
          and dispatch.offered_at is null
        returning dispatch.craftsman_id
      ),
      queued as (
        insert into public.notifications (profile_id, title, body, data)
        select
          refreshed.craftsman_id,
          'إعادة إرسال طلب خدمة',
          @body,
          jsonb_build_object(
            'request_id', @requestId:uuid,
            'notification_type', 'order',
            'redispatched', true,
            'dispatch_notification', true,
            'actionable', true
          )
        from refreshed
        returning id
      )
      select count(*)::int as notified_count
      from queued
      ''',
      parameters: {
        'requestId': requestId,
        'intervalMinutes': intervalMinutes,
        'body': urgent
            ? 'أعاد العميل إرسال طلب عاجل ضمن تخصصك.'
            : 'أعاد العميل إرسال طلب خدمة ضمن تخصصك.',
      },
    );
    return rows.isEmpty ? 0 : _intValue(rows.single['notified_count']);
  }

  Future<int> _notifyAdminsAboutManualRequest(
    MaestroDbSession session, {
    required String requestId,
    required String publicCode,
    bool redispatched = false,
  }) {
    return session.execute(
      '''
      insert into public.notifications (profile_id, title, body, data)
      select
        p.id,
        'طلب يحتاج توزيع يدوي',
        @body,
        jsonb_build_object(
          'request_id', @requestId:uuid,
          'notification_type', 'admin_request_dispatch',
          'redispatched', @redispatched:boolean
        )
      from public.profiles p
      where p.role = 'admin'
        and p.status = 'active'
        and p.notifications_enabled = true
      ''',
      parameters: {
        'requestId': requestId,
        'redispatched': redispatched,
        'body':
            '${redispatched ? 'أعاد العميل إرسال الطلب' : 'الطلب'} ${publicCode.isEmpty ? requestId : publicCode} وينتظر اختيار فني من الإدارة.',
      },
    );
  }

  Future<void> _closeRequestDispatchNotifications(
    MaestroDbSession session, {
    required String requestId,
    required String status,
    String? craftsmanId,
  }) {
    return session.execute(
      '''
      update public.notifications notification
      set
        read_at = coalesce(notification.read_at, now()),
        data = notification.data || jsonb_build_object(
          'dispatch_status', @status,
          'actionable', false
        ),
        push_status = case
          when notification.push_status in ('pending', 'failed')
            then 'skipped'
          else notification.push_status
        end,
        push_error = case
          when notification.push_status in ('pending', 'failed')
            then 'Dispatch notification is no longer actionable.'
          else notification.push_error
        end
      where notification.data ->> 'request_id' = @requestId
        and (
          cast(@craftsmanId as uuid) is null
          or notification.profile_id = cast(@craftsmanId as uuid)
        )
        and (
          notification.data ->> 'dispatch_notification' = 'true'
          or (
            notification.data ->> 'notification_type' = 'order'
            and notification.title in (
              'طلب خدمة جديد',
              'إعادة إرسال طلب خدمة'
            )
          )
        )
      ''',
      parameters: {
        'requestId': requestId,
        'status': status,
        'craftsmanId': craftsmanId,
      },
    );
  }

  Future<void> _closeOfferNotifications(
    MaestroDbSession session, {
    required String requestId,
    required String status,
  }) {
    return session.execute(
      '''
      update public.notifications notification
      set
        read_at = coalesce(notification.read_at, now()),
        data = notification.data || jsonb_build_object(
          'offer_status', @status,
          'actionable', false
        ),
        push_status = case
          when notification.push_status in ('pending', 'failed')
            then 'skipped'
          else notification.push_status
        end,
        push_error = case
          when notification.push_status in ('pending', 'failed')
            then 'Offer notification is no longer actionable.'
          else notification.push_error
        end
      where notification.data ->> 'request_id' = @requestId
        and notification.data ->> 'notification_type' = 'offer'
      ''',
      parameters: {'requestId': requestId, 'status': status},
    );
  }

  Future<List<Map<String, dynamic>>> _favoritesForCustomer(
    MaestroDbSession session,
    String customerId,
  ) {
    return session.select(
      '''
      select
        p.id,
        p.full_name,
        p.avatar_url,
        cp.profession,
        cp.rating,
        cp.completed_jobs,
        cp.on_time_percent,
        cp.is_verified,
        fc.created_at as saved_at
      from public.favorite_craftsmen fc
      join public.profiles p on p.id = fc.craftsman_id
      join public.craftsman_profiles cp on cp.profile_id = fc.craftsman_id
      where fc.customer_id = @customerId
        and p.status = 'active'
      order by fc.created_at desc
      ''',
      parameters: {'customerId': customerId},
    );
  }

  Future<List<Map<String, dynamic>>> _requestsForProfile(
    MaestroDbSession session,
    String profileId, {
    String? knownRole,
  }) async {
    var role = knownRole;
    if (role == null) {
      final roleRows = await session.select(
        '''
        with expiry_sweep as (
          select maestro_private.expire_stale_service_requests()
            as expired_count
        )
        select profile.role
        from public.profiles profile
        cross join expiry_sweep
        where profile.id = @profileId
        ''',
        parameters: {'profileId': profileId},
      );
      if (roleRows.isEmpty) return [];
      role = roleRows.single['role'].toString();
    }
    if (role == 'customer') {
      return session.select(
        '''
        select
          sr.*,
          sc.name_ar as category_name,
          sc.icon_key,
          sc.icon_url,
          sc.availability_status,
          coalesce(
            (
              select jsonb_agg(
                jsonb_build_object(
                  'url', ra.public_url,
                  'content_type', ra.content_type,
                  'resource_type', ra.resource_type
                )
                order by ra.created_at
              )
              from public.request_attachments ra
              where ra.request_id = sr.id
            ),
            '[]'::jsonb
          ) as attachments,
          (
            select count(*)::int
            from public.offers o
            where o.request_id = sr.id and o.status = 'submitted'
          ) as offers_count,
          exists (
            select 1
            from public.reviews r
            where r.request_id = sr.id
              and r.customer_id = sr.customer_id
          ) as review_submitted,
          rp.total_amount as payment_total_amount,
          rp.inspection_amount as payment_inspection_amount,
          rp.wallet_reserved_amount,
          rp.cash_due_amount,
          rp.status as payment_status,
          rp.cash_received_confirmed,
          public.maestro_distance_km(
            sr.latitude,
            sr.longitude,
            accepted_cp.last_latitude,
            accepted_cp.last_longitude
          ) as distance_km,
          case
            when sr.status in ('accepted', 'on_the_way', 'started')
              then accepted_cp.last_latitude
          end as craftsman_latitude,
          case
            when sr.status in ('accepted', 'on_the_way', 'started')
              then accepted_cp.last_longitude
          end as craftsman_longitude,
          case
            when sr.status in ('accepted', 'on_the_way', 'started')
              then accepted_cp.location_updated_at
          end as craftsman_location_updated_at,
          accepted_p.full_name as craftsman_name,
          accepted_p.avatar_url as craftsman_avatar_url,
          greatest(
            sr.created_at,
            coalesce(sr.last_redispatched_at, sr.created_at),
            coalesce(
              (
                select max(redispatch_rd.notified_at)
                from public.request_dispatches redispatch_rd
                where redispatch_rd.request_id = sr.id
              ),
              sr.created_at
            )
          ) + interval '1 hour' as next_redispatch_at,
          (
            sr.status in ('submitted', 'offers_received')
            and sr.accepted_offer_id is null
            and sr.expires_at > now()
            and now() >= greatest(
              sr.created_at,
              coalesce(sr.last_redispatched_at, sr.created_at),
              coalesce(
                (
                  select max(redispatch_check.notified_at)
                  from public.request_dispatches redispatch_check
                  where redispatch_check.request_id = sr.id
                ),
                sr.created_at
              )
            ) + interval '1 hour'
          ) as can_redispatch,
          timeline.submitted_at,
          timeline.offers_received_at,
          timeline.accepted_at,
          timeline.on_the_way_at,
          timeline.arrived_at,
          timeline.started_at,
          timeline.completed_at
        from public.service_requests sr
        join public.service_categories sc on sc.id = sr.category_id
        left join public.request_payments rp on rp.request_id = sr.id
        left join public.offers accepted_o on accepted_o.id = sr.accepted_offer_id
        left join public.craftsman_profiles accepted_cp
          on accepted_cp.profile_id = accepted_o.craftsman_id
        left join public.profiles accepted_p
          on accepted_p.id = accepted_o.craftsman_id
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
        where sr.customer_id = @profileId
        order by sr.created_at desc
        limit 100
        ''',
        parameters: {'profileId': profileId},
      );
    }
    if (role == 'craftsman') {
      final requests = await session.select(
        '''
        select
          sr.id,
          sr.public_code,
          sr.category_id,
          sr.status,
          sr.title,
          sr.description,
          sr.urgency,
          sr.scheduled_for,
          sr.city,
          sr.area,
          case
            when o.status = 'accepted' then sr.address_id
          end as address_id,
          case
            when o.status = 'accepted' then sr.address_text
          end as address_text,
          case
            when o.status = 'accepted' then sr.latitude
          end as latitude,
          case
            when o.status = 'accepted' then sr.longitude
          end as longitude,
          sr.voice_note_url,
          sr.created_at,
          sr.updated_at,
          sr.expires_at,
          sr.accepted_offer_id,
          sr.payment_method,
          sr.cancellation_mode,
          sr.cancellation_reason,
          sr.cancelled_at,
          sr.inspection_due_amount,
          sc.name_ar as category_name,
          sc.icon_key,
          sc.icon_url,
          sc.availability_status,
          coalesce(
            (
              select jsonb_agg(
                jsonb_build_object(
                  'url', ra.public_url,
                  'content_type', ra.content_type,
                  'resource_type', ra.resource_type
                )
                order by ra.created_at
              )
              from public.request_attachments ra
              where ra.request_id = sr.id
            ),
            '[]'::jsonb
          ) as attachments,
          p.full_name as customer_name,
          p.avatar_url as customer_avatar_url,
          o.id as my_offer_id,
          o.status as my_offer_status,
          o.total_amount as my_offer_amount,
          latest_revision.id as revision_id,
          latest_revision.status as revision_status,
          latest_revision.total_amount as revision_total_amount,
          latest_revision.labor_amount as revision_labor_amount,
          latest_revision.materials_amount as revision_materials_amount,
          latest_revision.inspection_fee as revision_inspection_fee,
          latest_revision.note as revision_note,
          latest_revision.response_note as revision_response_note,
          latest_revision.created_at as revision_created_at,
          latest_revision.responded_at as revision_responded_at,
          rp.total_amount as payment_total_amount,
          rp.inspection_amount as payment_inspection_amount,
          rp.wallet_reserved_amount,
          rp.cash_due_amount,
          rp.status as payment_status,
          rp.cash_received_confirmed,
          public.maestro_distance_km(
            sr.latitude,
            sr.longitude,
            viewer_cp.last_latitude,
            viewer_cp.last_longitude
          ) as distance_km,
          case
            when o.status = 'accepted' then sr.address_text
            else coalesce(sr.area, sr.city)
          end as visible_address,
          timeline.submitted_at,
          timeline.offers_received_at,
          timeline.accepted_at,
          timeline.on_the_way_at,
          timeline.arrived_at,
          timeline.started_at,
          timeline.completed_at
        from public.service_requests sr
        join public.service_categories sc on sc.id = sr.category_id
        join public.profiles p on p.id = sr.customer_id
        join public.craftsman_profiles viewer_cp
          on viewer_cp.profile_id = @profileId
        join public.craftsman_services cs
          on cs.category_id = sr.category_id
         and cs.craftsman_id = @profileId
        left join public.offers o
          on o.request_id = sr.id
         and o.craftsman_id = @profileId
        left join lateral (
          select revision.*
          from public.offer_revision_requests revision
          where revision.offer_id = o.id
          order by revision.created_at desc, revision.id desc
          limit 1
        ) latest_revision on true
        left join public.request_payments rp on rp.request_id = sr.id
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
                when sr.accepted_offer_id is not null then o.updated_at
              end
            ) as accepted_at,
            min(rse.created_at) filter (where rse.status = 'on_the_way') as on_the_way_at,
            null::timestamptz as arrived_at,
            min(rse.created_at) filter (where rse.status = 'started') as started_at,
            min(rse.created_at) filter (where rse.status = 'completed') as completed_at
          from public.request_status_events rse
          where rse.request_id = sr.id
        ) timeline on true
        where sr.status in (
          'submitted',
          'offers_received',
          'accepted',
          'on_the_way',
          'started'
        )
          and (
            sr.accepted_offer_id is null
            or sr.accepted_offer_id = o.id
          )
          and (
            o.id is not null
            or exists (
              select 1
              from public.request_dispatches rd
              where rd.request_id = sr.id
                and rd.craftsman_id = @profileId
                and rd.expires_at > now()
            )
          )
        order by sr.urgency desc, sr.created_at desc
        limit 100
        ''',
        parameters: {'profileId': profileId},
      );
      return requests.map((request) {
        final sanitized = Map<String, dynamic>.from(request);
        if (sanitized['my_offer_status']?.toString() != 'accepted') {
          sanitized
            ..remove('address_id')
            ..remove('address_text')
            ..remove('latitude')
            ..remove('longitude');
        }
        return sanitized;
      }).toList();
    }
    return session.select('''
      select sr.*, sc.name_ar as category_name
      from public.service_requests sr
      join public.service_categories sc on sc.id = sr.category_id
      order by sr.created_at desc
      limit 100
      ''');
  }

  Future<Map<String, dynamic>> _assertRequestParticipant(
    MaestroDbSession session,
    String profileId,
    String requestId,
  ) async {
    final rows = await session.select(
      '''
      select
        sr.customer_id,
        sr.status,
        o.craftsman_id
      from public.service_requests sr
      left join public.offers o on o.id = sr.accepted_offer_id
      where sr.id = @requestId
        and (
          sr.customer_id = @profileId
          or o.craftsman_id = @profileId
        )
      limit 1
      ''',
      parameters: {'profileId': profileId, 'requestId': requestId},
    );
    if (rows.isEmpty) {
      throw const PlatformRuleException(
        'لا يمكنك الوصول إلى محادثة هذا الطلب.',
        statusCode: 403,
      );
    }
    return rows.single;
  }

  Future<Map<String, dynamic>> _assertSupportConversationAccess(
    MaestroDbSession session, {
    required String profileId,
    required String role,
    required String conversationId,
    bool lock = false,
  }) async {
    final rows = await session.select(
      '''
      select *
      from public.support_tickets
      where id = @conversationId
        and (
          cast(@isAdmin as boolean)
          or profile_id = @profileId
        )
      limit 1
      ${lock ? 'for update' : ''}
      ''',
      parameters: {
        'conversationId': conversationId,
        'profileId': profileId,
        'isAdmin': role == 'admin',
      },
    );
    if (rows.isEmpty) {
      throw const PlatformRuleException(
        'محادثة الدعم غير موجودة أو لا تملك صلاحية الوصول إليها.',
        statusCode: 404,
      );
    }
    return rows.single;
  }

  Future<void> _assertOwnedManagedAttachment(
    MaestroDbSession session, {
    required String ownerId,
    required Object? publicUrl,
    required Object? providerPublicId,
    required Object? resourceType,
    String? expectedPurpose,
  }) async {
    if (publicUrl == null && providerPublicId == null) return;
    final rows = await session.select(
      '''
      select id
      from public.managed_media_assets
      where owner_id = @ownerId
        and provider = 'cloudinary'
        and provider_public_id = @providerPublicId
        and resource_type = @resourceType
        and public_url = @publicUrl
        and (
          @expectedPurpose:text is null
          or purpose = @expectedPurpose:text
        )
        and status = 'active'
      limit 1
      ''',
      parameters: {
        'ownerId': ownerId,
        'providerPublicId': providerPublicId,
        'resourceType': resourceType,
        'publicUrl': publicUrl,
        'expectedPurpose': expectedPurpose,
      },
    );
    if (rows.isEmpty) {
      throw const PlatformRuleException(
        'المرفق غير مسجل لهذا الحساب. أعد رفع الملف ثم حاول مجددًا.',
        statusCode: 422,
      );
    }
  }

  Future<void> _consumeOwnedManagedAttachment(
    MaestroDbSession session, {
    required String ownerId,
    required Object? publicUrl,
    required Object? providerPublicId,
    required Object? resourceType,
    required String expectedPurpose,
    required String consumedByType,
    required Object consumedById,
  }) async {
    if (publicUrl == null && providerPublicId == null) return;
    final rows = await session.select(
      '''
      update public.managed_media_assets
      set
        consumed_by_type = @consumedByType,
        consumed_by_id = @consumedById,
        consumed_at = coalesce(consumed_at, now())
      where owner_id = @ownerId
        and provider = 'cloudinary'
        and provider_public_id = @providerPublicId
        and resource_type = @resourceType
        and public_url = @publicUrl
        and purpose = @expectedPurpose
        and status = 'active'
        and (
          consumed_at is null
          or (
            consumed_by_type = @consumedByType
            and consumed_by_id = @consumedById
          )
        )
      returning id
      ''',
      parameters: {
        'ownerId': ownerId,
        'providerPublicId': providerPublicId,
        'resourceType': resourceType,
        'publicUrl': publicUrl,
        'expectedPurpose': expectedPurpose,
        'consumedByType': consumedByType,
        'consumedById': consumedById.toString(),
      },
    );
    if (rows.isEmpty) {
      throw const PlatformRuleException(
        'هذا الملف مستخدم مسبقًا أو غير مسجل لهذا الحساب. ارفع ملفًا جديدًا ثم حاول مجددًا.',
        statusCode: 409,
      );
    }
  }

  Future<void> _assertOwnedAvatar(
    MaestroDbSession session, {
    required String ownerId,
    required Object? publicUrl,
    required Object? providerPublicId,
    required Object? resourceType,
  }) async {
    final normalizedUrl = publicUrl?.toString().trim();
    if (normalizedUrl == null || normalizedUrl.isEmpty) return;

    final normalizedPublicId = providerPublicId?.toString().trim();
    final normalizedResourceType = resourceType?.toString().trim();
    if (normalizedPublicId != null &&
        normalizedPublicId.isNotEmpty &&
        normalizedResourceType != null &&
        normalizedResourceType.isNotEmpty) {
      await _assertOwnedManagedAttachment(
        session,
        ownerId: ownerId,
        publicUrl: normalizedUrl,
        providerPublicId: normalizedPublicId,
        resourceType: normalizedResourceType,
        expectedPurpose: 'avatars',
      );
      return;
    }

    // Older clients may resubmit the avatar already stored on the profile. This
    // remains safe because no new external URL can be introduced without the
    // ownership metadata returned by the authenticated upload endpoint.
    final existing = await session.select(
      '''
      select id
      from public.profiles
      where id = @ownerId
        and avatar_url = @publicUrl
      limit 1
      ''',
      parameters: {'ownerId': ownerId, 'publicUrl': normalizedUrl},
    );
    if (existing.isEmpty) {
      throw const PlatformRuleException(
        'بيانات ملكية الصورة الشخصية مفقودة. أعد رفع الصورة ثم حاول مجددًا.',
        statusCode: 422,
      );
    }
  }

  Future<void> _audit(
    MaestroDbSession session, {
    required String adminId,
    required String action,
    required String entityType,
    String? entityId,
    Map<String, dynamic> details = const {},
  }) async {
    await session.execute(
      '''
      insert into public.admin_audit_logs (
        admin_id,
        action,
        entity_type,
        entity_id,
        details
      )
      values (
        @adminId,
        @action,
        @entityType,
        @entityId,
        cast(@details as jsonb)
      )
      ''',
      parameters: {
        'adminId': adminId,
        'action': action,
        'entityType': entityType,
        'entityId': entityId,
        'details': _jsonText(details),
      },
    );
  }
}

class PlatformRuleException implements Exception {
  const PlatformRuleException(this.message, {this.statusCode = 400});

  final String message;
  final int statusCode;

  @override
  String toString() => 'PlatformRuleException($statusCode): $message';
}

class RequestRedispatchCooldownException extends PlatformRuleException {
  RequestRedispatchCooldownException(this.retryAt)
    : super(
        'يمكن إعادة إرسال الطلب مرة واحدة فقط كل 60 دقيقة.',
        statusCode: 429,
      );

  final DateTime retryAt;
}

const Set<String> _walletTopupStatuses = {'open', 'coming_soon', 'closed'};

const List<_WalletTopupMethod> _walletTopupMethodDefaults = [
  _WalletTopupMethod(
    id: 'coupon',
    titleAr: 'كوبون شحن',
    subtitleAr: 'أدخل رمز كوبون شحن المحفظة',
    status: 'open',
    sortOrder: 0,
    integrated: true,
    iconKey: 'confirmation_number',
  ),
  _WalletTopupMethod(
    id: 'libyana',
    titleAr: 'ليبيانا',
    subtitleAr: 'الشحن عبر ليبيانا',
    status: 'coming_soon',
    sortOrder: 10,
    integrated: false,
    iconKey: 'libyana',
  ),
  _WalletTopupMethod(
    id: 'sadad',
    titleAr: 'سداد',
    subtitleAr: 'الشحن عبر سداد',
    status: 'coming_soon',
    sortOrder: 20,
    integrated: false,
    iconKey: 'sadad',
  ),
  _WalletTopupMethod(
    id: 'bank_card_online',
    titleAr: 'البطاقة المصرفية (أونلاين)',
    subtitleAr: 'الشحن ببطاقة مصرفية',
    status: 'coming_soon',
    sortOrder: 30,
    integrated: false,
    iconKey: 'bank_card',
  ),
  _WalletTopupMethod(
    id: 'edfa3ly',
    titleAr: 'ادفعلي',
    subtitleAr: 'الشحن عبر ادفعلي',
    status: 'coming_soon',
    sortOrder: 40,
    integrated: false,
    iconKey: 'edfa3ly',
  ),
  _WalletTopupMethod(
    id: 'mobicash',
    titleAr: 'موبي كاش',
    subtitleAr: 'الشحن عبر موبي كاش',
    status: 'coming_soon',
    sortOrder: 50,
    integrated: false,
    iconKey: 'mobicash',
  ),
  _WalletTopupMethod(
    id: 'masrufi_pay',
    titleAr: 'مصرفي باي',
    subtitleAr: 'الشحن عبر مصرفي باي',
    status: 'coming_soon',
    sortOrder: 60,
    integrated: false,
    iconKey: 'masrufi_pay',
  ),
  _WalletTopupMethod(
    id: 'yusr_online',
    titleAr: 'يسر أونلاين',
    subtitleAr: 'الشحن عبر يسر أونلاين',
    status: 'coming_soon',
    sortOrder: 70,
    integrated: false,
    iconKey: 'yusr_online',
  ),
  _WalletTopupMethod(
    id: 'aqsat_online',
    titleAr: 'أقساط أونلاين (التجاري الوطني)',
    subtitleAr: 'الشحن عبر أقساط أونلاين',
    status: 'coming_soon',
    sortOrder: 80,
    integrated: false,
    iconKey: 'aqsat_online',
  ),
  _WalletTopupMethod(
    id: 'tadawul_online',
    titleAr: 'تداول (Online)',
    subtitleAr: 'الشحن عبر تداول',
    status: 'coming_soon',
    sortOrder: 90,
    integrated: false,
    iconKey: 'tadawul_online',
  ),
  _WalletTopupMethod(
    id: 'sahary_pay',
    titleAr: 'صحاري باي',
    subtitleAr: 'الشحن عبر صحاري باي',
    status: 'coming_soon',
    sortOrder: 100,
    integrated: false,
    iconKey: 'sahary_pay',
  ),
  _WalletTopupMethod(
    id: 'smart_pay',
    titleAr: 'سمارت باي (المتوسط)',
    subtitleAr: 'الشحن عبر سمارت باي',
    status: 'coming_soon',
    sortOrder: 110,
    integrated: false,
    iconKey: 'smart_pay',
  ),
];

class _WalletTopupMethod {
  const _WalletTopupMethod({
    required this.id,
    required this.titleAr,
    required this.subtitleAr,
    required this.status,
    required this.sortOrder,
    required this.integrated,
    this.iconKey,
  });

  final String id;
  final String titleAr;
  final String subtitleAr;
  final String status;
  final int sortOrder;
  final bool integrated;
  final String? iconKey;

  _WalletTopupMethod copyWith({String? status, int? sortOrder}) {
    return _WalletTopupMethod(
      id: id,
      titleAr: titleAr,
      subtitleAr: subtitleAr,
      status: status ?? this.status,
      sortOrder: sortOrder ?? this.sortOrder,
      integrated: integrated,
      iconKey: iconKey,
    );
  }

  Map<String, dynamic> toMap() {
    return {
      'id': id,
      'title_ar': titleAr,
      'subtitle_ar': subtitleAr,
      'status': status,
      'sort_order': sortOrder,
      'integrated': integrated,
      if (iconKey != null) 'icon_key': iconKey,
    };
  }
}

List<_WalletTopupMethod> _walletTopupMethodsFromRaw(Object? raw) {
  Object? decoded = raw;
  if (raw is String) {
    try {
      decoded = jsonDecode(raw);
    } on FormatException {
      decoded = null;
    }
  }
  final source = decoded is List
      ? decoded
      : decoded is Map && decoded['items'] is List
      ? decoded['items'] as List
      : const [];
  final stored = <String, Map<String, dynamic>>{};
  for (final rawItem in source) {
    if (rawItem is! Map) continue;
    final item = Map<String, dynamic>.from(rawItem);
    final id = item['id']?.toString().trim() ?? '';
    if (id.isNotEmpty) stored[id] = item;
  }

  final methods = _walletTopupMethodDefaults
      .map((fallback) {
        final item = stored[fallback.id];
        final rawStatus = item?['status']?.toString().trim();
        var status = _walletTopupStatuses.contains(rawStatus)
            ? rawStatus!
            : fallback.status;
        if (status == 'open' && !fallback.integrated) {
          status = 'coming_soon';
        }
        final rawOrder = item?['sort_order'];
        final parsedOrder = rawOrder is int
            ? rawOrder
            : rawOrder is num && rawOrder == rawOrder.roundToDouble()
            ? rawOrder.toInt()
            : int.tryParse(rawOrder?.toString() ?? '');
        final sortOrder =
            parsedOrder == null || parsedOrder < -100000 || parsedOrder > 100000
            ? fallback.sortOrder
            : parsedOrder;
        return fallback.copyWith(status: status, sortOrder: sortOrder);
      })
      .toList(growable: false);
  methods.sort(_compareWalletTopupMethods);
  return methods;
}

int _compareWalletTopupMethods(_WalletTopupMethod a, _WalletTopupMethod b) {
  final order = a.sortOrder.compareTo(b.sortOrder);
  return order != 0 ? order : a.id.compareTo(b.id);
}

void _validateWalletTopupImmutableFields(
  Map<String, dynamic> input,
  _WalletTopupMethod expected,
) {
  const allowed = {
    'id',
    'title_ar',
    'subtitle_ar',
    'status',
    'sort_order',
    'integrated',
    'icon_key',
  };
  for (final key in input.keys) {
    if (!allowed.contains(key)) {
      throw PlatformRuleException(
        'الحقل "$key" غير مدعوم في إعدادات طرق الشحن.',
        statusCode: 422,
      );
    }
  }
  final expectedFields = <String, Object?>{
    'title_ar': expected.titleAr,
    'subtitle_ar': expected.subtitleAr,
    'integrated': expected.integrated,
    'icon_key': expected.iconKey,
  };
  for (final entry in expectedFields.entries) {
    if (input.containsKey(entry.key) && input[entry.key] != entry.value) {
      throw PlatformRuleException(
        'لا يمكن تغيير الحقل "${entry.key}" لطريقة الشحن "${expected.id}".',
        statusCode: 422,
      );
    }
  }
}

class _RequestAutomationSettings {
  const _RequestAutomationSettings({
    required this.enabled,
    required this.batchSize,
    required this.intervalMinutes,
  });

  final bool enabled;
  final int batchSize;
  final int intervalMinutes;
}

String _roleLabel(String role) {
  return switch (role) {
    'customer' => 'عميل',
    'craftsman' => 'حرفي',
    'admin' => 'إدارة',
    _ => role,
  };
}

DateTime? _dateOrNull(Object? value) {
  if (value == null || value.toString().trim().isEmpty) return null;
  if (value is DateTime) return value;
  return DateTime.tryParse(value.toString());
}

double _money(Object? value) {
  if (value is num) return value.toDouble();
  return double.tryParse(value?.toString() ?? '') ?? 0;
}

String _addressText(Map<String, dynamic> address) {
  return [
        address['street'],
        address['building'],
        address['floor'],
        address['notes'],
      ]
      .where((value) => value != null && value.toString().trim().isNotEmpty)
      .join('، ');
}

String _jsonText(Object? value) {
  return jsonEncode(value);
}

Map<String, dynamic>? _jsonObject(Object? raw) {
  Object? decoded = raw;
  if (raw is String) {
    try {
      decoded = jsonDecode(raw);
    } on FormatException {
      return null;
    }
  }
  return decoded is Map ? Map<String, dynamic>.from(decoded) : null;
}

List<Map<String, dynamic>> _jsonObjectList(Object? raw) {
  Object? decoded = raw;
  if (raw is String) {
    try {
      decoded = jsonDecode(raw);
    } on FormatException {
      return const [];
    }
  }
  if (decoded is! List) return const [];
  return decoded
      .whereType<Map>()
      .map((item) => Map<String, dynamic>.from(item))
      .toList(growable: false);
}

Map<String, dynamic> _retentionSettings(Object? raw) {
  Object? decoded = raw;
  if (raw is String) {
    try {
      decoded = jsonDecode(raw);
    } on FormatException {
      decoded = null;
    }
  }
  final value = decoded is Map
      ? Map<String, dynamic>.from(decoded)
      : const <String, dynamic>{};
  int days(Object? candidate) {
    final parsed = candidate is int
        ? candidate
        : int.tryParse(candidate?.toString() ?? '');
    return (parsed ?? 0).clamp(0, 3650);
  }

  return {
    'enabled': value['enabled'] != false,
    'completed_request_media_days': days(value['completed_request_media_days']),
    'closed_support_message_days': days(value['closed_support_message_days']),
  };
}

List<Map<String, dynamic>> _homeBanners(Object? raw, {bool activeOnly = true}) {
  Object? decoded = raw;
  if (raw is String) {
    try {
      decoded = jsonDecode(raw);
    } on FormatException {
      decoded = null;
    }
  }
  final source = decoded is List
      ? decoded
      : decoded is Map && decoded['items'] is List
      ? decoded['items'] as List
      : const [];
  final banners = <Map<String, dynamic>>[];
  for (final rawItem in source) {
    if (rawItem is! Map) continue;
    final item = Map<String, dynamic>.from(rawItem);
    final imageUrl = item['image_url']?.toString().trim();
    final id = item['id']?.toString().trim();
    if (imageUrl == null || imageUrl.isEmpty || id == null || id.isEmpty) {
      continue;
    }
    final active = item['active'] != false;
    if (activeOnly && !active) continue;
    banners.add({
      'id': id,
      'image_url': imageUrl,
      'title': _blankToNull(item['title']),
      'subtitle': _blankToNull(item['subtitle']),
      'display_order': _intValue(item['display_order']),
      'active': active,
      'click_action': _clickAction(item['click_action']),
      'created_at':
          DateTime.tryParse(
            item['created_at']?.toString() ?? '',
          )?.toUtc().toIso8601String() ??
          DateTime.fromMillisecondsSinceEpoch(0, isUtc: true).toIso8601String(),
    });
  }
  banners.sort(_compareHomeBannerMaps);
  return banners;
}

int _compareHomeBannerMaps(Map<String, dynamic> a, Map<String, dynamic> b) {
  final order = _intValue(
    a['display_order'],
  ).compareTo(_intValue(b['display_order']));
  if (order != 0) return order;
  return (a['created_at']?.toString() ?? '').compareTo(
    b['created_at']?.toString() ?? '',
  );
}

Object? _blankToNull(Object? value) {
  final text = value?.toString().trim();
  return text == null || text.isEmpty ? null : text;
}

int _intValue(Object? value) {
  if (value is int) return value;
  if (value is num) return value.round();
  return int.tryParse(value?.toString() ?? '') ?? 0;
}

String _clickAction(Object? value) {
  final text = value?.toString().trim();
  if (text == null || text.isEmpty) return 'none';
  if (!_isSupportedHomeBannerAction(text)) return 'none';
  return text.length > 160 ? text.substring(0, 160) : text;
}

bool _isSupportedHomeBannerAction(String action) {
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

String _newCouponCode() {
  final buffer = StringBuffer(_secureRandom.nextInt(9) + 1);
  for (var index = 1; index < 13; index++) {
    buffer.write(_secureRandom.nextInt(10));
  }
  return buffer.toString();
}
