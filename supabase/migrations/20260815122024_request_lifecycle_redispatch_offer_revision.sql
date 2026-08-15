-- Enforce the request lifecycle at the database boundary. The HTTP backend is
-- still the only public entry point; these guards protect against races and
-- future maintenance scripts that insert requests directly.

alter table public.service_requests
  add column if not exists expires_at timestamptz,
  add column if not exists last_redispatched_at timestamptz,
  add column if not exists redispatch_count integer not null default 0;

update public.service_requests
set expires_at = created_at + interval '48 hours'
where expires_at is null;

alter table public.service_requests
  alter column expires_at set default (now() + interval '48 hours'),
  alter column expires_at set not null;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'service_requests_redispatch_count_check'
      and conrelid = 'public.service_requests'::regclass
  ) then
    alter table public.service_requests
      add constraint service_requests_redispatch_count_check
      check (redispatch_count >= 0);
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'service_requests_expiry_after_creation_check'
      and conrelid = 'public.service_requests'::regclass
  ) then
    alter table public.service_requests
      add constraint service_requests_expiry_after_creation_check
      check (expires_at >= created_at);
  end if;
end $$;

create index if not exists idx_service_requests_pending_expiry
  on public.service_requests (expires_at, id)
  where status in ('submitted', 'offers_received')
    and accepted_offer_id is null;

create or replace function public.enforce_one_active_request_per_category()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.status not in (
    'submitted',
    'offers_received',
    'accepted',
    'on_the_way',
    'started',
    'disputed'
  ) then
    return new;
  end if;

  -- Do not make an existing historical duplicate prevent the same request
  -- from advancing through its normal active lifecycle.
  if tg_op = 'UPDATE'
    and old.customer_id = new.customer_id
    and old.category_id = new.category_id
    and old.status in (
      'submitted',
      'offers_received',
      'accepted',
      'on_the_way',
      'started',
      'disputed'
    )
  then
    return new;
  end if;

  -- The transaction-scoped lock makes the check atomic without forcing a
  -- migration-time cancellation of historical duplicate rows.
  perform pg_advisory_xact_lock(
    hashtextextended(new.customer_id::text || ':' || new.category_id, 904027)
  );

  if exists (
    select 1
    from public.service_requests existing_request
    where existing_request.customer_id = new.customer_id
      and existing_request.category_id = new.category_id
      and existing_request.id is distinct from new.id
      and existing_request.status in (
        'submitted',
        'offers_received',
        'accepted',
        'on_the_way',
        'started',
        'disputed'
      )
  ) then
    raise exception using
      errcode = '23505',
      constraint = 'service_requests_one_active_category',
      message = 'يوجد طلب فعال سابق لنفس الخدمة.';
  end if;

  return new;
end;
$$;

drop trigger if exists enforce_one_active_request_per_category
  on public.service_requests;
create trigger enforce_one_active_request_per_category
before insert or update of customer_id, category_id, status
on public.service_requests
for each row execute function public.enforce_one_active_request_per_category();

-- A single pending counter offer per offer keeps concurrent taps idempotent.
with ranked_pending_revisions as (
  select
    id,
    row_number() over (
      partition by offer_id
      order by created_at desc, id desc
    ) as position
  from public.offer_revision_requests
  where status = 'pending'
),
cancelled_pending_revisions as (
  update public.offer_revision_requests revision
  set
    status = 'cancelled',
    response_note = coalesce(
      revision.response_note,
      'أُلغي تلقائيًا بعد إنشاء طلب تعديل أحدث.'
    ),
    responded_at = coalesce(revision.responded_at, now())
  from ranked_pending_revisions ranked
  where revision.id = ranked.id
    and ranked.position > 1
  returning revision.id
)
update public.notifications notification
set
  read_at = coalesce(notification.read_at, now()),
  data = notification.data || jsonb_build_object(
    'revision_status', 'cancelled',
    'actionable', false
  ),
  push_status = case
    when notification.push_status in ('pending', 'failed') then 'skipped'
    else notification.push_status
  end,
  push_error = case
    when notification.push_status in ('pending', 'failed')
      then 'Offer revision is no longer actionable.'
    else notification.push_error
  end
from cancelled_pending_revisions revision
where notification.data ->> 'revision_id' = revision.id::text;

create unique index if not exists idx_offer_revision_one_pending
  on public.offer_revision_requests (offer_id)
  where status = 'pending';

-- Keep expiry independent from the Render process. This schema is not exposed
-- through Supabase Data API, and the function remains invoker-secured.
create schema if not exists maestro_private;
revoke all on schema maestro_private from public, anon, authenticated;

create or replace function maestro_private.expire_stale_service_requests()
returns integer
language sql
security invoker
set search_path = ''
as $function$
  with expired as (
    update public.service_requests request
    set
      status = 'cancelled',
      cancellation_mode = 'no_entitlement',
      cancellation_reason =
        'انتهت صلاحية الطلب تلقائيًا بعد 48 ساعة دون قبول عرض.',
      cancelled_by = null,
      cancelled_at = now(),
      inspection_due_amount = 0,
      updated_at = now()
    where request.status in ('submitted', 'offers_received')
      and request.accepted_offer_id is null
      and request.expires_at <= now()
    returning request.id, request.customer_id
  ),
  expired_offers as (
    update public.offers offer
    set status = 'expired', updated_at = now()
    from expired
    where offer.request_id = expired.id
      and offer.status = 'submitted'
    returning offer.id
  ),
  cancelled_revisions as (
    update public.offer_revision_requests revision
    set
      status = 'cancelled',
      response_note = coalesce(
        revision.response_note,
        'أُلغي تلقائيًا لانتهاء صلاحية الطلب.'
      ),
      responded_at = coalesce(revision.responded_at, now())
    from expired
    where revision.request_id = expired.id
      and revision.status = 'pending'
    returning revision.id
  ),
  closed_revision_notifications as (
    update public.notifications notification
    set
      read_at = coalesce(notification.read_at, now()),
      data = notification.data || jsonb_build_object(
        'revision_status', 'cancelled',
        'actionable', false
      ),
      push_status = case
        when notification.push_status in ('pending', 'failed') then 'skipped'
        else notification.push_status
      end,
      push_error = case
        when notification.push_status in ('pending', 'failed')
          then 'Offer revision is no longer actionable.'
        else notification.push_error
      end
    from cancelled_revisions revision
    where notification.data ->> 'revision_id' = revision.id::text
    returning notification.id
  ),
  closed_dispatches as (
    update public.request_dispatches dispatch
    set expires_at = least(dispatch.expires_at, now())
    from expired
    where dispatch.request_id = expired.id
      and dispatch.expires_at > now()
    returning dispatch.id
  ),
  closed_dispatch_notifications as (
    update public.notifications notification
    set
      read_at = coalesce(notification.read_at, now()),
      data = notification.data || jsonb_build_object(
        'dispatch_status', 'cancelled',
        'actionable', false
      ),
      push_status = case
        when notification.push_status in ('pending', 'failed') then 'skipped'
        else notification.push_status
      end,
      push_error = case
        when notification.push_status in ('pending', 'failed')
          then 'Dispatch notification is no longer actionable.'
        else notification.push_error
      end
    from expired
    where notification.data ->> 'request_id' = expired.id::text
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
    returning notification.id
  ),
  closed_offer_notifications as (
    update public.notifications notification
    set
      read_at = coalesce(notification.read_at, now()),
      data = notification.data || jsonb_build_object(
        'offer_status', 'cancelled',
        'actionable', false
      ),
      push_status = case
        when notification.push_status in ('pending', 'failed') then 'skipped'
        else notification.push_status
      end,
      push_error = case
        when notification.push_status in ('pending', 'failed')
          then 'Offer notification is no longer actionable.'
        else notification.push_error
      end
    from expired
    where notification.data ->> 'request_id' = expired.id::text
      and notification.data ->> 'notification_type' = 'offer'
    returning notification.id
  ),
  status_events as (
    insert into public.request_status_events (
      request_id,
      status,
      actor_id,
      note
    )
    select expired.id, 'cancelled', null, 'auto_expired_no_offer'
    from expired
    returning id
  ),
  queued_notifications as (
    insert into public.notifications (profile_id, title, body, data)
    select
      expired.customer_id,
      'انتهت صلاحية الطلب',
      'أُلغي الطلب تلقائيًا بعد مرور 48 ساعة دون قبول عرض.',
      jsonb_build_object(
        'request_id', expired.id,
        'notification_type', 'order',
        'status', 'cancelled',
        'reason', 'expired_no_offer'
      )
    from expired
    returning id
  )
  select count(*)::integer
  from expired;
$function$;

revoke all on function maestro_private.expire_stale_service_requests()
  from public, anon, authenticated;

-- Bring existing stale rows into the same invariant immediately; pg_cron then
-- keeps it true without relying on the Render process being awake.
select maestro_private.expire_stale_service_requests();

-- A partial UNIQUE index is the final race-proof invariant. Stale duplicates
-- were expired above; any remaining active duplicate represents real data
-- requiring an explicit decision, so fail safely instead of deleting it.
do $active_duplicate_guard$
begin
  if exists (
    select 1
    from public.service_requests
    where status in (
      'submitted',
      'offers_received',
      'accepted',
      'on_the_way',
      'started',
      'disputed'
    )
    group by customer_id, category_id
    having count(*) > 1
  ) then
    raise exception
      'Active duplicate service requests remain after expiry cleanup.';
  end if;
end;
$active_duplicate_guard$;

create unique index if not exists idx_service_requests_one_active_category
  on public.service_requests (customer_id, category_id)
  where status in (
    'submitted',
    'offers_received',
    'accepted',
    'on_the_way',
    'started',
    'disputed'
  );

-- Supabase hosts pg_cron. Keep the migration deployable on a local PostgreSQL
-- without the extension by warning and retaining the backend/lazy fallback.
insert into public.app_settings (key, value, is_public, description)
values (
  'request_expiry_scheduler',
  jsonb_build_object(
    'provider', 'supabase_pg_cron',
    'enabled', false,
    'job_name', 'mastro-expire-stale-service-requests',
    'schedule', '*/5 * * * *'
  ),
  false,
  'Expires unaccepted service requests after 48 hours.'
)
on conflict (key) do update
set
  value = excluded.value,
  is_public = false,
  description = excluded.description;

do $cron_setup$
begin
  begin
    execute 'create extension if not exists pg_cron';
  exception
    when insufficient_privilege or undefined_file or feature_not_supported then
      raise warning
        'pg_cron could not be enabled; request expiry will use backend/lazy fallback.';
  end;

  if exists (
    select 1 from pg_extension where extname = 'pg_cron'
  ) then
    begin
      execute format(
        'select cron.schedule(%L, %L, %L)',
        'mastro-expire-stale-service-requests',
        '*/5 * * * *',
        'select maestro_private.expire_stale_service_requests();'
      );
      execute format(
        'select cron.alter_job('
          || '(select jobid from cron.job where jobname = %L), '
          || 'active := true)',
        'mastro-expire-stale-service-requests'
      );
      update public.app_settings
      set value = jsonb_set(value, '{enabled}', 'true'::jsonb, true)
      where key = 'request_expiry_scheduler';
    exception
      when insufficient_privilege or invalid_schema_name or undefined_function then
        raise warning
          'pg_cron is installed but the MASTRO expiry job could not be scheduled.';
    end;
  end if;
end;
$cron_setup$;
