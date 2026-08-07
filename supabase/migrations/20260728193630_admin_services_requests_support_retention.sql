-- Administration controls for service availability, request cancellation,
-- conversational support and durable media-retention cleanup.
--
-- The Maestro backend is the only component allowed to access these tables.

alter table public.service_categories
  add column if not exists icon_url text,
  add column if not exists availability_status text not null default 'open';

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'service_categories_availability_status_check'
      and conrelid = 'public.service_categories'::regclass
  ) then
    alter table public.service_categories
      add constraint service_categories_availability_status_check
      check (availability_status in ('open', 'closed', 'coming_soon'));
  end if;
end $$;

alter table public.service_requests
  add column if not exists cancellation_mode text,
  add column if not exists cancellation_reason text,
  add column if not exists cancelled_by uuid
    references public.profiles(id) on delete set null,
  add column if not exists cancelled_at timestamptz,
  add column if not exists inspection_due_amount numeric(14,2)
    not null default 0;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'service_requests_cancellation_mode_check'
      and conrelid = 'public.service_requests'::regclass
  ) then
    alter table public.service_requests
      add constraint service_requests_cancellation_mode_check
      check (
        cancellation_mode is null
        or cancellation_mode in ('inspection_due', 'no_entitlement')
      );
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'service_requests_inspection_due_amount_check'
      and conrelid = 'public.service_requests'::regclass
  ) then
    alter table public.service_requests
      add constraint service_requests_inspection_due_amount_check
      check (inspection_due_amount >= 0);
  end if;
end $$;

alter table public.support_tickets
  add column if not exists closed_at timestamptz,
  add column if not exists last_message_at timestamptz;

update public.support_tickets
set last_message_at = coalesce(last_message_at, updated_at, created_at)
where last_message_at is null;

update public.support_tickets
set closed_at = coalesce(closed_at, updated_at, created_at)
where status in ('resolved', 'closed')
  and closed_at is null;

alter table public.support_tickets
  alter column last_message_at set default now(),
  alter column last_message_at set not null;

create table if not exists public.support_messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null
    references public.support_tickets(id) on delete cascade,
  sender_id uuid references public.profiles(id) on delete set null,
  sender_type text not null
    check (sender_type in ('user', 'admin', 'system')),
  body text not null default '',
  attachment_url text,
  attachment_type text
    check (
      attachment_type is null
      or attachment_type in ('image', 'audio', 'file')
    ),
  attachment_public_id text,
  attachment_resource_type text
    check (
      attachment_resource_type is null
      or attachment_resource_type in ('image', 'video', 'raw')
    ),
  read_at timestamptz,
  created_at timestamptz not null default now(),
  check (
    length(btrim(body)) > 0
    or attachment_url is not null
  )
);

-- Preserve legacy ticket bodies as the first conversation message.
insert into public.support_messages (
  conversation_id,
  sender_id,
  sender_type,
  body,
  created_at
)
select
  st.id,
  st.profile_id,
  'user',
  st.body,
  st.created_at
from public.support_tickets st
where length(btrim(st.body)) > 0
  and not exists (
    select 1
    from public.support_messages sm
    where sm.conversation_id = st.id
  );

alter table public.job_messages
  add column if not exists attachment_public_id text,
  add column if not exists attachment_resource_type text;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'job_messages_attachment_resource_type_check'
      and conrelid = 'public.job_messages'::regclass
  ) then
    alter table public.job_messages
      add constraint job_messages_attachment_resource_type_check
      check (
        attachment_resource_type is null
        or attachment_resource_type in ('image', 'video', 'raw')
      );
  end if;
end $$;

create table if not exists public.media_cleanup_jobs (
  id uuid primary key default gen_random_uuid(),
  provider text not null default 'cloudinary',
  provider_public_id text not null,
  resource_type text not null default 'image'
    check (resource_type in ('image', 'video', 'raw')),
  source_type text not null,
  source_id text,
  status text not null default 'pending'
    check (status in ('pending', 'processing', 'deleted', 'failed')),
  attempts int not null default 0 check (attempts >= 0),
  last_error text,
  next_attempt_at timestamptz not null default now(),
  processed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (provider, resource_type, provider_public_id)
);

create table if not exists public.managed_media_assets (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles(id) on delete cascade,
  provider text not null default 'cloudinary',
  provider_public_id text not null,
  resource_type text not null
    check (resource_type in ('image', 'video', 'raw')),
  purpose text not null,
  public_url text not null,
  status text not null default 'active'
    check (status in ('active', 'delete_pending', 'deleted')),
  consumed_by_type text,
  consumed_by_id text,
  consumed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (
    (consumed_by_type is null and consumed_by_id is null and consumed_at is null)
    or
    (consumed_by_type is not null and consumed_by_id is not null and consumed_at is not null)
  ),
  unique (provider, resource_type, provider_public_id)
);

-- Existing request uploads were already produced by the backend, so their
-- ownership can be recovered safely from the request customer.
insert into public.managed_media_assets (
  owner_id,
  provider,
  provider_public_id,
  resource_type,
  purpose,
  public_url,
  consumed_by_type,
  consumed_by_id,
  consumed_at
)
select
  sr.customer_id,
  coalesce(ra.provider, 'cloudinary'),
  ra.provider_public_id,
  case
    when ra.resource_type in ('image', 'video', 'raw')
      then ra.resource_type
    else 'image'
  end,
  'service-requests',
  ra.public_url,
  'request_attachment',
  ra.id::text,
  ra.created_at
from public.request_attachments ra
join public.service_requests sr on sr.id = ra.request_id
where ra.provider_public_id is not null
  and ra.public_url is not null
on conflict (provider, resource_type, provider_public_id) do nothing;

create index if not exists idx_service_categories_availability_sort
  on public.service_categories(availability_status, sort_order)
  where is_active;

create index if not exists idx_service_requests_admin_status_created
  on public.service_requests(status, created_at desc);

create index if not exists idx_service_requests_cancelled_at
  on public.service_requests(cancelled_at desc)
  where status = 'cancelled';

create index if not exists idx_service_requests_cancelled_by
  on public.service_requests(cancelled_by)
  where cancelled_by is not null;

create index if not exists idx_support_messages_conversation_created
  on public.support_messages(conversation_id, created_at);

create index if not exists idx_support_messages_sender
  on public.support_messages(sender_id, created_at desc)
  where sender_id is not null;

create index if not exists idx_support_tickets_profile_active
  on public.support_tickets(profile_id, last_message_at desc)
  where status in ('open', 'in_progress');

create index if not exists idx_support_tickets_retention
  on public.support_tickets(closed_at)
  where status in ('resolved', 'closed');

create index if not exists idx_media_cleanup_jobs_due
  on public.media_cleanup_jobs(next_attempt_at, created_at)
  where status in ('pending', 'failed', 'processing');

create index if not exists idx_managed_media_assets_owner_created
  on public.managed_media_assets(owner_id, created_at desc);

create index if not exists idx_managed_media_assets_consumption
  on public.managed_media_assets(consumed_by_type, consumed_by_id)
  where consumed_at is not null;

drop index if exists public.idx_notifications_push_queue;
create index idx_notifications_push_queue
  on public.notifications(push_status, push_claimed_at, created_at)
  where push_status in ('pending', 'failed', 'processing');

drop trigger if exists set_media_cleanup_jobs_updated_at
  on public.media_cleanup_jobs;
create trigger set_media_cleanup_jobs_updated_at
before update on public.media_cleanup_jobs
for each row execute function public.set_updated_at();

drop trigger if exists set_managed_media_assets_updated_at
  on public.managed_media_assets;
create trigger set_managed_media_assets_updated_at
before update on public.managed_media_assets
for each row execute function public.set_updated_at();

insert into public.app_settings (key, value, is_public, description)
values (
  'media_retention',
  '{
    "enabled": true,
    "completed_request_media_days": 0,
    "closed_support_message_days": 0
  }'::jsonb,
  false,
  'Retention in days before completed-request media and closed support messages are removed.'
)
on conflict (key) do nothing;

alter table public.support_messages enable row level security;
alter table public.media_cleanup_jobs enable row level security;
alter table public.managed_media_assets enable row level security;

revoke all on table public.support_messages from anon, authenticated;
revoke all on table public.media_cleanup_jobs from anon, authenticated;
revoke all on table public.managed_media_assets from anon, authenticated;
