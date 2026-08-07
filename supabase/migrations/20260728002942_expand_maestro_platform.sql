-- Persistent authentication, addresses, media, wallets and administration.
-- All access is performed by the Maestro backend. Client applications never
-- receive database credentials or Cloudinary secrets.

alter table public.profiles
  add column if not exists blocked_reason text,
  add column if not exists notifications_enabled boolean not null default true;

alter table public.craftsman_profiles
  add column if not exists is_available boolean not null default true;

alter table public.craftsman_verification_documents
  add column if not exists provider text not null default 'cloudinary',
  add column if not exists public_url text,
  add column if not exists provider_public_id text;

alter table public.request_attachments
  add column if not exists provider text not null default 'cloudinary',
  add column if not exists public_url text,
  add column if not exists provider_public_id text,
  add column if not exists resource_type text not null default 'image';

alter table public.service_requests
  add column if not exists address_id uuid references public.customer_addresses(id) on delete set null;

create table if not exists public.app_settings (
  key text primary key,
  value jsonb not null,
  is_public boolean not null default false,
  description text,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.app_sessions (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references public.profiles(id) on delete cascade,
  token_hash text not null unique,
  device_name text,
  ip_address inet,
  expires_at timestamptz not null,
  last_seen_at timestamptz not null default now(),
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.wallets (
  profile_id uuid primary key references public.profiles(id) on delete cascade,
  available_balance numeric(14,2) not null default 0 check (available_balance >= 0),
  pending_balance numeric(14,2) not null default 0 check (pending_balance >= 0),
  total_earned numeric(14,2) not null default 0 check (total_earned >= 0),
  currency text not null default 'LYD',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.wallet_transactions (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references public.wallets(profile_id) on delete cascade,
  request_id uuid references public.service_requests(id) on delete set null,
  kind text not null check (
    kind in ('deposit', 'payment', 'refund', 'earning', 'withdrawal', 'adjustment')
  ),
  status text not null default 'completed' check (
    status in ('pending', 'completed', 'failed', 'cancelled')
  ),
  amount numeric(14,2) not null check (amount <> 0),
  currency text not null default 'LYD',
  description text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.favorite_craftsmen (
  customer_id uuid not null references public.profiles(id) on delete cascade,
  craftsman_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (customer_id, craftsman_id),
  check (customer_id <> craftsman_id)
);

create table if not exists public.craftsman_services (
  craftsman_id uuid not null references public.profiles(id) on delete cascade,
  category_id text not null references public.service_categories(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (craftsman_id, category_id)
);

create table if not exists public.notification_preferences (
  profile_id uuid primary key references public.profiles(id) on delete cascade,
  offers boolean not null default true,
  request_updates boolean not null default true,
  messages boolean not null default true,
  promotions boolean not null default true,
  quiet_hours_start time,
  quiet_hours_end time,
  updated_at timestamptz not null default now()
);

create table if not exists public.notification_devices (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references public.profiles(id) on delete cascade,
  platform text not null check (platform in ('android', 'ios', 'web')),
  push_token text not null unique,
  enabled boolean not null default true,
  last_seen_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create table if not exists public.notification_campaigns (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  body text not null,
  audience text not null check (
    audience in ('all', 'customers', 'craftsmen', 'profile')
  ),
  target_profile_id uuid references public.profiles(id) on delete cascade,
  data jsonb not null default '{}'::jsonb,
  scheduled_for timestamptz not null default now(),
  status text not null default 'scheduled' check (
    status in ('scheduled', 'processing', 'sent', 'cancelled', 'failed')
  ),
  sent_at timestamptz,
  error_message text,
  created_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  check (
    (audience = 'profile' and target_profile_id is not null)
    or (audience <> 'profile' and target_profile_id is null)
  )
);

alter table public.notifications
  add column if not exists campaign_id uuid references public.notification_campaigns(id) on delete set null;

create table if not exists public.support_tickets (
  id uuid primary key default gen_random_uuid(),
  public_code text not null unique default ('SUP-' || upper(substr(gen_random_uuid()::text, 1, 8))),
  profile_id uuid not null references public.profiles(id) on delete restrict,
  request_id uuid references public.service_requests(id) on delete set null,
  subject text not null,
  body text not null,
  status text not null default 'open' check (
    status in ('open', 'in_progress', 'resolved', 'closed')
  ),
  priority text not null default 'normal' check (
    priority in ('low', 'normal', 'high', 'urgent')
  ),
  assigned_admin_id uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.admin_audit_logs (
  id bigint generated by default as identity primary key,
  admin_id uuid references public.profiles(id) on delete set null,
  action text not null,
  entity_type text not null,
  entity_id text,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create unique index if not exists idx_customer_addresses_one_default
  on public.customer_addresses(customer_id)
  where is_default;
create index if not exists idx_app_sessions_active_token
  on public.app_sessions(token_hash)
  where revoked_at is null;
create index if not exists idx_app_sessions_profile_active
  on public.app_sessions(profile_id, expires_at desc)
  where revoked_at is null;
create index if not exists idx_wallet_transactions_profile_created
  on public.wallet_transactions(profile_id, created_at desc);
create index if not exists idx_favorite_craftsmen_customer
  on public.favorite_craftsmen(customer_id, created_at desc);
create index if not exists idx_craftsman_services_category
  on public.craftsman_services(category_id, craftsman_id);
create index if not exists idx_notification_devices_profile
  on public.notification_devices(profile_id)
  where enabled;
create index if not exists idx_notification_campaigns_due
  on public.notification_campaigns(scheduled_for)
  where status = 'scheduled';
create index if not exists idx_notifications_profile_created
  on public.notifications(profile_id, created_at desc);
create index if not exists idx_support_tickets_status_created
  on public.support_tickets(status, created_at desc);
create index if not exists idx_admin_audit_logs_admin_created
  on public.admin_audit_logs(admin_id, created_at desc);
create index if not exists idx_service_requests_address
  on public.service_requests(address_id);

drop trigger if exists set_app_settings_updated_at on public.app_settings;
create trigger set_app_settings_updated_at
before update on public.app_settings
for each row execute function public.set_updated_at();

drop trigger if exists set_wallets_updated_at on public.wallets;
create trigger set_wallets_updated_at
before update on public.wallets
for each row execute function public.set_updated_at();

drop trigger if exists set_notification_preferences_updated_at on public.notification_preferences;
create trigger set_notification_preferences_updated_at
before update on public.notification_preferences
for each row execute function public.set_updated_at();

drop trigger if exists set_support_tickets_updated_at on public.support_tickets;
create trigger set_support_tickets_updated_at
before update on public.support_tickets
for each row execute function public.set_updated_at();

insert into public.app_settings (key, value, is_public, description)
values
  (
    'test_login_enabled',
    'false'::jsonb,
    true,
    'Allows OTP-free sign-in only when APP_ENV is not production.'
  ),
  (
    'support',
    '{"phone":"","email":"","whatsapp":""}'::jsonb,
    true,
    'Public Maestro support contacts.'
  )
on conflict (key) do nothing;

insert into public.wallets (profile_id)
select id from public.profiles
on conflict (profile_id) do nothing;

insert into public.notification_preferences (profile_id)
select id from public.profiles
on conflict (profile_id) do nothing;

alter table public.app_settings enable row level security;
alter table public.app_sessions enable row level security;
alter table public.wallets enable row level security;
alter table public.wallet_transactions enable row level security;
alter table public.favorite_craftsmen enable row level security;
alter table public.craftsman_services enable row level security;
alter table public.notification_preferences enable row level security;
alter table public.notification_devices enable row level security;
alter table public.notification_campaigns enable row level security;
alter table public.support_tickets enable row level security;
alter table public.admin_audit_logs enable row level security;

revoke all on table public.app_settings from anon, authenticated;
revoke all on table public.app_sessions from anon, authenticated;
revoke all on table public.wallets from anon, authenticated;
revoke all on table public.wallet_transactions from anon, authenticated;
revoke all on table public.favorite_craftsmen from anon, authenticated;
revoke all on table public.craftsman_services from anon, authenticated;
revoke all on table public.notification_preferences from anon, authenticated;
revoke all on table public.notification_devices from anon, authenticated;
revoke all on table public.notification_campaigns from anon, authenticated;
revoke all on table public.support_tickets from anon, authenticated;
revoke all on table public.admin_audit_logs from anon, authenticated;
