-- Maestro core storage for Supabase PostgreSQL.
-- Run this migration from Supabase SQL Editor or the Supabase CLI.

create extension if not exists pgcrypto;

do $$
begin
  create type public.user_role as enum ('customer', 'craftsman', 'admin');
exception
  when duplicate_object then null;
end $$;

do $$
begin
  create type public.account_status as enum ('pending', 'active', 'suspended', 'deleted');
exception
  when duplicate_object then null;
end $$;

do $$
begin
  create type public.service_request_status as enum (
    'draft',
    'submitted',
    'offers_received',
    'accepted',
    'on_the_way',
    'started',
    'completed',
    'cancelled',
    'disputed'
  );
exception
  when duplicate_object then null;
end $$;

do $$
begin
  create type public.offer_status as enum ('submitted', 'accepted', 'rejected', 'withdrawn', 'expired');
exception
  when duplicate_object then null;
end $$;

do $$
begin
  create type public.message_sender_type as enum ('customer', 'craftsman', 'admin', 'system');
exception
  when duplicate_object then null;
end $$;

do $$
begin
  create type public.otp_purpose as enum ('login', 'phone_verification', 'password_reset');
exception
  when duplicate_object then null;
end $$;

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create table if not exists public.profiles (
  id uuid primary key default gen_random_uuid(),
  auth_user_id uuid unique references auth.users(id) on delete set null,
  role public.user_role not null,
  status public.account_status not null default 'pending',
  phone text not null unique check (phone ~ '^2189[0-9]{8}$'),
  full_name text,
  avatar_url text,
  city text not null default 'Benghazi',
  locale text not null default 'ar-LY',
  metadata jsonb not null default '{}'::jsonb,
  phone_verified_at timestamptz,
  last_login_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.craftsman_profiles (
  profile_id uuid primary key references public.profiles(id) on delete cascade,
  profession text not null,
  bio text,
  identity_type text,
  identity_number text,
  years_experience int not null default 0 check (years_experience >= 0),
  rating numeric(3,2) not null default 0 check (rating >= 0 and rating <= 5),
  completed_jobs int not null default 0 check (completed_jobs >= 0),
  on_time_percent int not null default 0 check (on_time_percent >= 0 and on_time_percent <= 100),
  is_verified boolean not null default false,
  verification_submitted_at timestamptz,
  verification_reviewed_at timestamptz,
  service_area jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.craftsman_profiles
  add column if not exists identity_type text,
  add column if not exists identity_number text,
  add column if not exists verification_submitted_at timestamptz,
  add column if not exists verification_reviewed_at timestamptz;

create table if not exists public.craftsman_verification_documents (
  id uuid primary key default gen_random_uuid(),
  craftsman_id uuid not null references public.profiles(id) on delete cascade,
  document_type text not null check (document_type in ('identity_front', 'identity_back', 'license', 'certificate')),
  storage_bucket text not null,
  storage_path text not null,
  content_type text,
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  rejection_reason text,
  created_at timestamptz not null default now(),
  reviewed_at timestamptz
);

create table if not exists public.customer_addresses (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.profiles(id) on delete cascade,
  label text not null,
  city text not null default 'Benghazi',
  area text,
  street text,
  building text,
  floor text,
  notes text,
  latitude numeric(10,7),
  longitude numeric(10,7),
  is_default boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.service_categories (
  id text primary key,
  name_ar text not null,
  name_en text,
  description_ar text,
  icon_key text,
  is_active boolean not null default true,
  sort_order int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.service_requests (
  id uuid primary key default gen_random_uuid(),
  public_code text not null unique default ('MS-' || upper(substr(gen_random_uuid()::text, 1, 8))),
  customer_id uuid not null references public.profiles(id) on delete restrict,
  accepted_offer_id uuid,
  category_id text not null references public.service_categories(id) on delete restrict,
  status public.service_request_status not null default 'submitted',
  title text not null,
  description text not null,
  urgency boolean not null default false,
  scheduled_for timestamptz,
  city text not null default 'Benghazi',
  area text,
  address_text text,
  latitude numeric(10,7),
  longitude numeric(10,7),
  voice_note_url text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.request_attachments (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null references public.service_requests(id) on delete cascade,
  storage_bucket text not null,
  storage_path text not null,
  content_type text,
  size_bytes bigint check (size_bytes is null or size_bytes >= 0),
  created_at timestamptz not null default now()
);

create table if not exists public.offers (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null references public.service_requests(id) on delete cascade,
  craftsman_id uuid not null references public.profiles(id) on delete restrict,
  status public.offer_status not null default 'submitted',
  total_amount numeric(12,2) not null check (total_amount >= 0),
  currency text not null default 'LYD',
  arrival_window text,
  estimated_duration text,
  warranty_text text,
  note text,
  expires_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (request_id, craftsman_id)
);

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'service_requests_accepted_offer_fk'
  ) then
    alter table public.service_requests
      add constraint service_requests_accepted_offer_fk
      foreign key (accepted_offer_id) references public.offers(id) on delete set null
      deferrable initially deferred;
  end if;
end $$;

create table if not exists public.request_status_events (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null references public.service_requests(id) on delete cascade,
  status public.service_request_status not null,
  actor_id uuid references public.profiles(id) on delete set null,
  note text,
  created_at timestamptz not null default now()
);

create table if not exists public.job_messages (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null references public.service_requests(id) on delete cascade,
  sender_id uuid references public.profiles(id) on delete set null,
  sender_type public.message_sender_type not null,
  body text not null,
  attachment_url text,
  read_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.reviews (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null unique references public.service_requests(id) on delete cascade,
  customer_id uuid not null references public.profiles(id) on delete restrict,
  craftsman_id uuid not null references public.profiles(id) on delete restrict,
  quality_rating int not null check (quality_rating between 1 and 5),
  punctuality_rating int not null check (punctuality_rating between 1 and 5),
  price_rating int not null check (price_rating between 1 and 5),
  communication_rating int not null check (communication_rating between 1 and 5),
  cleanliness_rating int not null check (cleanliness_rating between 1 and 5),
  comment text,
  complaint text,
  created_at timestamptz not null default now()
);

create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references public.profiles(id) on delete cascade,
  title text not null,
  body text not null,
  data jsonb not null default '{}'::jsonb,
  read_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.otp_codes (
  phone text primary key check (phone ~ '^2189[0-9]{8}$'),
  pin text not null,
  purpose public.otp_purpose not null default 'login',
  attempts int not null default 0 check (attempts >= 0),
  max_attempts int not null default 5 check (max_attempts > 0),
  resala_pin_id text,
  expires_at timestamptz not null,
  sent_at timestamptz not null default now(),
  verified_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.resala_delivery_logs (
  id uuid primary key default gen_random_uuid(),
  source text not null check (source in ('pin', 'message')),
  resala_id text,
  phone text check (phone is null or phone ~ '^2189[0-9]{8}$'),
  status text not null check (status in ('accepted', 'sent', 'delivered', 'undelivered', 'unknown')),
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_profiles_phone on public.profiles(phone);
create index if not exists idx_profiles_role on public.profiles(role);
create index if not exists idx_craftsman_verification_documents_craftsman on public.craftsman_verification_documents(craftsman_id, document_type);
create index if not exists idx_customer_addresses_customer on public.customer_addresses(customer_id);
create index if not exists idx_service_requests_customer on public.service_requests(customer_id);
create index if not exists idx_service_requests_category_status on public.service_requests(category_id, status);
create index if not exists idx_service_requests_created_at on public.service_requests(created_at desc);
create index if not exists idx_offers_request_status on public.offers(request_id, status);
create index if not exists idx_offers_craftsman on public.offers(craftsman_id);
create index if not exists idx_request_status_events_request on public.request_status_events(request_id, created_at desc);
create index if not exists idx_job_messages_request on public.job_messages(request_id, created_at);
create index if not exists idx_notifications_profile_unread on public.notifications(profile_id, created_at desc) where read_at is null;
create index if not exists idx_otp_codes_expires_at on public.otp_codes(expires_at);
create index if not exists idx_resala_delivery_logs_source_status on public.resala_delivery_logs(source, status, created_at desc);

drop trigger if exists set_profiles_updated_at on public.profiles;
create trigger set_profiles_updated_at
before update on public.profiles
for each row execute function public.set_updated_at();

drop trigger if exists set_craftsman_profiles_updated_at on public.craftsman_profiles;
create trigger set_craftsman_profiles_updated_at
before update on public.craftsman_profiles
for each row execute function public.set_updated_at();

drop trigger if exists set_customer_addresses_updated_at on public.customer_addresses;
create trigger set_customer_addresses_updated_at
before update on public.customer_addresses
for each row execute function public.set_updated_at();

drop trigger if exists set_service_categories_updated_at on public.service_categories;
create trigger set_service_categories_updated_at
before update on public.service_categories
for each row execute function public.set_updated_at();

drop trigger if exists set_service_requests_updated_at on public.service_requests;
create trigger set_service_requests_updated_at
before update on public.service_requests
for each row execute function public.set_updated_at();

drop trigger if exists set_offers_updated_at on public.offers;
create trigger set_offers_updated_at
before update on public.offers
for each row execute function public.set_updated_at();

drop trigger if exists set_otp_codes_updated_at on public.otp_codes;
create trigger set_otp_codes_updated_at
before update on public.otp_codes
for each row execute function public.set_updated_at();

insert into public.service_categories (id, name_ar, name_en, description_ar, icon_key, sort_order)
values
  ('plumbing', 'السباكة', 'Plumbing', 'تسريب، تركيب وصيانة', 'plumbing', 10),
  ('electricity', 'الكهرباء', 'Electricity', 'أعطال وتمديدات منزلية', 'electrical_services', 20),
  ('ac', 'التكييف والتبريد', 'Air conditioning', 'تنظيف، تعبئة وتركيب', 'ac_unit', 30)
on conflict (id) do update
set
  name_ar = excluded.name_ar,
  name_en = excluded.name_en,
  description_ar = excluded.description_ar,
  icon_key = excluded.icon_key,
  sort_order = excluded.sort_order,
  updated_at = now();

alter table public.profiles enable row level security;
alter table public.craftsman_profiles enable row level security;
alter table public.craftsman_verification_documents enable row level security;
alter table public.customer_addresses enable row level security;
alter table public.service_categories enable row level security;
alter table public.service_requests enable row level security;
alter table public.request_attachments enable row level security;
alter table public.offers enable row level security;
alter table public.request_status_events enable row level security;
alter table public.job_messages enable row level security;
alter table public.reviews enable row level security;
alter table public.notifications enable row level security;
alter table public.otp_codes enable row level security;
alter table public.resala_delivery_logs enable row level security;
