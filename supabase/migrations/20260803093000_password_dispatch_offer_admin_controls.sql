-- Password login, fair request dispatch, offer revision, warnings/deletion,
-- and customer rating controls. Backend-only access; mobile/web clients use API.

alter table public.profiles
  add column if not exists password_hash text,
  add column if not exists password_set_at timestamptz,
  add column if not exists password_reset_required boolean not null default true,
  add column if not exists warning_count int not null default 0
    check (warning_count >= 0),
  add column if not exists last_warning_at timestamptz;

update public.profiles
set password_reset_required = true
where password_hash is null;

create table if not exists public.user_warnings (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references public.profiles(id) on delete cascade,
  admin_id uuid references public.profiles(id) on delete set null,
  reason text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.request_dispatches (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null references public.service_requests(id) on delete cascade,
  craftsman_id uuid not null references public.profiles(id) on delete cascade,
  batch_no int not null default 1 check (batch_no > 0),
  source text not null default 'automation'
    check (source in ('automation', 'admin')),
  notified_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '1 hour'),
  offered_at timestamptz,
  created_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  unique (request_id, craftsman_id)
);

create table if not exists public.offer_revision_requests (
  id uuid primary key default gen_random_uuid(),
  offer_id uuid not null references public.offers(id) on delete cascade,
  request_id uuid not null references public.service_requests(id) on delete cascade,
  customer_id uuid not null references public.profiles(id) on delete cascade,
  craftsman_id uuid not null references public.profiles(id) on delete cascade,
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'rejected', 'cancelled')),
  total_amount numeric(12,2) not null check (total_amount >= 0),
  labor_amount numeric(12,2) not null default 0 check (labor_amount >= 0),
  materials_amount numeric(12,2) not null default 0 check (materials_amount >= 0),
  inspection_fee numeric(12,2) not null default 0 check (inspection_fee >= 0),
  note text,
  response_note text,
  responded_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (total_amount = labor_amount + materials_amount + inspection_fee)
);

create table if not exists public.customer_reviews (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null unique references public.service_requests(id) on delete cascade,
  customer_id uuid not null references public.profiles(id) on delete restrict,
  craftsman_id uuid not null references public.profiles(id) on delete restrict,
  rating int not null check (rating between 1 and 5),
  comment text,
  created_at timestamptz not null default now()
);

insert into public.app_settings (key, value, is_public, description)
values (
  'request_automation',
  '{"enabled": true, "batch_size": 5, "batch_interval_minutes": 60}'::jsonb,
  false,
  'Automatically dispatches each open request to a fair batch of craftsmen.'
)
on conflict (key) do nothing;

create index if not exists idx_user_warnings_profile_created
  on public.user_warnings(profile_id, created_at desc);

create index if not exists idx_request_dispatches_request_batch
  on public.request_dispatches(request_id, batch_no, notified_at desc);

create index if not exists idx_request_dispatches_craftsman_active
  on public.request_dispatches(craftsman_id, expires_at desc)
  where offered_at is null;

create index if not exists idx_request_dispatches_due
  on public.request_dispatches(request_id, expires_at desc);

create index if not exists idx_offer_revision_requests_offer_status
  on public.offer_revision_requests(offer_id, status, created_at desc);

create index if not exists idx_customer_reviews_customer
  on public.customer_reviews(customer_id, created_at desc);

drop trigger if exists set_offer_revision_requests_updated_at
  on public.offer_revision_requests;
create trigger set_offer_revision_requests_updated_at
before update on public.offer_revision_requests
for each row execute function public.set_updated_at();

alter table public.user_warnings enable row level security;
alter table public.request_dispatches enable row level security;
alter table public.offer_revision_requests enable row level security;
alter table public.customer_reviews enable row level security;

revoke all on table public.user_warnings from anon, authenticated;
revoke all on table public.request_dispatches from anon, authenticated;
revoke all on table public.offer_revision_requests from anon, authenticated;
revoke all on table public.customer_reviews from anon, authenticated;
