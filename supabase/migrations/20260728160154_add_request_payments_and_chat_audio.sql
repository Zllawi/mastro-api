alter table public.service_requests
  add column if not exists payment_method text not null default 'cash';

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'service_requests_payment_method_check'
  ) then
    alter table public.service_requests
      add constraint service_requests_payment_method_check
      check (payment_method in ('cash', 'wallet'));
  end if;
end $$;

alter table public.offers
  add column if not exists labor_amount numeric(12,2) not null default 0,
  add column if not exists materials_amount numeric(12,2) not null default 0,
  add column if not exists inspection_fee numeric(12,2) not null default 0;

-- Preserve historical offer totals when introducing the detailed breakdown.
update public.offers
set labor_amount = total_amount,
    materials_amount = 0,
    inspection_fee = 0
where labor_amount = 0
  and materials_amount = 0
  and inspection_fee = 0
  and total_amount > 0;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'offers_amount_breakdown_check'
  ) then
    alter table public.offers
      add constraint offers_amount_breakdown_check
      check (
        labor_amount >= 0
        and materials_amount >= 0
        and inspection_fee >= 0
        and total_amount = labor_amount + materials_amount + inspection_fee
      );
  end if;
end $$;

create table if not exists public.request_payments (
  request_id uuid primary key
    references public.service_requests(id) on delete cascade,
  offer_id uuid not null unique
    references public.offers(id) on delete restrict,
  customer_id uuid not null
    references public.profiles(id) on delete restrict,
  craftsman_id uuid not null
    references public.profiles(id) on delete restrict,
  payment_method text not null
    check (payment_method in ('cash', 'wallet')),
  status text not null default 'accepted'
    check (
      status in (
        'accepted',
        'inspection_reserved',
        'fully_reserved',
        'awaiting_cash_confirmation',
        'settled',
        'refunded'
      )
    ),
  total_amount numeric(14,2) not null check (total_amount >= 0),
  inspection_amount numeric(14,2) not null default 0
    check (inspection_amount >= 0),
  wallet_reserved_amount numeric(14,2) not null default 0
    check (wallet_reserved_amount >= 0),
  cash_due_amount numeric(14,2) not null default 0
    check (cash_due_amount >= 0),
  cash_received_confirmed boolean not null default false,
  cash_received_at timestamptz,
  cash_received_by uuid references public.profiles(id) on delete set null,
  started_at timestamptz,
  settled_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (inspection_amount <= total_amount),
  check (wallet_reserved_amount <= total_amount),
  check (cash_due_amount <= total_amount),
  check (wallet_reserved_amount + cash_due_amount <= total_amount)
);

create index if not exists request_payments_customer_created_idx
  on public.request_payments (customer_id, created_at desc);

create index if not exists request_payments_craftsman_created_idx
  on public.request_payments (craftsman_id, created_at desc);

drop trigger if exists set_request_payments_updated_at
  on public.request_payments;
create trigger set_request_payments_updated_at
before update on public.request_payments
for each row execute function public.set_updated_at();

alter table public.job_messages
  add column if not exists attachment_type text;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'job_messages_attachment_type_check'
  ) then
    alter table public.job_messages
      add constraint job_messages_attachment_type_check
      check (
        attachment_type is null
        or attachment_type in ('image', 'audio', 'file')
      );
  end if;
end $$;

alter table public.request_payments enable row level security;
revoke all on table public.request_payments from anon, authenticated;
