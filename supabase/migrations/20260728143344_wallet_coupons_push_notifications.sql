-- Push delivery state remains server-only. The mobile client reads the
-- notification itself, while the backend owns retries and Firebase errors.
alter table public.notifications
  add column if not exists push_status text not null default 'pending'
    check (push_status in ('pending', 'processing', 'sent', 'failed', 'skipped')),
  add column if not exists push_attempts integer not null default 0
    check (push_attempts >= 0),
  add column if not exists push_claimed_at timestamptz,
  add column if not exists push_sent_at timestamptz,
  add column if not exists push_error text;

-- Do not send the notification history as a burst when Firebase is connected
-- for the first time. New rows use the column default and enter the queue.
update public.notifications
set
  push_status = 'skipped',
  push_error = 'Created before push delivery was enabled.'
where push_status = 'pending'
  and push_attempts = 0;

create index if not exists idx_notifications_push_queue
  on public.notifications(push_status, created_at)
  where push_status in ('pending', 'failed');

create table if not exists public.wallet_topup_coupons (
  id uuid primary key default gen_random_uuid(),
  code text not null unique check (code ~ '^[0-9]{13}$'),
  amount numeric(14,2) not null check (amount > 0),
  status text not null default 'active'
    check (status in ('active', 'redeemed', 'disabled')),
  created_by uuid references public.profiles(id) on delete set null,
  redeemed_by uuid references public.profiles(id) on delete set null,
  redeemed_at timestamptz,
  expires_at timestamptz,
  created_at timestamptz not null default now(),
  check (
    (status = 'redeemed' and redeemed_by is not null and redeemed_at is not null)
    or
    (status <> 'redeemed' and redeemed_by is null and redeemed_at is null)
  )
);

alter table public.wallet_transactions
  add column if not exists coupon_id uuid
    references public.wallet_topup_coupons(id) on delete set null;

create unique index if not exists idx_wallet_transactions_coupon_once
  on public.wallet_transactions(coupon_id)
  where coupon_id is not null;

create index if not exists idx_wallet_topup_coupons_status_created
  on public.wallet_topup_coupons(status, created_at desc);

create index if not exists idx_wallet_topup_coupons_redeemed_by
  on public.wallet_topup_coupons(redeemed_by, redeemed_at desc)
  where redeemed_by is not null;

alter table public.wallet_topup_coupons enable row level security;
revoke all on table public.wallet_topup_coupons from anon, authenticated;
