-- Driver service options stored on the existing service_categories table.
-- This keeps "طلب سائق" editable from the current admin "الحرف والخدمات" panel.

alter table public.service_categories
  add column if not exists metadata jsonb not null default '{}'::jsonb;

update public.service_categories
set metadata = coalesce(metadata, '{}'::jsonb) || jsonb_build_object('service_kind', 'craft')
where metadata->>'service_kind' is null;

insert into public.service_categories (
  id,
  name_ar,
  name_en,
  description_ar,
  icon_key,
  availability_status,
  is_active,
  sort_order,
  metadata
)
values (
  'driver',
  'طلب سائق',
  'Driver request',
  'توصيل شخصي أو توصيل طرد حسب نوع المركبة والرحلة',
  'local_taxi',
  'open',
  true,
  80,
  jsonb_build_object(
    'service_kind', 'driver',
    'driver_vehicle_types', jsonb_build_array('سيارة', 'دراجة نارية', 'شاحنة صغيرة'),
    'driver_trip_types', jsonb_build_array('توصيل شخصي', 'توصيل طرد'),
    'driver_service_options', jsonb_build_array('مشوار داخل المدينة', 'توصيل طلبات', 'نقل خفيف')
  )
)
on conflict (id) do update
set
  name_ar = excluded.name_ar,
  name_en = excluded.name_en,
  description_ar = excluded.description_ar,
  icon_key = excluded.icon_key,
  availability_status = excluded.availability_status,
  is_active = true,
  sort_order = excluded.sort_order,
  metadata = coalesce(public.service_categories.metadata, '{}'::jsonb) || excluded.metadata,
  updated_at = now();

create index if not exists idx_service_categories_service_kind
  on public.service_categories ((metadata->>'service_kind'));
