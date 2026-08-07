alter table public.craftsman_profiles
  add column if not exists last_latitude numeric(10,7),
  add column if not exists last_longitude numeric(10,7),
  add column if not exists location_updated_at timestamptz;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'craftsman_profiles_last_location_check'
  ) then
    alter table public.craftsman_profiles
      add constraint craftsman_profiles_last_location_check
      check (
        (
          last_latitude is null
          and last_longitude is null
          and location_updated_at is null
        )
        or (
          last_latitude between -90 and 90
          and last_longitude between -180 and 180
          and location_updated_at is not null
        )
      );
  end if;
end $$;

create or replace function public.maestro_distance_km(
  first_latitude numeric,
  first_longitude numeric,
  second_latitude numeric,
  second_longitude numeric
)
returns numeric
language sql
immutable
parallel safe
returns null on null input
set search_path = ''
as $$
  select round(
    (
      6371 * acos(
        least(
          1.0,
          greatest(
            -1.0,
            cos(radians(first_latitude::double precision))
              * cos(radians(second_latitude::double precision))
              * cos(
                radians(second_longitude::double precision)
                  - radians(first_longitude::double precision)
              )
              + sin(radians(first_latitude::double precision))
                * sin(radians(second_latitude::double precision))
          )
        )
      )
    )::numeric,
    1
  )
$$;

revoke execute on function public.maestro_distance_km(
  numeric,
  numeric,
  numeric,
  numeric
) from public, anon, authenticated;
