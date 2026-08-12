-- Display configuration for wallet top-up methods.
-- Provider integrations other than coupons are intentionally not enabled yet.

insert into public.app_settings (
  key,
  value,
  is_public,
  description
)
values (
  'wallet_topup_methods',
  jsonb_build_object(
    'version', 1,
    'items', jsonb_build_array(
      jsonb_build_object(
        'id', 'coupon',
        'title_ar', 'كوبون شحن',
        'subtitle_ar', 'أدخل رمز كوبون شحن المحفظة',
        'status', 'open',
        'sort_order', 0,
        'integrated', true,
        'icon_key', 'confirmation_number'
      ),
      jsonb_build_object(
        'id', 'libyana',
        'title_ar', 'ليبيانا',
        'subtitle_ar', 'الشحن عبر ليبيانا',
        'status', 'coming_soon',
        'sort_order', 10,
        'integrated', false,
        'icon_key', 'libyana'
      ),
      jsonb_build_object(
        'id', 'sadad',
        'title_ar', 'سداد',
        'subtitle_ar', 'الشحن عبر سداد',
        'status', 'coming_soon',
        'sort_order', 20,
        'integrated', false,
        'icon_key', 'sadad'
      ),
      jsonb_build_object(
        'id', 'bank_card_online',
        'title_ar', 'البطاقة المصرفية (أونلاين)',
        'subtitle_ar', 'الشحن ببطاقة مصرفية',
        'status', 'coming_soon',
        'sort_order', 30,
        'integrated', false,
        'icon_key', 'bank_card'
      ),
      jsonb_build_object(
        'id', 'edfa3ly',
        'title_ar', 'ادفعلي',
        'subtitle_ar', 'الشحن عبر ادفعلي',
        'status', 'coming_soon',
        'sort_order', 40,
        'integrated', false,
        'icon_key', 'edfa3ly'
      ),
      jsonb_build_object(
        'id', 'mobicash',
        'title_ar', 'موبي كاش',
        'subtitle_ar', 'الشحن عبر موبي كاش',
        'status', 'coming_soon',
        'sort_order', 50,
        'integrated', false,
        'icon_key', 'mobicash'
      ),
      jsonb_build_object(
        'id', 'masrufi_pay',
        'title_ar', 'مصرفي باي',
        'subtitle_ar', 'الشحن عبر مصرفي باي',
        'status', 'coming_soon',
        'sort_order', 60,
        'integrated', false,
        'icon_key', 'masrufi_pay'
      ),
      jsonb_build_object(
        'id', 'yusr_online',
        'title_ar', 'يسر أونلاين',
        'subtitle_ar', 'الشحن عبر يسر أونلاين',
        'status', 'coming_soon',
        'sort_order', 70,
        'integrated', false,
        'icon_key', 'yusr_online'
      ),
      jsonb_build_object(
        'id', 'aqsat_online',
        'title_ar', 'أقساط أونلاين (التجاري الوطني)',
        'subtitle_ar', 'الشحن عبر أقساط أونلاين',
        'status', 'coming_soon',
        'sort_order', 80,
        'integrated', false,
        'icon_key', 'aqsat_online'
      ),
      jsonb_build_object(
        'id', 'tadawul_online',
        'title_ar', 'تداول (Online)',
        'subtitle_ar', 'الشحن عبر تداول',
        'status', 'coming_soon',
        'sort_order', 90,
        'integrated', false,
        'icon_key', 'tadawul_online'
      ),
      jsonb_build_object(
        'id', 'sahary_pay',
        'title_ar', 'صحاري باي',
        'subtitle_ar', 'الشحن عبر صحاري باي',
        'status', 'coming_soon',
        'sort_order', 100,
        'integrated', false,
        'icon_key', 'sahary_pay'
      ),
      jsonb_build_object(
        'id', 'smart_pay',
        'title_ar', 'سمارت باي (المتوسط)',
        'subtitle_ar', 'الشحن عبر سمارت باي',
        'status', 'coming_soon',
        'sort_order', 110,
        'integrated', false,
        'icon_key', 'smart_pay'
      )
    )
  ),
  true,
  'Wallet top-up methods shown in the customer and craftsman apps.'
)
on conflict (key) do nothing;
