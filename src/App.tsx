import { Menu } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { apiClient, type PublicConfigResponse } from './client/api';
import { AdminView } from './client/components/AdminView';
import { HomeView } from './client/components/HomeView';
import { LicensesView } from './client/components/LicensesView';
import { PaymentView } from './client/components/PaymentView';
import { PlansView } from './client/components/PlansView';
import { ProfileView } from './client/components/ProfileView';
import { Sidebar } from './client/components/Sidebar';
import { TrackingView } from './client/components/TrackingView';
import { copy, type Locale, type NavSection } from './client/i18n';
import type {
  AuthSessionResponse,
  DeviceRecord,
  LicenseRecord,
  OrderRecord,
  PaymentRecord,
  SubscriptionRecord,
} from './shared/types';

export default function App() {
  const [locale, setLocale] = useState<Locale>('fa');
  const [section, setSection] = useState<NavSection>('home');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [loading, setLoading] = useState(true);
  const [bootError, setBootError] = useState<string | null>(null);
  const [authNotice, setAuthNotice] = useState<string | null>(null);
  const [config, setConfig] = useState<PublicConfigResponse | null>(null);
  const [session, setSession] = useState<AuthSessionResponse | null>(null);
  const [orders, setOrders] = useState<OrderRecord[]>([]);
  const [payments, setPayments] = useState<PaymentRecord[]>([]);
  const [licenses, setLicenses] = useState<Array<LicenseRecord & { devices: DeviceRecord[] }>>([]);
  const [subscriptions, setSubscriptions] = useState<SubscriptionRecord[]>([]);
  const [selectedOrderCode, setSelectedOrderCode] = useState<string | null>(null);

  useEffect(() => {
    document.documentElement.lang = locale;
    document.documentElement.dir = locale === 'fa' ? 'rtl' : 'ltr';
  }, [locale]);

  useEffect(() => {
    window.Telegram?.WebApp?.ready?.();
    window.Telegram?.WebApp?.expand?.();
  }, []);

  const refreshUserWorkspace = useCallback(async () => {
    const [ordersRes, paymentsRes, licensesRes] = await Promise.all([
      apiClient.listOrders(),
      apiClient.listPayments(),
      apiClient.listLicenses(),
    ]);
    setOrders(ordersRes.orders);
    setPayments(paymentsRes.payments);
    setLicenses(licensesRes.licenses);
    setSubscriptions(licensesRes.subscriptions);
  }, []);

  const bootstrap = useCallback(async () => {
    setLoading(true);
    setBootError(null);
    setAuthNotice(null);
    try {
      const cfg = await apiClient.getPublicConfig();
      setConfig(cfg);

      // Exchange Telegram initData once for a short-lived HMAC Bearer token
      await apiClient.exchangeTelegramSession();

      try {
        const sess = await apiClient.getSession();
        setSession(sess);
        await refreshUserWorkspace();
      } catch (authErr) {
        const errCode = (authErr as Error & { code?: string }).code ?? (authErr as Error).message;
        setSession(null);
        setAuthNotice(errCode);
      }
    } catch (err) {
      setBootError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [refreshUserWorkspace]);

  useEffect(() => {
    bootstrap();
  }, [bootstrap]);

  const handleCreateOrder = async (planCode: string, expectedSenderWallet?: string) => {
    if (!session) {
      setSection('profile');
      return;
    }
    const res = await apiClient.createOrder(
      planCode,
      expectedSenderWallet ? { expectedSenderWallet } : undefined
    );
    await refreshUserWorkspace();
    setSelectedOrderCode(res.order.order_code);
    setSection('payment');
  };

  const t = copy[locale];

  const renderAuthRequiredCard = () => (
    <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-6 sm:p-8 max-w-2xl space-y-3">
      <h1 className="text-lg font-bold text-[#D4AF37]">
        {locale === 'fa'
          ? 'احراز هویت Telegram Mini App الزامی است'
          : 'Telegram Mini App Authentication Required'}
      </h1>
      <p className="text-sm text-[#CBD5E1] leading-relaxed">
        {locale === 'fa'
          ? 'در نسخه سخت‌سازی‌شده Phase 1، حالت Preview به‌صورت پیش‌فرض غیرفعال (Fail-Closed) است و دسترسی به ثبت سفارش، پرداخت، پروفایل، لایسنس و پنل مدیریت صرفاً از طریق نشست معتبر تلگرام در ربات @EDGE_LicenceBot امکان‌پذیر است.'
          : 'In Phase 1 Hardened mode, preview sessions are disabled by default (fail-closed). Orders, checkout, profile, licenses, and admin views require an authenticated Telegram Mini App session launched from @EDGE_LicenceBot.'}
      </p>
      {authNotice && (
        <div className="text-xs font-mono text-[#9CA3AF]" dir="ltr">
          Status: {authNotice}
        </div>
      )}
    </section>
  );

  return (
    <div className="min-h-screen bg-[#07090F] text-[#F3F4F6] flex">
      <Sidebar
        locale={locale}
        onLocaleChange={setLocale}
        activeSection={section}
        onNavigate={setSection}
        adminRole={session?.adminRole ?? null}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
      />

      <div className="flex-1 min-w-0 flex flex-col">
        {/* Clean SaaS Top Bar: Breadcrumb on start, 1 Primary Action on end */}
        <header className="sticky top-0 z-30 h-16 bg-[#07090F]/95 backdrop-blur border-b border-[#1F2C47] px-4 sm:px-8 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Open navigation"
              className="lg:hidden p-2 rounded-lg bg-[#0E1525] border border-[#1F2C47] text-[#CBD5E1]"
            >
              <Menu className="w-4 h-4" />
            </button>
            <div className="flex items-center gap-2 text-sm min-w-0">
              <span className="text-[#9CA3AF] truncate hidden sm:inline">{t.brandTitle}</span>
              <span className="text-[#475569] hidden sm:inline" aria-hidden="true">
                /
              </span>
              <span className="font-semibold text-[#F3F4F6] truncate">{t.nav[section]}</span>
            </div>
          </div>

          <button
            type="button"
            onClick={() => setSection('plans')}
            className="px-4 py-2 rounded-lg bg-[#D4AF37] hover:bg-[#E5C454] text-[#07090F] text-xs font-semibold transition-colors whitespace-nowrap shrink-0"
          >
            {t.ctaBuy}
          </button>
        </header>

        {/* Main Content Viewport */}
        <main className="flex-1 w-full max-w-[1280px] mx-auto px-4 sm:px-8 py-6 sm:py-8">
          {loading ? (
            <div className="space-y-4">
              <div className="h-44 rounded-xl bg-[#0E1525] border border-[#1F2C47]" />
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
                {[1, 2, 3, 4].map((i) => (
                  <div key={i} className="h-24 rounded-xl bg-[#0E1525] border border-[#1F2C47]" />
                ))}
              </div>
            </div>
          ) : bootError || !config ? (
            <div className="bg-[#0E1525] border border-[#7F1D1D] rounded-xl p-6 max-w-xl space-y-3">
              <h1 className="text-base font-semibold text-[#FCA5A5]">
                {locale === 'fa' ? 'خطا در اتصال به سرویس Backend' : 'Backend Connection Error'}
              </h1>
              <p className="text-sm text-[#CBD5E1] font-mono">{bootError ?? 'UNKNOWN_ERROR'}</p>
              <button
                type="button"
                onClick={bootstrap}
                className="px-4 py-2 rounded-lg bg-[#131C31] border border-[#2B3B5E] text-xs font-medium text-[#F3F4F6]"
              >
                {locale === 'fa' ? 'تلاش مجدد' : 'Retry'}
              </button>
            </div>
          ) : (
            <>
              {section === 'home' && (
                <HomeView
                  locale={locale}
                  config={config}
                  orders={orders}
                  licenses={licenses}
                  onNavigate={setSection}
                />
              )}
              {section === 'plans' && (
                <PlansView
                  locale={locale}
                  plans={config.plans}
                  paymentMode={config.paymentMode}
                  onCreateOrder={handleCreateOrder}
                />
              )}
              {section === 'payment' &&
                (session ? (
                  <PaymentView
                    locale={locale}
                    config={config}
                    orders={orders}
                    selectedOrderCode={selectedOrderCode}
                    onSelectOrder={setSelectedOrderCode}
                    onTxSubmitted={refreshUserWorkspace}
                    onNavigate={setSection}
                  />
                ) : (
                  renderAuthRequiredCard()
                ))}
              {section === 'tracking' &&
                (session ? (
                  <TrackingView
                    locale={locale}
                    orders={orders}
                    payments={payments}
                    onOpenOrderPayment={(orderCode) => {
                      setSelectedOrderCode(orderCode);
                      setSection('payment');
                    }}
                  />
                ) : (
                  renderAuthRequiredCard()
                ))}
              {section === 'profile' &&
                (session ? (
                  <ProfileView locale={locale} session={session} payments={payments} />
                ) : (
                  renderAuthRequiredCard()
                ))}
              {section === 'licenses' &&
                (session ? (
                  <LicensesView
                    locale={locale}
                    licenses={licenses}
                    subscriptions={subscriptions}
                    onRefresh={refreshUserWorkspace}
                  />
                ) : (
                  renderAuthRequiredCard()
                ))}
              {section === 'admin' &&
                (session ? (
                  <AdminView locale={locale} adminRole={session.adminRole} />
                ) : (
                  renderAuthRequiredCard()
                ))}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
