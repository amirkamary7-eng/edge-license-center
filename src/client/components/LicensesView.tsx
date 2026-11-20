import { useState } from 'react';
import type { DeviceRecord, LicenseRecord, SubscriptionRecord } from '../../shared/types';
import { apiClient } from '../api';
import { copy, type Locale } from '../i18n';

interface LicensesViewProps {
  locale: Locale;
  licenses: Array<LicenseRecord & { devices: DeviceRecord[] }>;
  subscriptions: SubscriptionRecord[];
  onRefresh?: () => Promise<void>;
}

export function LicensesView({
  locale,
  licenses,
  subscriptions,
  onRefresh,
}: LicensesViewProps) {
  const t = copy[locale];
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const handleUnbind = async (licenseKey: string, fingerprint: string) => {
    const id = `${licenseKey}:${fingerprint}`;
    setBusyKey(id);
    setNotice(null);
    try {
      await apiClient.unbindDevice(licenseKey, fingerprint);
      setNotice(
        locale === 'fa'
          ? 'دستگاه با موفقیت از لایسنس جدا شد.'
          : 'Android device unbound from license.'
      );
      if (onRefresh) await onRefresh();
    } catch (err) {
      setNotice((err as Error).message);
    } finally {
      setBusyKey(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="space-y-1.5">
        <h1 className="text-2xl font-bold text-[#F3F4F6] text-balance">{t.licenses.heading}</h1>
        <p className="text-sm text-[#9CA3AF]">{t.licenses.lead}</p>
      </div>

      {notice && (
        <div className="p-3.5 rounded-lg bg-[#092420] border border-[#14B8A6]/40 text-xs text-[#99F6E4]">
          {notice}
        </div>
      )}

      {licenses.length === 0 ? (
        <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-6 sm:p-8 space-y-3">
          <h2 className="text-base font-semibold text-[#D4AF37]">{t.licenses.emptyTitle}</h2>
          <p className="text-sm text-[#CBD5E1] leading-relaxed max-w-3xl">
            {t.licenses.emptyDesc}
          </p>
        </section>
      ) : (
        <div className="space-y-4">
          {licenses.map((lic) => (
            <section
              key={lic.id}
              className="bg-[#0E1525] border border-[#1F2C47] rounded-xl overflow-hidden"
            >
              <div className="px-6 py-4 border-b border-[#1F2C47] flex flex-wrap items-center justify-between gap-2">
                <code dir="ltr" className="text-sm font-mono font-semibold text-[#D4AF37]">
                  {lic.license_key}
                </code>
                <div className="text-xs font-mono text-[#9CA3AF]" dir="ltr">
                  <span className="text-[#2DD4BF]">{lic.status}</span> · Key ID {lic.rsa_key_id} ·
                  Expires {lic.expires_at.slice(0, 10)}
                </div>
              </div>
              <div className="px-6 py-4 space-y-2 text-xs text-[#CBD5E1]">
                <div>
                  Bound Android Devices:{' '}
                  <span className="font-mono tabular-nums text-[#F3F4F6]">
                    {lic.devices.filter((d) => d.status === 'active').length} / {lic.max_devices}
                  </span>
                </div>
                {lic.devices.length > 0 && (
                  <div className="divide-y divide-[#1F2C47] border-t border-[#1F2C47] pt-2">
                    {lic.devices.map((dev) => {
                      const rowBusy = busyKey === `${lic.license_key}:${dev.device_fingerprint}`;
                      return (
                        <div
                          key={dev.id}
                          className="py-2 flex flex-wrap items-center justify-between gap-4"
                        >
                          <span className="font-mono text-[#F3F4F6]" dir="ltr">
                            {dev.device_model ?? 'Android Device'} ({dev.device_fingerprint.slice(0, 12)})
                          </span>
                          <div className="flex items-center gap-3">
                            <span className="font-mono text-[#9CA3AF]" dir="ltr">
                              {dev.status} · Last seen {dev.last_seen_at.slice(0, 10)}
                            </span>
                            {dev.status === 'active' && (
                              <button
                                type="button"
                                disabled={rowBusy}
                                onClick={() => handleUnbind(lic.license_key, dev.device_fingerprint)}
                                className="px-2.5 py-1 rounded bg-[#131C31] border border-[#2B3B5E] hover:border-[#D4AF37] text-xs text-[#F3F4F6] disabled:opacity-50 whitespace-nowrap"
                              >
                                {locale === 'fa' ? 'جداسازی' : 'Unbind'}
                              </button>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </section>
          ))}
        </div>
      )}

      {subscriptions.length > 0 && (
        <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-[#1F2C47]">
            <h2 className="text-base font-semibold text-[#F3F4F6]">
              {locale === 'fa' ? 'سابقه اشتراک‌ها' : 'Subscriptions'}
            </h2>
          </div>
          <div className="divide-y divide-[#1F2C47]">
            {subscriptions.map((sub) => (
              <div
                key={sub.id}
                className="px-6 py-3.5 flex items-center justify-between text-xs font-mono"
                dir="ltr"
              >
                <span className="text-[#F3F4F6]">SUB #{sub.id}</span>
                <span className="text-[#2DD4BF]">{sub.status}</span>
                <span className="text-[#9CA3AF]">
                  {sub.starts_at.slice(0, 10)} → {sub.expires_at.slice(0, 10)}
                </span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* RSA & Cloudflare Worker Daily Validation Spec */}
      <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-6 space-y-3">
        <h2 className="text-base font-semibold text-[#F3F4F6]">{t.licenses.archTitle}</h2>
        <ul className="space-y-2 text-sm text-[#CBD5E1]">
          {t.licenses.archItems.map((item) => (
            <li key={item} className="leading-relaxed">
              · {item}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
