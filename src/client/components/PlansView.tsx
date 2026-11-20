import { useState } from 'react';
import { FIXED_PLANS } from '../../shared/constants';
import type { PlanRecord } from '../../shared/types';
import { copy, type Locale } from '../i18n';

interface PlansViewProps {
  locale: Locale;
  plans: PlanRecord[];
  paymentMode?: string;
  onCreateOrder: (planCode: string, expectedSenderWallet?: string) => Promise<void>;
}

export function PlansView({ locale, plans, paymentMode, onCreateOrder }: PlansViewProps) {
  const t = copy[locale];
  const [busyCode, setBusyCode] = useState<string | null>(null);
  const [senderWallet, setSenderWallet] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleSelect = async (planCode: string) => {
    setError(null);
    const trimmedWallet = senderWallet.trim();
    if (trimmedWallet && !/^0x[a-fA-F0-9]{40}$/.test(trimmedWallet)) {
      setError(
        locale === 'fa'
          ? 'آدرس کیف پول Polygon باید دقیقاً ۴۲ کاراکتر و با پیشوند 0x باشد.'
          : 'Polygon sender wallet must be a valid 42-character address starting with 0x.'
      );
      return;
    }
    setBusyCode(planCode);
    try {
      await onCreateOrder(planCode, trimmedWallet || undefined);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusyCode(null);
    }
  };

  return (
    <div className="space-y-8">
      <div className="space-y-2">
        <h1 className="text-2xl font-bold text-[#F3F4F6] text-balance">{t.plans.heading}</h1>
        <p className="text-sm text-[#9CA3AF] max-w-3xl">{t.plans.lead}</p>
      </div>

      {/* Buyer Polygon Sender Wallet Binding (Mandatory in LIVE, optional in DRY_RUN) */}
      <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-5 space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <label htmlFor="buyerSenderWallet" className="text-xs font-medium text-[#CBD5E1]">
            {locale === 'fa'
              ? 'آدرس کیف پول مبدأ شما در Polygon PoS (حفاظت ضد Front-Running)'
              : 'Your Polygon PoS Sender Wallet Address (Anti-Front-Running Binding)'}
          </label>
          <span className="text-xs font-mono text-[#D4AF37]" dir="ltr">
            {paymentMode === 'LIVE' ? 'Required (LIVE)' : 'Optional in DRY_RUN · Required in LIVE'}
          </span>
        </div>
        <input
          id="buyerSenderWallet"
          type="text"
          dir="ltr"
          value={senderWallet}
          onChange={(e) => setSenderWallet(e.target.value)}
          placeholder="0x... (42-character Polygon address you will pay from)"
          className="w-full px-3.5 py-2 rounded-lg bg-[#07090F] border border-[#1F2C47] focus:border-[#D4AF37] focus:outline-none text-xs font-mono text-[#F3F4F6] placeholder:text-[#475569]"
        />
      </section>

      {error && (
        <div className="p-4 rounded-lg bg-[#2A1215] border border-[#7F1D1D] text-sm text-[#FCA5A5]">
          {error}
        </div>
      )}

      {/* 4 Fixed Commercial Plans */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {plans.map((plan) => {
          const spec = FIXED_PLANS.find((f) => f.code === plan.code);
          const isBest = plan.code === 'EDGE_12M';
          const isLoading = busyCode === plan.code;

          return (
            <div
              key={plan.code}
              className={`flex flex-col justify-between bg-[#0E1525] rounded-xl p-6 border ${
                isBest ? 'border-[#D4AF37]/70' : 'border-[#1F2C47]'
              }`}
            >
              <div className="space-y-4">
                <div className="flex items-center justify-between gap-2 text-xs text-[#9CA3AF]">
                  <span className={isBest ? 'text-[#D4AF37] font-semibold' : 'text-[#2DD4BF]'}>
                    {locale === 'fa' ? spec?.badgeFa ?? plan.code : spec?.badgeEn ?? plan.code}
                  </span>
                  {spec && spec.savingsPercent > 0 && (
                    <span className="font-mono tabular-nums text-[#CBD5E1]">
                      {t.plans.save} {spec.savingsPercent}%
                    </span>
                  )}
                </div>

                <div>
                  <h2 className="text-lg font-semibold text-[#F3F4F6]">
                    {locale === 'fa' ? plan.name_fa : plan.name_en}
                  </h2>
                  <div className="mt-3 flex items-baseline gap-1.5" dir="ltr">
                    <span className="text-3xl font-bold font-mono tabular-nums text-[#D4AF37]">
                      ${plan.price_usd_display}
                    </span>
                    <span className="text-xs font-mono text-[#9CA3AF]">USDC</span>
                  </div>
                </div>

                <div className="pt-3 border-t border-[#1F2C47] space-y-2 text-xs text-[#CBD5E1]">
                  <div className="flex items-center justify-between">
                    <span className="text-[#9CA3AF]">{t.plans.colDuration}</span>
                    <span className="font-mono tabular-nums">
                      {plan.duration_days} {t.plans.days}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[#9CA3AF]">{t.plans.colDevices}</span>
                    <span className="font-mono tabular-nums">
                      {plan.max_devices} {t.plans.devices}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[#9CA3AF]">{t.plans.colSigning}</span>
                    <span className="font-mono text-[#2DD4BF]">RSA-2048</span>
                  </div>
                </div>
              </div>

              <button
                type="button"
                disabled={busyCode !== null}
                onClick={() => handleSelect(plan.code)}
                className={`mt-6 w-full py-2.5 px-4 rounded-lg text-sm font-semibold transition-colors whitespace-nowrap disabled:opacity-50 ${
                  isBest
                    ? 'bg-[#D4AF37] hover:bg-[#E5C454] text-[#07090F]'
                    : 'bg-[#131C31] hover:bg-[#1A2642] border border-[#2B3B5E] text-[#F3F4F6]'
                }`}
              >
                {isLoading ? t.plans.creating : t.plans.selectPlan}
              </button>
            </div>
          );
        })}
      </div>

      {/* Authoritative Comparison Table */}
      <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-[#1F2C47]">
          <h2 className="text-base font-semibold text-[#F3F4F6]">{t.plans.matrixTitle}</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1F2C47] text-xs text-[#9CA3AF] bg-[#0A0F1D]">
                <th className="px-6 py-3 text-start font-medium">{t.plans.colPlan}</th>
                <th className="px-6 py-3 text-start font-medium">{t.plans.colDuration}</th>
                <th className="px-6 py-3 text-start font-medium">{t.plans.colDevices}</th>
                <th className="px-6 py-3 text-start font-medium">{t.plans.colSigning}</th>
                <th className="px-6 py-3 text-end font-medium">{t.plans.colPrice}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1F2C47]">
              {plans.map((plan) => (
                <tr key={plan.code} className="hover:bg-[#131C31]/60 transition-colors">
                  <td className="px-6 py-3.5 font-medium text-[#F3F4F6]">
                    {locale === 'fa' ? plan.name_fa : plan.name_en}{' '}
                    <span className="text-xs font-mono text-[#64748B]" dir="ltr">
                      ({plan.code})
                    </span>
                  </td>
                  <td className="px-6 py-3.5 font-mono tabular-nums text-[#CBD5E1]">
                    {plan.duration_months}m / {plan.duration_days}d
                  </td>
                  <td className="px-6 py-3.5 font-mono tabular-nums text-[#CBD5E1]">
                    {plan.max_devices}
                  </td>
                  <td className="px-6 py-3.5 font-mono text-[#2DD4BF]">RSA-SHA256</td>
                  <td className="px-6 py-3.5 text-end font-mono tabular-nums font-semibold text-[#D4AF37]" dir="ltr">
                    ${plan.price_usd_display}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
