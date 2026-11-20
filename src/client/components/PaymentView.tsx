import { Check, Copy } from 'lucide-react';
import { useState } from 'react';
import type { OrderRecord } from '../../shared/types';
import { apiClient, type PublicConfigResponse } from '../api';
import { copy, type Locale, type NavSection } from '../i18n';

interface PaymentViewProps {
  locale: Locale;
  config: PublicConfigResponse;
  orders: OrderRecord[];
  selectedOrderCode: string | null;
  onSelectOrder: (orderCode: string) => void;
  onTxSubmitted: () => Promise<void>;
  onNavigate: (section: NavSection) => void;
}

function formatMicroUsdc(micro: number): string {
  return (micro / 1_000_000).toFixed(6);
}

export function PaymentView({
  locale,
  config,
  orders,
  selectedOrderCode,
  onSelectOrder,
  onTxSubmitted,
  onNavigate,
}: PaymentViewProps) {
  const t = copy[locale];
  const [txHash, setTxHash] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const activeOrder =
    orders.find((o) => o.order_code === selectedOrderCode) ?? orders[0] ?? null;

  const copyText = async (key: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1800);
    } catch {
      setCopiedKey(null);
    }
  };

  const handleSubmitTx = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeOrder) return;
    setFeedback(null);
    setSubmitting(true);
    try {
      const res = await apiClient.submitTx(activeOrder.order_code, txHash.trim());
      await onTxSubmitted();
      setTxHash('');
      setFeedback({
        type: 'ok',
        text: res.dryRunBlocked
          ? locale === 'fa'
            ? `هش تراکنش در حالت DRY_RUN بررسی و ثبت شد (${res.payment.status}). تسویه واقعی غیرفعال است.`
            : `TxID validated and recorded in DRY_RUN (${res.payment.status}). Live settlement is disabled.`
          : locale === 'fa'
          ? 'هش تراکنش با موفقیت در صف تأیید Polygon PoS قرار گرفت.'
          : 'Transaction hash queued for Polygon PoS on-chain verification.',
      });
    } catch (err) {
      setFeedback({ type: 'err', text: (err as Error).message });
    } finally {
      setSubmitting(false);
    }
  };

  if (!activeOrder) {
    return (
      <div className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-8 max-w-2xl space-y-4">
        <h1 className="text-xl font-bold text-[#F3F4F6]">{t.payment.noOrderTitle}</h1>
        <p className="text-sm text-[#9CA3AF] leading-relaxed">{t.payment.noOrderDesc}</p>
        <button
          type="button"
          onClick={() => onNavigate('plans')}
          className="px-5 py-2.5 rounded-lg bg-[#D4AF37] hover:bg-[#E5C454] text-[#07090F] text-sm font-semibold transition-colors whitespace-nowrap"
        >
          {t.payment.goToPlans}
        </button>
      </div>
    );
  }

  const exactPayable = formatMicroUsdc(
    activeOrder.payable_amount_usdc_micro ?? activeOrder.expected_amount_usdc_micro
  );

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <h1 className="text-2xl font-bold text-[#F3F4F6] text-balance">{t.payment.heading}</h1>
        <p className="text-sm text-[#9CA3AF] max-w-3xl">{t.payment.lead}</p>
      </div>

      {/* Order Selector if multiple orders exist */}
      {orders.length > 1 && (
        <div className="flex flex-wrap items-center gap-2">
          {orders.slice(0, 6).map((o) => (
            <button
              key={o.order_code}
              type="button"
              onClick={() => onSelectOrder(o.order_code)}
              dir="ltr"
              className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-colors whitespace-nowrap ${
                o.order_code === activeOrder.order_code
                  ? 'bg-[#131C31] border border-[#D4AF37] text-[#D4AF37]'
                  : 'bg-[#0E1525] border border-[#1F2C47] text-[#9CA3AF] hover:text-[#F3F4F6]'
              }`}
            >
              {o.order_code} · ${formatMicroUsdc(o.payable_amount_usdc_micro ?? o.expected_amount_usdc_micro)}
            </button>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
        {/* Order & Wallet Details */}
        <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-[#1F2C47]">
            <h2 className="text-base font-semibold text-[#F3F4F6]">{t.payment.orderSummary}</h2>
          </div>

          <div className="divide-y divide-[#1F2C47] text-sm">
            <div className="px-6 py-3.5 flex items-center justify-between gap-4">
              <span className="text-[#9CA3AF]">{t.payment.orderCode}</span>
              <code dir="ltr" className="font-mono text-[#F3F4F6]">
                {activeOrder.order_code}
              </code>
            </div>

            <div className="px-6 py-3.5 flex items-center justify-between gap-4">
              <span className="text-[#9CA3AF]">{t.payment.planLabel}</span>
              <span className="text-[#F3F4F6] font-medium">
                {locale === 'fa'
                  ? activeOrder.plan_name_fa ?? activeOrder.plan_code
                  : activeOrder.plan_name_en ?? activeOrder.plan_code}
              </span>
            </div>

            <div className="px-6 py-3.5 flex items-center justify-between gap-4">
              <span className="text-[#9CA3AF]">{t.payment.exactAmount}</span>
              <div className="flex items-center gap-2">
                <span dir="ltr" className="font-mono tabular-nums font-bold text-[#D4AF37]">
                  {exactPayable} USDC
                </span>
                <button
                  type="button"
                  onClick={() => copyText('amount', exactPayable)}
                  className="inline-flex items-center gap-1 text-xs text-[#2DD4BF] hover:underline"
                >
                  {copiedKey === 'amount' ? (
                    <Check className="w-3.5 h-3.5 text-[#14B8A6]" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>
            </div>

            <div className="px-6 py-3 flex items-center justify-between gap-4 text-xs">
              <span className="text-[#9CA3AF]">
                {locale === 'fa' ? 'قیمت پایه پلن / کد ضد Front-Running' : 'Base Plan / Anti-Front-Running Offset'}
              </span>
              <span dir="ltr" className="font-mono tabular-nums text-[#9CA3AF]">
                ${activeOrder.expected_amount_usd} + {activeOrder.unique_offset_micro ?? 0} µUSDC
              </span>
            </div>

            <div className="px-6 py-3.5 flex items-center justify-between gap-4">
              <span className="text-[#9CA3AF]">{t.payment.statusLabel}</span>
              <span dir="ltr" className="font-mono text-xs text-[#2DD4BF]">
                {activeOrder.status}
              </span>
            </div>

            <div className="px-6 py-3 flex items-center justify-between gap-4 text-xs">
              <span className="text-[#9CA3AF]">
                {locale === 'fa' ? 'مهلت پرداخت (UTC)' : 'Order Expires (UTC)'}
              </span>
              <span dir="ltr" className="font-mono text-[#CBD5E1]">
                {activeOrder.expires_at.slice(0, 19).replace('T', ' ')}
              </span>
            </div>

            <div className="px-6 py-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-[#9CA3AF]">{t.payment.destinationLabel}</span>
                <button
                  type="button"
                  onClick={() => copyText('dest', activeOrder.destination_wallet)}
                  className="inline-flex items-center gap-1 text-xs text-[#D4AF37] hover:underline"
                >
                  {copiedKey === 'dest' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-[#14B8A6]" />
                      <span>{t.copied}</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>{t.copy}</span>
                    </>
                  )}
                </button>
              </div>
              <code
                dir="ltr"
                className="block p-3 rounded-lg bg-[#07090F] border border-[#1F2C47] font-mono text-xs text-[#D4AF37] break-all"
              >
                {activeOrder.destination_wallet}
              </code>
            </div>

            <div className="px-6 py-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-[#9CA3AF]">{t.payment.contractLabel}</span>
                <button
                  type="button"
                  onClick={() => copyText('contract', config.network.usdcContractAddress)}
                  className="inline-flex items-center gap-1 text-xs text-[#2DD4BF] hover:underline"
                >
                  {copiedKey === 'contract' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-[#14B8A6]" />
                      <span>{t.copied}</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>{t.copy}</span>
                    </>
                  )}
                </button>
              </div>
              <code
                dir="ltr"
                className="block p-3 rounded-lg bg-[#07090F] border border-[#1F2C47] font-mono text-xs text-[#CBD5E1] break-all"
              >
                {config.network.usdcContractAddress}
              </code>
            </div>
          </div>
        </section>

        {/* TxID Submission Form */}
        <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-6 space-y-5">
          <div>
            <h2 className="text-base font-semibold text-[#F3F4F6]">{t.payment.txFormTitle}</h2>
            <p className="mt-1.5 text-xs text-[#9CA3AF] leading-relaxed">{t.payment.txHelp}</p>
          </div>

          <form onSubmit={handleSubmitTx} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="txHashInput" className="block text-xs font-medium text-[#CBD5E1]">
                Polygon PoS Transaction Hash (TxID)
              </label>
              <input
                id="txHashInput"
                type="text"
                dir="ltr"
                value={txHash}
                onChange={(e) => setTxHash(e.target.value)}
                placeholder={t.payment.txPlaceholder}
                required
                className="w-full px-3.5 py-2.5 rounded-lg bg-[#07090F] border border-[#1F2C47] focus:border-[#D4AF37] focus:outline-none text-xs font-mono text-[#F3F4F6] placeholder:text-[#475569]"
              />
            </div>

            {feedback && (
              <div
                className={`p-3.5 rounded-lg text-xs border leading-relaxed ${
                  feedback.type === 'ok'
                    ? 'bg-[#092420] border-[#14B8A6]/40 text-[#99F6E4]'
                    : 'bg-[#2A1215] border-[#7F1D1D] text-[#FCA5A5]'
                }`}
              >
                {feedback.text}
              </div>
            )}

            <button
              type="submit"
              disabled={submitting || !txHash.trim()}
              className="w-full py-2.5 px-4 rounded-lg bg-[#D4AF37] hover:bg-[#E5C454] text-[#07090F] text-sm font-semibold transition-colors disabled:opacity-50 whitespace-nowrap"
            >
              {submitting ? t.payment.txSubmitting : t.payment.txSubmit}
            </button>
          </form>
        </section>
      </div>
    </div>
  );
}
