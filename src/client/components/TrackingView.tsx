import { Search } from 'lucide-react';
import { useState } from 'react';
import type { OrderRecord, PaymentRecord } from '../../shared/types';
import { copy, type Locale } from '../i18n';

interface TrackingViewProps {
  locale: Locale;
  orders: OrderRecord[];
  payments: PaymentRecord[];
  onOpenOrderPayment: (orderCode: string) => void;
}

export function TrackingView({
  locale,
  orders,
  payments,
  onOpenOrderPayment,
}: TrackingViewProps) {
  const t = copy[locale];
  const [query, setQuery] = useState('');

  const q = query.trim().toLowerCase();
  const filteredOrders = orders.filter(
    (o) =>
      !q ||
      o.order_code.toLowerCase().includes(q) ||
      o.status.toLowerCase().includes(q) ||
      (o.plan_code ?? '').toLowerCase().includes(q)
  );
  const filteredPayments = payments.filter(
    (p) =>
      !q ||
      p.tx_hash.toLowerCase().includes(q) ||
      (p.order_code ?? '').toLowerCase().includes(q) ||
      p.status.toLowerCase().includes(q)
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div className="space-y-1.5">
          <h1 className="text-2xl font-bold text-[#F3F4F6] text-balance">{t.tracking.heading}</h1>
          <p className="text-sm text-[#9CA3AF]">{t.tracking.lead}</p>
        </div>

        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 text-[#64748B] absolute top-1/2 -translate-y-1/2 start-3 pointer-events-none" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t.tracking.searchPlaceholder}
            className="w-full ps-9 pe-3 py-2 rounded-lg bg-[#0E1525] border border-[#1F2C47] focus:border-[#D4AF37] focus:outline-none text-xs text-[#F3F4F6] placeholder:text-[#64748B]"
          />
        </div>
      </div>

      {/* Orders Table */}
      <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-[#1F2C47]">
          <h2 className="text-base font-semibold text-[#F3F4F6]">{t.tracking.ordersTable}</h2>
        </div>

        {filteredOrders.length === 0 ? (
          <div className="px-6 py-8 text-sm text-[#9CA3AF]">{t.tracking.emptyOrders}</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1F2C47] text-xs text-[#9CA3AF] bg-[#0A0F1D]">
                  <th className="px-6 py-3 text-start font-medium">Order Code</th>
                  <th className="px-6 py-3 text-start font-medium">Plan</th>
                  <th className="px-6 py-3 text-end font-medium">Amount</th>
                  <th className="px-6 py-3 text-start font-medium">Status</th>
                  <th className="px-6 py-3 text-end font-medium">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2C47]">
                {filteredOrders.map((order) => (
                  <tr key={order.id} className="hover:bg-[#131C31]/60 transition-colors">
                    <td className="px-6 py-3.5 font-mono text-xs text-[#F3F4F6]" dir="ltr">
                      {order.order_code}
                    </td>
                    <td className="px-6 py-3.5 text-[#CBD5E1]">
                      {locale === 'fa'
                        ? order.plan_name_fa ?? order.plan_code
                        : order.plan_name_en ?? order.plan_code}
                    </td>
                    <td className="px-6 py-3.5 text-end font-mono tabular-nums text-[#D4AF37]" dir="ltr">
                      ${order.expected_amount_usd}
                    </td>
                    <td className="px-6 py-3.5 font-mono text-xs text-[#2DD4BF]" dir="ltr">
                      {order.status}
                    </td>
                    <td className="px-6 py-3.5 text-end">
                      <button
                        type="button"
                        onClick={() => onOpenOrderPayment(order.order_code)}
                        className="text-xs font-medium text-[#D4AF37] hover:underline whitespace-nowrap"
                      >
                        {locale === 'fa' ? 'ثبت TxID' : 'Submit TxID'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Payments Table */}
      <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-[#1F2C47]">
          <h2 className="text-base font-semibold text-[#F3F4F6]">{t.tracking.paymentsTable}</h2>
        </div>

        {filteredPayments.length === 0 ? (
          <div className="px-6 py-8 text-sm text-[#9CA3AF]">{t.tracking.emptyPayments}</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1F2C47] text-xs text-[#9CA3AF] bg-[#0A0F1D]">
                  <th className="px-6 py-3 text-start font-medium">Order</th>
                  <th className="px-6 py-3 text-start font-medium">TxID (Polygon PoS)</th>
                  <th className="px-6 py-3 text-end font-medium">USDC</th>
                  <th className="px-6 py-3 text-start font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2C47]">
                {filteredPayments.map((pay) => (
                  <tr key={pay.id} className="hover:bg-[#131C31]/60 transition-colors">
                    <td className="px-6 py-3.5 font-mono text-xs text-[#CBD5E1]" dir="ltr">
                      {pay.order_code ?? `#${pay.order_id}`}
                    </td>
                    <td className="px-6 py-3.5 font-mono text-xs text-[#F3F4F6]" dir="ltr">
                      {pay.tx_hash.slice(0, 14)}...{pay.tx_hash.slice(-10)}
                    </td>
                    <td className="px-6 py-3.5 text-end font-mono tabular-nums text-[#D4AF37]" dir="ltr">
                      ${(pay.amount_usdc_micro / 1_000_000).toFixed(2)}
                    </td>
                    <td className="px-6 py-3.5 font-mono text-xs text-[#2DD4BF]" dir="ltr">
                      {pay.status}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Verification Pipeline Specification */}
      <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-6 space-y-3">
        <h2 className="text-base font-semibold text-[#F3F4F6]">{t.tracking.pipelineTitle}</h2>
        <ol className="space-y-2 text-sm text-[#CBD5E1]">
          {t.tracking.steps.map((step) => (
            <li key={step} className="leading-relaxed">
              {step}
            </li>
          ))}
        </ol>
      </section>
    </div>
  );
}
