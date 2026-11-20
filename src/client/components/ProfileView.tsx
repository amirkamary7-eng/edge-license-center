import type { AuthSessionResponse, PaymentRecord } from '../../shared/types';
import { copy, type Locale } from '../i18n';

interface ProfileViewProps {
  locale: Locale;
  session: AuthSessionResponse;
  payments: PaymentRecord[];
}

export function ProfileView({ locale, session, payments }: ProfileViewProps) {
  const t = copy[locale];

  return (
    <div className="space-y-6">
      <div className="space-y-1.5">
        <h1 className="text-2xl font-bold text-[#F3F4F6] text-balance">{t.profile.heading}</h1>
        <p className="text-sm text-[#9CA3AF]">{t.profile.lead}</p>
      </div>

      {/* Telegram Identity Summary */}
      <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-[#1F2C47]">
          <h2 className="text-base font-semibold text-[#F3F4F6]">{t.profile.accountInfo}</h2>
        </div>

        <div className="divide-y divide-[#1F2C47] text-sm">
          <div className="px-6 py-3.5 flex items-center justify-between gap-4">
            <span className="text-[#9CA3AF]">{t.profile.telegramId}</span>
            <span dir="ltr" className="font-mono tabular-nums text-[#F3F4F6]">
              {session.user.telegram_id}
            </span>
          </div>
          <div className="px-6 py-3.5 flex items-center justify-between gap-4">
            <span className="text-[#9CA3AF]">{t.profile.username}</span>
            <span dir="ltr" className="font-mono text-[#CBD5E1]">
              {session.user.username ? `@${session.user.username}` : session.user.first_name}
            </span>
          </div>
          <div className="px-6 py-3.5 flex items-center justify-between gap-4">
            <span className="text-[#9CA3AF]">{t.profile.authMode}</span>
            <span dir="ltr" className="font-mono text-xs text-[#2DD4BF]">
              {session.authMode}
            </span>
          </div>
          <div className="px-6 py-3.5 flex items-center justify-between gap-4">
            <span className="text-[#9CA3AF]">{t.profile.role}</span>
            <span dir="ltr" className="font-mono text-xs text-[#D4AF37]">
              {session.adminRole ?? 'customer'}
            </span>
          </div>
          <div className="px-6 py-3.5 flex items-center justify-between gap-4">
            <span className="text-[#9CA3AF]">{t.profile.status}</span>
            <span dir="ltr" className="font-mono text-xs text-[#CBD5E1]">
              {session.user.status}
            </span>
          </div>
        </div>
      </section>

      {/* Payment History Table */}
      <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-[#1F2C47]">
          <h2 className="text-base font-semibold text-[#F3F4F6]">{t.profile.paymentHistory}</h2>
        </div>

        {payments.length === 0 ? (
          <div className="px-6 py-8 text-sm text-[#9CA3AF]">{t.profile.emptyHistory}</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1F2C47] text-xs text-[#9CA3AF] bg-[#0A0F1D]">
                  <th className="px-6 py-3 text-start font-medium">Order</th>
                  <th className="px-6 py-3 text-start font-medium">TxID</th>
                  <th className="px-6 py-3 text-end font-medium">Amount</th>
                  <th className="px-6 py-3 text-start font-medium">Status</th>
                  <th className="px-6 py-3 text-end font-medium">Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2C47]">
                {payments.map((pay) => (
                  <tr key={pay.id} className="hover:bg-[#131C31]/60 transition-colors">
                    <td className="px-6 py-3.5 font-mono text-xs text-[#F3F4F6]" dir="ltr">
                      {pay.order_code ?? `#${pay.order_id}`}
                    </td>
                    <td className="px-6 py-3.5 font-mono text-xs text-[#CBD5E1]" dir="ltr">
                      {pay.tx_hash.slice(0, 12)}...{pay.tx_hash.slice(-8)}
                    </td>
                    <td className="px-6 py-3.5 text-end font-mono tabular-nums text-[#D4AF37]" dir="ltr">
                      ${(pay.amount_usdc_micro / 1_000_000).toFixed(2)}
                    </td>
                    <td className="px-6 py-3.5 font-mono text-xs text-[#2DD4BF]" dir="ltr">
                      {pay.status}
                    </td>
                    <td className="px-6 py-3.5 text-end font-mono tabular-nums text-xs text-[#9CA3AF]" dir="ltr">
                      {pay.created_at.slice(0, 10)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
