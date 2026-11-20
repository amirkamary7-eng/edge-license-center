import { ArrowUpRight, Check, Copy } from 'lucide-react';
import { useState } from 'react';
import type { LicenseRecord, OrderRecord } from '../../shared/types';
import type { PublicConfigResponse } from '../api';
import { copy, type Locale, type NavSection } from '../i18n';

interface HomeViewProps {
  locale: Locale;
  config: PublicConfigResponse;
  orders: OrderRecord[];
  licenses: LicenseRecord[];
  onNavigate: (section: NavSection) => void;
}

export function HomeView({ locale, config, orders, licenses, onNavigate }: HomeViewProps) {
  const t = copy[locale];
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const handleCopy = async (field: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 1800);
    } catch {
      setCopiedField(null);
    }
  };

  const activeLicensesCount = licenses.filter((l) => l.status === 'active').length;

  return (
    <div className="space-y-8">
      {/* Primary Hero Anchor */}
      <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-6 sm:p-8">
        <div className="max-w-3xl space-y-4">
          <div className="flex flex-wrap items-center gap-2 text-xs text-[#9CA3AF]">
            <span className="text-[#D4AF37] font-medium">{config.brandName}</span>
            <span aria-hidden="true">·</span>
            <span>{config.brandOwner}</span>
            <span aria-hidden="true">·</span>
            <span dir="ltr" className="font-mono text-[#2DD4BF]">
              {config.network.name} / {config.network.currencySymbol}
            </span>
          </div>

          <h1 className="text-2xl sm:text-3xl font-bold text-[#F3F4F6] tracking-tight text-balance">
            {t.home.heading}
          </h1>

          <p className="text-sm sm:text-base text-[#CBD5E1] leading-relaxed">{t.home.lead}</p>

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <button
              type="button"
              onClick={() => onNavigate('plans')}
              className="px-5 py-2.5 rounded-lg bg-[#D4AF37] hover:bg-[#E5C454] text-[#07090F] text-sm font-semibold transition-colors whitespace-nowrap shrink-0"
            >
              {t.home.primaryAction}
            </button>
            <button
              type="button"
              onClick={() => onNavigate('tracking')}
              className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-lg bg-[#131C31] hover:bg-[#1A2642] border border-[#2B3B5E] text-[#F3F4F6] text-sm font-medium transition-colors whitespace-nowrap shrink-0"
            >
              <span>{t.home.secondaryAction}</span>
              <ArrowUpRight className="w-4 h-4 text-[#14B8A6]" />
            </button>
          </div>
        </div>
      </section>

      {/* 4-Column Summary Strip */}
      <section className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-5">
          <div className="text-xs text-[#9CA3AF]">{t.home.metrics.activeLicenses}</div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-[#F3F4F6]">
            {activeLicensesCount}
          </div>
        </div>

        <div className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-5">
          <div className="text-xs text-[#9CA3AF]">{t.home.metrics.openOrders}</div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-[#D4AF37]">
            {orders.length}
          </div>
        </div>

        <div className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-5">
          <div className="text-xs text-[#9CA3AF]">{t.home.metrics.network}</div>
          <div className="mt-2 text-lg font-semibold font-mono text-[#2DD4BF]" dir="ltr">
            {config.network.name} ({config.network.chainId})
          </div>
        </div>

        <div className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-5">
          <div className="text-xs text-[#9CA3AF]">{t.home.metrics.bot}</div>
          <div className="mt-2 text-lg font-semibold font-mono text-[#F3F4F6]" dir="ltr">
            {config.botHandle}
          </div>
        </div>
      </section>

      {/* Phase 0 Governance Notice */}
      <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-5 sm:p-6">
        <h2 className="text-sm font-semibold text-[#D4AF37]">{t.phase0NoticeTitle}</h2>
        <p className="mt-2 text-sm text-[#CBD5E1] leading-relaxed">{t.phase0NoticeBody}</p>
      </section>

      {/* Authoritative Payment Specifications Table */}
      <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-[#1F2C47]">
          <h2 className="text-base font-semibold text-[#F3F4F6]">{t.home.specTitle}</h2>
        </div>

        <div className="divide-y divide-[#1F2C47]">
          <div className="px-6 py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <span className="text-sm text-[#9CA3AF]">{t.home.specNetwork}</span>
            <span dir="ltr" className="text-sm font-mono text-[#F3F4F6]">
              {config.network.name} · Chain ID {config.network.chainId}
            </span>
          </div>

          <div className="px-6 py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <span className="text-sm text-[#9CA3AF]">{t.home.specAsset}</span>
            <span dir="ltr" className="text-sm font-mono text-[#2DD4BF]">
              {config.network.currencySymbol} · {config.network.tokenStandard}
            </span>
          </div>

          <div className="px-6 py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <span className="text-sm text-[#9CA3AF]">{t.home.specContract}</span>
            <div className="flex items-center gap-2 min-w-0">
              <code
                dir="ltr"
                className="text-xs sm:text-sm font-mono text-[#F3F4F6] truncate max-w-[260px] sm:max-w-none"
              >
                {config.network.usdcContractAddress}
              </code>
              <button
                type="button"
                onClick={() => handleCopy('contract', config.network.usdcContractAddress)}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md bg-[#131C31] hover:bg-[#1A2642] border border-[#2B3B5E] text-xs text-[#CBD5E1] shrink-0"
              >
                {copiedField === 'contract' ? (
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
          </div>

          <div className="px-6 py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <span className="text-sm text-[#9CA3AF]">{t.home.specWallet}</span>
            <div className="flex items-center gap-2 min-w-0">
              <code
                dir="ltr"
                className="text-xs sm:text-sm font-mono text-[#D4AF37] truncate max-w-[260px] sm:max-w-none"
              >
                {config.network.destinationWalletAddress}
              </code>
              <button
                type="button"
                onClick={() => handleCopy('wallet', config.network.destinationWalletAddress)}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md bg-[#131C31] hover:bg-[#1A2642] border border-[#2B3B5E] text-xs text-[#CBD5E1] shrink-0"
              >
                {copiedField === 'wallet' ? (
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
          </div>

          <div className="px-6 py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <span className="text-sm text-[#9CA3AF]">{t.home.specConfirmations}</span>
            <span className="text-sm font-mono tabular-nums text-[#F3F4F6]">
              {config.network.minConfirmations} blocks
            </span>
          </div>

          <div className="px-6 py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <span className="text-sm text-[#9CA3AF]">{t.home.specValidation}</span>
            <span className="text-sm text-[#CBD5E1]">{t.home.specValidationValue}</span>
          </div>
        </div>
      </section>
    </div>
  );
}
