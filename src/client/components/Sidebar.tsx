import {
  CreditCard,
  Home,
  KeyRound,
  Layers,
  SearchCheck,
  ShieldCheck,
  User,
  X,
} from 'lucide-react';
import type { AdminRole } from '../../shared/types';
import { copy, type Locale, type NavSection } from '../i18n';

interface SidebarProps {
  locale: Locale;
  onLocaleChange: (next: Locale) => void;
  activeSection: NavSection;
  onNavigate: (section: NavSection) => void;
  adminRole: AdminRole | null;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

export function Sidebar({
  locale,
  onLocaleChange,
  activeSection,
  onNavigate,
  adminRole,
  mobileOpen,
  onCloseMobile,
}: SidebarProps) {
  const t = copy[locale];

  const items: Array<{ id: NavSection; label: string; icon: typeof Home; adminOnly?: boolean }> = [
    { id: 'home', label: t.nav.home, icon: Home },
    { id: 'plans', label: t.nav.plans, icon: Layers },
    { id: 'payment', label: t.nav.payment, icon: CreditCard },
    { id: 'tracking', label: t.nav.tracking, icon: SearchCheck },
    { id: 'profile', label: t.nav.profile, icon: User },
    { id: 'licenses', label: t.nav.licenses, icon: KeyRound },
    { id: 'admin', label: t.nav.admin, icon: ShieldCheck, adminOnly: true },
  ];

  const visibleItems = items.filter((item) => !item.adminOnly || Boolean(adminRole));

  const sidebarContent = (
    <div className="flex h-full flex-col bg-[#0A0F1D] border-e border-[#1F2C47]">
      {/* Brand Lockup */}
      <div className="flex items-center justify-between px-5 py-5 border-b border-[#1F2C47]">
        <div className="flex items-center gap-3 min-w-0">
          <svg
            width="30"
            height="30"
            viewBox="0 0 32 32"
            fill="none"
            aria-hidden="true"
            className="shrink-0"
          >
            <rect
              x="1.5"
              y="1.5"
              width="29"
              height="29"
              rx="6"
              fill="#0E1525"
              stroke="#D4AF37"
              strokeWidth="1.5"
            />
            <path d="M9 11H23L20.5 14.5H12.5V17.5H19L16.5 21H9V11Z" fill="#D4AF37" />
            <path d="M20.5 17.5H23V21H18.5L20.5 17.5Z" fill="#14B8A6" />
          </svg>
          <div className="min-w-0">
            <div className="text-sm font-bold tracking-tight text-[#F3F4F6] truncate">
              EDGE LICENSE
            </div>
            <div className="text-xs text-[#9CA3AF] truncate">by AMIRBTC</div>
          </div>
        </div>
        <button
          type="button"
          onClick={onCloseMobile}
          aria-label="Close navigation"
          className="lg:hidden p-2 text-[#9CA3AF] hover:text-[#F3F4F6] rounded-md"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto" aria-label="Primary Navigation">
        {visibleItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeSection === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                onNavigate(item.id);
                onCloseMobile();
              }}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors whitespace-nowrap ${
                isActive
                  ? 'bg-[#131C31] text-[#D4AF37] border border-[#2B3B5E]'
                  : 'text-[#CBD5E1] hover:bg-[#0E1525] hover:text-[#F3F4F6] border border-transparent'
              }`}
            >
              <Icon
                className={`w-4 h-4 shrink-0 ${
                  isActive ? 'text-[#D4AF37]' : item.adminOnly ? 'text-[#14B8A6]' : 'text-[#64748B]'
                }`}
              />
              <span className="truncate">{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Workspace Language Switcher & Bot Reference */}
      <div className="p-4 border-t border-[#1F2C47] space-y-3">
        <div
          className="grid grid-cols-2 gap-1 p-1 bg-[#07090F] rounded-lg border border-[#1F2C47]"
          role="group"
          aria-label="Language"
        >
          <button
            type="button"
            onClick={() => onLocaleChange('fa')}
            className={`py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
              locale === 'fa'
                ? 'bg-[#131C31] text-[#D4AF37]'
                : 'text-[#9CA3AF] hover:text-[#F3F4F6]'
            }`}
          >
            فارسی
          </button>
          <button
            type="button"
            onClick={() => onLocaleChange('en')}
            className={`py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
              locale === 'en'
                ? 'bg-[#131C31] text-[#D4AF37]'
                : 'text-[#9CA3AF] hover:text-[#F3F4F6]'
            }`}
          >
            English
          </button>
        </div>

        <div className="flex items-center justify-between text-xs text-[#9CA3AF] px-1">
          <span>Bot</span>
          <span dir="ltr" className="font-mono text-[#2DD4BF]">
            @EDGE_LicenceBot
          </span>
        </div>
      </div>
    </div>
  );

  return (
    <>
      <aside className="hidden lg:block w-[260px] shrink-0 h-screen sticky top-0">
        {sidebarContent}
      </aside>
      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div className="w-[270px] max-w-[82vw] h-full">{sidebarContent}</div>
          <button
            type="button"
            aria-label="Dismiss menu"
            onClick={onCloseMobile}
            className="flex-1 bg-black/70"
          />
        </div>
      )}
    </>
  );
}
