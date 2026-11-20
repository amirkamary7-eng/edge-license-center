/**
 * EDGE LICENSE CENTER by AMIRBTC
 * Immutable Core Commercial & Blockchain Specifications
 *
 * Phase 0 Governance Rule:
 * Payment addresses, token contract, network, bot handle, and base plan prices
 * are frozen constants and MUST NOT be altered without explicit project owner approval.
 */

export const BRAND_NAME = 'EDGE LICENSE CENTER' as const;
export const BRAND_OWNER = 'AMIRBTC' as const;
export const PRODUCT_NAME = 'EDGE by AMIRBTC' as const;
export const TELEGRAM_BOT_HANDLE = '@EDGE_LicenceBot' as const;
export const TELEGRAM_BOT_USERNAME = 'EDGE_LicenceBot' as const;

export const PAYMENT_NETWORK = {
  name: 'Polygon PoS',
  chainId: 137,
  currencySymbol: 'USDC',
  tokenStandard: 'ERC-20 (Native USDC)',
  tokenDecimals: 6,
  usdcContractAddress: '0x3c499c542cef5e3811e1192ce70d8cc03d5c3359',
  destinationWalletAddress: '0xf5fdefb5b02be3b7e16df37859dca111526bcc05',
  /** keccak256("Transfer(address,address,uint256)") */
  erc20TransferTopic:
    '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
  minConfirmations: 30,
  orderExpiryMinutes: 45,
} as const;

export interface FixedPlanSpec {
  readonly code: 'EDGE_1M' | 'EDGE_3M' | 'EDGE_6M' | 'EDGE_12M';
  readonly nameEn: string;
  readonly nameFa: string;
  readonly durationMonths: 1 | 3 | 6 | 12;
  readonly durationDays: number;
  readonly priceUsd: number;
  readonly priceCents: number;
  readonly priceUsdcMicro: number;
  readonly maxDevices: number;
  readonly badgeEn: string;
  readonly badgeFa: string;
  readonly savingsPercent: number;
  readonly sortOrder: number;
}

export const FIXED_PLANS: readonly FixedPlanSpec[] = [
  {
    code: 'EDGE_1M',
    nameEn: '1 Month Access',
    nameFa: 'اشتراک ۱ ماهه',
    durationMonths: 1,
    durationDays: 30,
    priceUsd: 1.99,
    priceCents: 199,
    priceUsdcMicro: 1_990_000,
    maxDevices: 1,
    badgeEn: 'Starter',
    badgeFa: 'شروع سریع',
    savingsPercent: 0,
    sortOrder: 1,
  },
  {
    code: 'EDGE_3M',
    nameEn: '3 Months Access',
    nameFa: 'اشتراک ۳ ماهه',
    durationMonths: 3,
    durationDays: 90,
    priceUsd: 4.99,
    priceCents: 499,
    priceUsdcMicro: 4_990_000,
    maxDevices: 1,
    badgeEn: 'Quarterly',
    badgeFa: 'فصلی',
    savingsPercent: 16,
    sortOrder: 2,
  },
  {
    code: 'EDGE_6M',
    nameEn: '6 Months Access',
    nameFa: 'اشتراک ۶ ماهه',
    durationMonths: 6,
    durationDays: 180,
    priceUsd: 8.99,
    priceCents: 899,
    priceUsdcMicro: 8_990_000,
    maxDevices: 2,
    badgeEn: 'Popular',
    badgeFa: 'پرطرفدار',
    savingsPercent: 25,
    sortOrder: 3,
  },
  {
    code: 'EDGE_12M',
    nameEn: '12 Months Access',
    nameFa: 'اشتراک ۱۲ ماهه',
    durationMonths: 12,
    durationDays: 365,
    priceUsd: 16.99,
    priceCents: 1699,
    priceUsdcMicro: 16_990_000,
    maxDevices: 2,
    badgeEn: 'Best Value',
    badgeFa: 'به‌صرفه‌ترین',
    savingsPercent: 29,
    sortOrder: 4,
  },
] as const;

export const SYSTEM_PHASE = 'PHASE_0_BOOTSTRAP' as const;
