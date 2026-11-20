import {
  BRAND_NAME,
  BRAND_OWNER,
  PAYMENT_NETWORK,
  TELEGRAM_BOT_HANDLE,
  TELEGRAM_BOT_USERNAME,
} from '../../shared/constants';
import type { SqliteDb } from '../db/connection';
import { AuditService } from '../modules/audit/auditService';
import { LicenseService } from '../modules/license/licenseService';
import { formatMicroUsdc, PaymentService } from '../modules/payment/paymentService';
import { PlanRepository } from '../modules/plans/planRepository';
import { SupportService } from '../modules/support/supportService';
import { UserRepository } from '../modules/users/userRepository';
import type { TelegramInlineKeyboardButton } from './telegramClient';

export interface TelegramUpdate {
  update_id: number;
  message?: {
    message_id: number;
    from: {
      id: number;
      first_name: string;
      last_name?: string;
      username?: string;
      language_code?: string;
    };
    chat: { id: number; type: string };
    text?: string;
  };
  callback_query?: {
    id: string;
    from: {
      id: number;
      first_name: string;
      last_name?: string;
      username?: string;
      language_code?: string;
    };
    data?: string;
  };
}

export interface BotReplyPayload {
  chatId: number;
  text: string;
  parseMode: 'HTML';
  callbackQueryId?: string;
  callbackToast?: string;
  inlineKeyboard: TelegramInlineKeyboardButton[][];
}

/**
 * Strips optional `@EDGE_LicenceBot` suffix from slash commands (e.g., `/start@EDGE_LicenceBot`).
 */
export function normalizeBotCommand(rawToken: string): string {
  const token = rawToken.trim();
  if (!token.startsWith('/')) return token;
  const atIdx = token.indexOf('@');
  if (atIdx === -1) return token.toLowerCase();
  const cmd = token.slice(0, atIdx).toLowerCase();
  const target = token.slice(atIdx + 1).toLowerCase();
  if (target === TELEGRAM_BOT_USERNAME.toLowerCase()) {
    return cmd;
  }
  return token.toLowerCase();
}

export class EdgeBotRouter {
  private readonly users: UserRepository;
  private readonly plans: PlanRepository;
  private readonly audit: AuditService;
  private readonly support: SupportService;

  constructor(
    private readonly db: SqliteDb,
    private readonly paymentService: PaymentService,
    private readonly licenseService: LicenseService,
    private readonly miniAppUrl: string
  ) {
    this.users = new UserRepository(db);
    this.plans = new PlanRepository(db);
    this.audit = new AuditService(db);
    this.support = new SupportService(db);
  }

  private mainMenuKeyboard(isAdmin: boolean): TelegramInlineKeyboardButton[][] {
    const rows: TelegramInlineKeyboardButton[][] = [
      [{ text: '🚀 باز کردن پنل Mini App', web_app: { url: this.miniAppUrl } }],
      [
        { text: '💎 خرید اشتراک', callback_data: 'menu:plans' },
        { text: '🔄 تمدید / ارتقا', callback_data: 'menu:renew' },
      ],
      [
        { text: '🧾 ثبت TxID پرداخت', callback_data: 'menu:tx' },
        { text: '📦 وضعیت سفارش‌ها', callback_data: 'menu:orders' },
      ],
      [
        { text: '👤 پروفایل و لایسنس', callback_data: 'menu:profile' },
        { text: '🛟 پشتیبانی و تیکت', callback_data: 'menu:support' },
      ],
    ];

    if (isAdmin) {
      rows.push([{ text: '🛡 بخش مدیریت (Admin)', callback_data: 'menu:admin' }]);
    }
    return rows;
  }

  handleUpdate(update: TelegramUpdate): BotReplyPayload | null {
    const actor = update.message?.from ?? update.callback_query?.from;
    if (!actor) return null;

    const chatId = update.message?.chat.id ?? actor.id;
    const callbackQueryId = update.callback_query?.id;

    const user = this.users.upsertFromTelegram({
      telegramId: String(actor.id),
      username: actor.username ?? null,
      firstName: actor.first_name,
      lastName: actor.last_name ?? null,
      languageCode: actor.language_code ?? 'fa',
    });

    // Enforce account ban/suspension in Telegram Bot as well as Mini App
    if (user.status !== 'active') {
      this.audit.record({
        actorType: 'bot',
        actorId: user.telegram_id,
        action: 'BOT_BLOCKED_USER_ATTEMPT',
        entityType: 'user',
        entityId: String(user.id),
        severity: 'warning',
        metadata: { status: user.status, updateId: update.update_id },
      });
      return {
        chatId,
        parseMode: 'HTML',
        callbackQueryId,
        callbackToast: 'حساب شما محدود شده است.',
        text: `حساب شما در وضعیت <b>${user.status}</b> قرار دارد و امکان استفاده از ربات وجود ندارد.`,
        inlineKeyboard: [],
      };
    }

    const admin = this.users.findActiveAdminByTelegramId(user.telegram_id);
    const isAdmin = Boolean(admin);

    const rawInput = (update.message?.text ?? update.callback_query?.data ?? '').trim();
    const [rawCommand = '', ...args] = rawInput.split(/\s+/);
    const command = normalizeBotCommand(rawCommand);

    this.audit.record({
      actorType: 'bot',
      actorId: user.telegram_id,
      action: 'BOT_COMMAND_RECEIVED',
      entityType: 'telegram_update',
      entityId: String(update.update_id),
      metadata: { command },
    });

    if (command === '/start' || command === 'menu:home') {
      return {
        chatId,
        parseMode: 'HTML',
        callbackQueryId,
        text: [
          `<b>${BRAND_NAME} by ${BRAND_OWNER}</b>`,
          `ربات رسمی فروش، پرداخت و مدیریت لایسنس اپلیکیشن EDGE (${TELEGRAM_BOT_HANDLE})`,
          '',
          `• شبکه پرداخت: <b>${PAYMENT_NETWORK.name}</b>`,
          `• ارز رسمی: <b>Native ${PAYMENT_NETWORK.currencySymbol}</b>`,
          '',
          'از منوی زیر گزینه موردنظر را انتخاب کنید یا Mini App را باز کنید:',
        ].join('\n'),
        inlineKeyboard: this.mainMenuKeyboard(isAdmin),
      };
    }

    if (command === '/plans' || command === '/buy' || command === 'menu:plans') {
      const activePlans = this.plans.listActive();
      const planLines = activePlans.map(
        (p) => `• <b>${p.name_fa}</b> (${p.code}) — <code>$${p.price_usd_display} USDC</code>`
      );
      return {
        chatId,
        parseMode: 'HTML',
        callbackQueryId,
        text: [
          '<b>پلن‌های رسمی اشتراک EDGE by AMIRBTC</b>',
          '',
          ...planLines,
          '',
          `قرارداد رسمی Native USDC:\n<code>${PAYMENT_NETWORK.usdcContractAddress}</code>`,
          `آدرس کیف پول مقصد:\n<code>${PAYMENT_NETWORK.destinationWalletAddress}</code>`,
        ].join('\n'),
        inlineKeyboard: [
          ...activePlans.map((p) => [
            { text: `خرید ${p.name_fa} ($${p.price_usd_display})`, callback_data: `buy:${p.code}` },
          ]),
          [{ text: 'بازگشت به منوی اصلی', callback_data: 'menu:home' }],
        ],
      };
    }

    if (command === '/renew' || command === '/upgrade' || command === 'menu:renew') {
      const subs = this.licenseService.listUserSubscriptions(user.id);
      const activeSub = subs.find((s) => s.status === 'active') ?? subs[0];
      const activePlans = this.plans.listActive();
      const modePrefix = command === '/upgrade' ? 'upgrade' : 'renew';

      if (!activeSub) {
        return {
          chatId,
          parseMode: 'HTML',
          callbackQueryId,
          text: 'اشتراک قبلی برای تمدید یا ارتقا یافت نشد. لطفاً یک پلن جدید خریداری کنید:',
          inlineKeyboard: [
            ...activePlans.map((p) => [
              { text: `خرید ${p.name_fa} ($${p.price_usd_display})`, callback_data: `buy:${p.code}` },
            ]),
            [{ text: 'بازگشت به منوی اصلی', callback_data: 'menu:home' }],
          ],
        };
      }

      return {
        chatId,
        parseMode: 'HTML',
        callbackQueryId,
        text: [
          `<b>${modePrefix === 'upgrade' ? 'ارتقای اشتراک' : 'تمدید اشتراک'} EDGE</b>`,
          `اشتراک فعلی: <code>#${activeSub.id}</code> (انقضا: <code>${activeSub.expires_at.slice(0, 10)}</code>)`,
          'پلن موردنظر برای تمدید/ارتقا را انتخاب کنید:',
        ].join('\n'),
        inlineKeyboard: [
          ...activePlans.map((p) => [
            {
              text: `${modePrefix === 'upgrade' ? 'ارتقا به' : 'تمدید'} ${p.name_fa} ($${p.price_usd_display})`,
              callback_data: `${modePrefix}:${p.code}`,
            },
          ]),
          [{ text: 'بازگشت به منوی اصلی', callback_data: 'menu:home' }],
        ],
      };
    }

    if (
      command.startsWith('buy:') ||
      command.startsWith('renew:') ||
      command.startsWith('upgrade:')
    ) {
      const [actionType, planCode] = command.split(':');
      try {
        const subs = this.licenseService.listUserSubscriptions(user.id);
        const targetSub = subs.find((s) => s.status === 'active') ?? subs[0];
        const orderType =
          actionType === 'renew' ? 'renew' : actionType === 'upgrade' ? 'upgrade' : 'new';

        const order = this.paymentService.createOrder(user.id, planCode, null, {
          orderType,
          targetSubscriptionId: orderType !== 'new' && targetSub ? targetSub.id : null,
        });

        const payableDisplay = formatMicroUsdc(
          order.payable_amount_usdc_micro ?? order.expected_amount_usdc_micro
        );

        return {
          chatId,
          parseMode: 'HTML',
          callbackQueryId,
          callbackToast: `سفارش ${order.order_code} ایجاد شد`,
          text: [
            `<b>سفارش ثبت شد (${orderType})</b>`,
            `کد سفارش: <code>${order.order_code}</code>`,
            `مبلغ دقیق قابل پرداخت (ضد تداخل): <code>${payableDisplay} USDC</code>`,
            `شبکه: <b>${PAYMENT_NETWORK.name}</b>`,
            `آدرس مقصد: <code>${order.destination_wallet}</code>`,
            `مهلت پرداخت تا: <code>${order.expires_at.slice(0, 19).replace('T', ' ')} UTC</code>`,
            '',
            `پس از واریز، هش تراکنش را ارسال کنید:`,
            `<code>/tx ${order.order_code} 0x...</code>`,
          ].join('\n'),
          inlineKeyboard: this.mainMenuKeyboard(isAdmin),
        };
      } catch (err) {
        return {
          chatId,
          parseMode: 'HTML',
          callbackQueryId,
          callbackToast: 'خطا در ایجاد سفارش',
          text: `امکان ثبت سفارش وجود ندارد: <b>${(err as Error).message}</b>`,
          inlineKeyboard: this.mainMenuKeyboard(isAdmin),
        };
      }
    }

    if (command === '/tx' || command === '/pay' || command === 'menu:tx') {
      if (args.length < 2) {
        return {
          chatId,
          parseMode: 'HTML',
          callbackQueryId,
          text: 'برای ثبت هش تراکنش Polygon PoS از فرمت زیر استفاده کنید:\n<code>/tx EDGE-... 0xYour64HexTxHash</code>',
          inlineKeyboard: this.mainMenuKeyboard(isAdmin),
        };
      }
      const [orderCode, txHash] = args;
      try {
        const result = this.paymentService.submitTransactionHash({
          userId: user.id,
          orderCode,
          txHash,
        });
        return {
          chatId,
          parseMode: 'HTML',
          callbackQueryId,
          text: [
            `<b>ثبت تراکنش (${result.dryRunBlocked ? 'DRY_RUN' : 'در صف بررسی'})</b>`,
            `سفارش: <code>${result.order.order_code}</code>`,
            `TxID: <code>${result.payment.tx_hash}</code>`,
            `وضعیت: <b>${result.payment.status}</b>`,
          ].join('\n'),
          inlineKeyboard: this.mainMenuKeyboard(isAdmin),
        };
      } catch (err) {
        return {
          chatId,
          parseMode: 'HTML',
          callbackQueryId,
          text: `خطا در ثبت تراکنش: <b>${(err as Error).message}</b>`,
          inlineKeyboard: this.mainMenuKeyboard(isAdmin),
        };
      }
    }

    if (command === '/orders' || command === '/status' || command === 'menu:orders') {
      const orders = this.paymentService.listUserOrders(user.id);
      const payments = this.paymentService.listUserPayments(user.id);
      const body =
        orders.length === 0
          ? 'هنوز سفارشی ثبت نشده است.'
          : orders
              .slice(0, 5)
              .map((o) => {
                const pay = payments.find((p) => p.order_id === o.id);
                const paySuffix = pay ? ` | پرداخت: <b>${pay.status}</b> (${pay.confirmations} تأیید)` : '';
                return `• <code>${o.order_code}</code> — ${formatMicroUsdc(
                  o.payable_amount_usdc_micro ?? o.expected_amount_usdc_micro
                )} USDC — <b>${o.status}</b>${paySuffix}`;
              })
              .join('\n');
      return {
        chatId,
        parseMode: 'HTML',
        callbackQueryId,
        text: `<b>وضعیت سفارش‌ها و پرداخت‌های شما</b>\n\n${body}`,
        inlineKeyboard: this.mainMenuKeyboard(isAdmin),
      };
    }

    if (command === '/license' || command === '/licenses') {
      const licenses = this.licenseService.listUserLicenses(user.id);
      const body =
        licenses.length === 0
          ? 'هنوز لایسنس فعالی برای حساب شما صادر نشده است.'
          : licenses
              .slice(0, 5)
              .map(
                (l) =>
                  `• <code>${l.license_key}</code> — وضعیت: <b>${l.status}</b> — انقضا: <code>${l.expires_at.slice(0, 10)}</code>`
              )
              .join('\n');
      return {
        chatId,
        parseMode: 'HTML',
        callbackQueryId,
        text: `<b>لایسنس‌های EDGE شما</b>\n\n${body}`,
        inlineKeyboard: this.mainMenuKeyboard(isAdmin),
      };
    }

    if (command === '/profile' || command === 'menu:profile') {
      const licenses = this.licenseService.listUserLicenses(user.id);
      return {
        chatId,
        parseMode: 'HTML',
        callbackQueryId,
        text: [
          '<b>پروفایل کاربری</b>',
          `شناسه تلگرام: <code>${user.telegram_id}</code>`,
          `نام: ${user.first_name}`,
          `تعداد لایسنس‌ها: <b>${licenses.length}</b>`,
          `نقش کاربری: <b>${admin ? admin.role : 'customer'}</b>`,
        ].join('\n'),
        inlineKeyboard: this.mainMenuKeyboard(isAdmin),
      };
    }

    if (command === '/ticket') {
      const fullPayload = args.join(' ').trim();
      const [subjectPart, messagePart] = fullPayload.split('|').map((s) => s.trim());
      if (!subjectPart || !messagePart) {
        return {
          chatId,
          parseMode: 'HTML',
          callbackQueryId,
          text: 'برای ثبت تیکت پشتیبانی از فرمت زیر استفاده کنید:\n<code>/ticket موضوع تیکت | شرح کامل مشکل</code>',
          inlineKeyboard: this.mainMenuKeyboard(isAdmin),
        };
      }
      const ticket = this.support.createTicket({
        userId: user.id,
        actorId: user.telegram_id,
        subject: subjectPart.slice(0, 120),
        message: messagePart.slice(0, 2000),
      });
      return {
        chatId,
        parseMode: 'HTML',
        callbackQueryId,
        text: `<b>تیکت پشتیبانی ثبت شد</b>\nکد پیگیری: <code>${ticket.ticket_code}</code>\nوضعیت: <b>${ticket.status}</b>`,
        inlineKeyboard: this.mainMenuKeyboard(isAdmin),
      };
    }

    if (command === '/support' || command === 'menu:support') {
      return {
        chatId,
        parseMode: 'HTML',
        callbackQueryId,
        text: [
          '<b>پشتیبانی رسمی EDGE LICENSE CENTER</b>',
          `ربات رسمی: ${TELEGRAM_BOT_HANDLE}`,
          'برای ثبت تیکت مستقیم در سیستم از دستور زیر استفاده کنید:',
          '<code>/ticket موضوع | توضیحات و کد سفارش</code>',
        ].join('\n'),
        inlineKeyboard: this.mainMenuKeyboard(isAdmin),
      };
    }

    if (command === '/admin' || command === 'menu:admin') {
      if (!isAdmin) {
        return {
          chatId,
          parseMode: 'HTML',
          callbackQueryId,
          callbackToast: 'دسترسی غیرمجاز',
          text: 'دسترسی غیرمجاز: حساب شما دارای نقش ادمین فعال نیست.',
          inlineKeyboard: this.mainMenuKeyboard(false),
        };
      }
      return {
        chatId,
        parseMode: 'HTML',
        callbackQueryId,
        text: `<b>پنل مدیریت فعال است</b>\nنقش شما: <code>${admin?.role}</code>\nبرای مدیریت کامل از طریق Mini App وارد تب Admin شوید.`,
        inlineKeyboard: this.mainMenuKeyboard(true),
      };
    }

    return {
      chatId,
      parseMode: 'HTML',
      callbackQueryId,
      text: 'دستور شناخته‌شده نیست. لطفاً یکی از گزینه‌های منو را انتخاب کنید.',
      inlineKeyboard: this.mainMenuKeyboard(isAdmin),
    };
  }
}
