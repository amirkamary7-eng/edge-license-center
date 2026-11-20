/**
 * @EDGE_LicenceBot Native Cloudflare Worker Telegram Webhook & Command Router (Path B-1)
 * - Fail-closed X-Telegram-Bot-Api-Secret-Token verification (constant-time SHA-256 digest compare)
 * - D1 idempotency deduplication on Telegram update_id
 * - Strictly respects TELEGRAM_BOT_SEND_ENABLED=true before sending outbound Bot API calls
 */

import { randomHex, timingSafeEqualStrings } from './crypto';
import { DOMAIN_CONSTANTS, type D1Database, type WorkerEnv } from './d1Types';
import {
  claimSingleUseKey,
  createOrderD1,
  formatMicroUsdc,
  recordAuditLog,
  submitTransactionHashD1,
  upsertUserFromTelegram,
  type D1AdminRow,
  type D1OrderRow,
  type D1PaymentRow,
  type D1PlanRow,
} from './ordersAndPayments';

export interface TelegramInlineKeyboardButton {
  text: string;
  callback_data?: string;
  web_app?: { url: string };
}

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

export function normalizeBotCommand(rawToken: string): string {
  const token = rawToken.trim();
  if (!token.startsWith('/')) return token;
  const atIdx = token.indexOf('@');
  if (atIdx === -1) return token.toLowerCase();
  const cmd = token.slice(0, atIdx).toLowerCase();
  const target = token.slice(atIdx + 1).toLowerCase();
  if (target === DOMAIN_CONSTANTS.botUsername.toLowerCase()) {
    return cmd;
  }
  return token.toLowerCase();
}

export class WorkerTelegramBotClient {
  constructor(
    private readonly botToken: string,
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly apiRoot = 'https://api.telegram.org'
  ) {}

  private async postJson<T>(method: string, body: Record<string, unknown>): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const res = await this.fetchImpl(`${this.apiRoot}/bot${this.botToken}/${method}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      const json = (await res.json()) as { ok: boolean; result?: T; description?: string };
      if (!res.ok || !json.ok) {
        throw new Error(`TELEGRAM_BOT_API_ERROR: ${json.description ?? res.status}`);
      }
      return json.result as T;
    } finally {
      clearTimeout(timer);
    }
  }

  async sendMessage(params: {
    chatId: number;
    text: string;
    parseMode?: 'HTML';
    inlineKeyboard?: TelegramInlineKeyboardButton[][];
  }): Promise<{ ok: boolean; messageId?: number }> {
    const res = await this.postJson<{ message_id?: number }>('sendMessage', {
      chat_id: params.chatId,
      text: params.text,
      parse_mode: params.parseMode ?? 'HTML',
      disable_web_page_preview: true,
      ...(params.inlineKeyboard && params.inlineKeyboard.length > 0
        ? { reply_markup: { inline_keyboard: params.inlineKeyboard } }
        : {}),
    });
    return { ok: true, messageId: res?.message_id };
  }

  async answerCallbackQuery(params: { callbackQueryId: string; text?: string }): Promise<{ ok: boolean }> {
    await this.postJson('answerCallbackQuery', {
      callback_query_id: params.callbackQueryId,
      ...(params.text ? { text: params.text } : {}),
    });
    return { ok: true };
  }
}

function mainMenuKeyboard(miniAppUrl: string, isAdmin: boolean): TelegramInlineKeyboardButton[][] {
  const rows: TelegramInlineKeyboardButton[][] = [];
  if (miniAppUrl.startsWith('https://')) {
    rows.push([{ text: '🚀 باز کردن پنل Mini App', web_app: { url: miniAppUrl } }]);
  }
  rows.push(
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
    ]
  );
  if (isAdmin) {
    rows.push([{ text: '🛡 بخش مدیریت (Admin)', callback_data: 'menu:admin' }]);
  }
  return rows;
}

export async function routeTelegramUpdateD1(
  db: D1Database,
  env: WorkerEnv,
  update: TelegramUpdate
): Promise<BotReplyPayload | null> {
  const actor = update.message?.from ?? update.callback_query?.from;
  if (!actor) return null;

  const chatId = update.message?.chat.id ?? actor.id;
  const callbackQueryId = update.callback_query?.id;
  const miniAppUrl = env.MINI_APP_URL ?? '';

  const user = await upsertUserFromTelegram(db, {
    telegramId: String(actor.id),
    username: actor.username ?? null,
    firstName: actor.first_name,
    lastName: actor.last_name ?? null,
    languageCode: actor.language_code ?? 'fa',
  });

  if (user.status !== 'active') {
    await recordAuditLog(db, {
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

  const admin = await db
    .prepare(`SELECT * FROM admins WHERE telegram_id = ? AND is_active = 1`)
    .bind(user.telegram_id)
    .first<D1AdminRow>();
  const isAdmin = Boolean(admin);

  const rawInput = (update.message?.text ?? update.callback_query?.data ?? '').trim();
  const [rawCommand = '', ...args] = rawInput.split(/\s+/);
  const command = normalizeBotCommand(rawCommand);

  await recordAuditLog(db, {
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
        `<b>${DOMAIN_CONSTANTS.brandName} by ${DOMAIN_CONSTANTS.brandOwner}</b>`,
        `ربات رسمی فروش، پرداخت و مدیریت لایسنس اپلیکیشن EDGE (${DOMAIN_CONSTANTS.botHandle})`,
        '',
        `• شبکه پرداخت: <b>${DOMAIN_CONSTANTS.networkName}</b>`,
        `• ارز رسمی: <b>Native USDC</b>`,
        '',
        'از منوی زیر گزینه موردنظر را انتخاب کنید یا Mini App را باز کنید:',
      ].join('\n'),
      inlineKeyboard: mainMenuKeyboard(miniAppUrl, isAdmin),
    };
  }

  if (command === '/plans' || command === '/buy' || command === 'menu:plans') {
    const plansRes = await db
      .prepare(`SELECT * FROM plans WHERE is_active = 1 ORDER BY sort_order ASC`)
      .all<D1PlanRow>();
    const activePlans = plansRes.results ?? [];
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
        `قرارداد رسمی Native USDC:\n<code>${DOMAIN_CONSTANTS.usdcContractAddress}</code>`,
        `آدرس کیف پول مقصد:\n<code>${DOMAIN_CONSTANTS.destinationWalletAddress}</code>`,
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
    const subsRes = await db
      .prepare(`SELECT id, status, expires_at FROM subscriptions WHERE user_id = ? ORDER BY id DESC`)
      .bind(user.id)
      .all<{ id: number; status: string; expires_at: string }>();
    const subs = subsRes.results ?? [];
    const activeSub = subs.find((s) => s.status === 'active') ?? subs[0];
    const plansRes = await db
      .prepare(`SELECT * FROM plans WHERE is_active = 1 ORDER BY sort_order ASC`)
      .all<D1PlanRow>();
    const activePlans = plansRes.results ?? [];
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

  if (command.startsWith('buy:') || command.startsWith('renew:') || command.startsWith('upgrade:')) {
    const [actionType, planCode] = command.split(':');
    try {
      const subsRes = await db
        .prepare(`SELECT id, status FROM subscriptions WHERE user_id = ? ORDER BY id DESC`)
        .bind(user.id)
        .all<{ id: number; status: string }>();
      const targetSub = (subsRes.results ?? []).find((s) => s.status === 'active') ?? subsRes.results?.[0];
      const orderType = actionType === 'renew' ? 'renew' : actionType === 'upgrade' ? 'upgrade' : 'new';

      const order = await createOrderD1(db, env, {
        userId: user.id,
        planCode: planCode.toUpperCase(),
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
          `شبکه: <b>${DOMAIN_CONSTANTS.networkName}</b>`,
          `آدرس مقصد: <code>${order.destination_wallet}</code>`,
          `مهلت پرداخت تا: <code>${order.expires_at.slice(0, 19).replace('T', ' ')} UTC</code>`,
          '',
          `پس از واریز، هش تراکنش را ارسال کنید:`,
          `<code>/tx ${order.order_code} 0x...</code>`,
        ].join('\n'),
        inlineKeyboard: mainMenuKeyboard(miniAppUrl, isAdmin),
      };
    } catch (err) {
      return {
        chatId,
        parseMode: 'HTML',
        callbackQueryId,
        callbackToast: 'خطا در ایجاد سفارش',
        text: `امکان ثبت سفارش وجود ندارد: <b>${(err as Error).message}</b>`,
        inlineKeyboard: mainMenuKeyboard(miniAppUrl, isAdmin),
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
        inlineKeyboard: mainMenuKeyboard(miniAppUrl, isAdmin),
      };
    }
    const [orderCode, txHash] = args;
    try {
      const result = await submitTransactionHashD1(db, env, {
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
        inlineKeyboard: mainMenuKeyboard(miniAppUrl, isAdmin),
      };
    } catch (err) {
      return {
        chatId,
        parseMode: 'HTML',
        callbackQueryId,
        text: `خطا در ثبت تراکنش: <b>${(err as Error).message}</b>`,
        inlineKeyboard: mainMenuKeyboard(miniAppUrl, isAdmin),
      };
    }
  }

  if (command === '/orders' || command === '/status' || command === 'menu:orders') {
    const ordersRes = await db
      .prepare(`SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC LIMIT 5`)
      .bind(user.id)
      .all<D1OrderRow>();
    const paysRes = await db
      .prepare(`SELECT * FROM payments WHERE user_id = ? ORDER BY id DESC LIMIT 10`)
      .bind(user.id)
      .all<D1PaymentRow>();
    const orders = ordersRes.results ?? [];
    const payments = paysRes.results ?? [];

    const body =
      orders.length === 0
        ? 'هنوز سفارشی ثبت نشده است.'
        : orders
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
      inlineKeyboard: mainMenuKeyboard(miniAppUrl, isAdmin),
    };
  }

  if (command === '/license' || command === '/licenses') {
    const licRes = await db
      .prepare(`SELECT license_key, status, expires_at FROM licenses WHERE user_id = ? ORDER BY id DESC LIMIT 5`)
      .bind(user.id)
      .all<{ license_key: string; status: string; expires_at: string }>();
    const licenses = licRes.results ?? [];
    const body =
      licenses.length === 0
        ? 'هنوز لایسنس فعالی برای حساب شما صادر نشده است.'
        : licenses
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
      inlineKeyboard: mainMenuKeyboard(miniAppUrl, isAdmin),
    };
  }

  if (command === '/profile' || command === 'menu:profile') {
    const cntRow = await db
      .prepare(`SELECT COUNT(*) AS cnt FROM licenses WHERE user_id = ?`)
      .bind(user.id)
      .first<{ cnt: number }>();
    return {
      chatId,
      parseMode: 'HTML',
      callbackQueryId,
      text: [
        '<b>پروفایل کاربری</b>',
        `شناسه تلگرام: <code>${user.telegram_id}</code>`,
        `نام: ${user.first_name}`,
        `تعداد لایسنس‌ها: <b>${cntRow?.cnt ?? 0}</b>`,
        `نقش کاربری: <b>${admin ? admin.role : 'customer'}</b>`,
      ].join('\n'),
      inlineKeyboard: mainMenuKeyboard(miniAppUrl, isAdmin),
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
        inlineKeyboard: mainMenuKeyboard(miniAppUrl, isAdmin),
      };
    }
    const ticketCode = `TKT-${Date.now().toString(36).toUpperCase()}-${randomHex(2).toUpperCase()}`;
    await db
      .prepare(
        `INSERT INTO support_tickets (ticket_code, user_id, subject, message, status, priority)
         VALUES (?, ?, ?, ?, 'open', 'normal')`
      )
      .bind(ticketCode, user.id, subjectPart.slice(0, 120), messagePart.slice(0, 2000))
      .run();
    return {
      chatId,
      parseMode: 'HTML',
      callbackQueryId,
      text: `<b>تیکت پشتیبانی ثبت شد</b>\nکد پیگیری: <code>${ticketCode}</code>\nوضعیت: <b>open</b>`,
      inlineKeyboard: mainMenuKeyboard(miniAppUrl, isAdmin),
    };
  }

  if (command === '/support' || command === 'menu:support') {
    return {
      chatId,
      parseMode: 'HTML',
      callbackQueryId,
      text: [
        '<b>پشتیبانی رسمی EDGE LICENSE CENTER</b>',
        `ربات رسمی: ${DOMAIN_CONSTANTS.botHandle}`,
        'برای ثبت تیکت مستقیم در سیستم از دستور زیر استفاده کنید:',
        '<code>/ticket موضوع | توضیحات و کد سفارش</code>',
      ].join('\n'),
      inlineKeyboard: mainMenuKeyboard(miniAppUrl, isAdmin),
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
        inlineKeyboard: mainMenuKeyboard(miniAppUrl, false),
      };
    }
    return {
      chatId,
      parseMode: 'HTML',
      callbackQueryId,
      text: `<b>پنل مدیریت فعال است</b>\nنقش شما: <code>${admin?.role}</code>\nبرای مدیریت کامل از طریق Mini App وارد تب Admin شوید.`,
      inlineKeyboard: mainMenuKeyboard(miniAppUrl, true),
    };
  }

  return {
    chatId,
    parseMode: 'HTML',
    callbackQueryId,
    text: 'دستور شناخته‌شده نیست. لطفاً یکی از گزینه‌های منو را انتخاب کنید.',
    inlineKeyboard: mainMenuKeyboard(miniAppUrl, isAdmin),
  };
}

export async function handleTelegramWebhookWorker(
  request: Request,
  db: D1Database,
  env: WorkerEnv,
  clientIp: string
): Promise<{ status: number; body: Record<string, unknown> }> {
  const expectedSecret = env.TELEGRAM_WEBHOOK_SECRET?.trim() ?? '';
  if (!expectedSecret) {
    await recordAuditLog(db, {
      actorType: 'system',
      actorId: 'bot_webhook',
      action: 'WEBHOOK_SECRET_MISSING_BLOCKED',
      entityType: 'security',
      severity: 'critical',
      ipAddress: clientIp,
    });
    return { status: 503, body: { error: 'WEBHOOK_SECRET_NOT_CONFIGURED' } };
  }

  const providedSecret = request.headers.get('X-Telegram-Bot-Api-Secret-Token') ?? '';
  if (!providedSecret || !(await timingSafeEqualStrings(providedSecret, expectedSecret))) {
    await recordAuditLog(db, {
      actorType: 'system',
      actorId: 'bot_webhook',
      action: 'WEBHOOK_INVALID_SECRET',
      entityType: 'security',
      severity: 'warning',
      ipAddress: clientIp,
    });
    return { status: 401, body: { error: 'INVALID_WEBHOOK_SECRET' } };
  }

  const update = (await request.json().catch(() => null)) as TelegramUpdate | null;
  if (!update || typeof update.update_id !== 'number' || !Number.isInteger(update.update_id)) {
    return { status: 400, body: { error: 'INVALID_TELEGRAM_UPDATE' } };
  }

  const claimed = await claimSingleUseKey(db, {
    scope: 'telegram_bot_update',
    key: String(update.update_id),
    actorId: String(update.message?.from?.id ?? update.callback_query?.from?.id ?? 'unknown'),
    ttlSeconds: 86400,
  });

  if (!claimed) {
    return { status: 200, body: { ok: true, duplicate: true, updateId: update.update_id } };
  }

  const reply = await routeTelegramUpdateD1(db, env, update);
  let dispatched = false;
  const sendEnabled = env.TELEGRAM_BOT_SEND_ENABLED === 'true';

  if (reply && sendEnabled && env.TELEGRAM_BOT_TOKEN) {
    const botClient = new WorkerTelegramBotClient(env.TELEGRAM_BOT_TOKEN, env.FETCH_IMPL ?? fetch);
    try {
      if (reply.callbackQueryId) {
        await botClient.answerCallbackQuery({
          callbackQueryId: reply.callbackQueryId,
          text: reply.callbackToast,
        });
      }
      await botClient.sendMessage({
        chatId: reply.chatId,
        text: reply.text,
        parseMode: reply.parseMode,
        inlineKeyboard: reply.inlineKeyboard,
      });
      dispatched = true;
    } catch (err) {
      await recordAuditLog(db, {
        actorType: 'bot',
        actorId: String(reply.chatId),
        action: 'BOT_API_DISPATCH_FAILED',
        entityType: 'telegram_update',
        entityId: String(update.update_id),
        severity: 'warning',
        metadata: { reason: err instanceof Error ? err.message : 'DISPATCH_ERROR' },
      });
    }
  }

  return {
    status: 200,
    body: { ok: true, duplicate: false, dispatched, reply },
  };
}
