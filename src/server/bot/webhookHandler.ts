import crypto from 'crypto';
import type { Request, Response } from 'express';
import type { AuditService } from '../modules/audit/auditService';
import type { IdempotencyStore } from '../security/idempotency';
import { EdgeBotRouter, type TelegramUpdate } from './commands';
import type { TelegramBotTransport } from './telegramClient';

export function verifyWebhookSecretToken(
  providedHeader: string | undefined,
  expectedSecret: string
): boolean {
  if (!expectedSecret || !expectedSecret.trim()) return false;
  if (!providedHeader || !providedHeader.trim()) return false;
  const a = Buffer.from(providedHeader, 'utf8');
  const b = Buffer.from(expectedSecret, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export interface WebhookHandlerOptions {
  botRouter: EdgeBotRouter;
  webhookSecret: string;
  idempotency: IdempotencyStore;
  audit: AuditService;
  botClient?: TelegramBotTransport;
  sendRepliesViaApi?: boolean;
}

/**
 * Fail-closed Telegram Webhook Handler:
 * 1. Rejects with 503 if `TELEGRAM_WEBHOOK_SECRET` is unset (never fail-open).
 * 2. Rejects with 401 on invalid/missing `X-Telegram-Bot-Api-Secret-Token`.
 * 3. Deduplicates Telegram `update_id` via SQLite `idempotency_records`.
 * 4. Dispatches `answerCallbackQuery` & `sendMessage` via `TelegramBotApiClient` when enabled.
 */
export function createTelegramWebhookHandler(options: WebhookHandlerOptions) {
  return async (req: Request, res: Response) => {
    if (!options.webhookSecret || !options.webhookSecret.trim()) {
      options.audit.record({
        actorType: 'system',
        actorId: 'bot_webhook',
        action: 'WEBHOOK_SECRET_MISSING_BLOCKED',
        entityType: 'security',
        severity: 'critical',
        ipAddress: req.ip,
      });
      res.status(503).json({ error: 'WEBHOOK_SECRET_NOT_CONFIGURED' });
      return;
    }

    const secretHeader = req.header('x-telegram-bot-api-secret-token');
    if (!verifyWebhookSecretToken(secretHeader, options.webhookSecret)) {
      options.audit.record({
        actorType: 'system',
        actorId: 'bot_webhook',
        action: 'WEBHOOK_INVALID_SECRET',
        entityType: 'security',
        severity: 'warning',
        ipAddress: req.ip,
      });
      res.status(401).json({ error: 'INVALID_WEBHOOK_SECRET' });
      return;
    }

    const update = req.body as TelegramUpdate;
    if (!update || typeof update.update_id !== 'number' || !Number.isInteger(update.update_id)) {
      res.status(400).json({ error: 'INVALID_TELEGRAM_UPDATE' });
      return;
    }

    // Deduplicate retried webhook deliveries using SQLite idempotency_records
    const claimed = options.idempotency.claimOnce({
      scope: 'telegram_bot_update',
      key: String(update.update_id),
      actorId: String(update.message?.from?.id ?? update.callback_query?.from?.id ?? 'unknown'),
      ttlSeconds: 86400,
    });

    if (!claimed) {
      res.status(200).json({
        ok: true,
        duplicate: true,
        updateId: update.update_id,
      });
      return;
    }

    const reply = options.botRouter.handleUpdate(update);
    let dispatched = false;

    if (reply && options.sendRepliesViaApi && options.botClient) {
      try {
        if (reply.callbackQueryId) {
          await options.botClient.answerCallbackQuery({
            callbackQueryId: reply.callbackQueryId,
            text: reply.callbackToast,
          });
        }
        await options.botClient.sendMessage({
          chatId: reply.chatId,
          text: reply.text,
          parseMode: reply.parseMode,
          inlineKeyboard: reply.inlineKeyboard,
        });
        dispatched = true;
      } catch (err) {
        options.audit.record({
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

    res.status(200).json({
      ok: true,
      duplicate: false,
      dispatched,
      reply,
    });
  };
}
