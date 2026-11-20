export interface TelegramInlineKeyboardButton {
  text: string;
  callback_data?: string;
  web_app?: { url: string };
}

export interface SendMessageParams {
  chatId: number;
  text: string;
  parseMode?: 'HTML';
  inlineKeyboard?: TelegramInlineKeyboardButton[][];
}

export interface AnswerCallbackQueryParams {
  callbackQueryId: string;
  text?: string;
  showAlert?: boolean;
}

export interface TelegramBotTransport {
  sendMessage(params: SendMessageParams): Promise<{ ok: boolean; messageId?: number }>;
  answerCallbackQuery(params: AnswerCallbackQueryParams): Promise<{ ok: boolean }>;
}

/**
 * Official Telegram Bot API HTTP client supporting `sendMessage` and `answerCallbackQuery`.
 * Accepts an injectable `fetchImpl` so tests can verify real API calls without network I/O.
 */
export class TelegramBotApiClient implements TelegramBotTransport {
  private readonly baseUrl: string;

  constructor(
    private readonly botToken: string,
    private readonly options?: {
      apiRoot?: string;
      timeoutMs?: number;
      fetchImpl?: typeof fetch;
    }
  ) {
    const root = (options?.apiRoot ?? 'https://api.telegram.org').replace(/\/$/, '');
    this.baseUrl = `${root}/bot${botToken}`;
  }

  private async postJson<T>(method: string, payload: Record<string, unknown>): Promise<T> {
    if (!this.botToken.trim()) {
      throw new Error('TELEGRAM_BOT_TOKEN_NOT_CONFIGURED');
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.options?.timeoutMs ?? 8000);
    const fetcher = this.options?.fetchImpl ?? fetch;

    try {
      const res = await fetcher(`${this.baseUrl}/${method}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      const data = (await res.json().catch(() => ({}))) as {
        ok?: boolean;
        description?: string;
        result?: unknown;
      };

      if (!res.ok || !data.ok) {
        throw new Error(`TELEGRAM_API_ERROR_${method}_${res.status}`);
      }
      return data as T;
    } finally {
      clearTimeout(timer);
    }
  }

  async sendMessage(params: SendMessageParams): Promise<{ ok: boolean; messageId?: number }> {
    const body: Record<string, unknown> = {
      chat_id: params.chatId,
      text: params.text,
      parse_mode: params.parseMode ?? 'HTML',
    };
    if (params.inlineKeyboard && params.inlineKeyboard.length > 0) {
      body.reply_markup = { inline_keyboard: params.inlineKeyboard };
    }

    const res = await this.postJson<{ ok: boolean; result?: { message_id?: number } }>(
      'sendMessage',
      body
    );
    return { ok: true, messageId: res.result?.message_id };
  }

  async answerCallbackQuery(params: AnswerCallbackQueryParams): Promise<{ ok: boolean }> {
    await this.postJson<{ ok: boolean }>('answerCallbackQuery', {
      callback_query_id: params.callbackQueryId,
      text: params.text,
      show_alert: params.showAlert ?? false,
    });
    return { ok: true };
  }
}
