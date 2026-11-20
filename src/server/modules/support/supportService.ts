import crypto from 'crypto';
import type {
  NotificationChannel,
  NotificationRecord,
  SupportTicketRecord,
  TicketPriority,
  TicketStatus,
} from '../../../shared/types';
import { runImmediateTransaction, type SqliteDb } from '../../db/connection';
import { AuditService } from '../audit/auditService';

export class SupportService {
  private readonly audit: AuditService;

  constructor(private readonly db: SqliteDb) {
    this.audit = new AuditService(db);
  }

  createTicket(params: {
    userId: number;
    actorId: string;
    subject: string;
    message: string;
    orderId?: number | null;
    priority?: TicketPriority;
  }): SupportTicketRecord {
    const ticketCode = `TKT-${Date.now().toString(36).toUpperCase()}-${crypto
      .randomBytes(2)
      .toString('hex')
      .toUpperCase()}`;

    return runImmediateTransaction(this.db, () => {
      const res = this.db
        .prepare(
          `INSERT INTO support_tickets (ticket_code, user_id, order_id, subject, message, priority, status)
           VALUES (?, ?, ?, ?, ?, ?, 'open')`
        )
        .run(
          ticketCode,
          params.userId,
          params.orderId ?? null,
          params.subject.trim(),
          params.message.trim(),
          params.priority ?? 'normal'
        );
      const id = Number(res.lastInsertRowid);

      this.audit.record({
        actorType: 'user',
        actorId: params.actorId,
        action: 'SUPPORT_TICKET_CREATED',
        entityType: 'support_ticket',
        entityId: ticketCode,
        metadata: { priority: params.priority ?? 'normal' },
      });

      return this.db.prepare('SELECT * FROM support_tickets WHERE id = ?').get(id) as SupportTicketRecord;
    });
  }

  listUserTickets(userId: number): SupportTicketRecord[] {
    return this.db
      .prepare('SELECT * FROM support_tickets WHERE user_id = ? ORDER BY id DESC LIMIT 50')
      .all(userId) as SupportTicketRecord[];
  }

  listAllTickets(limit = 100): SupportTicketRecord[] {
    return this.db
      .prepare('SELECT * FROM support_tickets ORDER BY id DESC LIMIT ?')
      .all(limit) as SupportTicketRecord[];
  }

  replyAndUpdateTicket(params: {
    ticketId: number;
    status: TicketStatus;
    adminReply?: string;
    adminId: number;
    adminActorId: string;
  }): SupportTicketRecord {
    return runImmediateTransaction(this.db, () => {
      const existing = this.db
        .prepare('SELECT * FROM support_tickets WHERE id = ?')
        .get(params.ticketId) as SupportTicketRecord | undefined;
      if (!existing) {
        throw new Error('TICKET_NOT_FOUND');
      }

      const nowIso = new Date().toISOString();
      const closedAt = params.status === 'closed' || params.status === 'resolved' ? nowIso : null;

      this.db
        .prepare(
          `UPDATE support_tickets
           SET status = ?, admin_reply = COALESCE(?, admin_reply), assigned_admin_id = ?, closed_at = ?, updated_at = ?
           WHERE id = ?`
        )
        .run(
          params.status,
          params.adminReply ?? null,
          params.adminId,
          closedAt,
          nowIso,
          params.ticketId
        );

      this.queueNotification({
        userId: existing.user_id,
        channel: 'telegram_bot',
        type: 'SUPPORT_TICKET_UPDATED',
        title: `بروزرسانی تیکت ${existing.ticket_code}`,
        body: params.adminReply ?? `وضعیت تیکت شما به ${params.status} تغییر یافت.`,
      });

      this.audit.record({
        actorType: 'admin',
        actorId: params.adminActorId,
        action: 'SUPPORT_TICKET_UPDATED',
        entityType: 'support_ticket',
        entityId: existing.ticket_code,
        metadata: { previousStatus: existing.status, newStatus: params.status },
      });

      return this.db
        .prepare('SELECT * FROM support_tickets WHERE id = ?')
        .get(params.ticketId) as SupportTicketRecord;
    });
  }

  queueNotification(params: {
    userId: number;
    channel: NotificationChannel;
    type: string;
    title: string;
    body: string;
  }): NotificationRecord {
    const res = this.db
      .prepare(
        `INSERT INTO notifications (user_id, channel, type, title, body, status)
         VALUES (?, ?, ?, ?, ?, 'pending')`
      )
      .run(params.userId, params.channel, params.type, params.title, params.body);
    return this.db
      .prepare('SELECT * FROM notifications WHERE id = ?')
      .get(Number(res.lastInsertRowid)) as NotificationRecord;
  }

  listUserNotifications(userId: number, limit = 50): NotificationRecord[] {
    return this.db
      .prepare('SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT ?')
      .all(userId, limit) as NotificationRecord[];
  }
}
