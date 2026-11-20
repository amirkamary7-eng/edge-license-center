import type { NextFunction, Request, Response } from 'express';
import type { AuditService } from '../modules/audit/auditService';

export interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
  bucketName: string;
  enabled?: boolean;
  keyGenerator?: (req: Request) => string;
  audit?: AuditService;
}

interface BucketEntry {
  timestamps: number[];
}

/**
 * In-memory sliding-window rate limiter middleware for Express.
 * Emits standard Retry-After / X-RateLimit-* headers and logs abuse attempts to audit_logs.
 */
export function createRateLimiter(options: RateLimitOptions) {
  const store = new Map<string, BucketEntry>();
  let sweepCounter = 0;

  return (req: Request, res: Response, next: NextFunction) => {
    if (options.enabled === false) {
      next();
      return;
    }

    const now = Date.now();
    const cutoff = now - options.windowMs;
    const rawKey = options.keyGenerator
      ? options.keyGenerator(req)
      : req.authUser?.telegram_id ?? req.ip ?? 'unknown';
    const key = `${options.bucketName}:${rawKey}`;

    let entry = store.get(key);
    if (!entry) {
      entry = { timestamps: [] };
      store.set(key, entry);
    }

    // Prune timestamps outside sliding window
    while (entry.timestamps.length > 0 && entry.timestamps[0] <= cutoff) {
      entry.timestamps.shift();
    }

    if (entry.timestamps.length >= options.maxRequests) {
      const oldest = entry.timestamps[0] ?? now;
      const retryAfterSec = Math.max(1, Math.ceil((oldest + options.windowMs - now) / 1000));
      res.setHeader('Retry-After', String(retryAfterSec));
      res.setHeader('X-RateLimit-Limit', String(options.maxRequests));
      res.setHeader('X-RateLimit-Remaining', '0');

      options.audit?.record({
        actorType: req.authUser ? 'user' : 'system',
        actorId: req.authUser?.telegram_id ?? req.ip ?? 'anonymous',
        action: 'RATE_LIMIT_EXCEEDED',
        entityType: 'rate_limit',
        entityId: options.bucketName,
        severity: 'warning',
        metadata: { path: req.path, limit: options.maxRequests, windowMs: options.windowMs },
        ipAddress: req.ip,
      });

      res.status(429).json({
        error: 'RATE_LIMIT_EXCEEDED',
        retryAfterSeconds: retryAfterSec,
      });
      return;
    }

    entry.timestamps.push(now);
    res.setHeader('X-RateLimit-Limit', String(options.maxRequests));
    res.setHeader('X-RateLimit-Remaining', String(Math.max(0, options.maxRequests - entry.timestamps.length)));

    // Periodic lazy sweep to bound memory usage
    sweepCounter += 1;
    if (sweepCounter % 500 === 0) {
      for (const [k, v] of store.entries()) {
        if (v.timestamps.length === 0 || v.timestamps[v.timestamps.length - 1] <= cutoff) {
          store.delete(k);
        }
      }
    }

    next();
  };
}
