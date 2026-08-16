import "server-only";

import { and, eq, inArray, isNull, lte, or, sql } from "drizzle-orm";
import { db } from "../../db/client.js";
import { notificationDeliveries } from "../../db/schema.js";

export const MAX_DELIVERY_ATTEMPTS = 5;

export function nextRetryAt(attemptCount, now = new Date()) {
  const attempt = Math.max(1, Number(attemptCount || 1));
  const baseSeconds = Math.min(300, 2 ** attempt * 15);
  const jitterSeconds = Math.floor(Math.random() * 10);
  return new Date(now.getTime() + (baseSeconds + jitterSeconds) * 1000);
}

export function classifyDeliveryResult(result, attemptCount, maxAttempts = MAX_DELIVERY_ATTEMPTS) {
  if (result.ok) {
    return { status: "delivered", retry: false };
  }

  if (!result.retryable) {
    return { status: result.errorCode === "blocked_destination" ? "blocked" : "failed", retry: false };
  }

  return attemptCount >= maxAttempts
    ? { status: "failed", retry: false }
    : { status: "retry", retry: true };
}

export async function claimPendingDeliveries({
  database = db(),
  limit = 10,
  now = new Date(),
} = {}) {
  const boundedLimit = Math.min(Math.max(Number(limit) || 10, 1), 50);

  return database.transaction(async (tx) => {
    const rows = await tx.execute(sql`
      update notification_deliveries
      set status = 'claimed',
          claimed_at = ${now},
          updated_at = ${now}
      where id in (
        select id
        from notification_deliveries
        where status in ('pending', 'retry')
          and (next_attempt_at is null or next_attempt_at <= ${now})
        order by created_at asc
        limit ${boundedLimit}
        for update skip locked
      )
      returning *
    `);

    return rows.rows || rows;
  });
}

export async function markDeliveryResult({
  database = db(),
  delivery,
  result,
  now = new Date(),
} = {}) {
  const attemptCount = Number(delivery.attemptCount || delivery.attempt_count || 0) + 1;
  const maxAttempts = Number(delivery.maxAttempts || delivery.max_attempts || MAX_DELIVERY_ATTEMPTS);
  const classified = classifyDeliveryResult(result, attemptCount, maxAttempts);

  const [updated] = await database
    .update(notificationDeliveries)
    .set({
      status: classified.status,
      attemptCount,
      responseStatus: result.status,
      lastErrorCode: result.errorCode,
      nextAttemptAt: classified.retry ? nextRetryAt(attemptCount, now) : null,
      deliveredAt: classified.status === "delivered" ? now : null,
      updatedAt: now,
    })
    .where(eq(notificationDeliveries.id, delivery.id))
    .returning();

  return updated;
}

export function pendingDeliveryPredicate(now = new Date()) {
  return and(
    inArray(notificationDeliveries.status, ["pending", "retry"]),
    or(isNull(notificationDeliveries.nextAttemptAt), lte(notificationDeliveries.nextAttemptAt, now)),
  );
}
