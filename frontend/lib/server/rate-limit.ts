import { getClientIp } from "@/lib/server/request-security";

declare global {
  // eslint-disable-next-line no-var
  var __ghostRateLimitStore: Map<string, number[]> | undefined;
}

function getStore() {
  if (!global.__ghostRateLimitStore) {
    global.__ghostRateLimitStore = new Map();
  }

  return global.__ghostRateLimitStore;
}

function compactWindow(now: number, windowMs: number, hits: number[]) {
  return hits.filter((timestamp) => now - timestamp < windowMs);
}

export function rateLimitKey(
  request: Request,
  bucket: string,
  subject?: string,
) {
  const ip = getClientIp(request);
  const normalizedSubject = subject?.trim().toLowerCase() || "anonymous";
  return `${bucket}:${ip}:${normalizedSubject}`;
}

export function consumeRateLimit(
  key: string,
  limit: number,
  windowMs: number,
) {
  const now = Date.now();
  const store = getStore();
  const activeHits = compactWindow(now, windowMs, store.get(key) ?? []);

  if (activeHits.length >= limit) {
    const retryAfterMs = windowMs - (now - activeHits[0]);
    store.set(key, activeHits);
    return { allowed: false, retryAfterMs };
  }

  activeHits.push(now);
  store.set(key, activeHits);
  return { allowed: true, retryAfterMs: 0 };
}

export function rateLimitResponse(retryAfterMs: number, message: string) {
  const retryAfterSeconds = Math.max(1, Math.ceil(retryAfterMs / 1000));
  return Response.json(
    { error: message },
    {
      status: 429,
      headers: { "Retry-After": String(retryAfterSeconds) },
    },
  );
}
