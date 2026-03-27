import type { MiddlewareHandler } from "hono";
import { CONFIG } from "./config.js";

export const securityHeaders: MiddlewareHandler = async (c, next) => {
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
  c.header("X-XSS-Protection", "1; mode=block");
  c.header("Referrer-Policy", "strict-origin-when-cross-origin");
  c.header("Cache-Control", "no-store");
  c.header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'");
  if (c.req.url.startsWith("https")) {
    c.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  await next();
};

// Block cross-origin mutation requests (CSRF protection)
export const originCheck: MiddlewareHandler = async (c, next) => {
  const method = c.req.method;
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
    return next();
  }
  const origin = c.req.header("origin");
  const referer = c.req.header("referer");
  const allowed = CONFIG.SERVER_URL;
  if (origin && !origin.startsWith(allowed)) {
    auditLog("csrf_blocked", { origin, method, path: c.req.path });
    return c.text("Forbidden", 403);
  }
  if (!origin && referer && !referer.startsWith(allowed)) {
    auditLog("csrf_blocked", { referer, method, path: c.req.path });
    return c.text("Forbidden", 403);
  }
  await next();
};

interface RateEntry {
  count: number;
  resetAt: number;
}

const rateMaps = new Map<string, Map<string, RateEntry>>();

export function rateLimit(max: number, windowMs: number): MiddlewareHandler {
  const key = `${max}-${windowMs}`;
  if (!rateMaps.has(key)) rateMaps.set(key, new Map());
  const store = rateMaps.get(key)!;

  setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of store) {
      if (entry.resetAt < now) store.delete(ip);
    }
  }, 300_000);

  return async (c, next) => {
    const ip = c.req.header("x-forwarded-for")?.split(",")[0]?.trim()
      || c.req.header("x-real-ip")
      || "unknown";
    const now = Date.now();
    const entry = store.get(ip);

    if (!entry || entry.resetAt < now) {
      store.set(ip, { count: 1, resetAt: now + windowMs });
    } else {
      entry.count++;
      if (entry.count > max) {
        return c.text("Too Many Requests", 429);
      }
    }
    await next();
  };
}

export function auditLog(event: string, details: Record<string, unknown> = {}) {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    event,
    ...details,
  }));
}
