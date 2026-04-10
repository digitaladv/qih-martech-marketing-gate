import type { Hono } from "hono";
import { parseSession } from "./auth.js";
import { CONFIG } from "./config.js";
import { auditLog } from "./security.js";
import { isApiExempt, isHostProtected, registerHost } from "./store.js";

const AUTH_HOST = new URL(CONFIG.SERVER_URL).hostname;

// Derive the expected domain suffix from COOKIE_DOMAIN or SERVER_URL
// e.g. ".marketing.qih-tech.com" → "marketing.qih-tech.com"
const EXPECTED_DOMAIN = CONFIG.COOKIE_DOMAIN
  ? CONFIG.COOKIE_DOMAIN.replace(/^\./, "")
  : new URL(CONFIG.SERVER_URL).hostname;

/** Normalise host: strip www. prefix */
function normaliseHost(raw: string): string {
  return raw.startsWith("www.") ? raw.slice(4) : raw;
}

/** Only auto-discover hosts under the expected domain */
function isOwnDomain(host: string): boolean {
  return host === EXPECTED_DOMAIN || host.endsWith(`.${EXPECTED_DOMAIN}`);
}

// Cap auto-discovered hosts to prevent store flooding via crafted headers
const MAX_AUTO_DISCOVERED = 200;
let autoDiscoveredCount = 0;

export function setupVerifyRoute(app: Hono) {
  app.get("/verify", async (c) => {
    const rawHost = (c.req.header("x-forwarded-host") || "")
      .split(":")[0]
      .toLowerCase();
    const host = normaliseHost(rawHost);
    const proto = c.req.header("x-forwarded-proto") || "https";
    const uri = c.req.header("x-forwarded-uri") || "/";

    // Always pass the auth host itself (prevents login page auth loop)
    if (host === AUTH_HOST) {
      return c.text("OK", 200);
    }

    // Check admin-managed API exemptions (replaces blanket /api/ bypass)
    if (isApiExempt(host, uri)) {
      return c.text("OK", 200);
    }

    // Check if host is known and its protection status
    const status = isHostProtected(host);

    // Unknown host → auto-register only if it belongs to our domain
    if (!status.known && host) {
      if (!isOwnDomain(host)) {
        auditLog("host_rejected_foreign", { host, rawHost });
        return c.text("Forbidden", 403);
      }
      if (autoDiscoveredCount < MAX_AUTO_DISCOVERED) {
        registerHost(host);
        autoDiscoveredCount++;
        auditLog("host_discovered", { host });
      } else {
        auditLog("host_discovery_capped", { host });
      }
    }

    // Host is open (not protected) → pass through
    if (status.known && !status.protected) {
      return c.text("OK", 200);
    }

    // Host is protected → check session cookie
    const session = await parseSession(c);

    if (session) {
      c.header("X-Auth-User", session.email);
      return c.text("OK", 200);
    }

    // No valid session → redirect to login
    const originalUrl = `${proto}://${host}${uri}`;
    const loginUrl = `${CONFIG.SERVER_URL}/auth/login?redirect=${encodeURIComponent(originalUrl)}`;
    return c.redirect(loginUrl, 302);
  });
}
