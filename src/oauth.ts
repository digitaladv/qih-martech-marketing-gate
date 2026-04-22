import crypto from "node:crypto";
import type { Hono } from "hono";
import { sign } from "hono/jwt";
import { parseSession } from "./auth.js";
import { CONFIG } from "./config.js";
import { MCP_TOKEN_AUDIENCE, MCP_TOKEN_TTL_SECONDS } from "./mcp-token.js";
import { auditLog } from "./security.js";
import { getOAuthClient, getUser, isRedirectUriAllowed } from "./store.js";

/** Lifetime of an issued authorization code. */
export const AUTH_CODE_TTL_SECONDS = 60;

/** Single-use authorization code record. */
interface AuthCodeEntry {
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  email: string;
  name: string | null;
  expires_at: number;
  used: boolean;
}

/**
 * In-memory store of issued authorization codes.
 * Single-process QG (one replica) — no need for shared storage.
 * Exposed so tests can reset between cases.
 */
export const authCodes = new Map<string, AuthCodeEntry>();

/** Sweep expired codes. Runs every 30s in production. */
export function sweepExpiredCodes(now: number = Date.now() / 1000) {
  for (const [code, entry] of authCodes) {
    if (entry.expires_at < now) authCodes.delete(code);
  }
}

/** Background cleanup — only started from index.ts, not from tests. */
let cleanupTimer: NodeJS.Timeout | null = null;
export function startCodeCleanup() {
  if (cleanupTimer) return;
  cleanupTimer = setInterval(() => sweepExpiredCodes(), 30_000);
}

function appendQuery(url: string, params: Record<string, string>): string {
  const u = new URL(url);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  return u.toString();
}

function base64UrlFromBuffer(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Validate a PKCE verifier against the stored challenge (S256 only).
 * Per RFC 7636: challenge = base64url(sha256(verifier)), no padding.
 */
export function verifyPkceS256(verifier: string, challenge: string): boolean {
  const computed = base64UrlFromBuffer(
    crypto.createHash("sha256").update(verifier).digest(),
  );
  // Constant-time compare
  if (computed.length !== challenge.length) return false;
  return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(challenge));
}

interface McpTokenPayload {
  sub: string;
  name: string | null;
  aud: string;
  iss: string;
  iat: number;
  exp: number;
  [key: string]: unknown;
}

/**
 * Sign an MCP access token. Same shape as /auth/mcp-token bridge tokens so
 * the MCP server has a single verify path. Kept local (rather than imported)
 * to avoid a circular import — the bridge module imports this flow's types.
 */
async function signAccessToken(
  email: string,
  name: string | null,
): Promise<{ token: string; payload: McpTokenPayload }> {
  const now = Math.floor(Date.now() / 1000);
  const payload: McpTokenPayload = {
    sub: email,
    name,
    aud: MCP_TOKEN_AUDIENCE,
    iss: CONFIG.SERVER_URL,
    iat: now,
    exp: now + MCP_TOKEN_TTL_SECONDS,
  };
  const token = await sign(payload, CONFIG.JWT_SECRET);
  return { token, payload };
}

/**
 * RFC 6749 §5.2-style error response. Generic errors on /token by design —
 * don't leak which specific check failed (client_id vs redirect_uri vs PKCE).
 */
function oauthErrorJson(
  error: string,
  description: string,
): { error: string; error_description: string } {
  return { error, error_description: description };
}

export function setupOAuthRoutes(app: Hono) {
  /**
   * `GET /oauth/authorize` — start the authorization code flow.
   *
   * Validates client_id, redirect_uri, S256 PKCE, state presence, then either
   * (a) redirects to /auth/login wrapping this URL, or
   * (b) mints a code and 302s back to the client's redirect_uri.
   *
   * Errors before we trust the redirect_uri are surfaced as plain 400s so we
   * don't bounce the user back to an unvetted URL.
   */
  app.get("/oauth/authorize", async (c) => {
    const q = c.req.query();
    const {
      response_type,
      client_id,
      redirect_uri,
      state,
      code_challenge,
      code_challenge_method,
      scope,
    } = q as Record<string, string | undefined>;

    if (!client_id) {
      return c.text("invalid_request: missing client_id", 400);
    }
    const client = getOAuthClient(client_id);
    if (!client) {
      return c.text("unauthorized_client: unknown client_id", 400);
    }

    if (!redirect_uri) {
      return c.text("invalid_request: missing redirect_uri", 400);
    }
    if (!isRedirectUriAllowed(client, redirect_uri)) {
      auditLog("oauth_redirect_uri_rejected", {
        client_id,
        redirect_uri,
      });
      return c.text("invalid_request: redirect_uri not whitelisted", 400);
    }

    // Beyond this point, errors can safely redirect to redirect_uri per
    // RFC 6749 §4.1.2.1 (but we still return 400 for missing state/PKCE to
    // avoid open-redirector abuse).

    if (response_type !== "code") {
      return c.text("unsupported_response_type", 400);
    }
    if (!state) {
      return c.text("invalid_request: missing state (CSRF)", 400);
    }
    if (!code_challenge) {
      return c.text("invalid_request: missing code_challenge", 400);
    }
    if (code_challenge_method !== "S256") {
      return c.text("invalid_request: code_challenge_method must be S256", 400);
    }
    if (scope && scope !== "mcp") {
      return c.text("invalid_scope", 400);
    }

    // Require an authenticated QG session. If absent, bounce through the
    // existing Google SSO flow and come back to this exact authorize URL.
    const session = await parseSession(c);
    if (!session) {
      const originalUrl = c.req.url;
      return c.redirect(
        `/auth/login?redirect=${encodeURIComponent(originalUrl)}`,
      );
    }

    const userRecord = getUser(session.email);
    const name = userRecord?.name ?? session.name ?? null;

    // Mint single-use code. 32 random bytes is plenty of entropy.
    const code = base64UrlFromBuffer(crypto.randomBytes(32));
    const now = Math.floor(Date.now() / 1000);
    authCodes.set(code, {
      client_id,
      redirect_uri,
      code_challenge,
      email: session.email,
      name,
      expires_at: now + AUTH_CODE_TTL_SECONDS,
      used: false,
    });

    auditLog("oauth_code_issued", {
      client_id,
      email: session.email,
      redirect_uri,
    });

    return c.redirect(appendQuery(redirect_uri, { code, state }));
  });

  /**
   * `POST /oauth/token` — exchange an authorization code + PKCE verifier for
   * an access token. No refresh token: clients restart the flow on expiry.
   *
   * Errors are intentionally generic (`invalid_grant`) so a probing client
   * can't distinguish between a missing code, a used code, and a PKCE
   * mismatch.
   */
  app.post("/oauth/token", async (c) => {
    // Accept both application/x-www-form-urlencoded (spec) and JSON (leniency
    // for curl-based debugging). Hono's parseBody merges both.
    const body = await c.req.parseBody();
    const grant_type = String(body.grant_type ?? "");
    const code = String(body.code ?? "");
    const redirect_uri = String(body.redirect_uri ?? "");
    const client_id = String(body.client_id ?? "");
    const code_verifier = String(body.code_verifier ?? "");

    if (grant_type !== "authorization_code") {
      return c.json(
        oauthErrorJson("unsupported_grant_type", "only authorization_code"),
        400,
      );
    }

    if (!code || !redirect_uri || !client_id || !code_verifier) {
      return c.json(
        oauthErrorJson("invalid_request", "missing required parameter"),
        400,
      );
    }

    const entry = authCodes.get(code);
    const now = Math.floor(Date.now() / 1000);

    // Single generic failure path — don't leak which check failed.
    const fail = (reason: string) => {
      auditLog("oauth_code_rejected", { reason, client_id });
      return c.json(
        oauthErrorJson("invalid_grant", "code is invalid or expired"),
        400,
      );
    };

    if (!entry) return fail("unknown_code");
    if (entry.used) return fail("already_used");
    if (entry.expires_at < now) return fail("expired");
    if (entry.client_id !== client_id) return fail("client_mismatch");
    if (entry.redirect_uri !== redirect_uri) return fail("redirect_mismatch");
    if (!verifyPkceS256(code_verifier, entry.code_challenge)) {
      return fail("pkce_mismatch");
    }

    // Burn the code before issuing the token — even if signing throws, the
    // code cannot be reused.
    entry.used = true;
    authCodes.set(code, entry);

    const { token, payload } = await signAccessToken(entry.email, entry.name);

    auditLog("oauth_token_issued", {
      client_id,
      email: entry.email,
      aud: payload.aud,
      exp: payload.exp,
    });

    return c.json({
      access_token: token,
      token_type: "Bearer",
      expires_in: MCP_TOKEN_TTL_SECONDS,
      scope: "mcp",
    });
  });
}
