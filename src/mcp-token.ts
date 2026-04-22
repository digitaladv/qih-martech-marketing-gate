import type { Hono } from "hono";
import { sign } from "hono/jwt";
import { parseSession } from "./auth.js";
import { CONFIG } from "./config.js";
import { auditLog } from "./security.js";
import { getUser } from "./store.js";
import { mcpTokenPageHtml } from "./views/mcp-token.js";

/** Audience claim for tokens consumed by the analytics MCP server. */
export const MCP_TOKEN_AUDIENCE = "mcp-analytics";

/** Access token lifetime in seconds (matches session cookie TTL). */
export const MCP_TOKEN_TTL_SECONDS = 24 * 60 * 60;

interface McpTokenPayload {
  sub: string;
  name: string | null;
  aud: string;
  iss: string;
  iat: number;
  exp: number;
  // Required by hono/jwt's JWTPayload type (index signature)
  [key: string]: unknown;
}

/**
 * Sign an MCP access token for the given user.
 * Uses HS256 with the shared JWT_SECRET — the MCP server verifies against the
 * same secret (shared-secret bridge).
 */
async function signMcpToken(
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

export function setupMcpTokenRoutes(app: Hono) {
  // Bridge page — renders UI for generating a token. Requires session cookie.
  app.get("/auth/mcp-token", async (c) => {
    const session = await parseSession(c);
    if (!session) {
      return c.redirect(
        `/auth/login?redirect=${encodeURIComponent("/auth/mcp-token")}`,
      );
    }
    return c.html(mcpTokenPageHtml(session.email, CONFIG.MCP_SERVER_URL));
  });

  // Issue a token. Requires valid session cookie. No refresh: user re-generates.
  app.post("/auth/mcp-token", async (c) => {
    const session = await parseSession(c);
    if (!session) {
      return c.json({ error: "Authentication required" }, 401);
    }

    // Prefer the persisted display name from the user record, fall back to
    // session name (freshly captured at login), else null.
    const userRecord = getUser(session.email);
    const name = userRecord?.name ?? session.name ?? null;

    const { token, payload } = await signMcpToken(session.email, name);

    auditLog("mcp_token_issued", {
      email: session.email,
      aud: payload.aud,
      exp: payload.exp,
    });

    return c.json({
      token,
      expires_at: payload.exp,
      mcp_server_url: CONFIG.MCP_SERVER_URL,
    });
  });
}
