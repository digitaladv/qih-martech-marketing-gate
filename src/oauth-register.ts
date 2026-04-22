import type { Hono } from "hono";
import { randomBytes } from "node:crypto";
import { auditLog } from "./security.js";
import { registerOAuthClient, getOAuthClient } from "./store.js";
import type { OAuthClient } from "./store.js";

/**
 * OAuth 2.0 Dynamic Client Registration (RFC 7591).
 *
 * Claude Desktop (and other MCP clients) attempts DCR on first connection to
 * any unseen MCP server. Without this endpoint, Claude Desktop's connector UI
 * fails silently with "Couldn't connect" before ever showing a login page.
 *
 * Posture — intentionally narrow:
 *   - Only public clients (token_endpoint_auth_method = "none")
 *   - Only authorization_code + S256 PKCE
 *   - Only localhost/127.0.0.1 redirect_uris (MCP clients are desktop apps
 *     that bind an ephemeral localhost port) OR claude.ai organization
 *     callbacks
 *   - No client_secret ever issued
 *   - Generated client_id is random, unguessable, scoped to our store only
 *
 * Pre-registered entries in store.ts (claude-desktop, claude-code, claude-web)
 * continue to work for clients that know their own client_id — DCR is the
 * fallback path for clients that don't.
 */
export function setupOAuthRegisterRoute(app: Hono) {
  app.post("/oauth/register", async (c) => {
    const ct = c.req.header("content-type") || "(none)";
    let raw = "";
    try {
      raw = await c.req.text();
    } catch {
      // leave empty
    }
    console.log(
      `[oauth-register-debug] content-type="${ct}" body_len=${raw.length} body_preview=${JSON.stringify(raw.slice(0, 400))}`,
    );

    let body: {
      client_name?: string;
      redirect_uris?: string[];
      token_endpoint_auth_method?: string;
      grant_types?: string[];
      response_types?: string[];
      scope?: string;
    };

    try {
      body = JSON.parse(raw);
    } catch {
      console.log(
        `[oauth-register-debug] JSON.parse failed — rejecting with invalid_request`,
      );
      return c.json(
        { error: "invalid_request", error_description: "Invalid JSON body" },
        400,
      );
    }

    const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
    if (redirectUris.length === 0) {
      return c.json(
        {
          error: "invalid_redirect_uri",
          error_description: "redirect_uris is required and must be non-empty",
        },
        400,
      );
    }

    // Validate every redirect URI. Acceptable: localhost/127.0.0.1 on any
    // port, or https://claude.ai/* (the web connector path). Rejects arbitrary
    // public URIs to prevent open-redirector abuse against our issuer.
    for (const uri of redirectUris) {
      if (!isSafeRegisteredRedirectUri(uri)) {
        auditLog("oauth_register_rejected_uri", { uri });
        return c.json(
          {
            error: "invalid_redirect_uri",
            error_description: `redirect_uri not allowed: ${uri}`,
          },
          400,
        );
      }
    }

    // Enforce the posture: public client, authorization_code only.
    if (
      body.token_endpoint_auth_method &&
      body.token_endpoint_auth_method !== "none"
    ) {
      return c.json(
        {
          error: "invalid_client_metadata",
          error_description:
            "Only public clients (token_endpoint_auth_method=none) are supported",
        },
        400,
      );
    }
    // Clients (notably Claude) include "refresh_token" in the requested grants
    // alongside "authorization_code". We don't issue refresh tokens today (24h
    // JWT, user re-auths), but rejecting the DCR here would block the whole
    // flow. Accept both and signal authorization_code only in the response so
    // a spec-compliant client knows refresh isn't actually available.
    const allowedGrants = new Set(["authorization_code", "refresh_token"]);
    if (
      body.grant_types &&
      !body.grant_types.every((g) => allowedGrants.has(g))
    ) {
      return c.json(
        {
          error: "invalid_client_metadata",
          error_description:
            "Only authorization_code and refresh_token grants are permitted",
        },
        400,
      );
    }

    // Mint a random client_id. Avoid collisions with pre-registered ones by
    // using a long random string. No client_secret — public client only.
    let clientId = `mcp-${randomBytes(16).toString("hex")}`;
    let tries = 0;
    while (getOAuthClient(clientId) && tries < 5) {
      clientId = `mcp-${randomBytes(16).toString("hex")}`;
      tries += 1;
    }

    const client: OAuthClient = {
      client_id: clientId,
      name: body.client_name?.slice(0, 100) || `dynamic-${clientId.slice(0, 12)}`,
      redirect_uris: redirectUris,
    };
    registerOAuthClient(client);

    auditLog("oauth_client_registered", {
      client_id: clientId,
      name: client.name,
      redirect_uri_count: redirectUris.length,
    });

    // RFC 7591 response. client_id_issued_at is seconds-since-epoch.
    return c.json(
      {
        client_id: clientId,
        client_name: client.name,
        redirect_uris: redirectUris,
        grant_types: ["authorization_code"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
        client_id_issued_at: Math.floor(Date.now() / 1000),
      },
      201,
    );
  });
}

/**
 * Acceptance rules for DCR redirect_uri. Deliberately narrow because the only
 * legitimate callers are desktop OAuth clients (which bind an ephemeral port
 * on localhost) and Claude.ai's web connector.
 */
function isSafeRegisteredRedirectUri(uri: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }

  // Localhost / 127.0.0.1 — any port, any path.
  if (parsed.protocol === "http:" || parsed.protocol === "https:") {
    if (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1") {
      return true;
    }
  }

  // Claude.ai web connector callback.
  if (
    parsed.protocol === "https:" &&
    parsed.hostname === "claude.ai" &&
    parsed.pathname.startsWith("/api/")
  ) {
    return true;
  }

  return false;
}
