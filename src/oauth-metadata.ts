import type { Hono } from "hono";
import { CONFIG } from "./config.js";

/**
 * OAuth 2.0 Authorization Server Metadata (RFC 8414).
 *
 * Claude Desktop's Custom Connector UI fetches this document to discover the
 * authorize/token endpoints for a given MCP server. We publish a minimal
 * advertised surface:
 *   - only the authorization code grant (no refresh, no client credentials)
 *   - PKCE with S256 mandatory
 *   - public clients (no client secret)  → `token_endpoint_auth_methods` = `none`
 *   - single `mcp` scope
 */
export function setupOAuthMetadataRoute(app: Hono) {
  app.get("/.well-known/oauth-authorization-server", (c) => {
    const base = CONFIG.SERVER_URL;
    return c.json({
      issuer: base,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: ["mcp"],
    });
  });
}
