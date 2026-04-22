import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { setupAdminRoutes } from "./admin.js";
import { setupAuthRoutes } from "./auth.js";
import { CONFIG, validateConfig } from "./config.js";
import { setupMcpTokenRoutes } from "./mcp-token.js";
import { setupOAuthRoutes, startCodeCleanup } from "./oauth.js";
import { setupOAuthMetadataRoute } from "./oauth-metadata.js";
import {
  auditLog,
  originCheck,
  rateLimit,
  securityHeaders,
} from "./security.js";
import { setupVerifyRoute } from "./verify.js";

validateConfig();

const app = new Hono();

// Global middleware
app.use("*", securityHeaders);

// Health check (always public)
app.get("/health", (c) => c.json({ status: "ok", service: "quantum-gate" }));

// ForwardAuth endpoint (called by Traefik — must be fast, no rate limit)
setupVerifyRoute(app);

// OAuth metadata (RFC 8414) — public, cacheable, no rate limit
setupOAuthMetadataRoute(app);

// Auth routes (rate-limited)
app.use("/auth/*", rateLimit(30, 60_000));
setupAuthRoutes(app);
setupMcpTokenRoutes(app);

// OAuth 2.1 authorize + token endpoints (rate-limited)
app.use("/oauth/*", rateLimit(60, 60_000));
setupOAuthRoutes(app);
startCodeCleanup();

// Admin routes (rate-limited + CSRF protection)
app.use("/admin", rateLimit(30, 60_000));
app.use("/api/*", rateLimit(60, 60_000));
app.use("/api/*", originCheck);
setupAdminRoutes(app);

// Start
serve({ fetch: app.fetch, port: CONFIG.PORT }, () => {
  auditLog("server_started", { port: CONFIG.PORT, url: CONFIG.SERVER_URL });
  console.log(`Quantum Gate running on port ${CONFIG.PORT}`);
  console.log(`Login: ${CONFIG.SERVER_URL}/auth/login`);
  console.log(`Admin: ${CONFIG.SERVER_URL}/admin`);
});
