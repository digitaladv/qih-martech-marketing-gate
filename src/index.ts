import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { CONFIG, validateConfig } from "./config.js";
import { securityHeaders, originCheck, rateLimit, auditLog } from "./security.js";
import { setupAuthRoutes } from "./auth.js";
import { setupVerifyRoute } from "./verify.js";
import { setupAdminRoutes } from "./admin.js";

validateConfig();

const app = new Hono();

// Global middleware
app.use("*", securityHeaders);

// Health check (always public)
app.get("/health", (c) => c.json({ status: "ok", service: "quantum-gate" }));

// ForwardAuth endpoint (called by Traefik — must be fast, no rate limit)
setupVerifyRoute(app);

// Auth routes (rate-limited)
app.use("/auth/*", rateLimit(30, 60_000));
setupAuthRoutes(app);

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
