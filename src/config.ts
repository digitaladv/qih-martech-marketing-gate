import "dotenv/config";

function env(key: string, fallback?: string): string {
  const v = process.env[key] ?? fallback;
  if (v === undefined) {
    console.error(`Missing required env var: ${key}`);
    process.exit(1);
  }
  return v;
}

export const CONFIG = {
  PORT: Number(env("PORT", "3000")),
  SERVER_URL: env("SERVER_URL", "http://localhost:3000"),
  GOOGLE_CLIENT_ID: env("GOOGLE_CLIENT_ID"),
  GOOGLE_CLIENT_SECRET: env("GOOGLE_CLIENT_SECRET"),
  JWT_SECRET: env("JWT_SECRET"),
  ALLOWED_DOMAIN: env("ALLOWED_DOMAIN", "quantum.media"),
  COOKIE_DOMAIN: env("COOKIE_DOMAIN", ""),
  COOKIE_NAME: env("COOKIE_NAME", "qm_session"),
  COOKIE_MAX_AGE: 86400, // 24h
  SUPER_ADMIN: env("SUPER_ADMIN", "alessandro.moretti@quantum.media"),
  // Full URL to the analytics MCP server endpoint (used to build the
  // claude_desktop_config.json snippet on /auth/mcp-token).
  MCP_SERVER_URL: env(
    "MCP_SERVER_URL",
    "https://analytics-mcp.marketing.qih-tech.com/mcp",
  ),
  NODE_ENV: env("NODE_ENV", "development"),
  get isDev() {
    return this.NODE_ENV === "development";
  },
  get isSecure() {
    return this.SERVER_URL.startsWith("https");
  },
};

export function validateConfig() {
  if (CONFIG.JWT_SECRET.length < 32) {
    console.error("JWT_SECRET must be at least 32 characters");
    process.exit(1);
  }
  if (!CONFIG.GOOGLE_CLIENT_ID || !CONFIG.GOOGLE_CLIENT_SECRET) {
    console.error("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are required");
    process.exit(1);
  }
  console.log(`[config] Server URL: ${CONFIG.SERVER_URL}`);
  console.log(`[config] Allowed domain: @${CONFIG.ALLOWED_DOMAIN}`);
  console.log(
    `[config] Cookie domain: ${CONFIG.COOKIE_DOMAIN || "(localhost)"}`,
  );
  console.log(`[config] Admin: ${CONFIG.SUPER_ADMIN}`);
}
