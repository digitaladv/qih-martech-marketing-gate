import { Hono } from "hono";
import { sign, verify } from "hono/jwt";
import { describe, expect, it, vi } from "vitest";
import { CONFIG } from "./config.js";
import {
  MCP_TOKEN_AUDIENCE,
  MCP_TOKEN_TTL_SECONDS,
  setupMcpTokenRoutes,
} from "./mcp-token.js";
import { buildClaudeDesktopSnippet } from "./views/mcp-token.js";

// Mock store: provide stable getUser response, avoid FS writes
vi.mock("./store.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./store.js")>();
  return {
    ...actual,
    getUser: (email: string) =>
      email === "stored@quantum.media"
        ? {
            email,
            name: "Stored Name",
            lastLogin: new Date().toISOString(),
            loginCount: 1,
          }
        : null,
  };
});

function makeApp() {
  const app = new Hono();
  setupMcpTokenRoutes(app);
  return app;
}

async function makeSessionCookie(
  email = "test@quantum.media",
  name = "Test User",
  overrides: { exp?: number; iat?: number } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const token = await sign(
    {
      email,
      name,
      iat: overrides.iat ?? now,
      exp: overrides.exp ?? now + 3600,
    },
    CONFIG.JWT_SECRET,
  );
  return `${CONFIG.COOKIE_NAME}=${token}`;
}

describe("POST /auth/mcp-token", () => {
  it("returns 401 when no cookie is present", async () => {
    const app = makeApp();
    const res = await app.request("/auth/mcp-token", { method: "POST" });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("Authentication");
  });

  it("returns 401 when cookie is garbage", async () => {
    const app = makeApp();
    const res = await app.request("/auth/mcp-token", {
      method: "POST",
      headers: { Cookie: `${CONFIG.COOKIE_NAME}=not-a-real-jwt` },
    });
    expect(res.status).toBe(401);
  });

  it("returns 401 when session cookie is expired", async () => {
    const app = makeApp();
    const past = Math.floor(Date.now() / 1000) - 10_000;
    const cookie = await makeSessionCookie("expired@quantum.media", "Expired", {
      iat: past - 1000,
      exp: past,
    });
    const res = await app.request("/auth/mcp-token", {
      method: "POST",
      headers: { Cookie: cookie },
    });
    expect(res.status).toBe(401);
  });

  it("returns a valid JWT with correct claims for authed user", async () => {
    const app = makeApp();
    const cookie = await makeSessionCookie("test@quantum.media", "Test User");

    const before = Math.floor(Date.now() / 1000);
    const res = await app.request("/auth/mcp-token", {
      method: "POST",
      headers: { Cookie: cookie },
    });
    const after = Math.floor(Date.now() / 1000);

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      token: string;
      expires_at: number;
      mcp_server_url: string;
    };
    expect(typeof body.token).toBe("string");
    expect(body.token.split(".").length).toBe(3); // header.payload.signature
    expect(body.mcp_server_url).toBe(CONFIG.MCP_SERVER_URL);
    expect(body.expires_at).toBeGreaterThanOrEqual(
      before + MCP_TOKEN_TTL_SECONDS - 5,
    );
    expect(body.expires_at).toBeLessThanOrEqual(
      after + MCP_TOKEN_TTL_SECONDS + 5,
    );

    // Token verifies against the same shared secret (what MCP will do)
    const payload = (await verify(body.token, CONFIG.JWT_SECRET, "HS256")) as {
      sub: string;
      name: string | null;
      aud: string;
      iss: string;
      iat: number;
      exp: number;
    };
    expect(payload.sub).toBe("test@quantum.media");
    expect(payload.aud).toBe(MCP_TOKEN_AUDIENCE);
    expect(payload.iss).toBe(CONFIG.SERVER_URL);
    expect(payload.exp).toBe(body.expires_at);
    expect(payload.exp - payload.iat).toBe(MCP_TOKEN_TTL_SECONDS);
  });

  it("prefers the persisted user record name over session name", async () => {
    const app = makeApp();
    // Session name deliberately differs from stored name
    const cookie = await makeSessionCookie(
      "stored@quantum.media",
      "Old Session Name",
    );
    const res = await app.request("/auth/mcp-token", {
      method: "POST",
      headers: { Cookie: cookie },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { token: string };
    const payload = (await verify(body.token, CONFIG.JWT_SECRET, "HS256")) as {
      name: string | null;
    };
    expect(payload.name).toBe("Stored Name");
  });

  it("falls back to session name when no stored user record exists", async () => {
    const app = makeApp();
    const cookie = await makeSessionCookie(
      "brand-new@quantum.media",
      "Fresh Login",
    );
    const res = await app.request("/auth/mcp-token", {
      method: "POST",
      headers: { Cookie: cookie },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { token: string };
    const payload = (await verify(body.token, CONFIG.JWT_SECRET, "HS256")) as {
      name: string | null;
    };
    expect(payload.name).toBe("Fresh Login");
  });

  it("issues tokens signed with the shared JWT_SECRET (MCP-side verify works)", async () => {
    const app = makeApp();
    const cookie = await makeSessionCookie();
    const res = await app.request("/auth/mcp-token", {
      method: "POST",
      headers: { Cookie: cookie },
    });
    const body = (await res.json()) as { token: string };

    // Wrong secret must fail — confirms HS256 signing
    await expect(
      verify(body.token, "wrong-secret-0123456789-0123456789", "HS256"),
    ).rejects.toThrow();
  });
});

describe("GET /auth/mcp-token", () => {
  it("redirects to login when not authenticated", async () => {
    const app = makeApp();
    const res = await app.request("/auth/mcp-token", { redirect: "manual" });
    expect(res.status).toBe(302);
    const loc = res.headers.get("location") || "";
    expect(loc).toContain("/auth/login");
    expect(loc).toContain("redirect=");
    expect(loc).toContain(encodeURIComponent("/auth/mcp-token"));
  });

  it("renders the bridge page when authenticated", async () => {
    const app = makeApp();
    const cookie = await makeSessionCookie(
      "render@quantum.media",
      "Render User",
    );
    const res = await app.request("/auth/mcp-token", {
      headers: { Cookie: cookie },
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("MCP Access Token");
    expect(html).toContain("render@quantum.media");
    expect(html).toContain("Generate Token");
    expect(html).toContain("X-API-Key");
  });

  it("escapes the email in the rendered HTML", async () => {
    const app = makeApp();
    // Craft a session with a pathological email (shouldn't happen in prod,
    // but the rendering path must be XSS-safe regardless)
    const cookie = await makeSessionCookie(
      "<script>alert(1)</script>@quantum.media",
      "x",
    );
    const res = await app.request("/auth/mcp-token", {
      headers: { Cookie: cookie },
    });
    const html = await res.text();
    expect(html).not.toContain("<script>alert(1)</script>@quantum.media");
    expect(html).toContain("&lt;script&gt;");
  });

  it("renders the config snippet with MCP_SERVER_URL baked in", async () => {
    const app = makeApp();
    const cookie = await makeSessionCookie("user@quantum.media", "User");
    const res = await app.request("/auth/mcp-token", {
      headers: { Cookie: cookie },
    });
    const html = await res.text();

    // Snippet blocks are rendered on page load with a placeholder token
    expect(html).toContain("claude_desktop_config.json");
    expect(html).toContain("mcpServers");
    expect(html).toContain("mcp-remote");
    expect(html).toContain("--header");
    expect(html).toContain("X-API-Key:&lt;TOKEN_WILL_APPEAR_HERE&gt;");
    // MCP_SERVER_URL is interpolated from config
    expect(html).toContain(CONFIG.MCP_SERVER_URL);
  });

  it("renders chooser hint, docs link, and platform-specific config paths", async () => {
    const app = makeApp();
    const cookie = await makeSessionCookie("user@quantum.media", "User");
    const res = await app.request("/auth/mcp-token", {
      headers: { Cookie: cookie },
    });
    const html = await res.text();

    // Top-of-page chooser
    expect(html).toContain("Which one do I copy");
    expect(html).toContain("Claude Desktop");
    expect(html).toContain("Claude Code CLI");
    // New guidance nudging non-devs to the Claude Desktop UI flow
    expect(html).toContain("Most users");
    expect(html).toContain("Add Custom Connector");

    // Help link to MCP quickstart
    expect(html).toContain("modelcontextprotocol.io/quickstart/user");

    // Platform-specific config file paths
    expect(html).toContain("~/Library/Application Support/Claude");
    expect(html).toContain("%APPDATA%");

    // Separate copy buttons for snippet and raw token
    expect(html).toContain('id="copySnippetBtn"');
    expect(html).toContain('id="copyTokenBtn"');
  });
});

describe("buildClaudeDesktopSnippet", () => {
  it("produces a valid JSON snippet with token and URL embedded", () => {
    const snippet = buildClaudeDesktopSnippet(
      "https://example.com/mcp",
      "abc.def.ghi",
    );
    const parsed = JSON.parse(snippet);
    expect(parsed.mcpServers.analytics.command).toBe("npx");
    expect(parsed.mcpServers.analytics.args).toEqual([
      "-y",
      "mcp-remote",
      "https://example.com/mcp",
      "--header",
      "X-API-Key:abc.def.ghi",
    ]);
  });

  it("joins header name and token with NO space (mcp-remote splits on whitespace)", () => {
    const snippet = buildClaudeDesktopSnippet(
      "https://example.com/mcp",
      "mytoken",
    );
    const parsed = JSON.parse(snippet);
    const headerValue = parsed.mcpServers.analytics.args[4];
    expect(headerValue).toBe("X-API-Key:mytoken");
    expect(headerValue).not.toContain(" ");
  });

  it("emits pretty-printed JSON (human-copyable)", () => {
    const snippet = buildClaudeDesktopSnippet("https://x/mcp", "t");
    expect(snippet).toContain("\n");
    expect(snippet).toContain('  "mcpServers"');
  });
});
