import crypto from "node:crypto";
import { Hono } from "hono";
import { sign, verify } from "hono/jwt";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CONFIG } from "./config.js";
import { MCP_TOKEN_AUDIENCE, MCP_TOKEN_TTL_SECONDS } from "./mcp-token.js";
import {
  AUTH_CODE_TTL_SECONDS,
  authCodes,
  setupOAuthRoutes,
  sweepExpiredCodes,
  verifyPkceS256,
} from "./oauth.js";
import { setupOAuthMetadataRoute } from "./oauth-metadata.js";
import { isRedirectUriAllowed } from "./store.js";

// Mock store getUser — tests don't need persisted UserRecords.
// Leave the seeded OAuth clients intact.
vi.mock("./store.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./store.js")>();
  return {
    ...actual,
    getUser: (_email: string) => null,
  };
});

function makeApp() {
  const app = new Hono();
  setupOAuthMetadataRoute(app);
  setupOAuthRoutes(app);
  return app;
}

async function makeSessionCookie(
  email = "user@quantum.media",
  name = "User Name",
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const token = await sign(
    { email, name, iat: now, exp: now + 3600 },
    CONFIG.JWT_SECRET,
  );
  return `${CONFIG.COOKIE_NAME}=${token}`;
}

/** Build a PKCE verifier + S256 challenge pair. */
function makePkce(): { verifier: string; challenge: string } {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");
  return { verifier, challenge };
}

function buildAuthorizeUrl(
  overrides: Partial<Record<string, string>> = {},
): string {
  const params: Record<string, string> = {
    response_type: "code",
    client_id: "claude-desktop",
    redirect_uri: "http://localhost:55123/callback",
    state: "state-abc",
    code_challenge: "placeholder",
    code_challenge_method: "S256",
    scope: "mcp",
    ...overrides,
  };
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) qs.set(k, v);
  }
  return `/oauth/authorize?${qs}`;
}

beforeEach(() => {
  authCodes.clear();
});

// ------------------------------------------------------------
// Metadata
// ------------------------------------------------------------

describe("GET /.well-known/oauth-authorization-server", () => {
  it("returns the RFC 8414 metadata document with the expected surface", async () => {
    const app = makeApp();
    const res = await app.request("/.well-known/oauth-authorization-server");
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;

    expect(body.issuer).toBe(CONFIG.SERVER_URL);
    expect(body.authorization_endpoint).toBe(
      `${CONFIG.SERVER_URL}/oauth/authorize`,
    );
    expect(body.token_endpoint).toBe(`${CONFIG.SERVER_URL}/oauth/token`);
    expect(body.response_types_supported).toEqual(["code"]);
    expect(body.grant_types_supported).toEqual(["authorization_code"]);
    expect(body.code_challenge_methods_supported).toEqual(["S256"]);
    expect(body.token_endpoint_auth_methods_supported).toEqual(["none"]);
    expect(body.scopes_supported).toEqual(["mcp"]);
  });
});

// ------------------------------------------------------------
// /oauth/authorize
// ------------------------------------------------------------

describe("GET /oauth/authorize", () => {
  it("redirects to login when there's no session", async () => {
    const app = makeApp();
    const { challenge } = makePkce();
    const url = buildAuthorizeUrl({ code_challenge: challenge });
    const res = await app.request(url, { redirect: "manual" });
    expect(res.status).toBe(302);
    const loc = res.headers.get("location") || "";
    expect(loc).toContain("/auth/login");
    // The original authorize URL must be round-tripped through the redirect
    expect(loc).toContain("redirect=");
    expect(loc).toContain(encodeURIComponent("/oauth/authorize"));
  });

  it("issues a code and redirects to the client when the session is valid", async () => {
    const app = makeApp();
    const { challenge } = makePkce();
    const cookie = await makeSessionCookie("ok@quantum.media", "OK");
    const url = buildAuthorizeUrl({ code_challenge: challenge });

    const res = await app.request(url, {
      headers: { Cookie: cookie },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    const loc = res.headers.get("location") || "";
    expect(loc.startsWith("http://localhost:55123/callback")).toBe(true);
    const parsed = new URL(loc);
    const code = parsed.searchParams.get("code");
    expect(code).toBeTruthy();
    expect(parsed.searchParams.get("state")).toBe("state-abc");

    // Code is persisted with the exact challenge + email we expect
    const entry = authCodes.get(code as string);
    expect(entry).toBeDefined();
    expect(entry?.client_id).toBe("claude-desktop");
    expect(entry?.redirect_uri).toBe("http://localhost:55123/callback");
    expect(entry?.code_challenge).toBe(challenge);
    expect(entry?.email).toBe("ok@quantum.media");
    expect(entry?.used).toBe(false);
  });

  it("rejects unknown client_id", async () => {
    const app = makeApp();
    const { challenge } = makePkce();
    const cookie = await makeSessionCookie();
    const url = buildAuthorizeUrl({
      client_id: "nope",
      code_challenge: challenge,
    });
    const res = await app.request(url, { headers: { Cookie: cookie } });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("unauthorized_client");
  });

  it("rejects a redirect_uri that doesn't match the client's whitelist", async () => {
    const app = makeApp();
    const { challenge } = makePkce();
    const cookie = await makeSessionCookie();
    const url = buildAuthorizeUrl({
      redirect_uri: "https://evil.example.com/steal",
      code_challenge: challenge,
    });
    const res = await app.request(url, { headers: { Cookie: cookie } });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("redirect_uri");
  });

  it("rejects requests missing state (CSRF defense)", async () => {
    const app = makeApp();
    const { challenge } = makePkce();
    const cookie = await makeSessionCookie();
    const url = buildAuthorizeUrl({
      state: undefined,
      code_challenge: challenge,
    });
    const res = await app.request(url, { headers: { Cookie: cookie } });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("state");
  });

  it("rejects code_challenge_method != S256", async () => {
    const app = makeApp();
    const { challenge } = makePkce();
    const cookie = await makeSessionCookie();
    const url = buildAuthorizeUrl({
      code_challenge: challenge,
      code_challenge_method: "plain",
    });
    const res = await app.request(url, { headers: { Cookie: cookie } });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("S256");
  });

  it("rejects response_type != code", async () => {
    const app = makeApp();
    const { challenge } = makePkce();
    const cookie = await makeSessionCookie();
    const url = buildAuthorizeUrl({
      response_type: "token",
      code_challenge: challenge,
    });
    const res = await app.request(url, { headers: { Cookie: cookie } });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("unsupported_response_type");
  });

  it("accepts claude-web redirect matching the Claude.ai org wildcard", async () => {
    const app = makeApp();
    const { challenge } = makePkce();
    const cookie = await makeSessionCookie();
    const redirect =
      "https://claude.ai/api/organizations/abc-123/mcp/oauth/callback";
    const url = buildAuthorizeUrl({
      client_id: "claude-web",
      redirect_uri: redirect,
      code_challenge: challenge,
    });
    const res = await app.request(url, {
      headers: { Cookie: cookie },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")?.startsWith(redirect)).toBe(true);
  });
});

// ------------------------------------------------------------
// /oauth/token
// ------------------------------------------------------------

async function obtainCode(
  app: Hono,
  overrides: Partial<Record<string, string>> = {},
): Promise<{ code: string; verifier: string; redirectUri: string }> {
  const { verifier, challenge } = makePkce();
  const cookie = await makeSessionCookie("flow@quantum.media", "Flow");
  const url = buildAuthorizeUrl({
    code_challenge: challenge,
    ...overrides,
  });
  const res = await app.request(url, {
    headers: { Cookie: cookie },
    redirect: "manual",
  });
  expect(res.status).toBe(302);
  const loc = new URL(res.headers.get("location") || "");
  const code = loc.searchParams.get("code") as string;
  const redirectUri = `${loc.protocol}//${loc.host}${loc.pathname}`;
  return { code, verifier, redirectUri };
}

function tokenRequestBody(params: Record<string, string>): FormData {
  const fd = new FormData();
  for (const [k, v] of Object.entries(params)) fd.set(k, v);
  return fd;
}

describe("POST /oauth/token", () => {
  it("exchanges a valid code for a bearer token with correct claims", async () => {
    const app = makeApp();
    const { code, verifier, redirectUri } = await obtainCode(app);

    const res = await app.request("/oauth/token", {
      method: "POST",
      body: tokenRequestBody({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: "claude-desktop",
        code_verifier: verifier,
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      access_token: string;
      token_type: string;
      expires_in: number;
      scope: string;
    };
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(MCP_TOKEN_TTL_SECONDS);
    expect(body.scope).toBe("mcp");

    // JWT must carry the same claim shape as bridge tokens
    const payload = (await verify(
      body.access_token,
      CONFIG.JWT_SECRET,
      "HS256",
    )) as {
      sub: string;
      aud: string;
      iss: string;
      iat: number;
      exp: number;
    };
    expect(payload.sub).toBe("flow@quantum.media");
    expect(payload.aud).toBe(MCP_TOKEN_AUDIENCE);
    expect(payload.iss).toBe(CONFIG.SERVER_URL);
    expect(payload.exp - payload.iat).toBe(MCP_TOKEN_TTL_SECONDS);
  });

  it("rejects a code that has already been used (single-use)", async () => {
    const app = makeApp();
    const { code, verifier, redirectUri } = await obtainCode(app);

    const first = await app.request("/oauth/token", {
      method: "POST",
      body: tokenRequestBody({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: "claude-desktop",
        code_verifier: verifier,
      }),
    });
    expect(first.status).toBe(200);

    const second = await app.request("/oauth/token", {
      method: "POST",
      body: tokenRequestBody({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: "claude-desktop",
        code_verifier: verifier,
      }),
    });
    expect(second.status).toBe(400);
    const body = (await second.json()) as { error: string };
    expect(body.error).toBe("invalid_grant");
  });

  it("rejects an expired code", async () => {
    const app = makeApp();
    const { code, verifier, redirectUri } = await obtainCode(app);

    // Rewind the stored entry so sweep considers it expired
    const entry = authCodes.get(code);
    expect(entry).toBeDefined();
    if (entry) {
      entry.expires_at =
        Math.floor(Date.now() / 1000) - AUTH_CODE_TTL_SECONDS - 5;
      authCodes.set(code, entry);
    }

    const res = await app.request("/oauth/token", {
      method: "POST",
      body: tokenRequestBody({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: "claude-desktop",
        code_verifier: verifier,
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_grant");
  });

  it("rejects mismatched redirect_uri", async () => {
    const app = makeApp();
    const { code, verifier } = await obtainCode(app);

    const res = await app.request("/oauth/token", {
      method: "POST",
      body: tokenRequestBody({
        grant_type: "authorization_code",
        code,
        redirect_uri: "http://localhost:99999/other",
        client_id: "claude-desktop",
        code_verifier: verifier,
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_grant");
  });

  it("rejects mismatched client_id", async () => {
    const app = makeApp();
    const { code, verifier, redirectUri } = await obtainCode(app);

    const res = await app.request("/oauth/token", {
      method: "POST",
      body: tokenRequestBody({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: "claude-code",
        code_verifier: verifier,
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_grant");
  });

  it("rejects an invalid code_verifier (PKCE)", async () => {
    const app = makeApp();
    const { code, redirectUri } = await obtainCode(app);

    const res = await app.request("/oauth/token", {
      method: "POST",
      body: tokenRequestBody({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: "claude-desktop",
        code_verifier: "totally-the-wrong-verifier",
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_grant");
  });

  it("rejects unsupported grant_type", async () => {
    const app = makeApp();
    const res = await app.request("/oauth/token", {
      method: "POST",
      body: tokenRequestBody({
        grant_type: "client_credentials",
        code: "x",
        redirect_uri: "x",
        client_id: "claude-desktop",
        code_verifier: "x",
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("unsupported_grant_type");
  });

  it("rejects requests with missing params (invalid_request)", async () => {
    const app = makeApp();
    const res = await app.request("/oauth/token", {
      method: "POST",
      body: tokenRequestBody({
        grant_type: "authorization_code",
        // No code / redirect_uri / client_id / verifier
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_request");
  });

  it("issues a JWT with the same audience as the bridge flow", async () => {
    const app = makeApp();
    const { code, verifier, redirectUri } = await obtainCode(app);

    const res = await app.request("/oauth/token", {
      method: "POST",
      body: tokenRequestBody({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: "claude-desktop",
        code_verifier: verifier,
      }),
    });
    const body = (await res.json()) as { access_token: string };
    const payload = (await verify(
      body.access_token,
      CONFIG.JWT_SECRET,
      "HS256",
    )) as { aud: string };
    expect(payload.aud).toBe(MCP_TOKEN_AUDIENCE);
    // Wrong secret must fail — confirms HS256 with shared secret
    await expect(
      verify(body.access_token, "wrong-secret-0123456789-abcdef", "HS256"),
    ).rejects.toThrow();
  });
});

// ------------------------------------------------------------
// Redirect URI wildcard matching
// ------------------------------------------------------------

describe("isRedirectUriAllowed (wildcard matching)", () => {
  const localhostClient = {
    client_id: "x",
    name: "x",
    redirect_uris: ["http://localhost/*", "http://127.0.0.1/*"],
  };

  it("matches localhost on any port and path", () => {
    expect(
      isRedirectUriAllowed(localhostClient, "http://localhost:55123/callback"),
    ).toBe(true);
    expect(isRedirectUriAllowed(localhostClient, "http://localhost:1/x")).toBe(
      true,
    );
    expect(
      isRedirectUriAllowed(localhostClient, "http://127.0.0.1:8080/cb"),
    ).toBe(true);
  });

  it("rejects non-localhost hosts", () => {
    expect(
      isRedirectUriAllowed(localhostClient, "http://evil.com/callback"),
    ).toBe(false);
    // Subdomain sneaking under localhost must not match
    expect(
      isRedirectUriAllowed(
        localhostClient,
        "http://localhost.evil.com/callback",
      ),
    ).toBe(false);
  });

  it("handles mid-string wildcards (Claude.ai org id)", () => {
    const web = {
      client_id: "y",
      name: "y",
      redirect_uris: ["https://claude.ai/api/organizations/*/mcp/oauth/*"],
    };
    // Single-wildcard pattern — we only check one wildcard per pattern, so
    // inputs that exercise the FIRST wildcard are the supported case.
    expect(
      isRedirectUriAllowed(
        web,
        "https://claude.ai/api/organizations/abc-123/mcp/oauth/callback",
      ),
    ).toBe(true);
    expect(
      isRedirectUriAllowed(
        web,
        "https://claude.ai/api/organizations//mcp/oauth/callback",
      ),
    ).toBe(false);
  });
});

// ------------------------------------------------------------
// PKCE helper + sweep
// ------------------------------------------------------------

describe("verifyPkceS256", () => {
  it("validates a freshly generated S256 pair", () => {
    const { verifier, challenge } = makePkce();
    expect(verifyPkceS256(verifier, challenge)).toBe(true);
  });

  it("rejects a mismatched verifier", () => {
    const { challenge } = makePkce();
    expect(verifyPkceS256("not-the-verifier", challenge)).toBe(false);
  });
});

describe("sweepExpiredCodes", () => {
  it("removes expired entries and leaves live ones", () => {
    authCodes.clear();
    const now = Math.floor(Date.now() / 1000);
    authCodes.set("live", {
      client_id: "claude-desktop",
      redirect_uri: "x",
      code_challenge: "x",
      email: "x@q.m",
      name: null,
      expires_at: now + 60,
      used: false,
    });
    authCodes.set("dead", {
      client_id: "claude-desktop",
      redirect_uri: "x",
      code_challenge: "x",
      email: "x@q.m",
      name: null,
      expires_at: now - 60,
      used: false,
    });
    sweepExpiredCodes(now);
    expect(authCodes.has("live")).toBe(true);
    expect(authCodes.has("dead")).toBe(false);
  });
});
