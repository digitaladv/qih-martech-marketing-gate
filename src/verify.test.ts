import { Hono } from "hono";
import { sign } from "hono/jwt";
import { describe, expect, it } from "vitest";
import { CONFIG } from "./config.js";
import {
  addService,
  registerHost,
  removeService,
} from "./store.js";
import { setupVerifyRoute } from "./verify.js";

// In test env: SERVER_URL=http://localhost:3099, COOKIE_DOMAIN=""
// So EXPECTED_DOMAIN=localhost. Use "sub.localhost" for own-domain tests.

describe("verify route", () => {
  function makeApp() {
    const app = new Hono();
    setupVerifyRoute(app);
    return app;
  }

  it("passes through the auth host itself", async () => {
    const app = makeApp();
    const res = await app.request("/verify", {
      headers: {
        "x-forwarded-host": "localhost:3099",
        "x-forwarded-proto": "http",
        "x-forwarded-uri": "/auth/login",
      },
    });
    expect(res.status).toBe(200);
  });

  it("passes through /api/ paths via default exemption (backwards compatible)", async () => {
    const app = makeApp();
    const res = await app.request("/verify", {
      headers: {
        "x-forwarded-host": "app.localhost",
        "x-forwarded-proto": "https",
        "x-forwarded-uri": "/api/v1/deployments",
      },
    });
    expect(res.status).toBe(200);
  });

  it("passes through any /api/ subpath via default wildcard exemption", async () => {
    const app = makeApp();
    const res = await app.request("/verify", {
      headers: {
        "x-forwarded-host": "coolify.localhost",
        "x-forwarded-proto": "https",
        "x-forwarded-uri": "/api/v2/something",
      },
    });
    expect(res.status).toBe(200);
  });

  it("redirects unauthenticated users on own-domain hosts", async () => {
    const app = makeApp();
    const res = await app.request("/verify", {
      headers: {
        "x-forwarded-host": "protected.localhost",
        "x-forwarded-proto": "https",
        "x-forwarded-uri": "/dashboard",
      },
    });
    expect(res.status).toBe(302);
    const location = res.headers.get("location") || "";
    expect(location).toContain("/auth/login");
    expect(location).toContain("redirect=");
  });

  it("passes through open (unprotected) hosts", async () => {
    addService("open.localhost", "Open Host", false);

    const app = makeApp();
    const res = await app.request("/verify", {
      headers: {
        "x-forwarded-host": "open.localhost",
        "x-forwarded-proto": "https",
        "x-forwarded-uri": "/public-page",
      },
    });
    expect(res.status).toBe(200);

    removeService("open.localhost");
  });

  it("auto-discovers and protects unknown own-domain hosts", async () => {
    const testHost = `discover-${Date.now()}.localhost`;
    const app = makeApp();

    const res = await app.request("/verify", {
      headers: {
        "x-forwarded-host": testHost,
        "x-forwarded-proto": "https",
        "x-forwarded-uri": "/",
      },
    });
    // Auto-discovered as protected → redirect to login
    expect(res.status).toBe(302);

    removeService(testHost);
  });

  it("rejects foreign domain hosts with 403", async () => {
    const app = makeApp();
    const res = await app.request("/verify", {
      headers: {
        "x-forwarded-host": "www.google-analytics.com",
        "x-forwarded-proto": "https",
        "x-forwarded-uri": "/",
      },
    });
    expect(res.status).toBe(403);
  });

  it("strips www. prefix and normalises host", async () => {
    const testHost = `wwwtest-${Date.now()}.localhost`;
    registerHost(testHost);

    const app = makeApp();
    // Access with www. prefix — should resolve to the same host
    const res = await app.request("/verify", {
      headers: {
        "x-forwarded-host": `www.${testHost}`,
        "x-forwarded-proto": "https",
        "x-forwarded-uri": "/",
      },
    });
    // Should redirect to login (host is known and protected), not 403
    expect(res.status).toBe(302);

    removeService(testHost);
  });

  it("passes through authenticated users on protected hosts", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await sign(
      { email: "user@quantum.media", name: "User", iat: now, exp: now + 3600 },
      CONFIG.JWT_SECRET,
    );

    const testHost = `auth-${Date.now()}.localhost`;
    registerHost(testHost);

    const app = makeApp();
    const res = await app.request("/verify", {
      headers: {
        "x-forwarded-host": testHost,
        "x-forwarded-proto": "https",
        "x-forwarded-uri": "/dashboard",
        Cookie: `${CONFIG.COOKIE_NAME}=${token}`,
      },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("x-auth-user")).toBe("user@quantum.media");

    removeService(testHost);
  });

  it("redirect URL includes original proto, host and URI", async () => {
    const app = makeApp();
    const res = await app.request("/verify", {
      headers: {
        "x-forwarded-host": "myapp.localhost",
        "x-forwarded-proto": "https",
        "x-forwarded-uri": "/deep/path?query=1",
      },
    });
    expect(res.status).toBe(302);
    const location = res.headers.get("location") || "";
    expect(location).toContain(
      encodeURIComponent("https://myapp.localhost/deep/path?query=1"),
    );
  });

  it("handles host header with port number", async () => {
    const app = makeApp();
    const res = await app.request("/verify", {
      headers: {
        "x-forwarded-host": "localhost:3099",
        "x-forwarded-proto": "http",
        "x-forwarded-uri": "/",
      },
    });
    expect(res.status).toBe(200);
  });

  it("defaults proto to https and uri to /", async () => {
    const app = makeApp();
    const res = await app.request("/verify", {
      headers: {
        "x-forwarded-host": "unknown.localhost",
      },
    });
    expect(res.status).toBe(302);
    const location = res.headers.get("location") || "";
    expect(location).toContain("https%3A%2F%2Funknown.localhost%2F");
  });
});
