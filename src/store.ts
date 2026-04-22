import fs from "node:fs";
import path from "node:path";

export interface ServiceEntry {
  name: string;
  protected: boolean;
  discoveredAt: string;
}

export interface ApiExemption {
  host: string;
  pathPrefix: string;
  label: string;
  createdAt: string;
}

export interface OAuthClient {
  /** Client identifier (stable, human-readable). */
  client_id: string;
  /** Display name shown in audit logs / future consent screens. */
  name: string;
  /**
   * Allowed redirect URIs. Each entry supports a single `*` wildcard; matched
   * via prefix+suffix so `http://localhost/*` matches `http://localhost:53412/cb`.
   */
  redirect_uris: string[];
}

export interface LoginRecord {
  email: string;
  name: string;
  timestamp: string;
  ip: string;
}

export interface UserRecord {
  email: string;
  name: string;
  lastLogin: string;
  loginCount: number;
}

interface StoreData {
  services: Record<string, ServiceEntry>;
  admins: string[];
  users: Record<string, UserRecord>;
  recentLogins: LoginRecord[];
  apiExemptions: ApiExemption[];
  oauthClients: Record<string, OAuthClient>;
}

const DEFAULT_EXEMPTIONS: ApiExemption[] = [
  {
    host: "*",
    pathPrefix: "/api/",
    label: "All API paths (legacy default)",
    createdAt: new Date().toISOString(),
  },
];

/**
 * Pre-registered OAuth 2.1 clients. Seeded on first boot when
 * `oauthClients` is empty. Admins can hand-edit services.json to add more.
 * Wildcard redirect matching: each URI supports a single `*` wildcard for
 * Claude Desktop / Claude Code which bind an ephemeral localhost port, and
 * for Claude.ai whose callback path embeds a per-organization id.
 */
const DEFAULT_OAUTH_CLIENTS: Record<string, OAuthClient> = {
  "claude-desktop": {
    client_id: "claude-desktop",
    name: "Claude Desktop",
    redirect_uris: ["http://localhost/*", "http://127.0.0.1/*"],
  },
  "claude-code": {
    client_id: "claude-code",
    name: "Claude Code CLI",
    redirect_uris: ["http://localhost/*", "http://127.0.0.1/*"],
  },
  "claude-web": {
    client_id: "claude-web",
    name: "Claude.ai Web",
    redirect_uris: ["https://claude.ai/api/organizations/*/mcp/oauth/*"],
  },
};

const DATA_DIR = process.env.DATA_DIR || path.resolve(process.cwd(), "data");
const STORE_FILE = path.join(DATA_DIR, "services.json");
const MAX_LOGINS = 100;

let data: StoreData = {
  services: {},
  admins: [],
  users: {},
  recentLogins: [],
  apiExemptions: [],
  oauthClients: {},
};

function load() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (fs.existsSync(STORE_FILE)) {
    try {
      const raw = JSON.parse(fs.readFileSync(STORE_FILE, "utf-8"));
      data = {
        services: {},
        admins: [],
        users: {},
        recentLogins: [],
        apiExemptions: [],
        oauthClients: {},
        ...raw,
      };
    } catch {
      console.error("[store] Failed to parse services.json, starting fresh");
    }
  }
  // Seed defaults (idempotent): mutate in-memory state first, then persist
  // once. Combining the two seeds into a single persist() call avoids a
  // double-write that can race across parallel processes (observed in the
  // vitest parallel worker setup).
  let seeded = false;
  if (data.apiExemptions.length === 0) {
    data.apiExemptions = [...DEFAULT_EXEMPTIONS];
    seeded = true;
  }
  if (Object.keys(data.oauthClients).length === 0) {
    data.oauthClients = { ...DEFAULT_OAUTH_CLIENTS };
    seeded = true;
  }
  if (seeded) persist();
}

function persist() {
  // Unique tmp filename per call so concurrent processes (e.g. parallel
  // vitest workers) don't race on the same tmp path. A previous single-tmp
  // design observed ENOENT on rename when one worker's rename had just moved
  // the tmp away before another finished writing.
  const tmp = `${STORE_FILE}.tmp.${process.pid}.${Date.now()}.${Math.random()
    .toString(36)
    .slice(2)}`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  try {
    fs.renameSync(tmp, STORE_FILE);
  } catch (err) {
    // Best-effort cleanup — on some platforms rename fails across devices
    // or if the destination has just been atomically replaced by a peer.
    try {
      fs.unlinkSync(tmp);
    } catch {}
    throw err;
  }
}

load();

// --- Services ---

export function getServices(): Record<string, ServiceEntry> {
  return { ...data.services };
}

export function isHostProtected(host: string): {
  known: boolean;
  protected: boolean;
} {
  const entry = data.services[host];
  if (!entry) return { known: false, protected: true };
  return { known: true, protected: entry.protected };
}

export function registerHost(host: string): ServiceEntry {
  if (data.services[host]) return data.services[host];
  const entry: ServiceEntry = {
    name: host.split(".")[0],
    protected: true,
    discoveredAt: new Date().toISOString(),
  };
  data.services[host] = entry;
  persist();
  return entry;
}

export function setProtection(host: string, isProtected: boolean): boolean {
  if (!data.services[host]) return false;
  data.services[host].protected = isProtected;
  persist();
  return true;
}

export function addService(host: string, name: string, isProtected: boolean) {
  data.services[host] = {
    name,
    protected: isProtected,
    discoveredAt: new Date().toISOString(),
  };
  persist();
}

export function removeService(host: string): boolean {
  if (!data.services[host]) return false;
  delete data.services[host];
  persist();
  return true;
}

export function updateServiceName(host: string, name: string): boolean {
  if (!data.services[host]) return false;
  data.services[host].name = name;
  persist();
  return true;
}

// --- Admins ---

export function isAdmin(email: string): boolean {
  return data.admins.includes(email);
}

export function getAdmins(): string[] {
  return [...data.admins];
}

export function addAdmin(email: string): boolean {
  if (data.admins.includes(email)) return false;
  data.admins.push(email);
  persist();
  return true;
}

export function removeAdmin(email: string): boolean {
  const idx = data.admins.indexOf(email);
  if (idx === -1) return false;
  data.admins.splice(idx, 1);
  persist();
  return true;
}

// --- Login log ---

export function recordLogin(email: string, name: string, ip: string) {
  // Update user record
  const existing = data.users[email];
  data.users[email] = {
    email,
    name,
    lastLogin: new Date().toISOString(),
    loginCount: (existing?.loginCount || 0) + 1,
  };

  // Append to recent logins log
  data.recentLogins.unshift({
    email,
    name,
    timestamp: new Date().toISOString(),
    ip,
  });
  if (data.recentLogins.length > MAX_LOGINS)
    data.recentLogins.length = MAX_LOGINS;
  persist();
}

export function getRecentLogins(): LoginRecord[] {
  return data.recentLogins;
}

// --- Users ---

export function getUsers(): Record<string, UserRecord> {
  return { ...data.users };
}

export function getUser(email: string): UserRecord | null {
  return data.users[email] ?? null;
}

// --- API Exemptions ---

export function getApiExemptions(): ApiExemption[] {
  return [...data.apiExemptions];
}

/** Check if a host+uri combination is exempt from auth. */
export function isApiExempt(host: string, uri: string): boolean {
  return data.apiExemptions.some(
    (ex) =>
      (ex.host === "*" || ex.host === host) && uri.startsWith(ex.pathPrefix),
  );
}

export function addApiExemption(
  host: string,
  pathPrefix: string,
  label: string,
): boolean {
  const exists = data.apiExemptions.some(
    (e) => e.host === host && e.pathPrefix === pathPrefix,
  );
  if (exists) return false;
  data.apiExemptions.push({
    host,
    pathPrefix,
    label,
    createdAt: new Date().toISOString(),
  });
  persist();
  return true;
}

export function removeApiExemption(host: string, pathPrefix: string): boolean {
  const idx = data.apiExemptions.findIndex(
    (e) => e.host === host && e.pathPrefix === pathPrefix,
  );
  if (idx === -1) return false;
  data.apiExemptions.splice(idx, 1);
  persist();
  return true;
}

// --- OAuth clients ---

export function getOAuthClient(clientId: string): OAuthClient | null {
  return data.oauthClients[clientId] ?? null;
}

export function getOAuthClients(): Record<string, OAuthClient> {
  return { ...data.oauthClients };
}

/**
 * Check if a given redirect URI is permitted for a pre-registered client.
 *
 * Two supported pattern forms:
 *   1. Exact URL — used for stable production callbacks.
 *   2. Wildcard URL — URL parsed, scheme + hostname must match exactly; port
 *      and path may contain `*` which stands in for one-or-more characters.
 *      This is how `http://localhost/*` matches any
 *      `http://localhost:<port>/<path>` — Claude Desktop/Code bind an
 *      ephemeral localhost port per session. `https://claude.ai/api/organizations/*‍/mcp/oauth/*`
 *      matches any organization id + any callback path under it.
 *
 * We reject wildcard matches that would leave the wildcard segment empty
 * (so `http://localhost/` doesn't match `http://localhost/*`).
 */
export function isRedirectUriAllowed(
  client: OAuthClient,
  redirectUri: string,
): boolean {
  return client.redirect_uris.some((pattern) =>
    matchRedirectPattern(pattern, redirectUri),
  );
}

function escapeRegex(s: string): string {
  return s.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
}

function wildcardToRegex(segment: string): RegExp {
  // Split around each `*`, escape literal pieces, rejoin with `.+` (one-or-more
  // so wildcards never match empty segments).
  const parts = segment.split("*").map(escapeRegex);
  return new RegExp(`^${parts.join(".+")}$`);
}

function matchRedirectPattern(pattern: string, redirectUri: string): boolean {
  if (!pattern.includes("*")) return pattern === redirectUri;

  let patternUrl: URL;
  let candidateUrl: URL;
  try {
    // Replace `*` with a placeholder that's guaranteed valid in URL parsing,
    // then parse — this lets us inspect authority vs path separately even
    // when the wildcard sits in a position that would otherwise trip the
    // parser (e.g. `http://localhost/*` — actually parses fine, but
    // `http://*.example.com/` would not).
    patternUrl = new URL(pattern.replace(/\*/g, "__WILDCARD__"));
    candidateUrl = new URL(redirectUri);
  } catch {
    return false;
  }

  if (patternUrl.protocol !== candidateUrl.protocol) return false;

  // Hostname must match either exactly or via wildcard in pattern.
  const patternHost = patternUrl.hostname.replace(/__WILDCARD__/g, "*");
  if (patternHost.includes("*")) {
    if (!wildcardToRegex(patternHost).test(candidateUrl.hostname)) {
      return false;
    }
  } else if (patternHost !== candidateUrl.hostname) {
    return false;
  }

  // Port: a wildcard pattern with NO explicit port allows any port on the
  // candidate (common localhost case). Otherwise ports must be equal.
  if (patternUrl.port) {
    if (patternUrl.port !== candidateUrl.port) return false;
  }

  // Path: exact string or wildcard match. Always include search/hash in the
  // compared candidate path so patterns like `/cb` don't accidentally accept
  // `/cb?evil=1`.
  const patternPath =
    patternUrl.pathname.replace(/__WILDCARD__/g, "*") +
    patternUrl.search.replace(/__WILDCARD__/g, "*") +
    patternUrl.hash.replace(/__WILDCARD__/g, "*");
  const candidatePath =
    candidateUrl.pathname + candidateUrl.search + candidateUrl.hash;

  if (patternPath.includes("*")) {
    return wildcardToRegex(patternPath).test(candidatePath);
  }
  return patternPath === candidatePath;
}
