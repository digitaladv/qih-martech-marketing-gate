function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Anthropic docs explaining where the claude_desktop_config.json lives. */
const CLAUDE_DESKTOP_DOCS_URL =
  "https://modelcontextprotocol.io/quickstart/user";

/**
 * Build the claude_desktop_config.json snippet for a given MCP server URL and
 * access token. The token is embedded directly in the `--header` argument
 * using the `X-API-Key:<token>` form (no space) — mcp-remote splits `--header`
 * values on whitespace, so a single colon-joined string is the safe pattern.
 * Ref: https://www.npmjs.com/package/mcp-remote#custom-headers
 */
export function buildClaudeDesktopSnippet(
  mcpServerUrl: string,
  token: string,
): string {
  const config = {
    mcpServers: {
      analytics: {
        command: "npx",
        args: [
          "-y",
          "mcp-remote",
          mcpServerUrl,
          "--header",
          `X-API-Key:${token}`,
        ],
      },
    },
  };
  return JSON.stringify(config, null, 2);
}

/**
 * Bridge page for issuing short-lived MCP access tokens.
 * User must already be authenticated via the QG session cookie.
 * Inline scripts are permitted by the CSP (`script-src 'unsafe-inline'`).
 */
export function mcpTokenPageHtml(email: string, mcpServerUrl: string): string {
  const safeEmail = esc(email);
  // Placeholder snippet rendered with a stub token. The real token is injected
  // client-side after the POST succeeds. The URL is already baked in.
  const placeholderSnippet = buildClaudeDesktopSnippet(
    mcpServerUrl,
    "<TOKEN_WILL_APPEAR_HERE>",
  );
  const safePlaceholder = esc(placeholderSnippet);
  const safeMcpUrl = esc(mcpServerUrl);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP Access Token — Quantum Gate</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Inter', ui-sans-serif, system-ui, sans-serif;
      background: #f8fafe;
      color: #3d4449;
      min-height: 100vh;
      padding: 32px 16px;
    }
    .container { max-width: 720px; margin: 0 auto; }
    .card {
      background: white;
      border-radius: 16px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.06);
      border: 1px solid #e2e8f0;
      overflow: hidden;
    }
    .card-header {
      background: linear-gradient(135deg, #0086ff 0%, #0070d6 50%, #004d94 100%);
      padding: 24px 32px;
      color: white;
    }
    .card-header h1 { font-size: 1.3rem; font-weight: 700; margin-bottom: 4px; }
    .card-header p { font-size: 0.85rem; opacity: 0.85; }
    .card-body { padding: 28px 32px; }
    .user-row {
      display: flex; align-items: center; justify-content: space-between;
      padding: 12px 16px; background: #f1f5f9; border-radius: 10px;
      font-size: 0.85rem; margin-bottom: 20px;
    }
    .user-row strong { font-weight: 600; color: #3d4449; }
    .user-row a { color: #5a6268; text-decoration: none; font-size: 0.8rem; }
    .user-row a:hover { color: #0086ff; }
    .chooser {
      background: #e8f4ff; border: 1px solid #bfdbfe; border-radius: 10px;
      padding: 14px 18px; font-size: 0.85rem; line-height: 1.6;
      color: #1e3a8a; margin-bottom: 20px;
    }
    .chooser strong { color: #0c1e5c; }
    .chooser ul { margin: 6px 0 0 20px; padding: 0; }
    .chooser code {
      background: #dbeafe; padding: 1px 6px; border-radius: 4px;
      font-family: 'JetBrains Mono', monospace; font-size: 0.78rem;
      word-break: break-all;
    }
    .generate-btn {
      width: 100%; padding: 14px 24px;
      background: #0086ff; color: white; border: none;
      border-radius: 100px; font-family: inherit; font-weight: 600;
      font-size: 0.95rem; cursor: pointer; transition: all 0.2s;
    }
    .generate-btn:hover { background: #0070d6; transform: translateY(-1px); }
    .generate-btn:disabled { background: #cbd5e0; cursor: not-allowed; transform: none; }
    .token-section { margin-top: 28px; display: none; }
    .token-section.visible { display: block; }
    .block { margin-bottom: 22px; }
    .block-title {
      font-size: 0.95rem; font-weight: 700; color: #3d4449;
      margin-bottom: 4px;
    }
    .block-subtitle {
      font-size: 0.8rem; color: #5a6268; margin-bottom: 10px; line-height: 1.5;
    }
    .block-subtitle a { color: #0086ff; text-decoration: none; }
    .block-subtitle a:hover { text-decoration: underline; }
    .code-area {
      width: 100%; padding: 14px;
      border: 1px solid #e2e8f0; border-radius: 10px;
      font-family: 'JetBrains Mono', monospace; font-size: 0.78rem;
      color: #3d4449; background: #f8fafe;
      resize: vertical; word-break: break-all;
    }
    .code-area.snippet { min-height: 220px; word-break: normal; white-space: pre; overflow-x: auto; }
    .code-area.token { min-height: 110px; }
    .meta-row {
      display: flex; justify-content: space-between; align-items: center;
      margin-top: 10px; font-size: 0.78rem; color: #5a6268;
    }
    .copy-btn {
      padding: 8px 18px; background: white; color: #0086ff;
      border: 1px solid #0086ff; border-radius: 100px;
      font-family: inherit; font-weight: 600; font-size: 0.8rem; cursor: pointer;
    }
    .copy-btn:hover { background: #e8f4ff; }
    .copy-btn.copied { background: #10b395; color: white; border-color: #10b395; }
    .path-hint {
      background: #fffbeb; border: 1px solid #fde68a; border-radius: 10px;
      padding: 12px 16px; font-size: 0.8rem; color: #78350f;
      margin-top: 10px; line-height: 1.6;
    }
    .path-hint code {
      background: #fef3c7; padding: 1px 6px; border-radius: 4px;
      font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;
      word-break: break-all;
    }
    .error {
      margin-top: 16px; padding: 12px 16px;
      background: #fef2f2; border: 1px solid #fecaca; border-radius: 10px;
      color: #991b1b; font-size: 0.85rem; display: none;
    }
    .error.visible { display: block; }
    .divider {
      border: 0; border-top: 1px solid #e2e8f0; margin: 24px 0;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="card-header">
        <h1>MCP Access Token</h1>
        <p>Connect Claude Desktop (or another MCP client) to the analytics server</p>
      </div>
      <div class="card-body">
        <div class="user-row">
          <div>Signed in as <strong>${safeEmail}</strong></div>
          <a href="/auth/logout">Sign out</a>
        </div>

        <div class="chooser">
          <strong>Most users:</strong> add the connector directly in
          Claude Desktop's <em>Settings → Connectors → Add Custom Connector</em>
          using the URL <code>${safeMcpUrl}</code>. Claude will handle sign-in
          automatically. This page is for CLI and advanced users only.
          <br><br>
          <strong>Which one do I copy below?</strong>
          <ul>
            <li><strong>Claude Desktop (manual config):</strong> copy the JSON snippet into your config file.</li>
            <li><strong>Claude Code CLI or another MCP client:</strong> use the raw token.</li>
          </ul>
        </div>

        <button id="generateBtn" class="generate-btn" onclick="generateToken()">
          Generate Token
        </button>

        <div id="errorBox" class="error"></div>

        <div id="tokenSection" class="token-section">
          <div class="block">
            <div class="block-title">For Claude Desktop — claude_desktop_config.json</div>
            <div class="block-subtitle">
              Paste this into your Claude Desktop config file.
              <a href="${esc(CLAUDE_DESKTOP_DOCS_URL)}" target="_blank" rel="noopener noreferrer">How to find the file</a>.
              If the file already has other MCP servers, merge the <code>analytics</code> entry into the existing <code>mcpServers</code> object.
            </div>
            <textarea id="snippetArea" class="code-area snippet" readonly data-mcp-url="${safeMcpUrl}">${safePlaceholder}</textarea>
            <div class="meta-row">
              <span id="snippetHint">Token will appear above after generating.</span>
              <button id="copySnippetBtn" class="copy-btn" onclick="copySnippet()">Copy JSON</button>
            </div>
            <div class="path-hint">
              <strong>Config file location:</strong><br>
              macOS: <code>~/Library/Application Support/Claude/claude_desktop_config.json</code><br>
              Windows: <code>%APPDATA%\\Claude\\claude_desktop_config.json</code><br>
              After editing, fully quit and relaunch Claude Desktop.
            </div>
          </div>

          <hr class="divider">

          <div class="block">
            <div class="block-title">Raw token — for Claude Code CLI or custom clients</div>
            <div class="block-subtitle">
              Use this as the <code>X-API-Key</code> header when calling the MCP server directly.
            </div>
            <textarea id="tokenArea" class="code-area token" readonly></textarea>
            <div class="meta-row">
              <span id="tokenExpiry"></span>
              <button id="copyTokenBtn" class="copy-btn" onclick="copyToken()">Copy token</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    function buildSnippet(mcpUrl, token) {
      const config = {
        mcpServers: {
          analytics: {
            command: "npx",
            args: [
              "-y",
              "mcp-remote",
              mcpUrl,
              "--header",
              "X-API-Key:" + token,
            ],
          },
        },
      };
      return JSON.stringify(config, null, 2);
    }

    async function generateToken() {
      const btn = document.getElementById('generateBtn');
      const errorBox = document.getElementById('errorBox');
      const tokenSection = document.getElementById('tokenSection');
      const tokenArea = document.getElementById('tokenArea');
      const tokenExpiry = document.getElementById('tokenExpiry');
      const snippetArea = document.getElementById('snippetArea');
      const snippetHint = document.getElementById('snippetHint');

      btn.disabled = true;
      btn.textContent = 'Generating...';
      errorBox.classList.remove('visible');
      errorBox.textContent = '';

      try {
        const res = await fetch('/auth/mcp-token', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
        });
        if (!res.ok) {
          throw new Error('Request failed: ' + res.status);
        }
        const data = await res.json();
        tokenArea.value = data.token;
        const mcpUrl = data.mcp_server_url || snippetArea.dataset.mcpUrl;
        snippetArea.value = buildSnippet(mcpUrl, data.token);
        const expiresAt = new Date(data.expires_at * 1000);
        tokenExpiry.textContent = 'Expires ' + expiresAt.toLocaleString();
        snippetHint.textContent = 'Ready to copy. Expires ' + expiresAt.toLocaleString();
        tokenSection.classList.add('visible');
        btn.textContent = 'Regenerate Token';
      } catch (err) {
        errorBox.textContent = 'Failed to generate token. Your session may have expired — try reloading the page.';
        errorBox.classList.add('visible');
        btn.textContent = 'Generate Token';
      } finally {
        btn.disabled = false;
      }
    }

    async function copyArea(areaId, btnId) {
      const area = document.getElementById(areaId);
      const btn = document.getElementById(btnId);
      try {
        await navigator.clipboard.writeText(area.value);
      } catch {
        area.select();
        document.execCommand('copy');
      }
      const orig = btn.textContent;
      btn.classList.add('copied');
      btn.textContent = 'Copied';
      setTimeout(() => {
        btn.classList.remove('copied');
        btn.textContent = orig;
      }, 1500);
    }

    function copyToken() { copyArea('tokenArea', 'copyTokenBtn'); }
    function copySnippet() { copyArea('snippetArea', 'copySnippetBtn'); }
  </script>
</body>
</html>`;
}
