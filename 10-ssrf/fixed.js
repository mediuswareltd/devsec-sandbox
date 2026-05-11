const http = require('http');
const https = require('https');
const url = require('url');

const PORT = 3110;

// ✅ FIX 1: Block private/internal IP ranges and hostnames
function isPrivateIP(hostname) {
  const privatePatterns = [
    /^localhost$/i,
    /^127\./,
    /^10\./,
    /^192\.168\./,
    /^172\.(1[6-9]|2[0-9]|3[01])\./,
    /^169\.254\./,   // AWS/Azure/GCP metadata
    /^::1$/,         // IPv6 localhost
    /^0\./,          // 0.0.0.0/8
    /^fc00:/i,       // IPv6 unique local
    /^fe80:/i,       // IPv6 link-local
  ];
  return privatePatterns.some(p => p.test(hostname));
}

// ✅ FIX 2: Validate URL before making any request
function validateUrl(urlString) {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch (e) {
    return { allowed: false, reason: `Invalid URL format: ${e.message}` };
  }

  // Only allow http and https
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return {
      allowed: false,
      reason: `Protocol "${parsed.protocol}" is not allowed. Only http: and https: are permitted.`,
    };
  }

  // Block private IPs and localhost
  if (isPrivateIP(parsed.hostname)) {
    return {
      allowed: false,
      reason: `Host "${parsed.hostname}" is a private/internal address. Requests to internal networks are blocked to prevent SSRF attacks.`,
    };
  }

  // Block numeric IPs that could be private (basic check for decimal-encoded IPs)
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const ipMatch = parsed.hostname.match(ipv4Regex);
  if (ipMatch) {
    const [, a, b, c, d] = ipMatch.map(Number);
    if (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      a === 0
    ) {
      return {
        allowed: false,
        reason: `IP address "${parsed.hostname}" is in a private/reserved range and is blocked.`,
      };
    }
  }

  return { allowed: true, parsed };
}

function fetchUrl(targetUrl, callback) {
  try {
    const parsed = new URL(targetUrl);
    const client = parsed.protocol === 'https:' ? https : http;

    // ✅ FIX 3: Disable redirects to prevent redirect-based SSRF bypass
    const options = {
      timeout: 3000,
      // Do not follow redirects automatically — we check each one
    };

    const req = client.get(targetUrl, options, (res) => {
      // ✅ FIX 4: If server redirects, validate the redirect target too
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        const redirectTarget = res.headers.location;
        const validation = validateUrl(redirectTarget);
        if (!validation.allowed) {
          return callback(new Error(`Redirect blocked: ${validation.reason}`));
        }
      }

      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => callback(null, { status: res.statusCode, body: body.substring(0, 2000) }));
    });
    req.on('error', err => callback(err));
    req.on('timeout', () => { req.destroy(); callback(new Error('Request timed out')); });
  } catch (e) {
    callback(e);
  }
}

function getHomePage(fetchedUrl, result, error, blockedReason) {
  const exampleUrls = [
    { url: 'http://localhost:3009/logs', label: 'Internal service (localhost)', blocked: true },
    { url: 'http://127.0.0.1:3009/', label: 'Loopback IP', blocked: true },
    { url: 'http://169.254.169.254', label: 'AWS metadata endpoint', blocked: true },
    { url: 'http://10.0.0.1', label: 'Private network (10.x)', blocked: true },
    { url: 'file:///etc/passwd', label: 'File protocol', blocked: true },
    { url: 'https://example.com', label: 'Public HTTPS URL', blocked: false },
  ];

  const exampleRows = exampleUrls.map(e => `
    <tr>
      <td><code style="font-size:12px;">${e.url}</code></td>
      <td>${e.label}</td>
      <td style="color:${e.blocked ? '#e94560' : '#4caf50'};font-weight:bold;">
        ${e.blocked ? '&#10007; Blocked' : '&#10003; Allowed'}
      </td>
      <td><a href="/fetch?url=${encodeURIComponent(e.url)}" style="color:#4fc3f7;font-size:12px;">Try &rarr;</a></td>
    </tr>`).join('');

  let resultHtml = '';
  if (fetchedUrl) {
    if (blockedReason) {
      resultHtml = `
        <div class="result-box blocked">
          <div class="result-label blocked-label">&#128274; Request Blocked: ${fetchedUrl}</div>
          <div class="blocked-reason">${blockedReason}</div>
        </div>`;
    } else if (error) {
      resultHtml = `
        <div class="result-box error">
          <div class="result-label">Error fetching: ${fetchedUrl}</div>
          <pre>${error}</pre>
        </div>`;
    } else {
      resultHtml = `
        <div class="result-box success">
          <div class="result-label">Response from: <strong>${fetchedUrl}</strong> (HTTP ${result.status})</div>
          <pre>${result.body.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>
        </div>`;
    }
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>10 - SSRF (FIXED)</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #0d1f0d; color: #eee; min-height: 100vh; padding: 30px 20px; }
    h1 { color: #4caf50; margin-bottom: 6px; }
    .subtitle { color: #aaa; margin-bottom: 24px; font-size: 14px; }
    .fixed-banner {
      background: #0a2a0a; border: 2px solid #4caf50; border-radius: 8px;
      padding: 16px 20px; margin-bottom: 24px;
    }
    .fixed-banner h2 { color: #81c784; margin-bottom: 8px; font-size: 16px; }
    .fixed-banner ul { color: #a5d6a7; font-size: 14px; line-height: 1.8; padding-left: 20px; }
    .card { background: #111f11; border-radius: 10px; padding: 24px; margin-bottom: 20px; border: 1px solid #1b4d1b; }
    .card h2 { margin-bottom: 16px; font-size: 16px; color: #a5d6a7; }
    .input-row { display: flex; gap: 10px; }
    input[type=text] {
      flex: 1; padding: 10px 14px; border-radius: 6px; border: 1px solid #1b4d1b;
      background: #0a1a0a; color: #eee; font-size: 14px;
    }
    button {
      padding: 10px 22px; border-radius: 6px; border: none;
      background: #388e3c; color: #fff; font-size: 14px; cursor: pointer;
    }
    button:hover { background: #2e7d32; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; color: #888; font-weight: 600; padding: 6px 10px; border-bottom: 1px solid #1b4d1b; }
    td { padding: 7px 10px; border-bottom: 1px solid #0a1a0a; vertical-align: top; }
    .result-box { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-top: 16px; }
    .result-box.error { border-color: #f9a825; }
    .result-box.blocked { border-color: #e94560; background: #1a0505; }
    .result-box.success { border-color: #4caf50; }
    .result-label { font-size: 13px; color: #888; margin-bottom: 8px; }
    .blocked-label { color: #ff8a80; font-weight: bold; }
    .blocked-reason { color: #ffccbc; font-size: 13px; line-height: 1.6; padding: 8px 0; }
    pre { font-family: 'Courier New', monospace; font-size: 12px; color: #7ee787;
          white-space: pre-wrap; word-break: break-all; max-height: 350px; overflow-y: auto; }
    .result-box.error pre { color: #f9a825; }
    code { font-size: 12px; color: #ce9178; }
  </style>
</head>
<body>
  <h1>10 — Server-Side Request Forgery (SSRF)</h1>
  <p class="subtitle">FIXED version — running on port ${PORT}</p>

  <div class="fixed-banner">
    <h2>&#10003; SSRF Protection Active</h2>
    <ul>
      <li>Only <code>http:</code> and <code>https:</code> protocols are allowed</li>
      <li>All private IP ranges are blocked: 127.x, 10.x, 192.168.x, 172.16–31.x, 169.254.x</li>
      <li>localhost and loopback addresses are blocked</li>
      <li>Redirect targets are also validated before following</li>
    </ul>
  </div>

  <div class="card">
    <h2>URL Preview Tool (Protected)</h2>
    <form method="GET" action="/fetch">
      <div class="input-row">
        <input type="text" name="url" placeholder="Enter a public URL..." value="${fetchedUrl || ''}" autocomplete="off">
        <button type="submit">Fetch</button>
      </div>
    </form>
    ${resultHtml}
  </div>

  <div class="card">
    <h2>Try These URLs</h2>
    <table>
      <thead>
        <tr><th>URL</th><th>What it is</th><th>Status</th><th>Try it</th></tr>
      </thead>
      <tbody>${exampleRows}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>How the Protection Works</h2>
    <pre style="color:#a5d6a7;font-size:12px;">function isPrivateIP(hostname) {
  const privatePatterns = [
    /^localhost$/i,   // Block "localhost"
    /^127\\./,         // Block 127.0.0.0/8  (loopback)
    /^10\\./,          // Block 10.0.0.0/8   (private)
    /^192\\.168\\./,    // Block 192.168.0.0/16 (private)
    /^172\\.(1[6-9]|2[0-9]|3[01])\\./,  // Block 172.16-31.x
    /^169\\.254\\./,    // Block 169.254.0.0/16 (AWS metadata)
    /^::1$/,          // Block IPv6 loopback
  ];
  return privatePatterns.some(p => p.test(hostname));
}

// Only http/https allowed — blocks file://, ftp://, gopher://
if (!['http:', 'https:'].includes(parsed.protocol)) return BLOCKED;</pre>
  </div>
</body>
</html>`;
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  if (req.method === 'GET' && pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(getHomePage(null, null, null, null));
    return;
  }

  if (req.method === 'GET' && pathname === '/fetch') {
    const targetUrl = parsed.query.url;
    if (!targetUrl) {
      res.writeHead(302, { Location: '/' });
      res.end();
      return;
    }

    // ✅ Validate before touching the network
    const validation = validateUrl(targetUrl);
    if (!validation.allowed) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(getHomePage(targetUrl, null, null, validation.reason));
      return;
    }

    fetchUrl(targetUrl, (err, result) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      if (err) {
        res.end(getHomePage(targetUrl, null, err.message, null));
      } else {
        res.end(getHomePage(targetUrl, result, null, null));
      }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`[10-ssrf] FIXED server running on http://localhost:${PORT}`);
  console.log(`SSRF protection active: private IPs, localhost, and non-http protocols are blocked.`);
});
