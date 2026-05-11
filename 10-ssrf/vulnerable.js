const http = require('http');
const https = require('https');
const url = require('url');

const PORT = 3010;

// Simulated AWS metadata response shown when the metadata endpoint is requested
const SIMULATED_METADATA = JSON.stringify({
  instanceId: 'i-1234567890abcdef0',
  region: 'us-east-1',
  availabilityZone: 'us-east-1a',
  instanceType: 't2.micro',
  iamSecurityCredentials: {
    'ec2-role-name': {
      AccessKeyId: 'ASIAIOSFODNN7EXAMPLE',
      SecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      Token: 'AQoDYXdzEJr//////////wEaoAK1wvxJY12r2IHXpqtzCMrDc...',
      Expiration: '2024-01-15T23:59:59Z',
    },
  },
  userData: 'DATABASE_PASSWORD=supersecret123\nINTERNAL_API_KEY=sk_live_abc123xyz',
}, null, 2);

function isMetadataEndpoint(hostname) {
  // AWS metadata IP and common variants
  return hostname === '169.254.169.254' || hostname === 'metadata.internal';
}

function fetchUrl(targetUrl, callback) {
  try {
    const parsed = new URL(targetUrl);
    const client = parsed.protocol === 'https:' ? https : http;

    const req = client.get(targetUrl, { timeout: 3000 }, (res) => {
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

function getHomePage(fetchedUrl, result, error) {
  const exampleUrls = [
    { url: 'http://localhost:3009/logs', label: 'Internal log viewer (demo #09)', danger: 'high' },
    { url: 'http://127.0.0.1:3009/', label: 'Localhost service (any port)', danger: 'high' },
    { url: 'http://169.254.169.254', label: 'AWS EC2 metadata endpoint', danger: 'critical' },
    { url: 'http://localhost:3011/', label: 'Another internal demo server', danger: 'medium' },
    { url: 'https://example.com', label: 'Public URL (safe)', danger: 'none' },
  ];

  const dangerColors = { none: '#4caf50', medium: '#f9a825', high: '#ff7043', critical: '#e94560' };
  const dangerLabels = { none: 'Safe', medium: 'Internal', high: 'Internal', critical: 'Critical' };

  const exampleRows = exampleUrls.map(e => `
    <tr>
      <td><code style="font-size:12px;">${e.url}</code></td>
      <td>${e.label}</td>
      <td style="color:${dangerColors[e.danger]};font-weight:bold;">${dangerLabels[e.danger]}</td>
      <td>
        <a href="/fetch?url=${encodeURIComponent(e.url)}"
           style="color:#4fc3f7;font-size:12px;">Fetch &rarr;</a>
      </td>
    </tr>`).join('');

  let resultHtml = '';
  if (fetchedUrl) {
    if (error) {
      resultHtml = `
        <div class="result-box error">
          <div class="result-label">Error fetching: ${fetchedUrl}</div>
          <pre>${error}</pre>
        </div>`;
    } else {
      resultHtml = `
        <div class="result-box">
          <div class="result-label">Response from: <strong>${fetchedUrl}</strong> (HTTP ${result.status})</div>
          <pre>${result.body.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>
        </div>`;
    }
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>10 - SSRF (VULNERABLE)</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee; min-height: 100vh; padding: 30px 20px; }
    h1 { color: #e94560; margin-bottom: 6px; }
    .subtitle { color: #aaa; margin-bottom: 24px; font-size: 14px; }
    .warning-banner {
      background: #3d0000; border: 2px solid #e94560; border-radius: 8px;
      padding: 16px 20px; margin-bottom: 24px;
    }
    .warning-banner h2 { color: #ff6b6b; margin-bottom: 8px; font-size: 16px; }
    .warning-banner p { color: #ffaaaa; font-size: 14px; line-height: 1.6; }
    .card { background: #16213e; border-radius: 10px; padding: 24px; margin-bottom: 20px; border: 1px solid #0f3460; }
    .card h2 { margin-bottom: 16px; font-size: 16px; color: #a8dadc; }
    .input-row { display: flex; gap: 10px; }
    input[type=text] {
      flex: 1; padding: 10px 14px; border-radius: 6px; border: 1px solid #0f3460;
      background: #0d1b2a; color: #eee; font-size: 14px;
    }
    button {
      padding: 10px 22px; border-radius: 6px; border: none;
      background: #e94560; color: #fff; font-size: 14px; cursor: pointer;
    }
    button:hover { background: #c73652; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; color: #888; font-weight: 600; padding: 6px 10px; border-bottom: 1px solid #0f3460; }
    td { padding: 7px 10px; border-bottom: 1px solid #0a1628; vertical-align: top; }
    .result-box {
      background: #0d1117; border: 1px solid #30363d; border-radius: 8px;
      padding: 16px; margin-top: 16px;
    }
    .result-box.error { border-color: #e94560; }
    .result-label { font-size: 13px; color: #888; margin-bottom: 8px; }
    pre { font-family: 'Courier New', monospace; font-size: 12px; color: #7ee787;
          white-space: pre-wrap; word-break: break-all; max-height: 350px; overflow-y: auto; }
    .result-box.error pre { color: #ff8a80; }
  </style>
</head>
<body>
  <h1>10 — Server-Side Request Forgery (SSRF)</h1>
  <p class="subtitle">VULNERABLE version — running on port ${PORT}</p>

  <div class="warning-banner">
    <h2>&#9888; VULNERABILITY ACTIVE: No URL validation whatsoever</h2>
    <p>
      This server will fetch ANY URL you provide — including localhost services, internal networks,
      and cloud provider metadata endpoints. The server acts as a proxy that bypasses your firewall.
    </p>
  </div>

  <div class="card">
    <h2>URL Preview Tool (Vulnerable)</h2>
    <form method="GET" action="/fetch">
      <div class="input-row">
        <input type="text" name="url" placeholder="Enter any URL..." value="${fetchedUrl || ''}" autocomplete="off">
        <button type="submit">Fetch</button>
      </div>
    </form>
    ${resultHtml}
  </div>

  <div class="card">
    <h2>Attack Examples — Click to Try</h2>
    <table>
      <thead>
        <tr>
          <th>URL</th><th>What it exposes</th><th>Risk</th><th>Try it</th>
        </tr>
      </thead>
      <tbody>${exampleRows}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>Why This Is Dangerous</h2>
    <ul style="padding-left:20px;line-height:1.9;font-size:14px;color:#ccc;">
      <li>Attacker cannot reach <code>169.254.169.254</code> directly from their browser</li>
      <li>But they trick <em>your server</em> into fetching it — which CAN reach it</li>
      <li>Cloud metadata returns IAM credentials, secrets, and internal config</li>
      <li>Any internal microservice on localhost is now exposed to the world</li>
      <li>Even if internal services have no auth — they trust requests from localhost</li>
    </ul>
  </div>
</body>
</html>`;
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  if (req.method === 'GET' && pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(getHomePage(null, null, null));
    return;
  }

  if (req.method === 'GET' && pathname === '/fetch') {
    const targetUrl = parsed.query.url;
    if (!targetUrl) {
      res.writeHead(302, { Location: '/' });
      res.end();
      return;
    }

    // Educational: simulate metadata endpoint response instead of actually trying to connect
    let parsedTarget;
    try {
      parsedTarget = new URL(targetUrl);
    } catch (e) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(getHomePage(targetUrl, null, `Invalid URL: ${e.message}`));
      return;
    }

    if (isMetadataEndpoint(parsedTarget.hostname)) {
      // Return simulated metadata — educational demo of what the attack would reveal
      const simulatedBody = `SIMULATED AWS EC2 Metadata Response
=====================================
In a real attack, this endpoint returns actual credentials.
This is a simulation for educational purposes.

${SIMULATED_METADATA}`;
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(getHomePage(targetUrl, { status: 200, body: simulatedBody }, null));
      return;
    }

    // ❌ VULNERABLE: fetches ANY URL with no validation
    fetchUrl(targetUrl, (err, result) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      if (err) {
        res.end(getHomePage(targetUrl, null, err.message));
      } else {
        res.end(getHomePage(targetUrl, result, null));
      }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`[10-ssrf] VULNERABLE server running on http://localhost:${PORT}`);
});
