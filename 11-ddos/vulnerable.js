const http = require('http');

const PORT = 3011;

let totalRequests = 0;

function getHomePage(pingResults) {
  const resultsHtml = pingResults
    ? `<div class="results-box">
        <div class="results-label">Last batch results (${pingResults.length} requests):</div>
        ${pingResults.map((r, i) => `<div class="result-row ok">Request #${i + 1}: ${r}</div>`).join('')}
      </div>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>11 - DoS (VULNERABLE)</title>
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
    .counter-display {
      font-size: 48px; font-weight: bold; color: #e94560;
      text-align: center; padding: 20px 0; font-variant-numeric: tabular-nums;
    }
    .counter-label { text-align: center; color: #888; font-size: 13px; margin-top: -10px; margin-bottom: 16px; }
    .btn-row { display: flex; gap: 12px; flex-wrap: wrap; }
    button {
      padding: 12px 24px; border-radius: 6px; border: none;
      font-size: 14px; cursor: pointer; font-weight: 600;
    }
    .btn-flood { background: #e94560; color: #fff; }
    .btn-flood:hover { background: #c73652; }
    .btn-heavy { background: #f57c00; color: #fff; }
    .btn-heavy:hover { background: #e65100; }
    .btn-disabled { background: #444; color: #888; cursor: not-allowed; }
    .results-box { margin-top: 16px; background: #0d1117; border-radius: 6px; padding: 12px;
                   max-height: 250px; overflow-y: auto; }
    .results-label { font-size: 12px; color: #888; margin-bottom: 8px; }
    .result-row { font-size: 12px; padding: 2px 0; font-family: monospace; }
    .result-row.ok { color: #7ee787; }
    .result-row.err { color: #ff8a80; }
    #status { font-size: 13px; color: #f9a825; margin-top: 12px; min-height: 20px; }
    code { font-size: 12px; color: #ce9178; background: #0d1117; padding: 2px 6px; border-radius: 3px; }
    ul { padding-left: 20px; line-height: 1.9; font-size: 14px; color: #ccc; }
  </style>
</head>
<body>
  <h1>11 — Denial of Service (DoS)</h1>
  <p class="subtitle">VULNERABLE version — running on port ${PORT}</p>

  <div class="warning-banner">
    <h2>&#9888; VULNERABILITY ACTIVE: No rate limiting</h2>
    <p>
      This server accepts unlimited requests from any client with no throttling.
      A single script could send thousands of requests per second, exhausting
      server resources and making it unavailable for legitimate users.
    </p>
  </div>

  <div class="card">
    <h2>Server Request Counter</h2>
    <div class="counter-display" id="liveCounter">${totalRequests}</div>
    <div class="counter-label">Total requests served (all accepted, no limits)</div>
    <div class="btn-row">
      <button class="btn-flood" onclick="sendFlood()">Send 20 Requests Fast</button>
      <button class="btn-heavy" onclick="sendHeavy()">Heavy CPU Request</button>
    </div>
    <div id="status"></div>
    ${resultsHtml}
  </div>

  <div class="card">
    <h2>What Makes This Dangerous</h2>
    <ul>
      <li>Every single request to <code>/ping</code> or <code>/heavy</code> is accepted</li>
      <li>No IP-based tracking — one machine can send unlimited requests</li>
      <li><code>/heavy</code> runs a 10-million-iteration CPU loop — easy to abuse</li>
      <li>An attacker running the flood loop below could take this down in seconds</li>
    </ul>
  </div>

  <div class="card">
    <h2>Attacker Script (What We Are Not Protecting Against)</h2>
    <pre style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:14px;
         font-family:'Courier New',monospace;font-size:12px;color:#7ee787;white-space:pre-wrap;">
<span style="color:#8b949e"># Attacker runs this — unlimited requests, server has no defense:</span>

while True:
    for i in range(100):
        fetch("http://localhost:${PORT}/heavy")  <span style="color:#8b949e"># CPU intensive!</span>

<span style="color:#8b949e"># Each /heavy request burns CPU
# Server queues fill up
# Legitimate users get timeouts
# No rate limit = no protection</span>
    </pre>
  </div>

  <script>
    let requestLog = [];

    async function pingOnce() {
      const start = Date.now();
      const res = await fetch('/ping');
      const data = await res.json();
      const ms = Date.now() - start;
      document.getElementById('liveCounter').textContent = data.count;
      return \`HTTP \${res.status} — count=\${data.count} (\${ms}ms)\`;
    }

    async function sendFlood() {
      const status = document.getElementById('status');
      status.textContent = 'Sending 20 concurrent requests...';
      const promises = [];
      for (let i = 0; i < 20; i++) {
        promises.push(pingOnce().catch(e => 'Error: ' + e.message));
      }
      const results = await Promise.all(promises);
      status.textContent = \`Done! All \${results.length} requests accepted — no rejections.\`;

      const box = document.createElement('div');
      box.className = 'results-box';
      box.innerHTML = '<div class="results-label">Batch results (20 concurrent requests — all allowed):</div>' +
        results.map((r, i) => \`<div class="result-row ok">Request #\${i + 1}: \${r}</div>\`).join('');

      const card = document.querySelector('.card');
      const existing = card.querySelector('.results-box');
      if (existing) existing.replaceWith(box);
      else card.appendChild(box);
    }

    async function sendHeavy() {
      const status = document.getElementById('status');
      status.textContent = 'Sending heavy CPU request...';
      const start = Date.now();
      try {
        const res = await fetch('/heavy');
        const data = await res.json();
        const ms = Date.now() - start;
        document.getElementById('liveCounter').textContent = data.count;
        status.textContent = \`Heavy request completed in \${ms}ms. Result: \${data.result.toFixed(2)}. No limit applied.\`;
      } catch (e) {
        status.textContent = 'Error: ' + e.message;
      }
    }
  </script>
</body>
</html>`;
}

const server = http.createServer((req, res) => {
  const reqUrl = req.url.split('?')[0];

  if (req.method === 'GET' && reqUrl === '/') {
    totalRequests++;
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(getHomePage(null));
    return;
  }

  if (req.method === 'GET' && reqUrl === '/ping') {
    // ❌ No rate limiting — accepts unlimited requests
    totalRequests++;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', count: totalRequests }));
    return;
  }

  if (req.method === 'GET' && reqUrl === '/heavy') {
    // ❌ No rate limiting on CPU-intensive endpoint
    totalRequests++;

    // Simulate CPU-intensive work
    let result = 0;
    for (let i = 0; i < 10000000; i++) {
      result += Math.sqrt(i);
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', result, count: totalRequests }));
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`[11-ddos] VULNERABLE server running on http://localhost:${PORT}`);
  console.log(`No rate limiting active. Any number of requests will be accepted.`);
});
