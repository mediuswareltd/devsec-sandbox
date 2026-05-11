const http = require('http');

const PORT = 3111;

let totalRequests = 0;
let blockedRequests = 0;

// Rate limiter: max 5 requests per 10 seconds per IP
const rateLimitMap = new Map(); // ip -> { count, resetTime }

const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW_MS = 10000; // 10 seconds

function checkRateLimit(ip) {
  const now = Date.now();
  const limit = rateLimitMap.get(ip);

  if (!limit || now > limit.resetTime) {
    // New window: first request
    rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
    return { allowed: true, remaining: RATE_LIMIT_MAX - 1, resetIn: RATE_LIMIT_WINDOW_MS / 1000 };
  }

  if (limit.count >= RATE_LIMIT_MAX) {
    const retryAfter = Math.ceil((limit.resetTime - now) / 1000);
    return { allowed: false, retryAfter, remaining: 0 };
  }

  limit.count++;
  const remaining = RATE_LIMIT_MAX - limit.count;
  const resetIn = Math.ceil((limit.resetTime - now) / 1000);
  return { allowed: true, remaining, resetIn };
}

function getClientIp(req) {
  return (
    req.headers['x-forwarded-for'] ||
    req.socket.remoteAddress ||
    '0.0.0.0'
  );
}

// Periodically clean up expired rate limit entries to prevent memory growth
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of rateLimitMap.entries()) {
    if (now > data.resetTime) rateLimitMap.delete(ip);
  }
}, 30000);

function getHomePage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>11 - DoS (FIXED)</title>
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
    .counters { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 16px; }
    .counter-box { flex: 1; min-width: 140px; background: #0a1a0a; border-radius: 8px; padding: 14px; text-align: center; border: 1px solid #1b4d1b; }
    .counter-num { font-size: 36px; font-weight: bold; font-variant-numeric: tabular-nums; }
    .counter-num.green { color: #4caf50; }
    .counter-num.red { color: #e94560; }
    .counter-num.yellow { color: #f9a825; }
    .counter-label { font-size: 12px; color: #888; margin-top: 4px; }
    .rate-status { background: #0a1a0a; border-radius: 8px; padding: 14px; margin-bottom: 16px; border: 1px solid #1b4d1b; }
    .rate-status h3 { font-size: 13px; color: #a5d6a7; margin-bottom: 10px; }
    .rate-row { display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 6px; }
    .rate-row .label { color: #888; }
    .rate-row .value { color: #eee; font-weight: 600; }
    .progress-bar { height: 8px; background: #1b4d1b; border-radius: 4px; overflow: hidden; margin-top: 8px; }
    .progress-fill { height: 100%; border-radius: 4px; transition: width 0.3s, background 0.3s; }
    .btn-row { display: flex; gap: 12px; flex-wrap: wrap; }
    button {
      padding: 12px 24px; border-radius: 6px; border: none;
      font-size: 14px; cursor: pointer; font-weight: 600;
    }
    .btn-flood { background: #388e3c; color: #fff; }
    .btn-flood:hover { background: #2e7d32; }
    .btn-heavy { background: #f57c00; color: #fff; }
    .btn-heavy:hover { background: #e65100; }
    #status { font-size: 13px; color: #f9a825; margin-top: 12px; min-height: 20px; }
    .results-box { margin-top: 16px; background: #050f05; border-radius: 6px; padding: 12px;
                   max-height: 250px; overflow-y: auto; border: 1px solid #1b4d1b; }
    .results-label { font-size: 12px; color: #888; margin-bottom: 8px; }
    .result-row { font-size: 12px; padding: 2px 0; font-family: monospace; }
    .result-row.ok { color: #7ee787; }
    .result-row.rate-limited { color: #ff8a80; }
    code { font-size: 12px; color: #ce9178; background: #050f05; padding: 2px 6px; border-radius: 3px; }
    pre { background: #050f05; border: 1px solid #1b4d1b; border-radius: 6px; padding: 14px;
          font-family: 'Courier New', monospace; font-size: 12px; color: #a5d6a7;
          white-space: pre-wrap; }
  </style>
</head>
<body>
  <h1>11 — Denial of Service (DoS)</h1>
  <p class="subtitle">FIXED version — running on port ${PORT}</p>

  <div class="fixed-banner">
    <h2>&#10003; Rate Limiting Active</h2>
    <ul>
      <li>Maximum <strong>5 requests per 10 seconds</strong> per IP address</li>
      <li>Excess requests receive HTTP 429 Too Many Requests</li>
      <li>Retry-After header tells clients when to retry</li>
      <li>Rate limit windows reset automatically — legitimate users recover quickly</li>
    </ul>
  </div>

  <div class="card">
    <h2>Server Statistics</h2>
    <div class="counters">
      <div class="counter-box">
        <div class="counter-num green" id="totalCounter">${totalRequests}</div>
        <div class="counter-label">Total Requests</div>
      </div>
      <div class="counter-box">
        <div class="counter-num red" id="blockedCounter">${blockedRequests}</div>
        <div class="counter-label">Blocked (Rate Limited)</div>
      </div>
      <div class="counter-box">
        <div class="counter-num yellow" id="remainingCounter">—</div>
        <div class="counter-label">Your Remaining Quota</div>
      </div>
    </div>

    <div class="rate-status">
      <h3>Your Rate Limit Window</h3>
      <div class="rate-row">
        <span class="label">Limit</span>
        <span class="value">${RATE_LIMIT_MAX} requests / ${RATE_LIMIT_WINDOW_MS / 1000}s</span>
      </div>
      <div class="rate-row">
        <span class="label">Used</span>
        <span class="value" id="usedDisplay">—</span>
      </div>
      <div class="rate-row">
        <span class="label">Window resets in</span>
        <span class="value" id="resetDisplay">—</span>
      </div>
      <div class="progress-bar">
        <div class="progress-fill" id="progressFill" style="width:0%;background:#4caf50;"></div>
      </div>
    </div>

    <div class="btn-row">
      <button class="btn-flood" onclick="sendFlood()">Send 20 Requests Fast</button>
      <button class="btn-heavy" onclick="sendHeavy()">Heavy CPU Request</button>
    </div>
    <div id="status"></div>
    <div id="resultsContainer"></div>
  </div>

  <div class="card">
    <h2>How Rate Limiting Works</h2>
    <pre>// Per-IP sliding window rate limiter
const rateLimitMap = new Map(); // ip -> { count, resetTime }

function checkRateLimit(ip) {
  const now = Date.now();
  const limit = rateLimitMap.get(ip);

  if (!limit || now > limit.resetTime) {
    // New window starts fresh
    rateLimitMap.set(ip, { count: 1, resetTime: now + 10000 });
    return { allowed: true, remaining: 4 };
  }

  if (limit.count >= 5) {
    const retryAfter = Math.ceil((limit.resetTime - now) / 1000);
    return { allowed: false, retryAfter };  // → HTTP 429
  }

  limit.count++;
  return { allowed: true, remaining: 5 - limit.count };
}</pre>
  </div>
</body>

<script>
  async function pingOnce() {
    const res = await fetch('/ping');
    const data = await res.json();
    return { status: res.status, data };
  }

  function updateUI(data) {
    if (data.count !== undefined)
      document.getElementById('totalCounter').textContent = data.count;
    if (data.blocked !== undefined)
      document.getElementById('blockedCounter').textContent = data.blocked;
    if (data.remaining !== undefined) {
      document.getElementById('remainingCounter').textContent = data.remaining;
      const used = ${RATE_LIMIT_MAX} - data.remaining;
      document.getElementById('usedDisplay').textContent = used + ' / ${RATE_LIMIT_MAX}';
      const pct = (used / ${RATE_LIMIT_MAX}) * 100;
      const fill = document.getElementById('progressFill');
      fill.style.width = pct + '%';
      fill.style.background = pct >= 100 ? '#e94560' : pct >= 60 ? '#f9a825' : '#4caf50';
    }
    if (data.resetIn !== undefined) {
      document.getElementById('resetDisplay').textContent = data.resetIn + 's';
    }
  }

  async function sendFlood() {
    const status = document.getElementById('status');
    status.textContent = 'Sending 20 concurrent requests...';

    const promises = [];
    for (let i = 0; i < 20; i++) {
      promises.push(pingOnce().catch(e => ({ status: 0, data: { error: e.message } })));
    }
    const results = await Promise.all(promises);

    const allowed = results.filter(r => r.status === 200).length;
    const limited = results.filter(r => r.status === 429).length;
    status.textContent =
      \`Done! \${allowed} allowed, \${limited} rate-limited (HTTP 429).\`;

    // Update stats from last successful response
    const lastOk = results.find(r => r.status === 200 || r.status === 429);
    if (lastOk) updateUI(lastOk.data);

    const container = document.getElementById('resultsContainer');
    container.innerHTML = '<div class="results-box"><div class="results-label">Batch results (20 concurrent — most blocked after quota):</div>' +
      results.map((r, i) => {
        const cls = r.status === 200 ? 'ok' : 'rate-limited';
        const label = r.status === 200
          ? \`HTTP 200 OK (remaining: \${r.data.remaining})\`
          : r.status === 429
            ? \`HTTP 429 Too Many Requests — retry in \${r.data.retryAfter}s\`
            : \`Error: \${r.data.error || 'unknown'}\`;
        return \`<div class="result-row \${cls}">Request #\${i + 1}: \${label}</div>\`;
      }).join('') + '</div>';
  }

  async function sendHeavy() {
    const status = document.getElementById('status');
    status.textContent = 'Sending heavy CPU request (subject to rate limit)...';
    const start = Date.now();
    try {
      const res = await fetch('/heavy');
      const data = await res.json();
      const ms = Date.now() - start;
      updateUI(data);
      if (res.status === 429) {
        status.textContent = \`Rate limited! HTTP 429. Retry in \${data.retryAfter}s.\`;
      } else {
        status.textContent = \`Heavy request completed in \${ms}ms. Result: \${data.result ? data.result.toFixed(2) : 'N/A'}.\`;
      }
    } catch (e) {
      status.textContent = 'Error: ' + e.message;
    }
  }

  // Fetch initial stats
  fetch('/ping').then(r => r.json()).then(updateUI).catch(() => {});
</script>
</html>`;
}

const server = http.createServer((req, res) => {
  const reqUrl = req.url.split('?')[0];
  const ip = getClientIp(req);

  if (req.method === 'GET' && reqUrl === '/') {
    totalRequests++;
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(getHomePage());
    return;
  }

  if (req.method === 'GET' && reqUrl === '/ping') {
    const rl = checkRateLimit(ip);

    if (!rl.allowed) {
      blockedRequests++;
      res.writeHead(429, {
        'Content-Type': 'application/json',
        'Retry-After': String(rl.retryAfter),
        'X-RateLimit-Limit': String(RATE_LIMIT_MAX),
        'X-RateLimit-Remaining': '0',
      });
      res.end(JSON.stringify({
        error: 'Rate limit exceeded',
        retryAfter: rl.retryAfter,
        remaining: 0,
        blocked: blockedRequests,
        count: totalRequests,
      }));
      return;
    }

    totalRequests++;
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'X-RateLimit-Limit': String(RATE_LIMIT_MAX),
      'X-RateLimit-Remaining': String(rl.remaining),
    });
    res.end(JSON.stringify({
      status: 'ok',
      count: totalRequests,
      blocked: blockedRequests,
      remaining: rl.remaining,
      resetIn: rl.resetIn,
    }));
    return;
  }

  if (req.method === 'GET' && reqUrl === '/heavy') {
    const rl = checkRateLimit(ip);

    if (!rl.allowed) {
      blockedRequests++;
      res.writeHead(429, {
        'Content-Type': 'application/json',
        'Retry-After': String(rl.retryAfter),
      });
      res.end(JSON.stringify({
        error: 'Rate limit exceeded',
        retryAfter: rl.retryAfter,
        remaining: 0,
        blocked: blockedRequests,
        count: totalRequests,
      }));
      return;
    }

    totalRequests++;

    // CPU-intensive work (allowed because within rate limit)
    let result = 0;
    for (let i = 0; i < 10000000; i++) {
      result += Math.sqrt(i);
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      result,
      count: totalRequests,
      blocked: blockedRequests,
      remaining: rl.remaining,
      resetIn: rl.resetIn,
    }));
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`[11-ddos] FIXED server running on http://localhost:${PORT}`);
  console.log(`Rate limiting active: ${RATE_LIMIT_MAX} requests per ${RATE_LIMIT_WINDOW_MS / 1000}s per IP.`);
});
