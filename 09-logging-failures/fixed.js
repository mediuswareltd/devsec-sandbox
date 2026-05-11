const http = require('http');
const url = require('url');
const querystring = require('querystring');

const PORT = 3109;

const users = [
  { username: 'alice', password: 'alice123' },
  { username: 'admin', password: 'adminpass' },
];

// In-memory audit log
const auditLog = [];

// Track failed attempts per username for brute-force detection
// { username -> [timestamp, timestamp, ...] }
const failedAttempts = new Map();

const BRUTE_FORCE_THRESHOLD = 5;
const BRUTE_FORCE_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

function timestamp() {
  return new Date().toISOString().replace('T', ' ').substring(0, 19);
}

function getClientIp(req) {
  return (
    req.headers['x-forwarded-for'] ||
    req.socket.remoteAddress ||
    '0.0.0.0'
  );
}

function logEvent(level, message) {
  const entry = `[${timestamp()}] ${level} | ${message}`;
  auditLog.push(entry);
  console.log(entry);
}

function recordLoginAttempt(username, ip, success, reason) {
  const result = success ? 'SUCCESS' : 'FAILED';
  logEvent('LOGIN ATTEMPT', `user=${username} | ip=${ip} | result=${result} | reason=${reason}`);

  if (!success) {
    checkBruteForce(username, ip);
  }
}

function checkBruteForce(username, ip) {
  const now = Date.now();
  const attempts = failedAttempts.get(username) || [];

  // Prune old attempts outside the window
  const recent = attempts.filter(t => now - t < BRUTE_FORCE_WINDOW_MS);
  recent.push(now);
  failedAttempts.set(username, recent);

  if (recent.length >= BRUTE_FORCE_THRESHOLD) {
    logEvent(
      '*** ALERT ***',
      `Possible brute-force attack on user: ${username} | ${recent.length} failed attempts in ${BRUTE_FORCE_WINDOW_MS / 60000} minutes | source ip=${ip}`
    );
  }
}

function getLoginPage(message, messageType) {
  const logRows = auditLog.slice().reverse().map(entry => {
    const isAlert = entry.includes('ALERT');
    const isSuccess = entry.includes('SUCCESS');
    const color = isAlert ? '#ff6b6b' : isSuccess ? '#81c784' : '#f9a825';
    return `<div style="color:${color};font-size:12px;padding:2px 0;border-bottom:1px solid #1a2a1a;">${entry}</div>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="refresh" content="4">
  <title>09 - Logging Failures (FIXED)</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #0d1f0d; color: #eee; min-height: 100vh; padding: 30px 20px; }
    h1 { color: #4caf50; margin-bottom: 6px; }
    .subtitle { color: #aaa; margin-bottom: 24px; font-size: 14px; }
    .fixed-banner {
      background: #0a2a0a;
      border: 2px solid #4caf50;
      border-radius: 8px;
      padding: 16px 20px;
      margin-bottom: 24px;
    }
    .fixed-banner h2 { color: #81c784; margin-bottom: 8px; font-size: 16px; }
    .fixed-banner ul { color: #a5d6a7; font-size: 14px; line-height: 1.8; padding-left: 20px; }
    .card {
      background: #111f11;
      border-radius: 10px;
      padding: 24px;
      margin-bottom: 20px;
      border: 1px solid #1b4d1b;
    }
    .card h2 { margin-bottom: 16px; font-size: 16px; color: #a5d6a7; }
    label { display: block; margin-bottom: 6px; font-size: 14px; color: #bbb; }
    input[type=text], input[type=password] {
      width: 100%;
      padding: 10px 14px;
      border-radius: 6px;
      border: 1px solid #1b4d1b;
      background: #0a1a0a;
      color: #eee;
      font-size: 14px;
      margin-bottom: 14px;
    }
    button {
      padding: 10px 22px;
      border-radius: 6px;
      border: none;
      background: #388e3c;
      color: #fff;
      font-size: 14px;
      cursor: pointer;
    }
    button:hover { background: #2e7d32; }
    .msg-success { background: #1a3a1a; border: 1px solid #4caf50; color: #81c784; padding: 10px 14px; border-radius: 6px; margin-bottom: 14px; }
    .msg-error   { background: #3a1a1a; border: 1px solid #e94560; color: #ff8a80; padding: 10px 14px; border-radius: 6px; margin-bottom: 14px; }
    .log-box {
      background: #050f05;
      border: 1px solid #1b4d1b;
      border-radius: 8px;
      padding: 14px;
      max-height: 300px;
      overflow-y: auto;
      font-family: 'Courier New', monospace;
    }
    .empty-log { color: #555; font-size: 13px; font-family: monospace; }
    .hint { font-size: 12px; color: #888; margin-top: 8px; }
    .hint strong { color: #4caf50; }
    .nav-link { display: inline-block; margin-top: 10px; color: #81c784; font-size: 13px; text-decoration: none; }
    .nav-link:hover { text-decoration: underline; }
    .refresh-note { font-size: 11px; color: #666; margin-top: 8px; }
  </style>
</head>
<body>
  <h1>09 — Logging &amp; Monitoring Failures</h1>
  <p class="subtitle">FIXED version — running on port ${PORT}</p>

  <div class="fixed-banner">
    <h2>&#10003; Protection Active: Full Audit Logging Enabled</h2>
    <ul>
      <li>Every login attempt is logged with timestamp, IP, username, and result</li>
      <li>Failed attempts are tracked per username over a 5-minute window</li>
      <li>5+ failures trigger a brute-force ALERT in the log</li>
      <li>All events appear in the terminal AND on this page</li>
    </ul>
  </div>

  <div class="card">
    <h2>Login Form</h2>
    ${message ? `<div class="msg-${messageType}">${message}</div>` : ''}
    <form method="POST" action="/login">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" placeholder="Try: alice or admin" autocomplete="off">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="Password">
      <button type="submit">Login</button>
    </form>
    <p class="hint"><strong>Hint:</strong> Correct credentials — alice / alice123 &nbsp;|&nbsp; admin / adminpass</p>
    <p class="hint">Try entering wrong passwords 5+ times for the same user to trigger the brute-force alert.</p>
  </div>

  <div class="card">
    <h2>Live Audit Log <a class="nav-link" href="/logs">(full page view)</a></h2>
    <div class="log-box">
      ${auditLog.length === 0
        ? '<p class="empty-log">No events yet. Try logging in above.</p>'
        : logRows
      }
    </div>
    <p class="refresh-note">Page auto-refreshes every 4 seconds. <a class="nav-link" href="/">Refresh now</a></p>
  </div>
</body>
</html>`;
}

function getLogsPage() {
  const rows = auditLog.slice().reverse().map(entry => {
    const isAlert = entry.includes('ALERT');
    const isSuccess = entry.includes('SUCCESS');
    const color = isAlert ? '#ff6b6b' : isSuccess ? '#81c784' : '#f9a825';
    return `<div style="color:${color};padding:4px 0;border-bottom:1px solid #1a2a1a;font-size:13px;">${entry}</div>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="refresh" content="4">
  <title>Audit Log — 09 Fixed</title>
  <style>
    body { font-family: 'Courier New', monospace; background: #050f05; color: #eee; padding: 30px 20px; }
    h1 { color: #4caf50; margin-bottom: 6px; font-family: 'Segoe UI', sans-serif; }
    p { color: #888; margin-bottom: 20px; font-family: 'Segoe UI', sans-serif; font-size: 14px; }
    .log-container { max-width: 900px; }
    a { color: #81c784; }
  </style>
</head>
<body>
  <h1>Full Audit Log</h1>
  <p>Showing ${auditLog.length} events (newest first). Auto-refreshes every 4s. <a href="/">Back to login</a></p>
  <div class="log-container">
    ${auditLog.length === 0
      ? '<div style="color:#555">No events recorded yet.</div>'
      : rows
    }
  </div>
</body>
</html>`;
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  if (req.method === 'GET' && pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(getLoginPage(null, null));
    return;
  }

  if (req.method === 'GET' && pathname === '/logs') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(getLogsPage());
    return;
  }

  if (req.method === 'POST' && pathname === '/login') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      const data = querystring.parse(body);
      const { username, password } = data;
      const ip = getClientIp(req);

      if (!username) {
        recordLoginAttempt('(empty)', ip, false, 'no username provided');
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(getLoginPage('Username is required.', 'error'));
        return;
      }

      const user = users.find(u => u.username === username && u.password === password);

      if (user) {
        recordLoginAttempt(username, ip, true, 'correct credentials');
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(getLoginPage(`Welcome, ${username}! Login recorded in the audit log.`, 'success'));
      } else {
        const userExists = users.find(u => u.username === username);
        const reason = userExists ? 'wrong password' : 'unknown username';
        recordLoginAttempt(username, ip, false, reason);
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(getLoginPage('Invalid credentials. This failure has been logged.', 'error'));
      }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`[09-logging-failures] FIXED server running on http://localhost:${PORT}`);
  console.log(`Audit log is active. Visit http://localhost:${PORT}/logs for the full trail.`);
  logEvent('SERVER START', `Logging server started on port ${PORT}`);
});
