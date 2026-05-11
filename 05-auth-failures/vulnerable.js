/**
 * AUTHENTICATION FAILURES DEMO — VULNERABLE VERSION
 * ===================================================
 * Demonstrates multiple common authentication weaknesses in one small app.
 *
 * VULNERABILITIES DEMONSTRATED:
 *
 *  1. PLAIN TEXT PASSWORDS
 *     Passwords are stored as-is in the users array (and would be in any DB).
 *     If the server is breached, every password is immediately readable.
 *     Real systems must hash passwords with a slow algorithm (bcrypt, PBKDF2, Argon2).
 *
 *  2. SEQUENTIAL SESSION IDs
 *     After login, the session ID is just an incrementing integer: 1, 2, 3...
 *     An attacker who has session ID 5 can simply try 1, 2, 3, 4 to hijack
 *     other users' sessions. Session IDs must be randomly generated.
 *
 *  3. NO RATE LIMITING
 *     The login form accepts unlimited attempts with no delay or lockout.
 *     An automated script can try every common password in seconds.
 *
 *  4. WEAK PASSWORDS ACCEPTED
 *     alice's password is "123", admin's is "admin". The app has no minimum
 *     length or complexity requirement.
 *
 *  5. /db ENDPOINT EXPOSES EVERYTHING
 *     A debug route shows the entire user database including plain text passwords.
 *     Never leave debug endpoints in production!
 *
 * Uses only Node.js built-in modules: http, url, querystring, crypto
 */

const http        = require('http');
const url         = require('url');
const querystring = require('querystring');

const PORT = 3006;

// ── "Database" ────────────────────────────────────────────────────────────────
// ❌ VULNERABILITY 1: passwords stored in plain text.
//    If this object were written to a database file and that file were stolen,
//    every password is immediately readable — no cracking required.
const users = [
  { id: 1, username: 'alice', password: '123',      role: 'user'  },  // ❌ trivially weak
  { id: 2, username: 'bob',   password: 'password', role: 'user'  },  // ❌ in every wordlist
  { id: 3, username: 'admin', password: 'admin',    role: 'admin' },  // ❌ default credential
];

// ── Session store ─────────────────────────────────────────────────────────────
// Maps sessionId → userId
const sessions = {};

// ❌ VULNERABILITY 2: sequential session ID counter.
//    Session IDs are 1, 2, 3... — trivially enumerable.
let nextSessionId = 1;

// ── Failed-attempt tracking (no lockout is applied — shows the vulnerability) ─
// Maps IP → attempt count.  We track but never block — that's the bug.
const failedAttempts = {};

// ── Cookie helpers ────────────────────────────────────────────────────────────

function parseCookies(req) {
  const raw = req.headers.cookie || '';
  const cookies = {};
  raw.split(';').forEach(part => {
    const [k, ...v] = part.trim().split('=');
    if (k) cookies[k.trim()] = decodeURIComponent(v.join('='));
  });
  return cookies;
}

function getSessionUser(req) {
  const cookies   = parseCookies(req);
  const sessionId = cookies['sessionId'];
  if (!sessionId) return null;
  const userId = sessions[sessionId];
  if (!userId) return null;
  return users.find(u => u.id === userId) || null;
}

// ── HTML helpers ───────────────────────────────────────────────────────────────

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

function renderLogin(errorMsg, attempts, ip) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Login [VULNERABLE]</title>
  <style>
    body { font-family: sans-serif; padding: 24px; max-width: 500px; margin: 60px auto; }
    h1 { color: #c0392b; }
    .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 14px; border-radius: 6px; margin: 14px 0; font-size: 0.9rem; }
    label { display: block; margin-top: 12px; font-weight: bold; }
    input[type=text], input[type=password] { width: 100%; padding: 8px; margin-top: 4px; box-sizing: border-box; }
    button { margin-top: 14px; padding: 10px 24px; background: #c0392b; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }
    .error { color: red; margin-top: 10px; }
    .creds { background: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; border-radius: 4px; margin-top: 14px; font-family: monospace; font-size: 0.85rem; }
    .counter { margin-top: 12px; color: #666; font-size: 0.85rem; }
    a { color: #c0392b; }
  </style>
</head>
<body>
  <h1>Login [VULNERABLE]</h1>

  <div class="warning">
    <strong>&#9888; Multiple vulnerabilities active:</strong><br>
    &#8226; Passwords are plain text<br>
    &#8226; Session IDs are sequential integers (1, 2, 3...)<br>
    &#8226; No rate limiting — try wrong passwords endlessly<br>
    &#8226; <a href="/db">Visit /db</a> to see the "database" with plain text passwords
  </div>

  <form method="POST" action="/login">
    <label>Username</label>
    <input type="text" name="username" autocomplete="off">
    <label>Password</label>
    <input type="password" name="password">
    <button type="submit">Log In</button>
    ${errorMsg ? `<p class="error">${escapeHtml(errorMsg)}</p>` : ''}
  </form>

  <div class="creds">
    <strong>Test credentials (plain text passwords):</strong><br>
    alice / 123 &nbsp;&nbsp; bob / password &nbsp;&nbsp; admin / admin
  </div>

  <div class="counter">
    Failed attempts from your IP (${escapeHtml(ip)}): <strong>${attempts}</strong>
    &nbsp;—&nbsp; <em>No lockout will ever trigger (that's the vulnerability)</em>
  </div>

</body>
</html>`;
}

function renderDashboard(user, sessionId) {
  const nextId = sessionId + 1; // show that the next session ID is predictable
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Dashboard [VULNERABLE]</title>
  <style>
    body { font-family: sans-serif; padding: 24px; max-width: 600px; margin: 60px auto; }
    h1 { color: #c0392b; }
    .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 14px; border-radius: 6px; margin: 14px 0; }
    .info { background: #f9f9f9; border: 1px solid #ddd; padding: 14px; border-radius: 6px; font-family: monospace; }
    .danger { background: #f8d7da; border: 1px solid #f5c6cb; padding: 12px; border-radius: 4px; margin-top: 14px; font-size: 0.9rem; }
    a { color: #c0392b; }
    button { margin-top: 14px; padding: 8px 18px; background: #555; color: white; border: none; border-radius: 4px; cursor: pointer; }
  </style>
</head>
<body>
  <h1>Dashboard [VULNERABLE]</h1>

  <div class="info">
    <strong>Logged in as:</strong> ${escapeHtml(user.username)} (${escapeHtml(user.role)})<br>
    <strong>Your Session ID:</strong> <span style="color:#c0392b;font-size:1.2rem">${escapeHtml(String(sessionId))}</span><br>
    <strong>Next session ID will be:</strong> ${escapeHtml(String(nextId))} (predictable!)
  </div>

  <div class="warning">
    <strong>&#9888; Sequential Session ID Attack:</strong><br>
    Your session ID is <code>${escapeHtml(String(sessionId))}</code>.
    An attacker can simply try session IDs <code>1</code>, <code>2</code>, <code>3</code>...
    to find active sessions and hijack other users' accounts.<br><br>
    To simulate: open DevTools → Application → Cookies → change <code>sessionId</code>
    to a different number and reload.
  </div>

  <div class="danger">
    <strong>Also try:</strong>
    <a href="/db">View /db endpoint</a> — exposes all users and plain text passwords!
  </div>

  <form method="POST" action="/logout">
    <button type="submit">Log Out</button>
  </form>
</body>
</html>`;
}

function renderDb() {
  const rows = users.map(u =>
    `<tr>
      <td>${u.id}</td>
      <td>${escapeHtml(u.username)}</td>
      <td style="color:red;font-weight:bold">${escapeHtml(u.password)}</td>
      <td>${escapeHtml(u.role)}</td>
    </tr>`
  ).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>/db — User Database [VULNERABLE]</title>
  <style>
    body { font-family: sans-serif; padding: 24px; max-width: 600px; margin: 0 auto; }
    h1 { color: #c0392b; }
    .danger { background: #f8d7da; border: 1px solid #f5c6cb; padding: 14px; border-radius: 6px; margin: 14px 0; }
    table { width: 100%; border-collapse: collapse; margin-top: 14px; }
    th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }
    th { background: #f0f0f0; }
    a { color: #c0392b; }
  </style>
</head>
<body>
  <h1>/db — Full User Database [VULNERABLE]</h1>
  <div class="danger">
    <strong>&#9888; This endpoint should NEVER exist in production.</strong><br>
    It exposes every user account including plain text passwords.
    A single HTTP request to <code>/db</code> gives an attacker every credential.
  </div>
  <table>
    <tr><th>ID</th><th>Username</th><th>Password (PLAIN TEXT!)</th><th>Role</th></tr>
    ${rows}
  </table>
  <p><a href="/">Back to home</a></p>
</body>
</html>`;
}

// ── Request handler ────────────────────────────────────────────────────────────

function handleRequest(req, res) {
  const parsed   = url.parse(req.url);
  const pathname = parsed.pathname;
  const ip       = req.socket.remoteAddress || 'unknown';

  // ── GET / — dashboard or redirect to login ──────────────────────────────────
  if (req.method === 'GET' && pathname === '/') {
    const user = getSessionUser(req);
    if (!user) {
      res.writeHead(302, { Location: '/login' });
      res.end();
      return;
    }
    const sessionId = parseInt(parseCookies(req)['sessionId'], 10);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(renderDashboard(user, sessionId));
    return;
  }

  // ── GET /login ──────────────────────────────────────────────────────────────
  if (req.method === 'GET' && pathname === '/login') {
    const attempts = failedAttempts[ip] || 0;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(renderLogin(null, attempts, ip));
    return;
  }

  // ── POST /login ─────────────────────────────────────────────────────────────
  if (req.method === 'POST' && pathname === '/login') {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      const data     = querystring.parse(body);
      const username = (data.username || '').trim();
      const password = (data.password || '').trim();

      // ❌ VULNERABILITY 3: no rate limiting.
      //    We count failures but NEVER lock anything out.
      failedAttempts[ip] = (failedAttempts[ip] || 0);

      // ❌ VULNERABILITY 1: plain text password comparison.
      const user = users.find(u => u.username === username && u.password === password);

      if (!user) {
        failedAttempts[ip]++;
        console.log(`[FAIL] Login attempt for "${username}" from ${ip} — total failures: ${failedAttempts[ip]}`);
        const attempts = failedAttempts[ip];
        res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(renderLogin(`Invalid username or password. (Attempt #${attempts} — no lockout!)`, attempts, ip));
        return;
      }

      // ❌ VULNERABILITY 2: sequential session ID — just a counter.
      const sessionId = nextSessionId++;
      sessions[String(sessionId)] = user.id;

      console.log(`[LOGIN] ${user.username} logged in. Session ID: ${sessionId} (sequential!)`);

      res.writeHead(302, {
        'Location': '/',
        // ❌ No HttpOnly, no Secure, no SameSite flags
        'Set-Cookie': `sessionId=${sessionId}; Path=/`,
      });
      res.end();
    });
    return;
  }

  // ── POST /logout ────────────────────────────────────────────────────────────
  if (req.method === 'POST' && pathname === '/logout') {
    const cookies   = parseCookies(req);
    const sessionId = cookies['sessionId'];
    if (sessionId) delete sessions[sessionId];
    res.writeHead(302, {
      'Location': '/login',
      'Set-Cookie': 'sessionId=; Path=/; Max-Age=0',
    });
    res.end();
    return;
  }

  // ── GET /db — ❌ VULNERABILITY 4: debug endpoint exposes plain text passwords ─
  if (req.method === 'GET' && pathname === '/db') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(renderDb());
    return;
  }

  // ── 404 ─────────────────────────────────────────────────────────────────────
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
}

// ── Start server ───────────────────────────────────────────────────────────────

const server = http.createServer(handleRequest);
server.listen(PORT, () => {
  console.log('');
  console.log('=== AUTH FAILURES DEMO (VULNERABLE) ===');
  console.log(`Server running at http://localhost:${PORT}`);
  console.log('');
  console.log('Vulnerabilities to explore:');
  console.log('  1. Log in as alice / 123  (plain text, trivially weak password)');
  console.log('  2. Note your session ID — it is just a number (1, 2, 3...)');
  console.log('  3. Try wrong passwords repeatedly — no lockout ever triggers');
  console.log('  4. Visit http://localhost:' + PORT + '/db to see all plain text passwords');
  console.log('');
  console.log('Test credentials:  alice/123   bob/password   admin/admin');
  console.log('');
});
