/**
 * AUTHENTICATION FAILURES DEMO — FIXED VERSION
 * ==============================================
 * Same app structure as vulnerable.js, but all four vulnerabilities are corrected.
 *
 * FIXES APPLIED:
 *
 *  1. PBKDF2 PASSWORD HASHING  (crypto.pbkdf2Sync)
 *     Each password is hashed with a unique random 16-byte salt using PBKDF2
 *     with 100,000 iterations of SHA-512. The stored value is a 128-char hex
 *     string that reveals nothing about the original password.
 *     Even if the "database" is stolen, brute-forcing one password takes
 *     100,000 hash operations — orders of magnitude slower than plain-text lookup.
 *
 *  2. RANDOM SESSION IDs  (crypto.randomBytes)
 *     Session IDs are 32 random bytes encoded as 64 hex characters.
 *     With 2^256 possible values, guessing a valid session ID is computationally
 *     infeasible. Sequential integers (1, 2, 3) are replaced entirely.
 *
 *  3. RATE LIMITING / ACCOUNT LOCKOUT
 *     After 5 failed attempts from the same IP within 60 seconds, that IP is
 *     locked out for 60 seconds. A simple in-memory map tracks failures per IP
 *     and the timestamp of the first failure in each window.
 *
 *  4. MINIMUM PASSWORD LENGTH
 *     Passwords shorter than 8 characters are rejected at login and in the
 *     demo registration notes. (Full registration flow omitted for brevity.)
 *
 *  5. /db ENDPOINT REMOVED
 *     Replaced with /passwords — which shows only hashed values (safe to show
 *     for educational purposes; hashes cannot be reversed quickly).
 *
 * Uses only Node.js built-in modules: http, url, querystring, crypto
 */

const http        = require('http');
const url         = require('url');
const querystring = require('querystring');
const crypto      = require('crypto');

const PORT              = 3106;
const MAX_ATTEMPTS      = 5;      // lock out after this many failures
const LOCKOUT_SECONDS   = 60;     // lockout window in seconds
const MIN_PASSWORD_LEN  = 8;

// ── Password helpers ──────────────────────────────────────────────────────────

/**
 * Hash a plain-text password with PBKDF2 + random salt.
 * Returns { hash, salt } — both as hex strings.
 *
 * PBKDF2 parameters:
 *   - iterations: 100,000  (makes brute-force 100k× slower than plain SHA)
 *   - keylen:     64 bytes → 128 hex chars
 *   - digest:     sha512
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');   // 32 hex chars
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { hash, salt };
}

/**
 * Verify a plain-text password against a stored hash + salt.
 * Re-derives the hash with the same parameters and compares with
 * a constant-time comparison to prevent timing attacks.
 */
function verifyPassword(password, storedHash, salt) {
  const derived = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  // timingSafeEqual requires Buffer inputs of equal length
  const a = Buffer.from(derived,     'hex');
  const b = Buffer.from(storedHash,  'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ── Pre-hash passwords at startup ─────────────────────────────────────────────
// In a real app, hashing happens at registration time.
// Here we do it at startup so the demo has working credentials.

console.log('[STARTUP] Hashing passwords with PBKDF2 (100,000 iterations)...');

const aliceCreds = hashPassword('SecurePass1!');
const bobCreds   = hashPassword('MyS3cretPwd!');

// ✅ FIX 1: No plain-text passwords stored anywhere.
//    Only the hash and salt are kept. The original password is never retained.
const users = [
  { id: 1, username: 'alice', hash: aliceCreds.hash, salt: aliceCreds.salt, role: 'user'  },
  { id: 2, username: 'bob',   hash: bobCreds.hash,   salt: bobCreds.salt,   role: 'user'  },
];

console.log('[STARTUP] Password hashing complete.');
console.log(`          alice hash (first 32 chars): ${aliceCreds.hash.slice(0, 32)}...`);
console.log(`          bob   hash (first 32 chars): ${bobCreds.hash.slice(0, 32)}...`);
console.log('');

// ── Session store ─────────────────────────────────────────────────────────────
// Maps sessionId (64-char hex string) → userId
const sessions = {};

// ✅ FIX 2: cryptographically random session ID generation.
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');  // 64 hex chars, 2^256 space
}

// ── Rate limiting ─────────────────────────────────────────────────────────────
// Maps IP → { count, firstFailureTime }
const failedAttempts = {};

/**
 * ✅ FIX 3: Returns true if this IP is currently locked out.
 * Clears the record if the lockout window has expired.
 */
function isLockedOut(ip) {
  const record = failedAttempts[ip];
  if (!record) return false;

  const elapsedSeconds = (Date.now() - record.firstFailureTime) / 1000;
  if (elapsedSeconds > LOCKOUT_SECONDS) {
    // Window expired — reset the record
    delete failedAttempts[ip];
    return false;
  }

  return record.count >= MAX_ATTEMPTS;
}

/**
 * Records a failed attempt. Returns the current attempt count.
 */
function recordFailure(ip) {
  if (!failedAttempts[ip]) {
    failedAttempts[ip] = { count: 0, firstFailureTime: Date.now() };
  }
  failedAttempts[ip].count++;
  return failedAttempts[ip].count;
}

function remainingLockoutSeconds(ip) {
  const record = failedAttempts[ip];
  if (!record) return 0;
  const elapsed = (Date.now() - record.firstFailureTime) / 1000;
  return Math.max(0, Math.ceil(LOCKOUT_SECONDS - elapsed));
}

// ── Cookie helpers ─────────────────────────────────────────────────────────────

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

function renderLogin(errorMsg, ip) {
  const locked      = isLockedOut(ip);
  const remaining   = remainingLockoutSeconds(ip);
  const record      = failedAttempts[ip];
  const attempts    = record ? record.count : 0;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Login [FIXED]</title>
  <style>
    body { font-family: sans-serif; padding: 24px; max-width: 500px; margin: 60px auto; }
    h1 { color: #27ae60; }
    .safe { background: #d4edda; border: 1px solid #c3e6cb; padding: 14px; border-radius: 6px; margin: 14px 0; font-size: 0.9rem; }
    label { display: block; margin-top: 12px; font-weight: bold; }
    input[type=text], input[type=password] { width: 100%; padding: 8px; margin-top: 4px; box-sizing: border-box; }
    button { margin-top: 14px; padding: 10px 24px; background: #27ae60; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }
    button:disabled { background: #aaa; cursor: not-allowed; }
    .error { color: red; margin-top: 10px; }
    .lockout { background: #f8d7da; border: 1px solid #f5c6cb; padding: 12px; border-radius: 4px; margin-top: 12px; color: #721c24; }
    .creds { background: #d1ecf1; border: 1px solid #bee5eb; padding: 10px; border-radius: 4px; margin-top: 14px; font-family: monospace; font-size: 0.85rem; }
    .counter { margin-top: 12px; color: #666; font-size: 0.85rem; }
    a { color: #27ae60; }
  </style>
</head>
<body>
  <h1>Login [FIXED]</h1>

  <div class="safe">
    <strong>&#10003; Protections active:</strong><br>
    &#8226; Passwords hashed with PBKDF2 + random salt<br>
    &#8226; Session IDs are 64-char random hex strings<br>
    &#8226; Locked out after ${MAX_ATTEMPTS} failures for ${LOCKOUT_SECONDS}s<br>
    &#8226; Minimum password length: ${MIN_PASSWORD_LEN} characters<br>
    &#8226; <a href="/passwords">View hashed passwords</a> (safe — not reversible)
  </div>

  ${locked
    ? `<div class="lockout">
        <strong>&#128274; Too many failed attempts.</strong><br>
        Your IP (${escapeHtml(ip)}) is locked out for <strong>${remaining} more second(s)</strong>.
        Please wait before trying again.
       </div>`
    : ''}

  <form method="POST" action="/login">
    <label>Username</label>
    <input type="text" name="username" autocomplete="off" ${locked ? 'disabled' : ''}>
    <label>Password</label>
    <input type="password" name="password" ${locked ? 'disabled' : ''}>
    <button type="submit" ${locked ? 'disabled' : ''}>Log In</button>
    ${errorMsg ? `<p class="error">${escapeHtml(errorMsg)}</p>` : ''}
  </form>

  <div class="creds">
    <strong>Test credentials:</strong><br>
    alice / SecurePass1!<br>
    bob / MyS3cretPwd!
  </div>

  <div class="counter">
    Failed attempts from your IP (${escapeHtml(ip)}): <strong>${attempts} / ${MAX_ATTEMPTS}</strong>
    ${locked ? ` — <span style="color:red">LOCKED OUT (${remaining}s remaining)</span>` : ''}
  </div>

</body>
</html>`;
}

function renderDashboard(user, sessionId) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Dashboard [FIXED]</title>
  <style>
    body { font-family: sans-serif; padding: 24px; max-width: 600px; margin: 60px auto; }
    h1 { color: #27ae60; }
    .safe { background: #d4edda; border: 1px solid #c3e6cb; padding: 14px; border-radius: 6px; margin: 14px 0; }
    .info { background: #f9f9f9; border: 1px solid #ddd; padding: 14px; border-radius: 6px; font-family: monospace; word-break: break-all; }
    a { color: #27ae60; }
    button { margin-top: 14px; padding: 8px 18px; background: #555; color: white; border: none; border-radius: 4px; cursor: pointer; }
  </style>
</head>
<body>
  <h1>Dashboard [FIXED]</h1>

  <div class="info">
    <strong>Logged in as:</strong> ${escapeHtml(user.username)} (${escapeHtml(user.role)})<br><br>
    <strong>Session ID:</strong><br>
    <span style="color:#27ae60;font-size:0.85rem">${escapeHtml(sessionId)}</span><br><br>
    <em style="color:#666;font-size:0.8rem">
      64 hex characters = 32 random bytes = 2<sup>256</sup> possible values.
      An attacker cannot guess this.
    </em>
  </div>

  <div class="safe">
    <strong>&#10003; Compare to the vulnerable version:</strong><br>
    Vulnerable session ID: <code style="color:red">3</code> (trivially guessable)<br>
    This session ID: <code style="color:#27ae60;font-size:0.75rem">${escapeHtml(sessionId.slice(0, 16))}...</code> (256-bit random, unguessable)
  </div>

  <p><a href="/passwords">View hashed passwords (educational)</a></p>

  <form method="POST" action="/logout">
    <button type="submit">Log Out</button>
  </form>
</body>
</html>`;
}

function renderPasswordsPage() {
  const rows = users.map(u => `
    <tr>
      <td>${escapeHtml(u.username)}</td>
      <td style="font-family:monospace;font-size:0.75rem;word-break:break-all;color:#27ae60">${escapeHtml(u.hash)}</td>
      <td style="font-family:monospace;font-size:0.75rem">${escapeHtml(u.salt)}</td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Hashed Passwords [FIXED]</title>
  <style>
    body { font-family: sans-serif; padding: 24px; max-width: 900px; margin: 0 auto; }
    h1 { color: #27ae60; }
    .safe { background: #d4edda; border: 1px solid #c3e6cb; padding: 14px; border-radius: 6px; margin: 14px 0; }
    table { width: 100%; border-collapse: collapse; margin-top: 14px; }
    th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; vertical-align: top; }
    th { background: #f0f0f0; }
    .compare { display: flex; gap: 20px; margin-top: 20px; }
    .col { flex: 1; }
    .bad { background: #f8d7da; padding: 12px; border-radius: 4px; font-family: monospace; font-size: 0.85rem; }
    .good { background: #d4edda; padding: 12px; border-radius: 4px; font-family: monospace; font-size: 0.85rem; word-break: break-all; }
    a { color: #27ae60; }
  </style>
</head>
<body>
  <h1>Hashed Passwords (Safe to Show)</h1>

  <div class="safe">
    <strong>&#10003; Unlike /db in the vulnerable version, this page reveals nothing sensitive.</strong><br>
    These hashes cannot be reversed to recover the original password without brute-force guessing
    at 100,000 hash operations per guess. A 12-character random password would take longer than
    the age of the universe to crack on modern hardware.
  </div>

  <h2>Stored Values</h2>
  <table>
    <tr><th>Username</th><th>PBKDF2 Hash (128 hex chars)</th><th>Salt (32 hex chars)</th></tr>
    ${rows}
  </table>

  <h2>Plain Text vs Hashed — Side by Side</h2>
  <div class="compare">
    <div class="col">
      <strong style="color:red">Vulnerable (plain text):</strong>
      <div class="bad">
        alice: 123<br>
        bob:   password<br>
        admin: admin
      </div>
      <p style="font-size:0.85rem">If the DB is stolen, passwords are immediately usable.</p>
    </div>
    <div class="col">
      <strong style="color:#27ae60">Fixed (PBKDF2 hash):</strong>
      <div class="good">
        alice: ${escapeHtml(aliceCreds.hash.slice(0, 32))}...<br>
        bob:   ${escapeHtml(bobCreds.hash.slice(0, 32))}...
      </div>
      <p style="font-size:0.85rem">Even if stolen, each guess requires 100,000 SHA-512 operations.</p>
    </div>
  </div>

  <p><a href="/">Back to dashboard</a> | <a href="/login">Login page</a></p>
</body>
</html>`;
}

// ── Request handler ────────────────────────────────────────────────────────────

function handleRequest(req, res) {
  const parsed   = url.parse(req.url);
  const pathname = parsed.pathname;
  const ip       = req.socket.remoteAddress || 'unknown';

  // ── GET / ────────────────────────────────────────────────────────────────────
  if (req.method === 'GET' && pathname === '/') {
    const user = getSessionUser(req);
    if (!user) {
      res.writeHead(302, { Location: '/login' });
      res.end();
      return;
    }
    const sessionId = parseCookies(req)['sessionId'];
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(renderDashboard(user, sessionId));
    return;
  }

  // ── GET /login ───────────────────────────────────────────────────────────────
  if (req.method === 'GET' && pathname === '/login') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(renderLogin(null, ip));
    return;
  }

  // ── POST /login ──────────────────────────────────────────────────────────────
  if (req.method === 'POST' && pathname === '/login') {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      // ✅ FIX 3: Check lockout before even reading credentials
      if (isLockedOut(ip)) {
        const remaining = remainingLockoutSeconds(ip);
        console.log(`[BLOCKED] Login attempt from locked-out IP ${ip} (${remaining}s remaining)`);
        res.writeHead(429, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(renderLogin(`Too many failed attempts. Wait ${remaining} second(s).`, ip));
        return;
      }

      const data     = querystring.parse(body);
      const username = (data.username || '').trim();
      const password = (data.password || '').trim();

      // ✅ FIX 4: Minimum password length check
      if (password.length < MIN_PASSWORD_LEN) {
        recordFailure(ip);
        res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(renderLogin(`Password must be at least ${MIN_PASSWORD_LEN} characters.`, ip));
        return;
      }

      const user = users.find(u => u.username === username);

      // ✅ FIX 1: Use verifyPassword (PBKDF2) instead of plain text comparison
      if (!user || !verifyPassword(password, user.hash, user.salt)) {
        const count = recordFailure(ip);
        const locked = isLockedOut(ip);
        console.log(`[FAIL] Login for "${username}" from ${ip} — attempt ${count}/${MAX_ATTEMPTS}${locked ? ' — NOW LOCKED OUT' : ''}`);
        res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' });
        const remaining = MAX_ATTEMPTS - count;
        const msg = locked
          ? `Too many failed attempts. Locked out for ${LOCKOUT_SECONDS} seconds.`
          : `Invalid credentials. ${remaining} attempt(s) remaining before lockout.`;
        res.end(renderLogin(msg, ip));
        return;
      }

      // ✅ FIX 2: Random session ID — 32 bytes = 64 hex chars
      const sessionId = generateSessionId();
      sessions[sessionId] = user.id;

      // Reset failed attempts on successful login
      delete failedAttempts[ip];

      console.log(`[LOGIN] ${user.username} logged in. Session ID: ${sessionId.slice(0, 16)}... (random)`);

      res.writeHead(302, {
        'Location': '/',
        // HttpOnly prevents JavaScript from reading the cookie (XSS mitigation)
        'Set-Cookie': `sessionId=${sessionId}; Path=/; HttpOnly; SameSite=Strict`,
      });
      res.end();
    });
    return;
  }

  // ── POST /logout ─────────────────────────────────────────────────────────────
  if (req.method === 'POST' && pathname === '/logout') {
    const cookies   = parseCookies(req);
    const sessionId = cookies['sessionId'];
    if (sessionId) delete sessions[sessionId];
    res.writeHead(302, {
      'Location': '/login',
      'Set-Cookie': 'sessionId=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict',
    });
    res.end();
    return;
  }

  // ── GET /passwords — ✅ shows hashed values only (educational, not sensitive) ─
  if (req.method === 'GET' && pathname === '/passwords') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(renderPasswordsPage());
    return;
  }

  // ── 404 ──────────────────────────────────────────────────────────────────────
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
}

// ── Start server ───────────────────────────────────────────────────────────────

const server = http.createServer(handleRequest);
server.listen(PORT, () => {
  console.log('=== AUTH FAILURES DEMO (FIXED) ===');
  console.log(`Server running at http://localhost:${PORT}`);
  console.log('');
  console.log('Test credentials:  alice / SecurePass1!   bob / MyS3cretPwd!');
  console.log('');
  console.log('Protections active:');
  console.log('  1. Passwords hashed with PBKDF2 (100,000 iterations, random salt)');
  console.log('  2. Session IDs: 32 random bytes (64 hex chars)');
  console.log('  3. IP lockout: ' + MAX_ATTEMPTS + ' failures → ' + LOCKOUT_SECONDS + 's lockout');
  console.log('  4. Minimum password length: ' + MIN_PASSWORD_LEN + ' characters');
  console.log('  5. /db removed; /passwords shows only hashes');
  console.log('');
});
