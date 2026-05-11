// ============================================================
// 08-cryptographic-failures/fixed.js
// All cryptographic failures from vulnerable.js are corrected:
//   - PBKDF2 with random per-user salt instead of MD5
//   - Credit card masked to last 4 digits only
//   - No plain-text passwords stored
// Run: node fixed.js  →  http://localhost:3108
// ============================================================

const http        = require('http');
const url         = require('url');
const querystring = require('querystring');
const crypto      = require('crypto');

const PORT = 3108;

// ---------------------------------------------------------------
// ✅ FIX: PBKDF2 with a random per-user salt.
//
// Why PBKDF2 is better than MD5:
//   1. It is intentionally slow (100,000 iterations) — brute force
//      takes years instead of milliseconds.
//   2. A random salt means identical passwords produce different hashes —
//      rainbow tables are useless.
//   3. PBKDF2 is NIST-approved for password hashing (FIPS 140-2).
//
// Alternatives: bcrypt, scrypt, Argon2 (even better, but need npm packages).
// For Node.js built-ins, PBKDF2 is the right choice.
// ---------------------------------------------------------------

const PBKDF2_ITERATIONS = 100_000; // NIST recommends >= 10,000; 100k is solid
const PBKDF2_KEYLEN     = 64;      // 512-bit output
const PBKDF2_DIGEST     = 'sha512';

function hashPassword(password) {
  // ✅ Generate a cryptographically random salt — unique per user, per registration.
  // Even if two users have identical passwords they will have different salts
  // and therefore completely different hashes.
  const salt = crypto.randomBytes(16).toString('hex'); // 32 hex chars

  // ✅ PBKDF2 stretches the password through 100,000 rounds of SHA-512.
  // On modern hardware this takes roughly 0.1–1 second — acceptable for login
  // but makes brute-forcing billions of candidates completely impractical.
  const hash = crypto
    .pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST)
    .toString('hex'); // 128 hex chars

  // Store salt alongside hash so we can verify later.
  return { salt, hash };
}

function verifyPassword(password, storedSalt, storedHash) {
  // ✅ Re-derive using the same salt and compare.
  const hash = crypto
    .pbkdf2Sync(password, storedSalt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST)
    .toString('hex');
  // ✅ Use timingSafeEqual to prevent timing attacks.
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHash, 'hex'));
}

// ✅ FIX: Mask credit card — store only the last 4 digits.
// Never store full card numbers. PCI-DSS prohibits it.
function maskCard(cardNumber) {
  const digits = cardNumber.replace(/\D/g, ''); // strip non-digits
  if (digits.length < 4) return '****';
  return `****-****-****-${digits.slice(-4)}`;
}

// ---------------------------------------------------------------
// In-memory "database" — pre-populated with alice using PBKDF2.
// Note: every time the server restarts alice gets a NEW hash
// because randomBytes() generates a fresh salt each time.
// ---------------------------------------------------------------
const alicePassword = 'password123';
const aliceHashed   = hashPassword(alicePassword);

const users = [
  {
    username:     'alice',
    salt:         aliceHashed.salt,
    passwordHash: aliceHashed.hash, // 128-char hex — unique every server restart
    creditCard:   maskCard('4111111111111111'), // stored as ****-****-****-1111
  },
];

function renderUsersTable() {
  if (users.length === 0) return '<p>No registered users yet.</p>';

  let rows = users.map(u => `
    <tr>
      <td>${u.username}</td>
      <td style="font-family:monospace;font-size:0.75rem;word-break:break-all">${u.salt}</td>
      <td style="font-family:monospace;font-size:0.75rem;word-break:break-all;color:#155724">${u.passwordHash}</td>
      <td>${u.creditCard}</td>
    </tr>`).join('');

  return `
    <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;width:100%;font-size:0.9rem;">
      <thead style="background:#d4edda;">
        <tr>
          <th>Username</th>
          <th>Salt (random, 32 hex chars)</th>
          <th style="color:#155724">PBKDF2-SHA512 Hash (128 hex chars)</th>
          <th>Credit Card (masked)</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

const server = http.createServer((req, res) => {
  const parsed   = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // ---------------------------------------------------------------
  // GET / — Main page with registration form and user table
  // ---------------------------------------------------------------
  if (pathname === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Cryptographic Failures — FIXED</title>
  <style>
    body  { font-family: sans-serif; padding: 24px; max-width: 900px; margin: 0 auto; }
    h1    { color: #27ae60; }
    .ok   { background: #d4edda; border: 1px solid #c3e6cb; padding: 14px; border-radius: 6px; margin: 14px 0; }
    .info { background: #cce5ff; border: 1px solid #b8daff; padding: 14px; border-radius: 6px; margin: 14px 0; }
    label { display: block; margin: 10px 0 4px; font-weight: bold; }
    input[type=text], input[type=password] {
      width: 100%; padding: 8px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px;
    }
    button { padding: 9px 22px; background: #27ae60; color: white; border: none;
             border-radius: 4px; cursor: pointer; margin-top: 12px; }
    code   { background: #f4f4f4; padding: 2px 5px; border-radius: 3px; font-size: 0.9em; }
    table  { margin-top: 6px; }
    th, td { border: 1px solid #ccc; padding: 8px; }
  </style>
</head>
<body>
  <h1>Cryptographic Failures Demo [FIXED]</h1>

  <div class="ok">
    <strong>What's fixed here?</strong>
    <ul>
      <li>Passwords hashed with <strong>PBKDF2-SHA512, 100,000 iterations</strong> — built into Node.js <code>crypto</code>.</li>
      <li>Each user gets a <strong>unique random salt</strong> — identical passwords produce completely different hashes.</li>
      <li>100,000 iterations means brute-forcing a single candidate takes ~0.5 seconds — <em>years</em> for a full dictionary attack.</li>
      <li>Only the last 4 digits of the credit card are stored. Full card numbers are never saved.</li>
      <li>Plain-text passwords are never stored anywhere.</li>
    </ul>
  </div>

  <div class="info">
    <strong>Register two users with "password123"</strong> — notice each gets a
    <em>completely different</em> 128-character hash because of the random salt.
    An attacker who steals the database cannot use rainbow tables and must
    crack each hash individually — at 0.5 seconds per guess.
  </div>

  <h2>Register a new user</h2>
  <form method="POST" action="/register">
    <label>Username</label>
    <input type="text" name="username" placeholder="e.g. bob" required>
    <label>Password</label>
    <input type="password" name="password" placeholder="try 'password123' twice — different hashes!">
    <label>Credit Card</label>
    <input type="text" name="creditcard" placeholder="e.g. 5500-0000-0000-0004 — only last 4 stored">
    <button type="submit">Register</button>
  </form>

  <h2>Stored "Database" (safe even if breached)</h2>
  ${renderUsersTable()}

  <div class="ok" style="margin-top:16px;">
    <strong>PBKDF2 parameters used:</strong>
    iterations = ${PBKDF2_ITERATIONS.toLocaleString()},
    key length = ${PBKDF2_KEYLEN * 8} bits,
    digest = ${PBKDF2_DIGEST.toUpperCase()}<br>
    Salt length = 16 bytes (${16 * 2} hex chars), generated with <code>crypto.randomBytes()</code>.
  </div>
</body>
</html>`);
    return;
  }

  // ---------------------------------------------------------------
  // POST /register
  // ✅ Hashes with PBKDF2 + random salt, masks credit card
  // ---------------------------------------------------------------
  if (pathname === '/register' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      const data       = querystring.parse(body);
      const username   = (data.username   || '').trim();
      const password   = (data.password   || '').trim();
      const creditcard = (data.creditcard || '').trim();

      if (!username || !password) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Username and password required.');
        return;
      }

      // ✅ PBKDF2 with fresh random salt — slow and unique per user.
      const { salt, hash } = hashPassword(password);

      users.push({
        username,
        salt,
        passwordHash: hash,
        // ✅ Mask the card — store only what's needed for display.
        creditCard: creditcard ? maskCard(creditcard) : 'N/A',
      });

      res.writeHead(302, { Location: '/' });
      res.end();
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('404 Not Found');
});

server.listen(PORT, () => {
  console.log(`[FIXED] Cryptographic Failures server running at http://localhost:${PORT}`);
  console.log('Register two users with the same password — their PBKDF2 hashes will differ.');
  console.log(`PBKDF2 settings: ${PBKDF2_ITERATIONS.toLocaleString()} iterations, SHA-512, 64-byte key`);
});
