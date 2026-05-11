// ============================================================
// 08-cryptographic-failures/vulnerable.js
// Demonstrates weak password hashing (MD5, no salt) and
// plain-text storage of sensitive data.
// Run: node vulnerable.js  →  http://localhost:3008
// ============================================================

const http        = require('http');
const url         = require('url');
const querystring = require('querystring');
const crypto      = require('crypto');

const PORT = 3008;

// ---------------------------------------------------------------
// In-memory "database" — pre-populated with a well-known user.
// ❌ Stores plain-text passwords AND weak MD5 hashes AND raw credit cards.
// ---------------------------------------------------------------

// ❌ VULNERABILITY: MD5 is a fast, general-purpose hash — not designed for passwords.
// Cracking tools can test billions of MD5 hashes per second on a GPU.
// MD5('password123') = 482c811da5d5b4bc6d497ffa98491e38
// This exact value is in every rainbow table on the internet.
function md5(text) {
  return crypto.createHash('md5').update(text).digest('hex');
}

const users = [
  {
    username:     'alice',
    // ❌ NO SALT: identical passwords produce identical hashes.
    passwordHash: md5('password123'),   // 482c811da5d5b4bc6d497ffa98491e38
    // ❌ TERRIBLE: plain text password stored for "convenience"
    plainPassword: 'password123',
    // ❌ Credit card stored in full plain text
    creditCard:   '4111-1111-1111-1111',
  },
];

// Helper to render the users table (shows hashes, plain text — the horror)
function renderUsersTable() {
  if (users.length === 0) return '<p>No registered users yet.</p>';

  let rows = users.map(u => `
    <tr>
      <td>${u.username}</td>
      <td style="color:#c0392b;font-family:monospace">${u.passwordHash}</td>
      <td style="color:#c0392b;font-weight:bold">${u.plainPassword}</td>
      <td style="color:#c0392b">${u.creditCard}</td>
    </tr>`).join('');

  return `
    <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;width:100%;font-size:0.9rem;">
      <thead style="background:#f8d7da;">
        <tr>
          <th>Username</th>
          <th>Password Hash (MD5)</th>
          <th style="color:#c0392b">Plain Password (!)</th>
          <th style="color:#c0392b">Credit Card (plain text!)</th>
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
  <title>Cryptographic Failures — VULNERABLE</title>
  <style>
    body  { font-family: sans-serif; padding: 24px; max-width: 860px; margin: 0 auto; }
    h1    { color: #c0392b; }
    .warn { background: #fff3cd; border: 1px solid #ffc107; padding: 14px; border-radius: 6px; margin: 14px 0; }
    .bad  { background: #f8d7da; border: 1px solid #f5c6cb; padding: 14px; border-radius: 6px; margin: 14px 0; }
    label { display: block; margin: 10px 0 4px; font-weight: bold; }
    input[type=text], input[type=password] {
      width: 100%; padding: 8px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px;
    }
    button { padding: 9px 22px; background: #c0392b; color: white; border: none;
             border-radius: 4px; cursor: pointer; margin-top: 12px; }
    code   { background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }
    table  { margin-top: 6px; }
    th, td { border: 1px solid #ccc; padding: 8px; }
  </style>
</head>
<body>
  <h1>Cryptographic Failures Demo [VULNERABLE]</h1>

  <div class="bad">
    <strong>What's wrong here?</strong>
    <ul>
      <li>Passwords are hashed with <strong>MD5</strong> — a fast algorithm designed for checksums, not passwords.</li>
      <li>No salt is used — identical passwords produce <strong>identical hashes</strong>.</li>
      <li>MD5 hashes can be reversed with rainbow tables in milliseconds.</li>
      <li>Plain-text passwords are stored alongside the hash (worst practice).</li>
      <li>Credit card numbers are stored in full plain text.</li>
    </ul>
  </div>

  <div class="warn">
    <strong>Rainbow table fact:</strong> MD5 of "password123" =
    <code>482c811da5d5b4bc6d497ffa98491e38</code><br>
    Search that hash on <em>any</em> rainbow table website — it cracks instantly!
  </div>

  <h2>Register a new user</h2>
  <form method="POST" action="/register">
    <label>Username</label>
    <input type="text" name="username" placeholder="e.g. bob" required>
    <label>Password</label>
    <input type="text" name="password" placeholder="try 'password123' again — same MD5!">
    <label>Credit Card</label>
    <input type="text" name="creditcard" placeholder="e.g. 5500-0000-0000-0004">
    <button type="submit">Register</button>
  </form>

  <h2>Stored "Database" (what an attacker sees after a breach)</h2>
  ${renderUsersTable()}

  <div class="bad" style="margin-top:16px;">
    Register two users with the same password — notice they get <strong>the same MD5 hash</strong>.
    An attacker only needs to crack the hash once to compromise all matching accounts.
  </div>
</body>
</html>`);
    return;
  }

  // ---------------------------------------------------------------
  // POST /register
  // ❌ Hashes with MD5, no salt, stores plain text
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

      // ❌ VULNERABILITY 1: MD5 with no salt.
      // Two users with "password123" both get 482c811da5d5b4bc6d497ffa98491e38.
      const hash = md5(password);

      users.push({
        username,
        passwordHash:  hash,
        plainPassword: password,   // ❌ Never store the plain-text password!
        creditCard:    creditcard, // ❌ Never store full card numbers!
      });

      // Redirect back to main page to show the updated table.
      res.writeHead(302, { Location: '/' });
      res.end();
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('404 Not Found');
});

server.listen(PORT, () => {
  console.log(`[VULNERABLE] Cryptographic Failures server running at http://localhost:${PORT}`);
  console.log('Register users and watch MD5 hashes repeat for identical passwords.');
  console.log('Note: MD5("password123") = 482c811da5d5b4bc6d497ffa98491e38');
});
