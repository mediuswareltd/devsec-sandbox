/**
 * SQL INJECTION DEMO — FIXED (PARAMETERIZED QUERY) VERSION
 * ==========================================================
 * This file demonstrates the CORRECT approach: parameterized queries.
 *
 * HOW PARAMETERIZED QUERIES PREVENT SQL INJECTION:
 * --------------------------------------------------
 * Instead of concatenating user input into the query string, we:
 *   1. Define the query structure with placeholders: WHERE username = ? AND password = ?
 *   2. Pass the user's values separately as a parameter array: [username, password]
 *
 * The database engine (or ORM) treats those values as pure DATA, never as SQL syntax.
 * No matter what characters the attacker types — quotes, OR, --, semicolons — they are
 * compared literally against stored values, not interpreted as SQL.
 *
 * WHY THE ATTACK FAILS:
 *   Attacker submits username: ' OR '1'='1
 *   The parameterized lookup searches for a user whose username column literally equals
 *   the 14-character string  ' OR '1'='1  — which does not exist in the database.
 *   Authentication fails. Injection is impossible.
 *
 * HOW TO RUN:
 *   node sql-fixed.js
 *   Open http://localhost:3102
 *
 * Compare with sql-vulnerable.js to see the difference.
 */

'use strict';

const http        = require('http');
const url         = require('url');
const querystring = require('querystring');

const PORT = 3102;

// ---------------------------------------------------------------------------
// In-memory "database" — same data as the vulnerable version
// ---------------------------------------------------------------------------
const users = [
  { id: 1, username: 'admin', password: 'secret123',  role: 'administrator' },
  { id: 2, username: 'alice', password: 'mypassword', role: 'user'          },
];

// ---------------------------------------------------------------------------
// SAFE login function — simulates a parameterized query
// ---------------------------------------------------------------------------
/**
 * Simulates a parameterized SQL query:
 *   SELECT * FROM users WHERE username = ? AND password = ?
 *   Parameters: [username, password]
 *
 * In a real application using a database driver (e.g., sqlite3, pg, mysql2),
 * the equivalent code would be:
 *
 *   db.get(
 *     'SELECT * FROM users WHERE username = ? AND password = ?',
 *     [username, password],
 *     callback
 *   );
 *
 * The driver escapes the values and sends them to the database engine separately
 * from the query structure. The engine never re-parses user input as SQL.
 *
 * @param {string} username - User-supplied username
 * @param {string} password - User-supplied password
 * @returns {{ user: object|null, safeQuery: string, params: string[], injectionAttempted: boolean }}
 */
function safeLogin(username, password) {
  // Show the parameterized query pattern (educational display only)
  const safeQuery = 'SELECT * FROM users WHERE username = ? AND password = ?';
  const params    = [username, password];

  // Detect whether the attacker tried an injection (for educational display)
  const injectionPatterns = [
    /'\s*OR\s*'1'\s*=\s*'1/i,
    /'\s*OR\s*1\s*=\s*1/i,
    /'\s*--/,
    /'\s*;/,
    /'\s*OR\s*'[^']+'\s*=\s*'[^']+'/i,
  ];
  const injectionAttempted =
    injectionPatterns.some(p => p.test(username)) ||
    injectionPatterns.some(p => p.test(password));

  // FIX: Use exact string equality — user input is treated as data, not SQL.
  // Array.find() here represents what the parameterized driver does internally:
  // compare the literal value of the parameter against the stored value.
  const user = users.find(u => u.username === username && u.password === password) || null;

  return { user, safeQuery, params, injectionAttempted };
}

// ---------------------------------------------------------------------------
// HTML helpers
// ---------------------------------------------------------------------------
function htmlPage(title, bodyContent) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 820px; margin: 40px auto; padding: 0 20px; background: #0f0f0f; color: #e0e0e0; }
    h1   { color: #44dd88; }
    h2   { color: #44bb77; border-bottom: 1px solid #333; padding-bottom: 6px; }
    h3   { color: #88ffaa; }
    label { display: block; margin-bottom: 4px; color: #aaa; }
    input[type=text], input[type=password] {
      width: 100%; padding: 8px; margin-bottom: 14px; background: #1e1e1e;
      border: 1px solid #444; color: #e0e0e0; border-radius: 4px; box-sizing: border-box;
    }
    button {
      background: #1a6b40; color: #fff; border: none; padding: 10px 24px;
      border-radius: 4px; cursor: pointer; font-size: 1rem;
    }
    button:hover { background: #22884f; }
    .card { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
    .safe    { border-left: 4px solid #44dd88; }
    .info    { border-left: 4px solid #3399ff; }
    .blocked { border-left: 4px solid #ff9944; }
    .success { color: #44dd88; font-weight: bold; }
    .failure { color: #ff4d4d; font-weight: bold; }
    .blocked-msg { color: #ff9944; font-weight: bold; }
    pre  { background: #111; padding: 14px; border-radius: 4px; overflow-x: auto; color: #7ec8e3; font-size: 0.9rem; white-space: pre-wrap; word-break: break-all; }
    code { background: #222; padding: 2px 6px; border-radius: 3px; color: #88ffaa; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: bold; }
    .badge-safe  { background: #003320; color: #44dd88; border: 1px solid #44dd88; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 8px 12px; border: 1px solid #333; text-align: left; }
    th { background: #222; color: #88ffaa; }
  </style>
</head>
<body>
${bodyContent}
</body>
</html>`;
}

function loginForm(message) {
  return htmlPage('SQL Injection — Fixed', `
  <h1>SQL Injection Demo <span class="badge badge-safe">FIXED</span></h1>

  <div class="card safe">
    <h2>What changed?</h2>
    <p>
      This server uses a <strong>parameterized query</strong>. The SQL structure is defined
      once with placeholders (<code>?</code>), and user values are passed <em>separately</em>.
      The database engine never parses user input as SQL.
    </p>
    <p>Try the same injection attacks — they will all fail because input is treated as data.</p>
    <p>Switch to <code>sql-vulnerable.js</code> (same port) to see the broken version.</p>
  </div>

  <div class="card">
    <h2>Login</h2>
    <form method="POST" action="/login">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" placeholder="admin" autocomplete="off">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="password" autocomplete="off">
      <button type="submit">Sign In</button>
    </form>
  </div>

  ${message || ''}

  <div class="card info">
    <h2>Attacks to try (they all fail now)</h2>
    <table>
      <tr><th>Username</th><th>Password</th><th>Expected result</th></tr>
      <tr>
        <td><code>' OR '1'='1</code></td>
        <td><em>anything</em></td>
        <td>Login fails — no user with that literal username</td>
      </tr>
      <tr>
        <td><code>admin' --</code></td>
        <td><em>anything</em></td>
        <td>Login fails — treated as a literal string</td>
      </tr>
      <tr>
        <td><code>admin</code></td>
        <td><code>secret123</code></td>
        <td>Login succeeds (correct credentials)</td>
      </tr>
    </table>
  </div>

  <div class="card safe">
    <h2>The safe code</h2>
    <pre>// SAFE — parameterized query pattern
const sql    = 'SELECT * FROM users WHERE username = ? AND password = ?';
const params = [username, password];   // values are DATA, never parsed as SQL

// With a real DB driver (e.g., sqlite3, pg, mysql2):
db.get(sql, params, (err, row) => {
  if (row) { /* login success */ }
});

// The driver sends the query structure and parameter values separately.
// The database engine NEVER evaluates the parameter values as SQL.</pre>
  </div>
`);
}

function resultPage(username, password, result) {
  const { user, safeQuery, params, injectionAttempted } = result;

  const statusHtml = user
    ? `<p class="success">Login successful — welcome, ${escHtml(user.username)}!</p>`
    : `<p class="failure">Login failed — invalid credentials.</p>`;

  return htmlPage('SQL Injection — Result (Fixed)', `
  <h1>SQL Injection Demo <span class="badge badge-safe">FIXED</span></h1>

  <div class="card ${injectionAttempted && !user ? 'blocked' : 'safe'}">
    <h2>Result</h2>
    ${statusHtml}
    ${injectionAttempted && !user
      ? `<p class="blocked-msg">Injection attempt detected — but it was completely blocked!
         The attack string was treated as a literal value, not SQL syntax.</p>`
      : ''}
    ${user ? `<p>Role: <strong>${escHtml(user.role)}</strong></p>` : ''}
  </div>

  <div class="card safe">
    <h2>Parameterized Query (safe pattern)</h2>
    <p>Query structure (defined by the developer, never changes):</p>
    <pre>${escHtml(safeQuery)}</pre>
    <p>Parameter values (passed separately as data):</p>
    <pre>${escHtml(JSON.stringify(params, null, 2))}</pre>
    <p>
      Notice that the query structure is <em>fixed</em>. User input only appears in the
      parameter array. No matter what the attacker types, it can only ever be compared
      as a string value — it cannot alter the query's structure.
    </p>
  </div>

  <div class="card info">
    <h2>What you submitted</h2>
    <p>Username: <code>${escHtml(username)}</code></p>
    <p>Password: <code>${escHtml(password)}</code></p>
    ${injectionAttempted
      ? `<p>Injection syntax detected in input: <strong>blocked safely</strong>.</p>`
      : ''}
  </div>

  <p><a href="/" style="color:#3399ff">← Try again</a></p>
`);
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------
const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url);
  const pathname  = parsedUrl.pathname;

  if (req.method === 'GET' && pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(loginForm(null));
    return;
  }

  if (req.method === 'POST' && pathname === '/login') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      const params   = querystring.parse(body);
      const username = params.username || '';
      const password = params.password || '';

      // FIX: safeLogin uses exact string matching (parameterized query pattern).
      // Injection strings are compared literally — they will never match a real username.
      const result = safeLogin(username, password);

      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(resultPage(username, password, result));
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log('');
  console.log('==========================================================');
  console.log('  SQL INJECTION DEMO — FIXED SERVER (PARAMETERIZED QUERIES)');
  console.log(`  http://localhost:${PORT}`);
  console.log('==========================================================');
  console.log('');
  console.log('  This server uses parameterized queries.');
  console.log('  SQL injection attacks are completely blocked.');
  console.log('');
  console.log('  WHY IT IS SAFE:');
  console.log("    Query:  'SELECT * FROM users WHERE username = ? AND password = ?'");
  console.log("    Params: [username, password]");
  console.log('');
  console.log("    Even if username is  ' OR '1'='1  the database compares that");
  console.log('    literal string against the username column — it cannot alter');
  console.log('    the query structure.');
  console.log('');
  console.log('  Run sql-vulnerable.js to see the broken version.');
  console.log('');
});
