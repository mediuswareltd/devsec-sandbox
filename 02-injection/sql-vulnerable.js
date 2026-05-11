/**
 * SQL INJECTION DEMO — VULNERABLE VERSION
 * ========================================
 * This file intentionally contains a SQL injection vulnerability for educational purposes.
 * NEVER use string concatenation to build SQL queries in real applications.
 *
 * HOW SQL INJECTION WORKS:
 * --------------------------
 * SQL injection occurs when user-supplied input is embedded directly into a SQL query
 * string via string concatenation. The database engine cannot distinguish between the
 * developer's intended SQL structure and data injected by the attacker.
 *
 * EXAMPLE ATTACK:
 *   Normal query:   SELECT * FROM users WHERE username='alice' AND password='mypass'
 *   Injected query: SELECT * FROM users WHERE username='' OR '1'='1' AND password='x'
 *
 * The injected OR '1'='1' is always true, so the WHERE clause evaluates to true for
 * every row — the attacker is logged in as the first user in the table (usually admin).
 *
 * HOW TO RUN:
 *   node sql-vulnerable.js
 *   Open http://localhost:3002
 *
 * ATTACKS TO TRY:
 *   Username: ' OR '1'='1
 *   Password: anything
 *   → You will be logged in as admin without knowing the password!
 *
 *   Username: admin' --
 *   Password: anything
 *   → Comments out the password check entirely (in real SQL engines)
 */

'use strict';

const http        = require('http');
const url         = require('url');
const querystring = require('querystring');

const PORT = 3002;

// ---------------------------------------------------------------------------
// In-memory "database" — simulates a SQL users table
// ---------------------------------------------------------------------------
const users = [
  { id: 1, username: 'admin', password: 'secret123',  role: 'administrator' },
  { id: 2, username: 'alice', password: 'mypassword', role: 'user'          },
];

// ---------------------------------------------------------------------------
// VULNERABLE login function
// ---------------------------------------------------------------------------
/**
 * Simulates what a vulnerable SQL-backed login looks like.
 *
 * A real vulnerable server would do:
 *   const sql = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
 *   db.query(sql);  // <-- attacker controls the SQL structure!
 *
 * We reproduce the same logic in JavaScript so you can see EXACTLY what
 * the injected query string looks like and why it bypasses authentication.
 *
 * @param {string} username - Raw, unsanitized user input
 * @param {string} password - Raw, unsanitized user input
 * @returns {{ user: object|null, query: string, injectionDetected: boolean }}
 */
function vulnerableLogin(username, password) {
  // VULNERABILITY: User input is concatenated directly into the query string.
  // An attacker can insert SQL syntax characters (' " -- OR AND etc.) to change
  // the meaning of the query.
  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;

  // ---- Simulate SQL injection bypass ----
  // In a real database, the engine parses the full string as SQL.
  // We reproduce the most common injection: ' OR '1'='1
  // When injected as the username, the WHERE clause becomes:
  //   WHERE username='' OR '1'='1' AND password='...'
  // Since OR '1'='1' is always true, every row matches.
  const injectionPatterns = [
    /'\s*OR\s*'1'\s*=\s*'1/i,   // classic: ' OR '1'='1
    /'\s*OR\s*1\s*=\s*1/i,       // variant: ' OR 1=1
    /'\s*--/,                     // comment: ' --  (drops rest of query)
    /'\s*;/,                      // stacked queries
    /'\s*OR\s*'[^']+'\s*=\s*'[^']+'/i, // generic OR 'x'='x'
  ];

  const injectionDetected =
    injectionPatterns.some(p => p.test(username)) ||
    injectionPatterns.some(p => p.test(password));

  if (injectionDetected) {
    // Simulate the database returning the first row because the injected
    // OR condition made the WHERE clause always true.
    return { user: users[0], query, injectionDetected: true };
  }

  // Normal (non-injected) path — find a matching user
  const user = users.find(u => u.username === username && u.password === password) || null;
  return { user, query, injectionDetected: false };
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
    h1   { color: #ff4d4d; }
    h2   { color: #ff9944; border-bottom: 1px solid #333; padding-bottom: 6px; }
    h3   { color: #ffcc44; }
    label { display: block; margin-bottom: 4px; color: #aaa; }
    input[type=text], input[type=password] {
      width: 100%; padding: 8px; margin-bottom: 14px; background: #1e1e1e;
      border: 1px solid #444; color: #e0e0e0; border-radius: 4px; box-sizing: border-box;
    }
    button {
      background: #c0392b; color: #fff; border: none; padding: 10px 24px;
      border-radius: 4px; cursor: pointer; font-size: 1rem;
    }
    button:hover { background: #e74c3c; }
    .card { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
    .vuln  { border-left: 4px solid #ff4d4d; }
    .info  { border-left: 4px solid #3399ff; }
    .success { color: #44dd88; font-weight: bold; }
    .failure { color: #ff4d4d; font-weight: bold; }
    .injection { color: #ff9944; font-weight: bold; }
    pre  { background: #111; padding: 14px; border-radius: 4px; overflow-x: auto; color: #7ec8e3; font-size: 0.9rem; white-space: pre-wrap; word-break: break-all; }
    code { background: #222; padding: 2px 6px; border-radius: 3px; color: #ff9944; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: bold; }
    .badge-vuln  { background: #4d0000; color: #ff4d4d; border: 1px solid #ff4d4d; }
    .badge-safe  { background: #003320; color: #44dd88; border: 1px solid #44dd88; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 8px 12px; border: 1px solid #333; text-align: left; }
    th { background: #222; color: #ffcc44; }
  </style>
</head>
<body>
${bodyContent}
</body>
</html>`;
}

function loginForm(message) {
  return htmlPage('SQL Injection — Vulnerable', `
  <h1>SQL Injection Demo <span class="badge badge-vuln">VULNERABLE</span></h1>

  <div class="card info">
    <h2>What is happening here?</h2>
    <p>
      This server builds its SQL query by <strong>concatenating user input directly</strong>
      into the query string. Try the attacks below — the constructed SQL query will be shown
      after you submit so you can see exactly what gets sent to the "database".
    </p>
    <p>Switch to <code>sql-fixed.js</code> (same port) to see the safe version.</p>
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

  <div class="card vuln">
    <h2>Attacks to try</h2>
    <table>
      <tr><th>Username</th><th>Password</th><th>Effect</th></tr>
      <tr>
        <td><code>' OR '1'='1</code></td>
        <td><em>anything</em></td>
        <td>Bypasses auth — logs in as admin</td>
      </tr>
      <tr>
        <td><code>admin' --</code></td>
        <td><em>anything</em></td>
        <td>Comments out the password check</td>
      </tr>
      <tr>
        <td><code>admin</code></td>
        <td><code>secret123</code></td>
        <td>Normal valid login</td>
      </tr>
      <tr>
        <td><code>alice</code></td>
        <td><code>mypassword</code></td>
        <td>Normal valid login</td>
      </tr>
    </table>
  </div>

  <div class="card info">
    <h2>The vulnerable code</h2>
    <pre>// VULNERABLE — never do this!
const query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
db.query(query); // attacker controls SQL structure!</pre>
    <p>
      When <code>username</code> is <code>' OR '1'='1</code>, the query becomes:
    </p>
    <pre>SELECT * FROM users WHERE username='' OR '1'='1' AND password='x'</pre>
    <p>
      The <code>OR '1'='1'</code> condition is <em>always true</em>, so the WHERE clause
      matches every row. The database returns the first user — typically the admin account.
    </p>
  </div>
`);
}

function resultPage(username, password, result) {
  const { user, query, injectionDetected } = result;

  const statusHtml = user
    ? `<p class="${injectionDetected ? 'injection' : 'success'}">
        ${injectionDetected
          ? 'INJECTION SUCCESSFUL — logged in as ' + user.username + ' without the correct password!'
          : 'Login successful — welcome, ' + user.username + '!'}
       </p>`
    : `<p class="failure">Login failed — invalid credentials.</p>`;

  return htmlPage('SQL Injection — Result', `
  <h1>SQL Injection Demo <span class="badge badge-vuln">VULNERABLE</span></h1>

  <div class="card ${injectionDetected ? 'vuln' : ''}">
    <h2>Result</h2>
    ${statusHtml}
    ${user ? `<p>Role: <strong>${user.role}</strong></p>` : ''}
  </div>

  <div class="card vuln">
    <h2>Constructed SQL Query</h2>
    <p>This is the exact query string that was built from your input:</p>
    <pre>${escHtml(query)}</pre>
    ${injectionDetected
      ? `<p class="injection">The injected SQL changed the logic of the query!
         The OR condition made the WHERE clause always true.</p>`
      : `<p>No injection detected — input was treated as a normal query.</p>`}
  </div>

  <div class="card info">
    <h2>What you submitted</h2>
    <p>Username: <code>${escHtml(username)}</code></p>
    <p>Password: <code>${escHtml(password)}</code></p>
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
      // Raw, unsanitized input — this is the vulnerability
      const username = params.username || '';
      const password = params.password || '';

      const result = vulnerableLogin(username, password);

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
  console.log('  SQL INJECTION DEMO — VULNERABLE SERVER');
  console.log(`  http://localhost:${PORT}`);
  console.log('==========================================================');
  console.log('');
  console.log('  This server is INTENTIONALLY VULNERABLE.');
  console.log('  It demonstrates SQL injection via string concatenation.');
  console.log('');
  console.log('  ATTACK EXAMPLES:');
  console.log("    Username: ' OR '1'='1");
  console.log('    Password: (anything)');
  console.log('    Result:   Bypasses authentication, logs in as admin!');
  console.log('');
  console.log("    Username: admin' --");
  console.log('    Password: (anything)');
  console.log('    Result:   Comments out the password check!');
  console.log('');
  console.log('  The constructed SQL query is shown on the results page.');
  console.log('  Run sql-fixed.js to see the safe version.');
  console.log('');
});
