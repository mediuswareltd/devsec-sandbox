// ============================================================
// 06-security-misconfiguration/vulnerable.js
// Demonstrates MULTIPLE security misconfigurations in one server.
// Run: node vulnerable.js  →  http://localhost:3007
// ============================================================

const http = require('http');
const url  = require('url');

const PORT = 3007;

const server = http.createServer((req, res) => {
  const parsed  = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // ❌ MISCONFIGURATION 1: Leaking technology stack in every response header.
  // Attackers scan for "X-Powered-By" to know exactly which runtime and
  // framework version to target with known exploits.
  res.setHeader('X-Powered-By', 'Node.js v18.0.0');
  // ❌ Pretending to be Express just to show header-based info leakage.
  res.setHeader('Server', 'express/4.18.0');

  // ---------------------------------------------------------------
  // Route: GET /
  // ❌ MISCONFIGURATION 2: Sensitive credentials left in HTML comments.
  // Developers sometimes leave API keys or passwords in source code
  // comments "temporarily". Attackers simply View Source to find them.
  // ---------------------------------------------------------------
  if (pathname === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Misconfiguration — VULNERABLE</title>
  <style>
    body { font-family: sans-serif; padding: 24px; max-width: 720px; margin: 0 auto; }
    h1   { color: #c0392b; }
    .warn { background: #fff3cd; border: 1px solid #ffc107; padding: 14px;
            border-radius: 6px; margin: 14px 0; }
    a    { display: inline-block; margin: 6px 8px 6px 0; padding: 8px 16px;
           background: #c0392b; color: white; border-radius: 4px; text-decoration: none; }
    code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
  </style>
</head>
<body>
  <!-- ❌ VULNERABILITY: Secrets in HTML comments — visible to anyone who does View Source!
       TODO: remove this before prod.
       DB_PASSWORD=supersecret123
       API_KEY=sk-abc123def456
       STRIPE_SECRET=sk_live_abc999xyz
  -->

  <h1>Security Misconfiguration Demo [VULNERABLE]</h1>

  <div class="warn">
    <strong>Check DevTools Network tab</strong> — look at the response headers.<br>
    <code>X-Powered-By: Node.js v18.0.0</code> and <code>Server: express/4.18.0</code>
    are being sent on every request, revealing our tech stack to attackers.
  </div>

  <div class="warn">
    <strong>Right-click → View Page Source</strong> — find the secret API key
    and DB password hidden in an HTML comment near the top.
  </div>

  <h2>Try these misconfigured endpoints:</h2>
  <a href="/crash">/crash — exposes full stack trace</a>
  <a href="/admin">/admin — default credentials</a>
  <a href="/debug">/debug — exposes process.env</a>
</body>
</html>`);
    return;
  }

  // ---------------------------------------------------------------
  // Route: GET /crash
  // ❌ MISCONFIGURATION 3: Full stack trace sent to the browser.
  // Stack traces reveal file paths, library versions, and internal
  // logic — a treasure map for an attacker.
  // ---------------------------------------------------------------
  if (pathname === '/crash' && req.method === 'GET') {
    try {
      // Simulate an internal error (e.g., DB timeout).
      throw new Error(
        'Database connection failed: pg.connect() timeout after 5000ms ' +
        'at /etc/myapp/config/db.js:42'
      );
    } catch (err) {
      // ❌ VULNERABILITY: sends the full stack trace to the user!
      // The attacker now knows file paths, library versions, and where
      // to look for further weaknesses.
      res.writeHead(500, { 'Content-Type': 'text/html' });
      res.end(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>500 Error</title>
<style>body{font-family:sans-serif;padding:24px;} pre{color:red;background:#fff0f0;padding:12px;border-radius:4px;overflow:auto;}</style>
</head>
<body>
  <h2>500 Internal Server Error</h2>
  <!-- ❌ Full stack trace exposed to anyone on the internet! -->
  <pre>${err.stack}</pre>
  <p><strong>Full error exposed to user!</strong> Attackers love stack traces —
  they reveal your file layout, framework, and exact failure point.</p>
</body>
</html>`);
    }
    return;
  }

  // ---------------------------------------------------------------
  // Route: GET /admin  (and /admin?password=admin)
  // ❌ MISCONFIGURATION 4: Default credentials that everyone knows,
  // AND the default password is shown right on the login page.
  // ---------------------------------------------------------------
  if (pathname === '/admin' && req.method === 'GET') {
    const password = parsed.query.password;

    // ❌ VULNERABILITY: The default password is "admin" and it is printed
    // on the page in plain sight so users know how to log in.
    if (password === 'admin') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Admin Panel</title>
<style>body{font-family:sans-serif;padding:24px;} .secret{background:#d4edda;padding:14px;border-radius:6px;}</style>
</head>
<body>
  <h2>Admin Panel — Access Granted</h2>
  <div class="secret">
    <p>Secret admin data:</p>
    <ul>
      <li>Users in DB: 42,000</li>
      <li>Revenue this month: $128,400</li>
      <li>Internal API endpoint: http://internal.corp/api/v1/users</li>
    </ul>
  </div>
  <p>You logged in with the default password <code>admin</code>.
  The password was displayed on the login page — anyone could get in.</p>
</body>
</html>`);
    } else {
      // ❌ VULNERABILITY: Shows the default password on the unauthenticated page.
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Admin Login</title>
<style>body{font-family:sans-serif;padding:24px;} .warn{background:#fff3cd;padding:14px;border-radius:6px;}</style>
</head>
<body>
  <h2>Admin Panel</h2>
  <div class="warn">
    Enter password: <strong>admin</strong> (default — never changed)<br><br>
    <a href="/admin?password=admin">Click here to log in with default password</a>
  </div>
  <p>❌ The default credential is publicly visible on this page!</p>
</body>
</html>`);
    }
    return;
  }

  // ---------------------------------------------------------------
  // Route: GET /debug
  // ❌ MISCONFIGURATION 5: Debug endpoint left open in production.
  // Dumps ALL environment variables — including secrets, tokens,
  // database URLs — to anyone who visits the URL.
  // ---------------------------------------------------------------
  if (pathname === '/debug' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      // ❌ VULNERABILITY: process.env exposes ALL environment variables!
      // This can contain AWS keys, database passwords, API tokens, etc.
      nodeVersion:   process.version,
      platform:      process.platform,
      env:           process.env,   // ← dumps everything: PATH, HOME, secrets...
      uptime:        process.uptime(),
      memoryUsage:   process.memoryUsage(),
      cwd:           process.cwd(), // reveals server's working directory
    }, null, 2));
    return;
  }

  // 404 fallback
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('404 Not Found');
});

server.listen(PORT, () => {
  console.log(`[VULNERABLE] Security Misconfiguration server running at http://localhost:${PORT}`);
  console.log('Try:');
  console.log(`  http://localhost:${PORT}/        — view source for hidden secrets`);
  console.log(`  http://localhost:${PORT}/crash   — full stack trace in browser`);
  console.log(`  http://localhost:${PORT}/admin   — default credentials`);
  console.log(`  http://localhost:${PORT}/debug   — dumps process.env`);
});
