// ============================================================
// 06-security-misconfiguration/fixed.js
// All misconfigurations from vulnerable.js are corrected here.
// Run: node fixed.js  →  http://localhost:3107
// ============================================================

const http = require('http');
const url  = require('url');

const PORT = 3107;

// ✅ FIX: Store the admin token as an environment variable (or config file).
// Never hardcode credentials. Here we use a random-looking bearer token.
// In production this would come from process.env.ADMIN_TOKEN.
const ADMIN_TOKEN = 'Bearer s3cur3-r4nd0m-t0k3n-d0-n0t-sh4re';

const server = http.createServer((req, res) => {
  const parsed   = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // ✅ FIX 1: Remove technology-revealing headers.
  // Do NOT set X-Powered-By or Server. If a framework sets them automatically,
  // explicitly delete them (e.g., app.disable('x-powered-by') in Express).

  // ✅ FIX: Add security headers on every response.
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');

  // ---------------------------------------------------------------
  // Route: GET /
  // ✅ FIX 2: No sensitive comments in HTML source.
  // ---------------------------------------------------------------
  if (pathname === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Misconfiguration — FIXED</title>
  <style>
    body { font-family: sans-serif; padding: 24px; max-width: 720px; margin: 0 auto; }
    h1   { color: #27ae60; }
    .ok  { background: #d4edda; border: 1px solid #c3e6cb; padding: 14px;
           border-radius: 6px; margin: 14px 0; }
    a    { display: inline-block; margin: 6px 8px 6px 0; padding: 8px 16px;
           background: #27ae60; color: white; border-radius: 4px; text-decoration: none; }
    code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
  </style>
</head>
<body>
  <!-- No secrets here. Production HTML should never contain credentials,
       API keys, or internal paths, not even in comments. -->

  <h1>Security Misconfiguration Demo [FIXED]</h1>

  <div class="ok">
    <strong>Headers fixed.</strong> No <code>X-Powered-By</code> or <code>Server</code>
    header is sent. Security headers (<code>X-Content-Type-Options</code>,
    <code>X-Frame-Options</code>) are present instead.
  </div>

  <div class="ok">
    <strong>View Page Source</strong> — no secrets in HTML comments.
  </div>

  <h2>Try these fixed endpoints:</h2>
  <a href="/crash">/crash — generic error message only</a>
  <a href="/admin">/admin — requires Authorization header</a>
</body>
</html>`);
    return;
  }

  // ---------------------------------------------------------------
  // Route: GET /crash
  // ✅ FIX 3: Generic error message to the user; full detail logged
  //           server-side only (where only operators can see it).
  // ---------------------------------------------------------------
  if (pathname === '/crash' && req.method === 'GET') {
    try {
      throw new Error(
        'Database connection failed: pg.connect() timeout after 5000ms ' +
        'at /etc/myapp/config/db.js:42'
      );
    } catch (err) {
      // ✅ Log the real error server-side (visible only to operators).
      console.error('[ERROR]', new Date().toISOString(), err.stack);

      // ✅ Return a generic message — no stack trace, no file paths.
      res.writeHead(500, { 'Content-Type': 'text/html' });
      res.end(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Error</title>
<style>body{font-family:sans-serif;padding:24px;} .box{background:#f8d7da;padding:14px;border-radius:6px;}</style>
</head>
<body>
  <h2>Something went wrong</h2>
  <div class="box">
    An error occurred while processing your request. Reference: <strong>ERR-001</strong><br><br>
    Please try again or contact support if the problem persists.
  </div>
  <p>The full error was logged server-side (check your terminal).
  No stack trace is sent to the browser.</p>
</body>
</html>`);
    }
    return;
  }

  // ---------------------------------------------------------------
  // Route: GET /admin
  // ✅ FIX 4: Requires a proper Authorization header.
  //           Returns 401 with no hints about what the credential is.
  //           The /debug endpoint is removed entirely.
  // ---------------------------------------------------------------
  if (pathname === '/admin' && req.method === 'GET') {
    const authHeader = req.headers['authorization'];

    // ✅ Check for a strong bearer token, not a trivial password in a query string.
    if (authHeader !== ADMIN_TOKEN) {
      // ✅ Return 401 — do NOT reveal the expected credential or hint at a default.
      res.writeHead(401, {
        'Content-Type': 'text/html',
        'WWW-Authenticate': 'Bearer realm="Admin Area"',
      });
      res.end(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>401 Unauthorized</title>
<style>body{font-family:sans-serif;padding:24px;} .box{background:#f8d7da;padding:14px;border-radius:6px;}</style>
</head>
<body>
  <h2>401 Unauthorized</h2>
  <div class="box">
    Access denied. A valid <code>Authorization</code> header is required.<br><br>
    No default credentials. No hints. Contact your administrator.
  </div>
</body>
</html>`);
      return;
    }

    // Authenticated — show admin panel.
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Admin Panel</title>
<style>body{font-family:sans-serif;padding:24px;} .secret{background:#d4edda;padding:14px;border-radius:6px;}</style>
</head>
<body>
  <h2>Admin Panel — Access Granted</h2>
  <div class="secret">
    <p>You authenticated with a valid bearer token (provided via Authorization header).</p>
    <ul>
      <li>Users in DB: 42,000</li>
      <li>Revenue this month: $128,400</li>
    </ul>
  </div>
  <p>The token was never shown on a public page and is not a trivial default value.</p>
</body>
</html>`);
    return;
  }

  // ✅ FIX 5: The /debug endpoint simply does not exist.
  // There is no route that dumps process.env or internal server state.

  // 404 fallback — generic message, no framework version leak.
  res.writeHead(404, { 'Content-Type': 'text/html' });
  res.end(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>404</title></head>
<body><h2>404 — Page not found</h2></body>
</html>`);
});

server.listen(PORT, () => {
  console.log(`[FIXED] Security Misconfiguration server running at http://localhost:${PORT}`);
  console.log('Admin endpoint requires header:');
  console.log(`  Authorization: ${ADMIN_TOKEN}`);
  console.log('Example curl:');
  console.log(`  curl -H "Authorization: ${ADMIN_TOKEN}" http://localhost:${PORT}/admin`);
});
