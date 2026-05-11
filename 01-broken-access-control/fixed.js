// ============================================================
// FIXED VERSION: Broken Access Control (IDOR)
// ============================================================
// THE FIX:
//   Before returning any profile data, the server checks:
//   "Does the requested id match the logged-in user's id?"
//   If not → 403 Forbidden.
//
// HOW TO TEST THE FIX:
//   1. Run: node fixed.js
//   2. Open: http://localhost:3101
//   3. Try http://localhost:3101/profile?id=2
//      → You will get "Access Denied" because you are alice (id=1)
// ============================================================

const http = require('http');
const url  = require('url');

const users = [
  { id: 1, username: 'alice',   email: 'alice@example.com',   balance: 5000,  ssn: '123-45-6789', address: '10 Maple St' },
  { id: 2, username: 'bob',     email: 'bob@example.com',     balance: 3200,  ssn: '987-65-4321', address: '22 Oak Ave'  },
  { id: 3, username: 'charlie', email: 'charlie@example.com', balance: 8750,  ssn: '456-78-9012', address: '5 Pine Rd'   },
];

const LOGGED_IN_USER_ID = 1; // Alice is logged in

function page(title, body) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
  <title>${title}</title>
  <style>
    body  { font-family: sans-serif; padding: 24px; max-width: 620px; margin: 0 auto; }
    h1    { color: #27ae60; }
    .box  { background: #d4edda; border: 1px solid #c3e6cb; padding: 14px; border-radius: 6px; margin: 16px 0; }
    .deny { background: #f8d7da; border: 1px solid #f5c6cb; padding: 14px; border-radius: 6px; color: #721c24; }
    .fix  { background: #d1ecf1; border: 1px solid #bee5eb; padding: 14px; border-radius: 6px; margin-top: 20px; }
    a     { display: inline-block; padding: 8px 14px; margin: 4px 0; background: #eee;
            border-radius: 4px; text-decoration: none; color: #333; }
    a:hover { background: #ddd; }
    .label { color: #888; font-size: 0.85rem; }
  </style></head><body>${body}</body></html>`;
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);

  if (parsed.pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(page('Profile App (FIXED)', `
      <h1>Profile Viewer [FIXED]</h1>
      <div class="box">
        You are logged in as: <strong>alice (id=1)</strong><br>
        You can only view your own profile. Try clicking another user's profile!
      </div>
      <h3>Choose a profile to view:</h3>
      <a href="/profile?id=1">Your own profile (alice, id=1)</a>
      <a href="/profile?id=2">Bob's profile (id=2) &larr; Will be blocked!</a>
      <a href="/profile?id=3">Charlie's profile (id=3) &larr; Will be blocked!</a>
    `));

  } else if (parsed.pathname === '/profile') {
    const requestedId = parseInt(parsed.query.id, 10);

    // ✅ THE FIX: Check that the requested profile belongs to the logged-in user.
    // If someone tries to view another user's profile, return 403 Forbidden.
    if (requestedId !== LOGGED_IN_USER_ID) {
      res.writeHead(403, { 'Content-Type': 'text/html' });
      res.end(page('Access Denied', `
        <h1 style="color:#c0392b">403 — Access Denied</h1>
        <div class="deny">
          You tried to view profile id=${requestedId}, but you are logged in as alice (id=1).<br>
          <strong>You can only view your own profile.</strong>
        </div>
        <div class="fix">
          <strong>Fix applied:</strong> The server now checks
          <code>if (requestedId !== LOGGED_IN_USER_ID)</code> before returning data.
          This is called <em>ownership check</em> or <em>authorization check</em>.
        </div>
        <a href="/">← Back</a>
      `));
      return;
    }

    const user = users.find(u => u.id === requestedId);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(page(`Profile: ${user.username}`, `
      <h1>Profile: ${user.username}</h1>
      <p><span class="label">Email:</span> ${user.email}</p>
      <p><span class="label">Balance:</span> $${user.balance}</p>
      <p><span class="label">SSN:</span> ${user.ssn}</p>
      <p><span class="label">Address:</span> ${user.address}</p>
      <div class="fix">
        <strong>This is your own profile</strong> — access permitted.
      </div>
      <a href="/">← Back</a>
    `));

  } else {
    res.writeHead(404); res.end('Not found');
  }
});

server.listen(3101, () => {
  console.log('');
  console.log('=== FIXED: Broken Access Control ===');
  console.log('Server running at http://localhost:3101');
  console.log('');
  console.log('Try visiting /profile?id=2 or /profile?id=3 — both will return 403 Forbidden');
  console.log('');
});
