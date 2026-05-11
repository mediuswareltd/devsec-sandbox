// ============================================================
// VULNERABILITY DEMO: Broken Access Control (IDOR)
// ============================================================
// WHAT IS THE BUG?
//   The server fetches any user's profile based on the ?id= parameter
//   in the URL, without checking if the logged-in user is allowed
//   to see that profile.
//
// HOW TO EXPLOIT:
//   1. Run this file: node vulnerable.js
//   2. Open: http://localhost:3001
//   3. You are logged in as Alice (id=1)
//   4. Visit http://localhost:3001/profile?id=2 to see Bob's SSN!
//   5. Visit http://localhost:3001/profile?id=3 to see Charlie's SSN!
// ============================================================

const http = require('http');
const url  = require('url');

// --- Simulated database (in a real app this would be a real DB) ---
const users = [
  { id: 1, username: 'alice',   email: 'alice@example.com',   balance: 5000,  ssn: '123-45-6789', address: '10 Maple St' },
  { id: 2, username: 'bob',     email: 'bob@example.com',     balance: 3200,  ssn: '987-65-4321', address: '22 Oak Ave'  },
  { id: 3, username: 'charlie', email: 'charlie@example.com', balance: 8750,  ssn: '456-78-9012', address: '5 Pine Rd'   },
];

// In a real app the logged-in user comes from a session cookie.
// For this demo we hardcode: Alice is always logged in.
const LOGGED_IN_USER_ID = 1;

// --- HTML helpers ---
function page(title, body) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
  <title>${title}</title>
  <style>
    body { font-family: sans-serif; padding: 24px; max-width: 620px; margin: 0 auto; }
    h1   { color: #c0392b; }
    .box { background: #fff3cd; border: 1px solid #ffc107; padding: 14px; border-radius: 6px; margin: 16px 0; }
    .bug { background: #f8d7da; border: 1px solid #f5c6cb; padding: 14px; border-radius: 6px; margin-top: 20px; color: #721c24; }
    a    { display: inline-block; padding: 8px 14px; margin: 4px 0; background: #eee;
           border-radius: 4px; text-decoration: none; color: #333; }
    a:hover { background: #ddd; }
    .label { color: #888; font-size: 0.85rem; }
    .sensitive { color: #c0392b; font-weight: bold; }
  </style></head><body>${body}</body></html>`;
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);

  // --- Home page ---
  if (parsed.pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(page('Profile App (VULNERABLE)', `
      <h1>Profile Viewer [VULNERABLE]</h1>
      <div class="box">
        You are logged in as: <strong>alice (id=1)</strong><br>
        Try clicking another user's profile to see their private data!
      </div>
      <h3>Choose a profile to view:</h3>
      <a href="/profile?id=1">Your own profile (alice, id=1)</a>
      <a href="/profile?id=2">Bob's profile (id=2) &larr; Try this!</a>
      <a href="/profile?id=3">Charlie's profile (id=3) &larr; Try this!</a>
    `));

  // --- Profile page ---
  } else if (parsed.pathname === '/profile') {
    const requestedId = parseInt(parsed.query.id, 10);
    const user = users.find(u => u.id === requestedId);

    if (!user) {
      res.writeHead(404, { 'Content-Type': 'text/html' });
      res.end(page('Not Found', '<h1>User not found</h1><a href="/">Back</a>'));
      return;
    }

    // ❌ VULNERABILITY IS HERE:
    // We find the user by ID and show ALL their data.
    // We NEVER check: "Is the logged-in user (alice, id=1) allowed to view this profile?"
    // An attacker just changes ?id=2 to see Bob's private information.
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(page(`Profile: ${user.username}`, `
      <h1>Profile: ${user.username}</h1>
      <p><span class="label">Email:</span> ${user.email}</p>
      <p><span class="label">Balance:</span> $${user.balance}</p>
      <p class="sensitive"><span class="label">SSN:</span> ${user.ssn}</p>
      <p class="sensitive"><span class="label">Address:</span> ${user.address}</p>
      <div class="bug">
        <strong>Bug found!</strong> You are <em>alice</em> (id=1) but you just read
        <em>${user.username}</em>'s SSN and address. The server never checked your permission!
      </div>
      <a href="/">← Back</a>
    `));

  } else {
    res.writeHead(404); res.end('Not found');
  }
});

server.listen(3001, () => {
  console.log('');
  console.log('=== VULNERABLE: Broken Access Control ===');
  console.log('Server running at http://localhost:3001');
  console.log('');
  console.log('You are Alice (id=1). Try:');
  console.log('  http://localhost:3001/profile?id=2  <-- See Bob\'s SSN!');
  console.log('  http://localhost:3001/profile?id=3  <-- See Charlie\'s SSN!');
  console.log('');
});
