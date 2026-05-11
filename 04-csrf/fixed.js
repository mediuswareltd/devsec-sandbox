// ============================================================
// FIXED VERSION: Cross-Site Request Forgery (CSRF)
// ============================================================
// THE FIX:
//   1. On GET /, generate a random CSRF token and store it in a session
//   2. Embed the token as a hidden field in the transfer form
//   3. On POST /transfer, verify the submitted token matches the stored one
//   4. An attacker's page cannot know the token → transfer blocked
// ============================================================

const http   = require('http');
const url    = require('url');
const qs     = require('querystring');
const crypto = require('crypto');

let accounts = { alice: 1000, bob: 500 };
const CURRENT_USER = 'alice';

// Simple in-memory session store: sessionId → { csrfToken }
const sessions = {};

// Generate a random session ID for Alice when server starts (simplified for demo)
const ALICE_SESSION_ID = crypto.randomBytes(16).toString('hex');
sessions[ALICE_SESSION_ID] = { csrfToken: null };

function generateCsrfToken(sessionId) {
  // ✅ FIX: Generate a new random token each time the page is loaded
  const token = crypto.randomBytes(32).toString('hex');
  sessions[sessionId].csrfToken = token;
  return token;
}

function bankPage(csrfToken, message) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
  <title>SafeBank (FIXED)</title>
  <style>
    body  { font-family: sans-serif; padding: 24px; max-width: 580px; margin: 0 auto; }
    h1    { color: #27ae60; }
    .box  { background: #d4edda; border: 1px solid #c3e6cb; padding: 14px; border-radius: 6px; margin: 14px 0; }
    .msg  { background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; border-radius: 4px; margin-bottom: 14px; }
    .fix  { background: #d1ecf1; border: 1px solid #bee5eb; padding: 12px; border-radius: 4px; margin-top: 14px; font-size: 0.9rem; }
    input  { padding: 6px; margin: 4px 0; width: 200px; display: block; }
    button { padding: 8px 20px; background: #27ae60; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
    a      { display: inline-block; margin-top: 10px; padding: 8px 14px; background: #eee; border-radius: 4px; text-decoration: none; color: #333; }
  </style></head><body>
  <h1>SafeBank [FIXED]</h1>
  <div class="box">
    Logged in as: <strong>alice</strong><br>
    Alice's balance: <strong>$${accounts.alice}</strong><br>
    Bob's balance: $${accounts.bob}
  </div>
  ${message ? `<div class="msg">${message}</div>` : ''}
  <h3>Transfer Money</h3>
  <form method="POST" action="/transfer">
    <label>To: <input name="to" value="bob"></label>
    <label>Amount: <input name="amount" type="number" value="100"></label>
    <!-- ✅ FIX: Hidden CSRF token field. The attacker's page doesn't know this value! -->
    <input type="hidden" name="_csrf" value="${csrfToken}">
    <button type="submit">Transfer</button>
  </form>
  <a href="/attacker">⚠️ Try Attacker's Page (will fail now)</a>
  <a href="/reset">Reset balances</a>
  <div class="fix">
    <strong>Protection active:</strong> Every form includes a hidden CSRF token
    (<code>${csrfToken.substring(0,16)}...</code>).<br>
    An attacker's page cannot know this random token, so cross-site form submissions are rejected.
  </div>
  </body></html>`;
}

const attackerPage = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>WIN A FREE iPHONE!!!</title>
<style>body{font-family:sans-serif;padding:24px;background:#fffbe6}
h1{color:#e67e22}.blocked{background:#d4edda;border:1px solid #c3e6cb;padding:14px;border-radius:6px;margin-top:20px}</style>
</head><body>
<h1>Congratulations! You won a FREE iPhone!</h1>
<form id="csrf-form" method="POST" action="http://localhost:3105/transfer" style="display:none">
  <input name="to" value="bob">
  <input name="amount" value="200">
  <!-- ❌ No _csrf token — this will be rejected by the fixed server! -->
</form>
<script>window.onload = function(){ document.getElementById('csrf-form').submit(); };</script>
<div class="blocked">
  <strong>Attack failed!</strong> The bank rejected the transfer because
  the form did not contain a valid CSRF token. The attacker cannot guess the token.
</div>
</body></html>`;

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);

  if (req.method === 'GET' && parsed.pathname === '/') {
    const token = generateCsrfToken(ALICE_SESSION_ID);
    res.writeHead(200, {
      'Content-Type': 'text/html',
      // In a real app this cookie would be HttpOnly and Secure
      'Set-Cookie': `sessionId=${ALICE_SESSION_ID}; Path=/`
    });
    res.end(bankPage(token, ''));

  } else if (req.method === 'GET' && parsed.pathname === '/attacker') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(attackerPage);

  } else if (req.method === 'GET' && parsed.pathname === '/reset') {
    accounts = { alice: 1000, bob: 500 };
    res.writeHead(302, { Location: '/' }); res.end();

  } else if (req.method === 'POST' && parsed.pathname === '/transfer') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      const params  = qs.parse(body);
      const session = sessions[ALICE_SESSION_ID];

      // ✅ FIX: Verify the CSRF token before processing
      if (!params._csrf || params._csrf !== session.csrfToken) {
        res.writeHead(403, { 'Content-Type': 'text/html' });
        res.end(`<!DOCTYPE html><html><body style="font-family:sans-serif;padding:24px">
          <h1 style="color:#c0392b">403 — CSRF Token Invalid</h1>
          <p>The request was rejected because it did not include a valid CSRF token.</p>
          <p>This is what blocks cross-site attacks: the attacker's page cannot know your token.</p>
          <a href="/">← Back to bank</a></body></html>`);
        return;
      }

      const amount = parseInt(params.amount, 10) || 0;
      const to     = params.to;
      if (accounts[CURRENT_USER] >= amount && accounts[to] !== undefined) {
        accounts[CURRENT_USER] -= amount;
        accounts[to]           += amount;
        const newToken = generateCsrfToken(ALICE_SESSION_ID); // rotate token after use
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(bankPage(newToken, `Transferred $${amount} to ${to}.`));
      } else {
        const newToken = generateCsrfToken(ALICE_SESSION_ID);
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(bankPage(newToken, 'Transfer failed.'));
      }
    });

  } else {
    res.writeHead(404); res.end('Not found');
  }
});

server.listen(3105, () => {
  console.log('');
  console.log('=== FIXED: CSRF Demo ===');
  console.log('Bank running at http://localhost:3105');
  console.log('Try the attacker page — the transfer will be blocked with 403.');
  console.log('');
});
