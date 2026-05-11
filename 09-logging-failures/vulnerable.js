const http = require('http');
const url = require('url');
const querystring = require('querystring');

const PORT = 3009;

const users = [
  { username: 'alice', password: 'alice123' },
  { username: 'admin', password: 'adminpass' },
];

function getLoginPage(message, messageType, attemptCount) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>09 - Logging Failures (VULNERABLE)</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee; min-height: 100vh; padding: 30px 20px; }
    h1 { color: #e94560; margin-bottom: 6px; }
    .subtitle { color: #aaa; margin-bottom: 24px; font-size: 14px; }
    .warning-banner {
      background: #3d0000;
      border: 2px solid #e94560;
      border-radius: 8px;
      padding: 16px 20px;
      margin-bottom: 24px;
    }
    .warning-banner h2 { color: #ff6b6b; margin-bottom: 8px; font-size: 16px; }
    .warning-banner p { color: #ffaaaa; font-size: 14px; line-height: 1.6; }
    .card {
      background: #16213e;
      border-radius: 10px;
      padding: 24px;
      margin-bottom: 20px;
      border: 1px solid #0f3460;
    }
    .card h2 { margin-bottom: 16px; font-size: 16px; color: #a8dadc; }
    label { display: block; margin-bottom: 6px; font-size: 14px; color: #bbb; }
    input[type=text], input[type=password] {
      width: 100%;
      padding: 10px 14px;
      border-radius: 6px;
      border: 1px solid #0f3460;
      background: #0d1b2a;
      color: #eee;
      font-size: 14px;
      margin-bottom: 14px;
    }
    button {
      padding: 10px 22px;
      border-radius: 6px;
      border: none;
      background: #e94560;
      color: #fff;
      font-size: 14px;
      cursor: pointer;
    }
    button:hover { background: #c73652; }
    .msg-success { background: #1a3a1a; border: 1px solid #4caf50; color: #81c784; padding: 10px 14px; border-radius: 6px; margin-bottom: 14px; }
    .msg-error   { background: #3a1a1a; border: 1px solid #e94560; color: #ff8a80; padding: 10px 14px; border-radius: 6px; margin-bottom: 14px; }
    .attacker-box {
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 16px;
      font-family: 'Courier New', monospace;
      font-size: 13px;
      color: #7ee787;
      white-space: pre-wrap;
    }
    .attacker-box .comment { color: #8b949e; }
    .counter {
      font-size: 13px;
      color: #f9a825;
      margin-top: 10px;
    }
    .hint { font-size: 12px; color: #888; margin-top: 8px; }
    .hint strong { color: #e94560; }
  </style>
</head>
<body>
  <h1>09 — Logging &amp; Monitoring Failures</h1>
  <p class="subtitle">VULNERABLE version — running on port ${PORT}</p>

  <div class="warning-banner">
    <h2>&#9888; VULNERABILITY ACTIVE: This server logs NOTHING</h2>
    <p>
      Every login attempt — successful or failed — is completely invisible to the server operator.
      An attacker can try thousands of passwords with zero trace in any log, terminal, or audit trail.
      Check your terminal right now: you will see no output no matter how many times you log in.
    </p>
  </div>

  <div class="card">
    <h2>Login Form</h2>
    ${message ? `<div class="msg-${messageType}">${message}</div>` : ''}
    <form method="POST" action="/login">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" placeholder="Try: alice or admin" autocomplete="off">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="Password">
      <button type="submit">Login</button>
    </form>
    <p class="counter" id="counter">Client-side attempt counter: <strong id="cnt">${attemptCount}</strong> (resets on page reload — server has NO counter)</p>
    <p class="hint"><strong>Hint:</strong> Correct credentials — alice / alice123 &nbsp;|&nbsp; admin / adminpass</p>
  </div>

  <div class="card">
    <h2>What an attacker script looks like</h2>
    <div class="attacker-box"><span class="comment"># Attacker runs this — server will NEVER know:</span>

wordlist = ["password", "123456", "admin", "letmein", "adminpass", ...]

for password in wordlist:
    response = POST /login {
        username: "admin",
        password: password
    }
    if response contains "Welcome":
        print("FOUND:", password)
        break

<span class="comment"># → Server logs: (nothing)
# → Server alerts: (nothing)
# → Time to detect: NEVER</span></div>
  </div>

  <div class="card">
    <h2>Server Terminal Output Right Now</h2>
    <div class="attacker-box"><span class="comment"># Your terminal shows:
$ node vulnerable.js
Server running on port 3009

# That's it. No login attempts. No failures. No IPs. Nothing.</span></div>
  </div>

  <script>
    // Client-side only — meaningless for security, just for illustration
    const key = 'vuln09_attempts';
    let count = parseInt(sessionStorage.getItem(key) || '${attemptCount}', 10);
    document.getElementById('cnt').textContent = count;
  </script>
</body>
</html>`;
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  if (req.method === 'GET' && pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(getLoginPage(null, null, 0));
    return;
  }

  if (req.method === 'POST' && pathname === '/login') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      const data = querystring.parse(body);
      const { username, password } = data;

      // ❌ NO LOGGING — nothing is recorded anywhere
      const user = users.find(u => u.username === username && u.password === password);

      if (user) {
        // ❌ Success not logged
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(getLoginPage(`Welcome, ${username}! (Login succeeded — but this was not logged anywhere.)`, 'success', 0));
      } else {
        // ❌ Failure not logged — attacker can try forever
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(getLoginPage('Invalid credentials. (This failure was NOT logged — try again silently!)', 'error', 0));
      }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`[09-logging-failures] VULNERABLE server running on http://localhost:${PORT}`);
  console.log(`Notice: This server logs NOTHING. Watch this terminal — it will stay silent no matter what.`);
});
