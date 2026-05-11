/**
 * COMMAND INJECTION DEMO — VULNERABLE VERSION
 * =============================================
 * This file intentionally contains a command injection vulnerability for educational purposes.
 * NEVER pass unsanitized user input to child_process.exec() in real applications.
 *
 * HOW COMMAND INJECTION WORKS:
 * ------------------------------
 * child_process.exec() passes its first argument to the OS shell (/bin/sh on Unix,
 * cmd.exe on Windows). The shell interprets special characters such as:
 *   &   (Windows)  — run another command after this one
 *   |   (both)     — pipe output to another command
 *   ;   (Unix)     — run another command after this one
 *   `   (Unix)     — command substitution
 *   $() (Unix)     — command substitution
 *
 * If user input is concatenated into the shell string, an attacker can append
 * these characters to inject and execute arbitrary OS commands.
 *
 * EXAMPLE ATTACK (Windows):
 *   User enters:  127.0.0.1 & dir C:\
 *   Shell runs:   ping -n 2 127.0.0.1 & dir C:\
 *   Result:       ping output PLUS a full directory listing of C:\
 *
 * EXAMPLE ATTACK (Linux/Mac):
 *   User enters:  127.0.0.1; ls /
 *   Shell runs:   ping -c 2 127.0.0.1; ls /
 *   Result:       ping output PLUS a full listing of the root filesystem
 *
 * HOW TO RUN:
 *   node command-vulnerable.js
 *   Open http://localhost:3003
 */

'use strict';

const http         = require('http');
const url          = require('url');
const querystring  = require('querystring');
const { exec }     = require('child_process');

const PORT      = 3003;
const isWindows = process.platform === 'win32';

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
    body { font-family: system-ui, sans-serif; max-width: 860px; margin: 40px auto; padding: 0 20px; background: #0f0f0f; color: #e0e0e0; }
    h1   { color: #ff4d4d; }
    h2   { color: #ff9944; border-bottom: 1px solid #333; padding-bottom: 6px; }
    label { display: block; margin-bottom: 4px; color: #aaa; }
    input[type=text] {
      width: 100%; padding: 8px; margin-bottom: 14px; background: #1e1e1e;
      border: 1px solid #444; color: #e0e0e0; border-radius: 4px; box-sizing: border-box;
      font-family: monospace;
    }
    button {
      background: #c0392b; color: #fff; border: none; padding: 10px 24px;
      border-radius: 4px; cursor: pointer; font-size: 1rem;
    }
    button:hover { background: #e74c3c; }
    .card { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
    .vuln  { border-left: 4px solid #ff4d4d; }
    .info  { border-left: 4px solid #3399ff; }
    pre  { background: #111; padding: 14px; border-radius: 4px; overflow-x: auto; color: #7ec8e3; font-size: 0.9rem; white-space: pre-wrap; word-break: break-all; }
    code { background: #222; padding: 2px 6px; border-radius: 3px; color: #ff9944; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: bold; }
    .badge-vuln { background: #4d0000; color: #ff4d4d; border: 1px solid #ff4d4d; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 8px 12px; border: 1px solid #333; text-align: left; }
    th { background: #222; color: #ffcc44; }
    .cmd-display { color: #ff4d4d; font-weight: bold; }
  </style>
</head>
<body>
${bodyContent}
</body>
</html>`;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function indexPage() {
  const windowsExample = '127.0.0.1 &amp; dir C:\\';
  const unixExample    = '127.0.0.1; ls /';
  const pipeExample    = '127.0.0.1 | whoami';

  return htmlPage('Command Injection — Vulnerable', `
  <h1>Network Diagnostic Tool <span class="badge badge-vuln">VULNERABLE</span></h1>

  <div class="card info">
    <h2>About this demo</h2>
    <p>
      This tool pings a hostname to test connectivity. It uses
      <code>child_process.exec()</code> and builds the command by <strong>concatenating
      user input directly into the shell string</strong>.
    </p>
    <p>
      An attacker can inject shell metacharacters to run <em>any command</em>
      on the server. The injected command runs with the same privileges as this
      Node.js process.
    </p>
    <p>Switch to <code>command-fixed.js</code> (same port) to see the safe version.</p>
  </div>

  <div class="card">
    <h2>Ping a host</h2>
    <form method="GET" action="/ping">
      <label for="host">Hostname or IP address</label>
      <input type="text" id="host" name="host" placeholder="127.0.0.1" autocomplete="off" value="127.0.0.1">
      <button type="submit">Ping</button>
    </form>
  </div>

  <div class="card vuln">
    <h2>Injection attacks to try</h2>
    <table>
      <tr><th>Platform</th><th>Input</th><th>What it does</th></tr>
      <tr>
        <td>Windows</td>
        <td><code>127.0.0.1 &amp; dir C:\</code></td>
        <td>Runs ping, then lists C:\\ directory</td>
      </tr>
      <tr>
        <td>Windows</td>
        <td><code>127.0.0.1 &amp; whoami</code></td>
        <td>Reveals the server's current user</td>
      </tr>
      <tr>
        <td>Windows</td>
        <td><code>127.0.0.1 | type C:\\Windows\\System32\\drivers\\etc\\hosts</code></td>
        <td>Reads the hosts file</td>
      </tr>
      <tr>
        <td>Linux/Mac</td>
        <td><code>127.0.0.1; ls /</code></td>
        <td>Runs ping, then lists root filesystem</td>
      </tr>
      <tr>
        <td>Linux/Mac</td>
        <td><code>127.0.0.1; whoami</code></td>
        <td>Reveals the server's current user</td>
      </tr>
      <tr>
        <td>Linux/Mac</td>
        <td><code>127.0.0.1; cat /etc/passwd</code></td>
        <td>Reads the passwd file</td>
      </tr>
    </table>
    <p style="color:#ff9944;margin-top:12px;">
      You are running on: <strong>${isWindows ? 'Windows' : 'Linux/Mac'}</strong>
    </p>
  </div>

  <div class="card vuln">
    <h2>The vulnerable code</h2>
    <pre>// VULNERABLE — never do this!
const { exec } = require('child_process');

app.get('/ping', (req, res) => {
  const host = req.query.host;  // raw, unsanitized!

  // exec() passes this string to the OS shell.
  // Shell metacharacters in 'host' will be interpreted!
  const cmd = \`ping -n 2 \${host}\`;  // Windows example

  exec(cmd, { timeout: 5000 }, (err, stdout, stderr) => {
    res.send(stdout + stderr);
  });
});</pre>
    <p>
      <code>exec()</code> invokes <code>cmd.exe</code> (Windows) or <code>/bin/sh</code> (Unix).
      The entire string is handed to the shell for parsing — including any injected operators.
    </p>
  </div>
`);
}

function pingResultPage(host, cmd, stdout, stderr, error) {
  const output = (stdout || '') + (stderr || '') + (error ? '\nError: ' + error.message : '');

  return htmlPage('Command Injection — Result', `
  <h1>Network Diagnostic Tool <span class="badge badge-vuln">VULNERABLE</span></h1>

  <div class="card vuln">
    <h2>Command executed</h2>
    <p>The following shell command was built from your input and executed:</p>
    <pre class="cmd-display">${escHtml(cmd)}</pre>
    <p>
      Notice how your input was inserted verbatim. If you used <code>&amp;</code>,
      <code>|</code>, or <code>;</code>, the shell ran additional commands.
    </p>
  </div>

  <div class="card">
    <h2>Output</h2>
    <pre>${escHtml(output || '(no output)')}</pre>
  </div>

  <div class="card info">
    <h2>Input received</h2>
    <p>host parameter: <code>${escHtml(host)}</code></p>
  </div>

  <p><a href="/" style="color:#3399ff">← Try another input</a></p>
`);
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------
const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname  = parsedUrl.pathname;

  if (req.method === 'GET' && pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(indexPage());
    return;
  }

  if (req.method === 'GET' && pathname === '/ping') {
    // VULNERABILITY: host is taken from the query string without any sanitization
    const host = parsedUrl.query.host || '';

    if (!host) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Missing host parameter');
      return;
    }

    // VULNERABILITY: user input is directly concatenated into the shell command string.
    // child_process.exec() passes this string to the OS shell.
    // The shell interprets &, |, ;, `, $() etc. as command operators.
    const cmd = isWindows
      ? `ping -n 2 ${host}`   // Windows: & chains commands
      : `ping -c 2 ${host}`;  // Unix:    ; or | chains commands

    console.log(`[VULNERABLE] Executing shell command: ${cmd}`);

    exec(cmd, { timeout: 8000 }, (error, stdout, stderr) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(pingResultPage(host, cmd, stdout, stderr, error));
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log('');
  console.log('==========================================================');
  console.log('  COMMAND INJECTION DEMO — VULNERABLE SERVER');
  console.log(`  http://localhost:${PORT}`);
  console.log('==========================================================');
  console.log('');
  console.log('  This server is INTENTIONALLY VULNERABLE.');
  console.log('  It passes user input directly to exec() without sanitization.');
  console.log('');
  if (isWindows) {
    console.log('  ATTACK EXAMPLE (you are on Windows):');
    console.log('    Host input:  127.0.0.1 & dir C:\\');
    console.log('    Shell runs:  ping -n 2 127.0.0.1 & dir C:\\');
    console.log('    The & operator runs dir C:\\ as a second command!');
  } else {
    console.log('  ATTACK EXAMPLE (you are on Linux/Mac):');
    console.log('    Host input:  127.0.0.1; ls /');
    console.log('    Shell runs:  ping -c 2 127.0.0.1; ls /');
    console.log('    The ; operator runs ls / as a second command!');
  }
  console.log('');
  console.log('  The exact command built from input is shown on the results page.');
  console.log('  Run command-fixed.js to see the safe version.');
  console.log('');
});
