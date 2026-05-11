/**
 * COMMAND INJECTION DEMO — FIXED VERSION
 * =========================================
 * This file demonstrates two complementary defenses against command injection:
 *
 *   1. INPUT VALIDATION — Whitelist regex that only permits valid hostname characters.
 *      Rejects the input before execution if it contains shell metacharacters.
 *
 *   2. execFile() INSTEAD OF exec() — Passes the command and arguments as an array,
 *      bypassing the shell entirely. No shell = no shell metacharacter interpretation.
 *
 * WHY BOTH DEFENSES?
 *   Validation alone is good but can have edge cases (encoding tricks, future regex gaps).
 *   execFile() alone is great but doesn't give the user clear feedback.
 *   Using both provides defense-in-depth.
 *
 * HOW TO RUN:
 *   node command-fixed.js
 *   Open http://localhost:3103
 *
 * Compare with command-vulnerable.js to see the difference.
 */

'use strict';

const http               = require('http');
const url                = require('url');
const querystring        = require('querystring');
const { execFile }       = require('child_process');

const PORT      = 3103;
const isWindows = process.platform === 'win32';

// ---------------------------------------------------------------------------
// FIX 1: Strict input validation — whitelist of allowed hostname characters
// ---------------------------------------------------------------------------
/**
 * A valid hostname or IP address contains ONLY:
 *   - letters (a-z, A-Z)
 *   - digits (0-9)
 *   - hyphens (-)
 *   - dots (.)
 *   - maximum length 253 characters (DNS limit)
 *
 * This regex REJECTS any input containing shell metacharacters such as:
 *   & | ; ` $ ( ) ! \ " ' space newline tab
 *
 * By failing early and loudly, we give the user a clear error message and
 * we never even attempt to execute a command with invalid input.
 */
const HOSTNAME_REGEX = /^[a-zA-Z0-9.\-]{1,253}$/;

function validateHostname(host) {
  if (!host || typeof host !== 'string') {
    return { valid: false, reason: 'Hostname must be a non-empty string.' };
  }
  if (!HOSTNAME_REGEX.test(host)) {
    return {
      valid: false,
      reason: 'Invalid hostname — only letters, numbers, dots, and hyphens are allowed. ' +
              'Shell metacharacters (&, |, ;, spaces, quotes, etc.) are rejected.',
    };
  }
  return { valid: true, reason: null };
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
    body { font-family: system-ui, sans-serif; max-width: 860px; margin: 40px auto; padding: 0 20px; background: #0f0f0f; color: #e0e0e0; }
    h1   { color: #44dd88; }
    h2   { color: #44bb77; border-bottom: 1px solid #333; padding-bottom: 6px; }
    label { display: block; margin-bottom: 4px; color: #aaa; }
    input[type=text] {
      width: 100%; padding: 8px; margin-bottom: 14px; background: #1e1e1e;
      border: 1px solid #444; color: #e0e0e0; border-radius: 4px; box-sizing: border-box;
      font-family: monospace;
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
    .error   { border-left: 4px solid #ff4d4d; }
    pre  { background: #111; padding: 14px; border-radius: 4px; overflow-x: auto; color: #7ec8e3; font-size: 0.9rem; white-space: pre-wrap; word-break: break-all; }
    code { background: #222; padding: 2px 6px; border-radius: 3px; color: #88ffaa; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: bold; }
    .badge-safe  { background: #003320; color: #44dd88; border: 1px solid #44dd88; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 8px 12px; border: 1px solid #333; text-align: left; }
    th { background: #222; color: #88ffaa; }
    .blocked-msg { color: #ff9944; font-weight: bold; }
    .success-msg { color: #44dd88; font-weight: bold; }
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
  return htmlPage('Command Injection — Fixed', `
  <h1>Network Diagnostic Tool <span class="badge badge-safe">FIXED</span></h1>

  <div class="card safe">
    <h2>What changed?</h2>
    <p>Two defenses are now active:</p>
    <ol>
      <li>
        <strong>Input validation</strong> — a strict whitelist regex
        (<code>/^[a-zA-Z0-9.\\-]{1,253}$/</code>) rejects any input containing
        shell metacharacters before the command is ever run.
      </li>
      <li>
        <strong><code>execFile()</code> instead of <code>exec()</code></strong> —
        the command and its arguments are passed as separate values to the OS.
        No shell is invoked, so metacharacters have no special meaning.
      </li>
    </ol>
    <p>Try the same injection attacks — both defenses will block them.</p>
    <p>Switch to <code>command-vulnerable.js</code> (same port) to see the broken version.</p>
  </div>

  <div class="card">
    <h2>Ping a host</h2>
    <form method="GET" action="/ping">
      <label for="host">Hostname or IP address</label>
      <input type="text" id="host" name="host" placeholder="127.0.0.1" autocomplete="off" value="127.0.0.1">
      <button type="submit">Ping</button>
    </form>
  </div>

  <div class="card info">
    <h2>Injection attempts to try (all blocked)</h2>
    <table>
      <tr><th>Platform</th><th>Input</th><th>Why it is blocked</th></tr>
      <tr>
        <td>Windows</td>
        <td><code>127.0.0.1 &amp; dir C:\\</code></td>
        <td>Space and &amp; fail the hostname regex</td>
      </tr>
      <tr>
        <td>Windows</td>
        <td><code>127.0.0.1 &amp; whoami</code></td>
        <td>Space and &amp; fail the hostname regex</td>
      </tr>
      <tr>
        <td>Linux/Mac</td>
        <td><code>127.0.0.1; ls /</code></td>
        <td>Semicolon and space fail the hostname regex</td>
      </tr>
      <tr>
        <td>Both</td>
        <td><code>127.0.0.1 | cat /etc/passwd</code></td>
        <td>Pipe and space fail the hostname regex</td>
      </tr>
    </table>
  </div>

  <div class="card safe">
    <h2>The safe code</h2>
    <pre>// FIX 1: Validate with a strict whitelist regex
const HOSTNAME_REGEX = /^[a-zA-Z0-9.\\-]{1,253}$/;
if (!HOSTNAME_REGEX.test(host)) {
  return res.status(400).send('Invalid hostname');
}

// FIX 2: Use execFile() — arguments are passed as an array, not a shell string.
// The OS receives the program name and arguments separately.
// Shell metacharacters in the argument are treated as LITERAL characters.
const { execFile } = require('child_process');

// Windows example:
execFile('ping', ['-n', '2', host], { timeout: 5000 }, (err, stdout, stderr) => {
  res.send(stdout + stderr);
});

// Linux/Mac example:
execFile('ping', ['-c', '2', host], { timeout: 5000 }, (err, stdout, stderr) => {
  res.send(stdout + stderr);
});

// No shell is spawned. Even if the regex somehow passed a bad character,
// execFile() would pass it as a literal argument — not interpreted by a shell.</pre>
  </div>
`);
}

function pingResultPage(host, stdout, stderr, error, wasBlocked, blockReason) {
  if (wasBlocked) {
    return htmlPage('Command Injection — Blocked', `
  <h1>Network Diagnostic Tool <span class="badge badge-safe">FIXED</span></h1>

  <div class="card blocked">
    <h2>Input Rejected by Validation</h2>
    <p class="blocked-msg">The injection attempt was blocked before any command was executed.</p>
    <p><strong>Reason:</strong> ${escHtml(blockReason)}</p>
    <p><strong>Submitted input:</strong> <code>${escHtml(host)}</code></p>
  </div>

  <div class="card safe">
    <h2>Validation rule</h2>
    <pre>const HOSTNAME_REGEX = /^[a-zA-Z0-9.\\-]{1,253}$/;
// Only allows: letters, digits, dots, hyphens
// Rejects:     spaces, &, |, ;, \`, $, (, ), ', ", \\, newlines, etc.</pre>
    <p>
      Your input contains characters that are not in the whitelist.
      The command was never built or executed.
    </p>
  </div>

  <p><a href="/" style="color:#3399ff">← Try a valid hostname</a></p>
`);
  }

  const output = (stdout || '') + (stderr || '') + (error && !stdout ? '\nError: ' + error.message : '');

  // execFile args for display
  const args = isWindows ? ['-n', '2', host] : ['-c', '2', host];
  const executable = isWindows ? 'ping' : 'ping';

  return htmlPage('Command Injection — Result (Fixed)', `
  <h1>Network Diagnostic Tool <span class="badge badge-safe">FIXED</span></h1>

  <div class="card safe">
    <h2>Safe execution via execFile()</h2>
    <p class="success-msg">Input passed validation. Command executed safely.</p>
    <p>Executable: <code>${escHtml(executable)}</code></p>
    <p>Arguments array (passed separately, not interpreted by a shell):</p>
    <pre>${escHtml(JSON.stringify(args, null, 2))}</pre>
    <p>
      Because <code>execFile()</code> does not invoke a shell, the argument
      <code>${escHtml(host)}</code> is passed literally to the <code>ping</code>
      program — it cannot contain shell operators that run extra commands.
    </p>
  </div>

  <div class="card">
    <h2>Output</h2>
    <pre>${escHtml(output || '(no output)')}</pre>
  </div>

  <p><a href="/" style="color:#3399ff">← Try another hostname</a></p>
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
    const host = parsedUrl.query.host || '';

    if (!host) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Missing host parameter');
      return;
    }

    // FIX 1: Validate the hostname before doing anything else
    const validation = validateHostname(host);
    if (!validation.valid) {
      console.log(`[FIXED] Rejected invalid input: ${JSON.stringify(host)}`);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(pingResultPage(host, '', '', null, true, validation.reason));
      return;
    }

    // FIX 2: Use execFile() with a separate arguments array.
    // execFile() does NOT spawn a shell. The OS receives:
    //   program: 'ping'
    //   args:    ['-n', '2', '127.0.0.1']   (or whatever valid host was given)
    // No shell metacharacter interpretation occurs.
    const args = isWindows ? ['-n', '2', host] : ['-c', '2', host];

    console.log(`[FIXED] execFile('ping', ${JSON.stringify(args)})`);

    execFile('ping', args, { timeout: 8000 }, (error, stdout, stderr) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(pingResultPage(host, stdout, stderr, error, false, null));
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log('');
  console.log('==========================================================');
  console.log('  COMMAND INJECTION DEMO — FIXED SERVER');
  console.log(`  http://localhost:${PORT}`);
  console.log('==========================================================');
  console.log('');
  console.log('  TWO DEFENSES ACTIVE:');
  console.log('    1. Hostname validation regex: /^[a-zA-Z0-9.\\-]{1,253}$/');
  console.log('       Rejects shell metacharacters before execution.');
  console.log('');
  console.log('    2. execFile() with arguments array — no shell is spawned.');
  console.log('       Metacharacters in args are literal, not operators.');
  console.log('');
  if (isWindows) {
    console.log('  Attack attempt:  127.0.0.1 & dir C:\\');
    console.log('  Result:          Blocked by regex (space + & not in whitelist)');
  } else {
    console.log('  Attack attempt:  127.0.0.1; ls /');
    console.log('  Result:          Blocked by regex (; and space not in whitelist)');
  }
  console.log('');
  console.log('  Run command-vulnerable.js to see the broken version.');
  console.log('');
});
