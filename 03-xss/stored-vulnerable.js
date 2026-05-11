/**
 * STORED XSS DEMO — VULNERABLE VERSION
 * =====================================
 * A "Guestbook" app where comments are saved in memory and displayed to ALL visitors.
 *
 * THE VULNERABILITY:
 *   When comments are displayed, they are injected directly into the page HTML
 *   using string concatenation. If a comment contains <script> tags or event
 *   handlers (like onerror=), those execute in every visitor's browser.
 *
 *   This is MORE dangerous than Reflected XSS because:
 *   - The payload is stored on the server
 *   - EVERY visitor who loads the page is attacked, not just one
 *   - The attacker doesn't need to trick victims into clicking a special URL
 *
 * HOW TO ATTACK:
 *   1. Run this server: node stored-vulnerable.js
 *   2. Visit http://localhost:3004
 *   3. Submit this comment: <img src=x onerror=alert('XSS! Stored attack!')>
 *   4. Reload the page — the alert fires again for every visitor!
 *   5. Every new tab opening this page is also attacked.
 *
 * Uses only Node.js built-in modules: http, url, querystring
 */

const http        = require('http');
const url         = require('url');
const querystring = require('querystring');

const PORT = 3004;

// In-memory "database" of comments.
// In a real app this would be a database table.
// Notice: we store EXACTLY what the user typed — no sanitization at all.
const comments = [
  // Pre-seeded with a safe comment to show the app is working
  'Hello, this is a normal comment!',
  'Great guestbook, love the design.',
];

// ─── HTML helpers ────────────────────────────────────────────────────────────

/**
 * Renders the full guestbook page.
 * ❌ VULNERABILITY: comments are placed into innerHTML via string concatenation.
 *    Any HTML/JS inside a comment will be executed by the browser.
 */
function renderPage(errorMsg) {
  // Build each comment as a raw HTML string.
  // If a comment is: <script>alert(1)</script>  — that script runs in the browser.
  const commentItems = comments
    .map((c, i) => `
      <div class="comment">
        <span class="num">#${i + 1}</span>
        <!-- ❌ VULNERABILITY: comment content placed verbatim into HTML -->
        <span class="text">${c}</span>
      </div>`)
    .join('');

  // Raw dump of stored data for educational purposes
  const rawDump = comments
    .map((c, i) => `${i + 1}: ${c}`)
    .join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Guestbook [VULNERABLE - Stored XSS]</title>
  <style>
    body { font-family: sans-serif; padding: 24px; max-width: 700px; margin: 0 auto; }
    h1 { color: #c0392b; }
    .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 14px; border-radius: 6px; margin: 14px 0; }
    .comment { background: #f9f9f9; border-left: 4px solid #c0392b; padding: 10px 14px; margin: 8px 0; border-radius: 0 4px 4px 0; }
    .num { color: #999; font-size: 0.8rem; margin-right: 8px; }
    .text { color: #222; }
    textarea { width: 100%; padding: 8px; height: 80px; font-family: monospace; }
    button { padding: 8px 18px; background: #c0392b; color: white; border: none; border-radius: 4px; cursor: pointer; margin-top: 8px; }
    .attack-box { background: #f8d7da; border: 1px solid #f5c6cb; padding: 12px; border-radius: 4px; margin-top: 14px; font-family: monospace; font-size: 0.85rem; }
    .raw { background: #1e1e1e; color: #0f0; padding: 12px; border-radius: 4px; font-family: monospace; font-size: 0.8rem; white-space: pre; margin-top: 10px; }
    .error { color: red; margin-top: 8px; }
  </style>
</head>
<body>
  <h1>Guestbook [VULNERABLE — Stored XSS]</h1>

  <div class="warning">
    <strong>&#9888; Vulnerable:</strong> Comments are stored and displayed using raw string interpolation.
    Any HTML or JavaScript in a comment executes in <em>every</em> visitor's browser.
  </div>

  <h2>Leave a Comment</h2>
  <form method="POST" action="/comment">
    <textarea name="comment" placeholder="Type your comment here... or an XSS payload!"></textarea>
    <br>
    <button type="submit">Post Comment</button>
    ${errorMsg ? `<p class="error">${errorMsg}</p>` : ''}
  </form>

  <div class="attack-box">
    <strong>Attack payloads to try:</strong><br>
    1. <code>&lt;img src=x onerror=alert('Stored XSS!')&gt;</code><br>
    2. <code>&lt;script&gt;document.body.style.background='red'&lt;/script&gt;</code><br>
    3. <code>&lt;b style="font-size:2rem;color:red"&gt;Page defaced!&lt;/b&gt;</code><br>
    4. <code>&lt;script&gt;alert('Cookie: ' + document.cookie)&lt;/script&gt;</code>
  </div>

  <h2>Comments (${comments.length} total)</h2>
  <div id="comments">
    ${commentItems.length ? commentItems : '<p>No comments yet.</p>'}
  </div>

  <h2>Raw Stored Data (server memory)</h2>
  <p style="color:#666;font-size:0.85rem">
    This shows what is actually saved. In a real attack the attacker's HTML/JS is stored here
    and injected into the page for every visitor.
  </p>
  <div class="raw">${escapeForCodeBlock(rawDump)}</div>

</body>
</html>`;
}

/**
 * Minimal escape used ONLY for the <pre> raw-data display block —
 * NOT used when rendering comments (that's the vulnerability).
 */
function escapeForCodeBlock(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// ─── Request handler ──────────────────────────────────────────────────────────

function handleRequest(req, res) {
  const parsed  = url.parse(req.url);
  const pathname = parsed.pathname;

  // ── GET / — show the guestbook ─────────────────────────────────────────────
  if (req.method === 'GET' && pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(renderPage(null));
    return;
  }

  // ── POST /comment — save a new comment ────────────────────────────────────
  if (req.method === 'POST' && pathname === '/comment') {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      const data    = querystring.parse(body);
      const comment = (data.comment || '').trim();

      if (!comment) {
        res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(renderPage('Comment cannot be empty.'));
        return;
      }

      // ❌ VULNERABILITY: store exactly what the user submitted — no escaping.
      //    This raw payload will be echoed into every future page load.
      comments.push(comment);
      console.log(`[STORED] New comment saved: ${comment}`);

      // Redirect back to home so the new comment is visible
      res.writeHead(302, { Location: '/' });
      res.end();
    });
    return;
  }

  // ── 404 ────────────────────────────────────────────────────────────────────
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
}

// ─── Start server ─────────────────────────────────────────────────────────────

const server = http.createServer(handleRequest);
server.listen(PORT, () => {
  console.log('');
  console.log('=== STORED XSS DEMO (VULNERABLE) ===');
  console.log(`Server running at http://localhost:${PORT}`);
  console.log('');
  console.log('HOW THE ATTACK WORKS:');
  console.log('  1. Visit the page and post this comment:');
  console.log('       <img src=x onerror=alert(\'Stored XSS!\')>');
  console.log('  2. The payload is saved in the server\'s memory.');
  console.log('  3. Reload the page — the alert fires for YOU.');
  console.log('  4. Open a new browser tab to the same URL — the alert fires AGAIN.');
  console.log('  5. Every visitor who loads the page is attacked automatically.');
  console.log('');
  console.log('This is why Stored XSS is considered more severe than Reflected XSS.');
  console.log('');
});
