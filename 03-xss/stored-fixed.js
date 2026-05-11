/**
 * STORED XSS DEMO — FIXED VERSION
 * =================================
 * Same guestbook app, but comments are HTML-escaped before being inserted
 * into the page. Attack payloads become harmless literal text.
 *
 * THE FIX — escape on output (preferred approach):
 *   We store comments exactly as the user typed them (preserves the original
 *   text faithfully), but when we build the HTML response we run every comment
 *   through escapeHtml() first. This converts:
 *     <  →  &lt;
 *     >  →  &gt;
 *     &  →  &amp;
 *     "  →  &quot;
 *     '  →  &#x27;
 *   The browser sees the escaped entities and displays them as text — it never
 *   parses them as HTML or executes them as JavaScript.
 *
 * Alternative approach (escape on input):
 *   You could also escape before storing. The downside is the stored value is
 *   already modified, which can cause double-escaping bugs if you forget.
 *   Escaping on output is generally the safer, cleaner practice.
 *
 * Uses only Node.js built-in modules: http, url, querystring
 */

const http        = require('http');
const url         = require('url');
const querystring = require('querystring');

const PORT = 3104;

// Same in-memory store — we still save the raw user input.
// The escaping happens at render time, not storage time.
const comments = [
  'Hello, this is a normal comment!',
  'Great guestbook, love the design.',
];

// ─── HTML escaping ─────────────────────────────────────────────────────────────

/**
 * ✅ THE FIX: Escapes all characters that have special meaning in HTML.
 * After escaping, the string is safe to embed inside any HTML attribute or element.
 *
 * Example:
 *   Input:  <script>alert('xss')</script>
 *   Output: &lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;
 *   The browser displays:  <script>alert('xss')</script>  — as plain text, never executed.
 */
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')   // must be first to avoid double-escaping
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ─── HTML helpers ──────────────────────────────────────────────────────────────

/**
 * Renders the guestbook page with properly escaped comments.
 * ✅ Every comment is passed through escapeHtml() before being placed into HTML.
 */
function renderPage(errorMsg) {
  const commentItems = comments
    .map((c, i) => `
      <div class="comment">
        <span class="num">#${i + 1}</span>
        <!-- ✅ FIX: escapeHtml() converts HTML special chars to safe entities -->
        <span class="text">${escapeHtml(c)}</span>
      </div>`)
    .join('');

  // Show stored raw vs escaped side-by-side for the last comment
  const lastRaw     = comments[comments.length - 1] || '(none yet)';
  const lastEscaped = escapeHtml(lastRaw);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Guestbook [FIXED - No XSS]</title>
  <style>
    body { font-family: sans-serif; padding: 24px; max-width: 700px; margin: 0 auto; }
    h1 { color: #27ae60; }
    .safe { background: #d4edda; border: 1px solid #c3e6cb; padding: 14px; border-radius: 6px; margin: 14px 0; }
    .comment { background: #f9f9f9; border-left: 4px solid #27ae60; padding: 10px 14px; margin: 8px 0; border-radius: 0 4px 4px 0; }
    .num { color: #999; font-size: 0.8rem; margin-right: 8px; }
    .text { color: #222; }
    textarea { width: 100%; padding: 8px; height: 80px; font-family: monospace; }
    button { padding: 8px 18px; background: #27ae60; color: white; border: none; border-radius: 4px; cursor: pointer; margin-top: 8px; }
    .fix-box { background: #d1ecf1; border: 1px solid #bee5eb; padding: 12px; border-radius: 4px; margin-top: 14px; font-size: 0.85rem; }
    .raw { background: #1e1e1e; color: #0f0; padding: 12px; border-radius: 4px; font-family: monospace; font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; margin-top: 10px; }
    .escaped { background: #1e1e1e; color: #7ec8e3; padding: 12px; border-radius: 4px; font-family: monospace; font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; margin-top: 4px; }
    .error { color: red; margin-top: 8px; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th, td { text-align: left; padding: 6px 10px; border: 1px solid #ddd; font-size: 0.85rem; }
    th { background: #f0f0f0; }
  </style>
</head>
<body>
  <h1>Guestbook [FIXED — No Stored XSS]</h1>

  <div class="safe">
    <strong>&#10003; Safe:</strong> All comments are passed through <code>escapeHtml()</code> before
    being inserted into HTML. Script tags and event handlers become harmless text.
  </div>

  <h2>Leave a Comment</h2>
  <form method="POST" action="/comment">
    <textarea name="comment" placeholder="Type your comment — try an XSS payload, it will display as plain text!"></textarea>
    <br>
    <button type="submit">Post Comment</button>
    ${errorMsg ? `<p class="error">${escapeHtml(errorMsg)}</p>` : ''}
  </form>

  <div class="fix-box">
    <strong>The fix — escapeHtml() entity-encodes dangerous characters:</strong>
    <table>
      <tr><th>Character</th><th>Becomes</th><th>Why</th></tr>
      <tr><td>&amp;</td><td>&amp;amp;</td><td>Must be first to prevent double-escaping</td></tr>
      <tr><td>&lt;</td><td>&amp;lt;</td><td>Stops tag injection</td></tr>
      <tr><td>&gt;</td><td>&amp;gt;</td><td>Stops tag closing</td></tr>
      <tr><td>"</td><td>&amp;quot;</td><td>Stops attribute injection</td></tr>
      <tr><td>'</td><td>&amp;#x27;</td><td>Stops attribute injection (single-quote)</td></tr>
    </table>
  </div>

  <h2>Comments (${comments.length} total)</h2>
  <div id="comments">
    ${commentItems.length ? commentItems : '<p>No comments yet.</p>'}
  </div>

  <h2>What escapeHtml() Does to the Latest Comment</h2>
  <p style="color:#666;font-size:0.85rem">
    The raw value is stored as-is. The escaped version is what gets sent to the browser.
  </p>
  <p><strong>Raw stored value (green):</strong></p>
  <div class="raw">${escapeHtml(lastRaw)}</div>
  <p><strong>After escapeHtml() — safe to embed in HTML (blue):</strong></p>
  <div class="escaped">${escapeHtml(lastEscaped)}</div>

</body>
</html>`;
}

// ─── Request handler ───────────────────────────────────────────────────────────

function handleRequest(req, res) {
  const parsed   = url.parse(req.url);
  const pathname = parsed.pathname;

  // ── GET / — show the guestbook ──────────────────────────────────────────────
  if (req.method === 'GET' && pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(renderPage(null));
    return;
  }

  // ── POST /comment — save a new comment ─────────────────────────────────────
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

      // Store the raw comment — escaping happens at render time.
      comments.push(comment);
      console.log(`[STORED] New comment saved (raw): ${comment}`);
      console.log(`[SAFE]   Will be rendered as:     ${escapeHtml(comment)}`);

      res.writeHead(302, { Location: '/' });
      res.end();
    });
    return;
  }

  // ── 404 ─────────────────────────────────────────────────────────────────────
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
}

// ─── Start server ──────────────────────────────────────────────────────────────

const server = http.createServer(handleRequest);
server.listen(PORT, () => {
  console.log('');
  console.log('=== STORED XSS DEMO (FIXED) ===');
  console.log(`Server running at http://localhost:${PORT}`);
  console.log('');
  console.log('Try submitting these payloads — they will display as plain text:');
  console.log('  <img src=x onerror=alert(\'XSS!\')>');
  console.log('  <script>alert(1)</script>');
  console.log('');
  console.log('The fix: escapeHtml() converts < > & " \' to HTML entities before output.');
  console.log('The browser renders them as visible text, never as executable code.');
  console.log('');
});
