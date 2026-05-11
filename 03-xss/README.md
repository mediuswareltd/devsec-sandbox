# 03 — Cross-Site Scripting (XSS)

## What is it?
XSS happens when user-supplied input is rendered as HTML/JavaScript in a browser.
The attacker's script runs in the victim's browser and can steal cookies, redirect users, or deface the page.

Two types demonstrated here:

### Reflected XSS (reflected-vulnerable.html)
Input comes from the URL (?q=...) and is immediately echoed back in the page.
The attack payload travels in the URL and only affects whoever clicks the malicious link.

### Stored XSS (stored-vulnerable.js / node server)
Input is saved to a database and shown to every visitor.
Much more dangerous — one malicious post infects ALL readers.

## How to run

### Reflected XSS
Open reflected-vulnerable.html in your browser directly (no server needed).
In the URL, after opening, add: ?q=<img src=x onerror=alert('XSS!')>
Or use the demo form on the page.

### Stored XSS
  node stored-vulnerable.js  → http://localhost:3004
  node stored-fixed.js       → http://localhost:3004

## Attack Payloads to Try

Basic alert:
  <script>alert('XSS')</script>

Image onerror (bypasses script-tag filters):
  <img src=x onerror=alert('XSS!')>

Cookie theft simulation:
  <script>alert('Your cookie: ' + document.cookie)</script>

## The Fix
NEVER use innerHTML with user input.
Use textContent for plain text, or escape HTML entities before inserting:
  & → &amp;   < → &lt;   > → &gt;   " → &quot;   ' → &#x27;
