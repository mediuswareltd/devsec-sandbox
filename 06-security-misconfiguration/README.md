# 06 — Security Misconfiguration

## What is it?
Security misconfiguration means the application or server is set up insecurely:
- Detailed error messages expose stack traces (helps attackers understand your code)
- Debug/admin endpoints left open without authentication
- Default credentials (admin/admin) never changed
- Server reveals its technology stack in headers (X-Powered-By, Server)
- Sensitive comments left in HTML source

## How to run
  node vulnerable.js  → http://localhost:3007
  node fixed.js       → http://localhost:3007

## What to try (Vulnerable version)
1. Visit http://localhost:3007/crash  → see a full stack trace in the browser!
2. Visit http://localhost:3007/admin  → open admin panel with default password "admin"
3. View page source → find a secret API key hidden in an HTML comment
4. Check browser DevTools → see X-Powered-By header revealing Node.js version

## The Fix
1. Generic error messages: "Something went wrong" (log details server-side only)
2. Admin endpoint requires Authorization header — no default credentials
3. No sensitive comments in HTML
4. Remove X-Powered-By and Server headers
