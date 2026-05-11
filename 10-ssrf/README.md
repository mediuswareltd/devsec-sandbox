# 10 — Server-Side Request Forgery (SSRF)

## What is it?
SSRF allows an attacker to make the SERVER send requests on their behalf.
The server can reach internal services that the attacker cannot access directly:
- Internal APIs (http://internal-api.company.com)
- Cloud metadata endpoints (http://169.254.169.254/latest/meta-data/)
- Other services running on localhost

## How to run
  node vulnerable.js  → http://localhost:3010
  node fixed.js       → http://localhost:3010

## What to try (Vulnerable version)
1. Fetch a safe external URL: https://example.com  → works
2. Try to access another running demo: http://localhost:3009/logs  → exposes internal logs!
3. Try: http://127.0.0.1:3007  → can reach any localhost service!
4. Try: http://169.254.169.254 → cloud metadata endpoint (simulated response)

## The Fix
1. Allow only specific safe domains (allowlist)
2. Block all private IP ranges: 127.x, 10.x, 192.168.x, 172.16-31.x
3. Block non-http/https protocols (file://, ftp://, etc.)
4. Never follow redirects to internal addresses
