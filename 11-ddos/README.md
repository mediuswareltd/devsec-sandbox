# 11 — Denial of Service (DoS)

## What is it?
A Denial of Service attack overwhelms a server with requests so it can't
serve legitimate users. Without rate limiting, even a single script can
take down a server.

## How to run
  node vulnerable.js  → http://localhost:3011
  node fixed.js       → http://localhost:3011

## What to try (Vulnerable version)
1. Click the "Send 20 Requests Fast" button on the page
2. All 20 requests succeed — the server has no protection
3. In theory, an attacker could send thousands per second

## What to try (Fixed version)
1. Click "Send 20 Requests Fast" again
2. After 5 requests per 10 seconds, you get 429 Too Many Requests
3. The server shows the Retry-After header telling you when to try again

## Real-world DoS vectors
- Slow loris: keep connections open slowly to exhaust connection pool
- XML bomb / Zip bomb: send tiny compressed payload that expands to huge data
- Algorithmic complexity attacks: trigger worst-case behavior in code
- Resource exhaustion: request heavy computation endlessly
