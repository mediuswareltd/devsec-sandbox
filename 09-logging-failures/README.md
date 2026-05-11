# 09 — Logging & Monitoring Failures

## What is it?
Without proper logging, attackers can:
- Brute-force passwords without anyone noticing
- Exfiltrate data with no audit trail
- Persist in a system for months (average breach detection: 200+ days)

## How to run
  node vulnerable.js  → http://localhost:3009
  node fixed.js       → http://localhost:3009

## What to try (Vulnerable version)
1. Try logging in with wrong passwords many times — no record anywhere
2. Check the server terminal — nothing is logged for failed attempts
3. An attacker could try every password in a wordlist completely silently

## What to try (Fixed version)
1. Try several failed logins — watch the terminal AND the /logs page
2. Each attempt is recorded with timestamp, IP, username, result
3. Visit http://localhost:3009/logs to see the full audit trail
4. After 5 failed attempts for the same username, an alert is triggered
