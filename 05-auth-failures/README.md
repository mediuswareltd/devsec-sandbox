# 05 — Identification & Authentication Failures

## What is it?
Authentication failures occur when an application has weak login security:
- Passwords stored as plain text (if DB is stolen, all passwords exposed)
- Predictable session IDs (attacker can guess another user's session)
- No rate limiting (attacker can try thousands of passwords)
- Accepting weak passwords like "123" or "password"

## How to run
  node vulnerable.js  → http://localhost:3006
  node fixed.js       → http://localhost:3006

## What to try (Vulnerable version)
1. Log in with alice / 123 (very weak password — accepted!)
2. Notice the session ID in the URL — it's just a number (1, 2, 3...)
3. Try logging in many times with wrong passwords — no lockout!
4. The "database" shows passwords in plain text

## The Fix (fixed.js)
1. Passwords hashed with PBKDF2 + random salt (Node.js built-in crypto)
2. Session IDs are 32-byte random hex strings (impossible to guess)
3. After 5 failed attempts from the same IP, that IP is locked out for 60 seconds
4. Password must be at least 8 characters
