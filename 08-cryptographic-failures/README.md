# 08 — Cryptographic Failures

## What is it?
Cryptographic failures happen when sensitive data is:
- Stored without encryption (plain text passwords, credit cards)
- Hashed with weak algorithms (MD5 or SHA1 are too fast — easily brute-forced)
- Hashed without a salt (identical passwords produce identical hashes — rainbow tables)

## How to run
  node vulnerable.js  → http://localhost:3008
  node fixed.js       → http://localhost:3008

## What to try (Vulnerable version)
1. Register with password "password123" — see the MD5 hash
2. Register another user with the same password — same MD5 hash! (no salt)
3. MD5 of "password123" is 482c811da5d5b4bc6d497ffa98491e38
   This is in every rainbow table — can be cracked in seconds.
4. The stored credit card is shown in plain text in the "database"

## The Fix
1. Use PBKDF2 with a random salt and 100,000 iterations
2. Same password → different hash every time (because of the random salt)
3. Sensitive data (credit card) is masked/never stored in plain text
4. The hash takes ~1 second to compute — makes brute force impractical
