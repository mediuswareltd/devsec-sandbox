# 01 — Broken Access Control (IDOR)

## What is it?
Broken Access Control means a user can access resources they are not authorized to see.
**IDOR (Insecure Direct Object Reference)** is the most common type:
the server uses a user-supplied ID (like ?id=2) to fetch data, but never checks
if the logged-in user is actually *allowed* to see that data.

## How to run
1. Open a terminal in this folder
2. Run: `node vulnerable.js`
3. Open: http://localhost:3001
4. When done, Ctrl+C to stop. Then run `node fixed.js` to see the fix.

## What to try (Attack)
- You are logged in as **alice** (user id=1)
- Click "View Bob's profile" — you can see Bob's SSN and bank balance!
- Click "View Charlie's profile" — same problem
- Change the URL manually: http://localhost:3001/profile?id=2

## Why does it work?
The server reads `?id=2` from the URL and fetches user 2's data.
It never checks: "Is the logged-in user allowed to see user 2?"

## The Fix (fixed.js)
Before returning any profile, the server checks:
`if (requestedId !== LOGGED_IN_USER_ID) → 403 Forbidden`
Only alice can see alice's data.

## Real-world examples
- Facebook 2015: could view any private photo by changing photo ID
- Venmo 2019: transaction IDs were sequential and exposed
- Any site where ?id=, ?user=, ?account= is not access-checked
