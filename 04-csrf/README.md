# 04 — Cross-Site Request Forgery (CSRF)

## What is it?
CSRF tricks a logged-in user's browser into making a request to a site
where they are authenticated — without the user knowing.

Example: You are logged in to your bank. You visit an attacker's website.
That website has a hidden form that submits to your bank's transfer endpoint.
Your browser sends the request with your cookies attached — the bank thinks it's you!

## How to run
1. `node vulnerable.js` → open http://localhost:3005
2. Note Alice's balance
3. Click "Visit Attacker's Page" → watch the balance change automatically!
4. Ctrl+C, then `node fixed.js`
5. Try the attacker page again — the transfer is now blocked with 403.

## What to try (Attack)
- Open http://localhost:3005 (the bank)
- Click the "Attacker's Page" link
- The attacker page auto-submits a hidden form to steal $500 from Alice!

## The Fix
A CSRF token is a random secret included in every HTML form.
When the form is submitted, the server checks the token matches what it issued.
An attacker's page cannot know Alice's CSRF token, so the attack fails.
