# 07 — Vulnerable & Outdated Components

## What is it?
Using libraries with known security vulnerabilities puts your app at risk.
Even widely-used libraries can have critical bugs that attackers actively exploit.

Famous real examples:
- Log4Shell (2021): Apache Log4j — arbitrary code execution, affected millions of apps
- Heartbleed (2014): OpenSSL — memory leak exposing private keys
- jQuery < 3.0 (various years): multiple XSS vulnerabilities

## This Demo
We simulate a "JSON settings parser" library:
- v1.0 (vulnerable): uses eval() to parse JSON — allows code injection!
- v2.0 (fixed): uses JSON.parse() safely

## How to run
Open directly in browser — no server needed:
  vulnerable.html
  fixed.html

## What to try (Vulnerable version)
In the "settings" input, paste:
  {"theme":"dark","__proto__":{"isAdmin":true}}

Or inject code via the eval():
  (function(){ document.body.style.background='red'; return {}; })()

## The Fix
- Update to a version that doesn't use eval()
- Audit dependencies regularly (npm audit, Snyk, OWASP Dependency-Check)
- Subscribe to security advisories for your dependencies
