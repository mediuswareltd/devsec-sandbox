# Vulnerability Playground

An educational security lab with 14 vulnerability demos. Each has a **vulnerable** version and a **fixed** version.

## Requirements

- **Node.js** (any recent version) — only built-in modules are used, no `npm install` needed
- A web browser

## How to Start

**Option A — Run everything at once (recommended)**
```
node start-all.js
```
Starts all 11 Node.js servers simultaneously. Then open `index.html` as your dashboard.

**Option B — Run one demo at a time**
1. Open `index.html` in your browser — this is your home dashboard
2. For each Node.js demo, `cd` into the folder and run the command shown on the dashboard
3. For HTML demos (07, 12, 13, 14), open the `.html` file directly in your browser

## Structure

```
vulnerability-playground/
├── index.html                        ← Start here (home dashboard)
├── 01-broken-access-control/
│   ├── README.md                     ← What, how to run, what to try
│   ├── vulnerable.js                 ← The broken version
│   └── fixed.js                      ← The fixed version
├── 02-injection/
│   ├── sql-vulnerable.js / sql-fixed.js
│   ├── command-vulnerable.js / command-fixed.js
│   ├── nosql-vulnerable.html / nosql-fixed.html
│   └── ldap-vulnerable.html / ldap-fixed.html
... (same pattern for all 14 folders)
```

## Port Reference

| Folder | Port |
|--------|------|
| 01-broken-access-control | 3001 |
| 02-injection (SQL) | 3002 |
| 02-injection (Command) | 3003 |
| 03-xss (Stored) | 3004 |
| 04-csrf | 3005 |
| 05-auth-failures | 3006 |
| 06-security-misconfiguration | 3007 |
| 08-cryptographic-failures | 3008 |
| 09-logging-failures | 3009 |
| 10-ssrf | 3010 |
| 11-ddos | 3011 |

## Tips for the Classroom

- Run one demo at a time (each uses a different port, so they can run simultaneously)
- Always read the `README.md` inside each folder first
- Try the vulnerable version, observe the attack, then run the fixed version and confirm it blocks the attack
- All data is in-memory — restart the server to reset state

## Safety

These demos are intentionally vulnerable. **Only run on localhost.** Never expose them on a public network.
