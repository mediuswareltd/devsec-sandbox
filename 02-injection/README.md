# 02 — Injection

## What is it?
Injection happens when untrusted user input is passed directly into an interpreter
(SQL engine, OS shell, LDAP server, etc.) and is treated as a command, not data.

This folder covers 4 types:

| Type | Demo | Port |
|------|------|------|
| SQL Injection | sql-vulnerable.js / sql-fixed.js | 3002 |
| Command Injection | command-vulnerable.js / command-fixed.js | 3003 |
| NoSQL Injection | nosql-vulnerable.html / nosql-fixed.html | (open file) |
| LDAP Injection | ldap-vulnerable.html / ldap-fixed.html | (open file) |

## SQL Injection
### How to run
  node sql-vulnerable.js   → http://localhost:3002
  node sql-fixed.js        → http://localhost:3002

### Attack
Username: `' OR '1'='1` and any password → logs in as admin without knowing the password!
The injected input changes the logic of the SQL query.

### Fix
Use parameterized queries — keep user input as *data*, never concatenate it into query strings.

## Command Injection
### How to run
  node command-vulnerable.js  → http://localhost:3003
  node command-fixed.js       → http://localhost:3003

### Attack (Windows)
In the hostname box, enter: `127.0.0.1 & dir C:\`
The & character chains a second OS command!

### Attack (Linux/Mac)
Enter: `127.0.0.1; ls /`

### Fix
Validate input with a strict regex. Only allow hostname characters [a-zA-Z0-9.-].
Use execFile() with separate argument arrays instead of exec() with a shell string.

## NoSQL Injection
Open nosql-vulnerable.html in a browser.
Instead of a password, inject: {"$gt":""} — this passes as a MongoDB operator and bypasses auth.

## LDAP Injection
Open ldap-vulnerable.html in a browser.
Inject in the username: *)(uid=*))(|(uid=*
This breaks the LDAP filter string and bypasses authentication.
