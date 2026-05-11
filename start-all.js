/**
 * Vulnerability Playground — Root Launcher
 *
 * Usage:  node start-all.js
 *
 * Starts all 22 Node.js servers simultaneously:
 *   - 11 vulnerable versions on ports 3001–3011
 *   - 11 fixed versions on ports 3101–3111
 *
 * HTML-only demos (07, 12, 13, 14) need no server — open the .html files directly.
 * Press Ctrl+C to stop everything.
 */

const { spawn } = require('child_process');
const path = require('path');

const SERVERS = [
  // ── Vulnerable versions (ports 3001–3011) ──────────────────────────────────
  { dir: '01-broken-access-control',     file: 'vulnerable.js',         port: 3001, type: 'vuln', label: '01 Broken Access Control' },
  { dir: '02-injection',                 file: 'sql-vulnerable.js',     port: 3002, type: 'vuln', label: '02 SQL Injection'          },
  { dir: '02-injection',                 file: 'command-vulnerable.js', port: 3003, type: 'vuln', label: '02 Command Injection'      },
  { dir: '03-xss',                       file: 'stored-vulnerable.js',  port: 3004, type: 'vuln', label: '03 Stored XSS'            },
  { dir: '04-csrf',                      file: 'vulnerable.js',         port: 3005, type: 'vuln', label: '04 CSRF'                  },
  { dir: '05-auth-failures',             file: 'vulnerable.js',         port: 3006, type: 'vuln', label: '05 Auth Failures'         },
  { dir: '06-security-misconfiguration', file: 'vulnerable.js',         port: 3007, type: 'vuln', label: '06 Misconfiguration'      },
  { dir: '08-cryptographic-failures',    file: 'vulnerable.js',         port: 3008, type: 'vuln', label: '08 Crypto Failures'       },
  { dir: '09-logging-failures',          file: 'vulnerable.js',         port: 3009, type: 'vuln', label: '09 Logging Failures'      },
  { dir: '10-ssrf',                      file: 'vulnerable.js',         port: 3010, type: 'vuln', label: '10 SSRF'                  },
  { dir: '11-ddos',                      file: 'vulnerable.js',         port: 3011, type: 'vuln', label: '11 DoS'                   },

  // ── Fixed versions (ports 3101–3111) ───────────────────────────────────────
  { dir: '01-broken-access-control',     file: 'fixed.js',              port: 3101, type: 'fix',  label: '01 Broken Access Control' },
  { dir: '02-injection',                 file: 'sql-fixed.js',          port: 3102, type: 'fix',  label: '02 SQL Injection'         },
  { dir: '02-injection',                 file: 'command-fixed.js',      port: 3103, type: 'fix',  label: '02 Command Injection'     },
  { dir: '03-xss',                       file: 'stored-fixed.js',       port: 3104, type: 'fix',  label: '03 Stored XSS'           },
  { dir: '04-csrf',                      file: 'fixed.js',              port: 3105, type: 'fix',  label: '04 CSRF'                  },
  { dir: '05-auth-failures',             file: 'fixed.js',              port: 3106, type: 'fix',  label: '05 Auth Failures'         },
  { dir: '06-security-misconfiguration', file: 'fixed.js',              port: 3107, type: 'fix',  label: '06 Misconfiguration'      },
  { dir: '08-cryptographic-failures',    file: 'fixed.js',              port: 3108, type: 'fix',  label: '08 Crypto Failures'       },
  { dir: '09-logging-failures',          file: 'fixed.js',              port: 3109, type: 'fix',  label: '09 Logging Failures'      },
  { dir: '10-ssrf',                      file: 'fixed.js',              port: 3110, type: 'fix',  label: '10 SSRF'                  },
  { dir: '11-ddos',                      file: 'fixed.js',              port: 3111, type: 'fix',  label: '11 DoS'                   },
];

const C = {
  reset:  '\x1b[0m',
  bold:   '\x1b[1m',
  dim:    '\x1b[2m',
  red:    '\x1b[31m',
  green:  '\x1b[32m',
  yellow: '\x1b[33m',
  cyan:   '\x1b[36m',
  gray:   '\x1b[90m',
};

function c(color, text) { return `${C[color]}${text}${C.reset}`; }

console.log('');
console.log(c('bold', '  Vulnerability Playground'));
console.log(c('dim',  `  Starting ${SERVERS.length} servers (11 vulnerable + 11 fixed)...\n`));
console.log(c('dim', '  PORT   TYPE      DEMO'));
console.log(c('dim', '  ' + '─'.repeat(52)));

const processes = [];

SERVERS.forEach(({ dir, file, port, type, label }) => {
  const cwd   = path.join(__dirname, dir);
  const isVuln = type === 'vuln';
  const typeTag = isVuln ? c('red',   ' VULN ') : c('green', ' FIXED');
  const portStr = String(port).padEnd(6);

  const child = spawn('node', [file], { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
  processes.push(child);

  const prefix = `${c('gray', portStr)} ${typeTag}  ${c('dim', label.padEnd(32))}`;

  child.stdout.on('data', data => {
    data.toString().split('\n').map(l => l.trim()).filter(Boolean)
      .forEach(line => {
        if (line.includes('running') || line.includes('listening') || line.includes('started')) {
          console.log(`  ${prefix} ${c('green', line)}`);
        }
      });
  });

  child.stderr.on('data', data => {
    data.toString().split('\n').map(l => l.trim()).filter(Boolean)
      .forEach(line => console.error(`  ${prefix} ${c('red', line)}`));
  });

  child.on('exit', code => {
    if (code !== 0 && code !== null) {
      console.log(`  ${prefix} ${c('red', `exited (code ${code})`)}`);
    }
  });

  console.log(`  ${portStr} ${isVuln ? 'vuln ' : 'fixed'}    ${label}`);
});

console.log('');
console.log(c('dim', '  Open index.html in your browser to use the dashboard.'));
console.log(c('dim', '  Ctrl+C to stop all servers.\n'));

process.on('SIGINT', () => {
  console.log(c('yellow', '\n  Shutting down all servers...'));
  processes.forEach(p => { try { p.kill(); } catch (_) {} });
  process.exit(0);
});
