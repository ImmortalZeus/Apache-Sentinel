/**
 * Apache Sentinel — Unified Attack Tool  (v3 — config-aware)
 * ============================================================
 * Fetches live thresholds from GET /api/config at startup, then
 * computes every test's request count dynamically so tests always
 * fire regardless of whether the backend is running in
 * development or production mode.
 *
 * Usage:
 *   node attack_tool.js              → interactive menu
 *   node attack_tool.js --test 1     → DoS regression
 *   node attack_tool.js --test 2     → Global volumetric flood
 *   node attack_tool.js --test 3     → Coordinated botnet
 *   node attack_tool.js --test 4     → Subnet /24 attack
 *   node attack_tool.js --test all   → all 4 in sequence with resets
 *
 * No external dependencies — Node.js stdlib only.
 */

'use strict';

const http     = require('http');
const readline = require('readline');

// ─── Backend connection ────────────────────────────────────────────────────

const BACKEND = { host: 'localhost', port: 3000 };

// ─── Fallback thresholds (used if backend is unreachable) ─────────────────
// Mirrors config.json  development  section

const FALLBACK = {
    dos: {
        WINDOW_MS:  10000,
        THRESHOLD:  120,
    },
    ddos: {
        GLOBAL_RATE_THRESHOLD:             100,
        GLOBAL_RATE_WINDOW_MS:             10000,
        COORDINATED_DISTINCT_IP_THRESHOLD: 10,
        COORDINATED_ERROR_RATIO_THRESHOLD: 0.8,
        SUBNET_RATE_THRESHOLD:             50,
        SUBNET_BLOCK_BASE_TTL_MS:          60000,
        PANIC_MODE_DURATION_MS:            60000,
        PANIC_MODE_COOLDOWN_MS:            60000,
    },
    env: 'development (fallback)',
};

// ─── HTTP helpers ──────────────────────────────────────────────────────────

function httpGet(path) {
    return new Promise((resolve, reject) => {
        const req = http.request(
            { hostname: BACKEND.host, port: BACKEND.port, path, method: 'GET' },
            (res) => {
                let body = '';
                res.setEncoding('utf8');
                res.on('data', d => body += d);
                res.on('end', () => {
                    try { resolve(JSON.parse(body)); }
                    catch { reject(new Error('Non-JSON response')); }
                });
            }
        );
        req.on('error', reject);
        req.setTimeout(3000, () => { req.destroy(); reject(new Error('timeout')); });
        req.end();
    });
}

function postLog(line) {
    return new Promise((resolve, reject) => {
        const req = http.request({
            hostname: BACKEND.host,
            port:     BACKEND.port,
            path:     '/log',
            method:   'POST',
            headers: {
                'Content-Type':   'text/plain',
                'Content-Length': Buffer.byteLength(line),
            },
        }, (res) => { res.resume(); resolve(res.statusCode); });
        req.on('error', reject);
        req.write(line);
        req.end();
    });
}

function resetServer() {
    return new Promise((resolve) => {
        const req = http.request(
            { hostname: BACKEND.host, port: BACKEND.port, path: '/debug/reset', method: 'POST' },
            (res) => { res.resume(); resolve(res.statusCode); }
        );
        req.on('error', () => resolve(500));
        req.end();
    });
}

// ─── Utilities ─────────────────────────────────────────────────────────────

const sleep = ms => new Promise(r => setTimeout(r, ms));

function makeLogLine(ip, method = 'GET', path = '/', status = 200) {
    const now   = new Date();
    const day   = String(now.getUTCDate()).padStart(2, '0');
    const month = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][now.getUTCMonth()];
    const ts    = `${day}/${month}/${now.getUTCFullYear()}:${now.toISOString().slice(11,19)} +0000`;
    return `${ip} - - [${ts}] "${method} ${path} HTTP/1.1" ${status} 512 "-" "SentinelAttackTool/3.0"`;
}

function tick(char = '.') { process.stdout.write(char); }
function nl()  { process.stdout.write('\n'); }

function pad(s, n) { return String(s).padEnd(n); }
function rpad(s, n) { return String(s).padStart(n); }

// ─── Config fetch ──────────────────────────────────────────────────────────

async function fetchLiveConfig() {
    try {
        const cfg = await httpGet('/api/config');
        if (cfg && cfg.dos && cfg.ddos) return cfg;
        throw new Error('incomplete config shape');
    } catch (err) {
        console.warn(`\n  [!] Could not fetch /api/config (${err.message})`);
        console.warn(`  [!] Falling back to hardcoded development defaults.\n`);
        return FALLBACK;
    }
}

// ─── Parameter calculator ──────────────────────────────────────────────────
/**
 * Derives every test's request counts from the live thresholds.
 * All counts are set to (threshold × HEADROOM) so tests always fire.
 *
 * HEADROOM = 1.6  →  60 % above threshold (generous safety margin)
 */
function buildParams(cfg) {
    const HEADROOM = 1.6;
    const dos  = cfg.dos;
    const ddos = cfg.ddos;

    // ── Test 1: Global Flood ───────────────────────────────────────────────
    // totalReqs must exceed GLOBAL_RATE_THRESHOLD.
    // Each IP sends ≤3 requests (well below per-IP threshold of dos.THRESHOLD).
    const t1_total  = Math.ceil(ddos.GLOBAL_RATE_THRESHOLD * HEADROOM);
    const t1_reqPer = 3;                                        // 3 req / IP
    const t1_ips    = Math.ceil(t1_total / t1_reqPer);          // IPs needed

    // ── Test 2: Coordinated Botnet ─────────────────────────────────────────
    // distinctIPs must exceed COORDINATED_DISTINCT_IP_THRESHOLD.
    // Error ratio must be ≥ COORDINATED_ERROR_RATIO_THRESHOLD.
    // We use ratio = 0.85 (5 % above threshold) for a safe margin.
    const t2_ips        = Math.ceil(ddos.COORDINATED_DISTINCT_IP_THRESHOLD * HEADROOM);
    const targetRatio   = Math.min(0.95, ddos.COORDINATED_ERROR_RATIO_THRESHOLD + 0.05);
    const t2_errorCount = Math.ceil(t2_ips * targetRatio);
    const t2_okCount    = t2_ips - t2_errorCount;

    // ── Test 3: Subnet Attack ──────────────────────────────────────────────
    // Total requests from the same /24 must exceed SUBNET_RATE_THRESHOLD.
    // Each host sends 1 request (so no single IP triggers DoS).
    const t3_total = Math.ceil(ddos.SUBNET_RATE_THRESHOLD * HEADROOM);

    // ── Test 4: DoS Regression ────────────────────────────────────────────
    // We need the anomaly score to remain ≥ anomalyScoreToPenalize (0.7) for
    // enough consecutive checks to drain trust from 50 down below 20 (block threshold).
    //   Penalties needed = ceil((initial - block) / penalty) = ceil((50-20)/15) = 2
    // We send 2× the per-IP threshold in a tight burst to guarantee sustained anomaly.
    const t4_total = Math.ceil(dos.THRESHOLD * 2.0);

    return { dos, ddos, t1_total, t1_reqPer, t1_ips, t2_ips, t2_errorCount, t2_okCount, targetRatio, t3_total, t4_total };
}

// ─── Calibration table ─────────────────────────────────────────────────────

function printCalibrationTable(cfg, p) {
    const ENV_COLOR = cfg.env.startsWith('prod') ? '\x1b[31m' : '\x1b[32m';
    const RST = '\x1b[0m';
    const DIM = '\x1b[2m';
    const CYA = '\x1b[36m';
    const YEL = '\x1b[33m';

    console.log(`\n  ${DIM}┌─────────────────────────────────────────────────────────────────────┐${RST}`);
    console.log(`  ${DIM}│${RST}  CALIBRATION TABLE — live thresholds vs. test attack volumes         ${DIM}│${RST}`);
    console.log(`  ${DIM}│${RST}  Environment: ${ENV_COLOR}${cfg.env}${RST}${' '.repeat(Math.max(0, 52 - cfg.env.length))}${DIM}│${RST}`);
    console.log(`  ${DIM}├───────┬──────────────────────────────┬───────────┬───────────┬────────┤${RST}`);
    console.log(`  ${DIM}│${RST} Test  ${DIM}│${RST} Detector / Threshold          ${DIM}│${RST}${CYA} Threshold${RST} ${DIM}│${RST}${YEL} Tool sends${RST} ${DIM}│${RST} Margin ${DIM}│${RST}`);
    console.log(`  ${DIM}├───────┼──────────────────────────────┼───────────┼───────────┼────────┤${RST}`);

    const row = (test, label, threshold, sends) => {
        const margin = ((sends / threshold - 1) * 100).toFixed(0) + '%';
        const ok = sends > threshold ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m';
        console.log(
            `  ${DIM}│${RST} ${ok} ${pad(test,3)}  ${DIM}│${RST} ${pad(label,30)} ${DIM}│${RST}${CYA}${rpad(threshold,10)}${RST} ${DIM}│${RST}${YEL}${rpad(sends,10)}${RST} ${DIM}│${RST} +${pad(margin,6)} ${DIM}│${RST}`
        );
    };

    row('T-4', 'DoS  THRESHOLD',                        p.dos.THRESHOLD,                         p.t4_total);
    row('T-1', 'DDoS GLOBAL_RATE_THRESHOLD',             p.ddos.GLOBAL_RATE_THRESHOLD,            p.t1_total);
    row('T-2', 'DDoS COORDINATED_IP_THRESHOLD',          p.ddos.COORDINATED_DISTINCT_IP_THRESHOLD, p.t2_ips);
    row('T-3', 'DDoS SUBNET_RATE_THRESHOLD',             p.ddos.SUBNET_RATE_THRESHOLD,            p.t3_total);

    console.log(`  ${DIM}├───────┴──────────────────────────────┴───────────┴───────────┴────────┤${RST}`);
    console.log(`  ${DIM}│${RST}  All sends > thresholds → every test WILL trigger detection           ${DIM}│${RST}`);
    console.log(`  ${DIM}└─────────────────────────────────────────────────────────────────────┘${RST}\n`);
}

// ─── Test Scenarios ────────────────────────────────────────────────────────

/**
 * TEST 1 — Global Volumetric Flood  (DDoS Strategy 1)
 *
 * Sends t1_total requests spread across t1_ips distinct IPs (t1_reqPer req/IP).
 * No single IP exceeds the per-IP DoS threshold.
 * Triggers GLOBAL_RATE_THRESHOLD.
 */
async function test1_GlobalFlood(p) {
    const { t1_total, t1_ips, t1_reqPer, ddos } = p;
    console.log('\n  ════════════════════════════════════════════════════════════');
    console.log('  TEST 1 — Global Volumetric Flood  (DDoS Stage 1)');
    console.log('  ════════════════════════════════════════════════════════════');
    console.log(`  Strategy : ${t1_total} reqs from ${t1_ips} IPs  (${t1_reqPer} req/IP, well below per-IP threshold)`);
    console.log(`  Threshold: GLOBAL_RATE_THRESHOLD = ${ddos.GLOBAL_RATE_THRESHOLD} req / ${ddos.GLOBAL_RATE_WINDOW_MS/1000} s`);
    console.log(`  Sends    : ${t1_total} req  →  +${((t1_total/ddos.GLOBAL_RATE_THRESHOLD-1)*100).toFixed(0)}% above threshold`);
    console.log('  Expected : [!] DDoS ALERT: Global Volumetric Flood detected  →  Panic Mode');
    console.log('');

    let sent = 0;
    const t0 = Date.now();

    for (let i = 0; i < t1_ips && sent < t1_total; i++) {
        const ip    = `10.20.${Math.floor(i / 253)}.${(i % 253) + 1}`;
        const batch = [];
        for (let j = 0; j < t1_reqPer && sent < t1_total; j++) {
            batch.push(postLog(makeLogLine(ip, 'GET', '/api/data', 200)));
            sent++;
        }
        const results = await Promise.all(batch);
        results.forEach(code => tick(code === 200 ? 'G' : 'x'));
        if (sent % 100 === 0) nl();
    }

    nl();
    console.log(`\n  ✓ Sent ${sent} requests in ${Date.now() - t0} ms`);
    console.log('  ✓ Watch backend for: [DDoS ALERT] Global Volumetric Flood');
    console.log(`  ✓ Panic Mode lasts: ${ddos.PANIC_MODE_DURATION_MS / 1000} s  (cooldown: ${ddos.PANIC_MODE_COOLDOWN_MS / 1000} s)`);
}

/**
 * TEST 2 — Coordinated Botnet  (DDoS Strategy 2)
 *
 * Sends requests to /login from t2_ips distinct IPs.
 * t2_errorCount of them return 404 → error ratio ≥ COORDINATED_ERROR_RATIO_THRESHOLD + 5%.
 * Triggers COORDINATED_DISTINCT_IP_THRESHOLD + error ratio check → Swarm Block.
 */
async function test2_CoordinatedBotnet(p) {
    const { t2_ips, t2_errorCount, t2_okCount, targetRatio, ddos } = p;
    const actualRatio = (t2_errorCount / t2_ips * 100).toFixed(0);

    console.log('\n  ════════════════════════════════════════════════════════════');
    console.log('  TEST 2 — Coordinated Botnet / Flash-Crowd Differentiation  (DDoS Stage 2)');
    console.log('  ════════════════════════════════════════════════════════════');
    console.log(`  Strategy : ${t2_ips} IPs → POST /login  (${t2_errorCount} return 404 = ${actualRatio}% error rate)`);
    console.log(`  Threshold: COORDINATED_DISTINCT_IP_THRESHOLD = ${ddos.COORDINATED_DISTINCT_IP_THRESHOLD} IPs`);
    console.log(`             COORDINATED_ERROR_RATIO_THRESHOLD  = ${(ddos.COORDINATED_ERROR_RATIO_THRESHOLD*100).toFixed(0)}%`);
    console.log(`  Sends    : ${t2_ips} distinct IPs  →  +${((t2_ips/ddos.COORDINATED_DISTINCT_IP_THRESHOLD-1)*100).toFixed(0)}% above IP threshold`);
    console.log(`             error ratio ${actualRatio}%  →  +${((targetRatio - ddos.COORDINATED_ERROR_RATIO_THRESHOLD)*100).toFixed(0)}% above ratio threshold`);
    console.log('  Expected : [!] DDoS ALERT: Coordinated attack on /login  →  Swarm Block all IPs');
    console.log('');

    const t0 = Date.now();
    // Build the IP list: errorCount 404s first, then okCount 200s
    for (let i = 0; i < t2_ips; i++) {
        const ip     = `172.16.${Math.floor(i / 253)}.${(i % 253) + 1}`;
        const status = i < t2_errorCount ? 404 : 200;
        try {
            const code = await postLog(makeLogLine(ip, 'POST', '/login', status));
            console.log(`  [${String(i+1).padStart(2)}/${t2_ips}] ${ip.padEnd(14)} → POST /login → ${status}  (backend: ${code})`);
        } catch (err) {
            console.error(`  [${i+1}/${t2_ips}] SEND ERROR: ${err.message}`);
        }
        await sleep(40);
    }

    console.log(`\n  ✓ Sent ${t2_ips} requests in ${Date.now() - t0} ms`);
    console.log('  ✓ Watch backend for: [DDoS ALERT] Coordinated attack on /login');
    console.log(`  ✓ All ${t2_ips} IPs should be added to the firewall block-list`);
}

/**
 * TEST 3 — Subnet Volumetric Blocking  (DDoS Strategy 3)
 *
 * Sends t3_total requests from sequential IPs in 192.168.100.0/24.
 * Each host sends exactly 1 request (no per-IP anomaly).
 * Triggers SUBNET_RATE_THRESHOLD → entire /24 blocked.
 */
async function test3_SubnetBlocking(p) {
    const { t3_total, ddos } = p;
    const subnet = '192.168.100';

    console.log('\n  ════════════════════════════════════════════════════════════');
    console.log('  TEST 3 — Subnet Volumetric Blocking  (/24 CIDR)  (DDoS Stage 3)');
    console.log('  ════════════════════════════════════════════════════════════');
    console.log(`  Strategy : ${t3_total} requests from ${subnet}.1–${t3_total}  (1 req per host, same /24)`);
    console.log(`  Threshold: SUBNET_RATE_THRESHOLD = ${ddos.SUBNET_RATE_THRESHOLD} req / window`);
    console.log(`  Sends    : ${t3_total} req  →  +${((t3_total/ddos.SUBNET_RATE_THRESHOLD-1)*100).toFixed(0)}% above threshold`);
    console.log(`  Expected : [!] DDoS ALERT: Subnet Volumetric Attack from ${subnet}.0/24`);
    console.log(`             Firewall blocks entire /24 for ${ddos.SUBNET_BLOCK_BASE_TTL_MS/1000} s`);
    console.log('');

    const t0 = Date.now();
    for (let i = 1; i <= t3_total; i++) {
        const ip = `${subnet}.${i}`;
        try {
            await postLog(makeLogLine(ip, 'GET', '/api/search', 200));
            tick('S');
        } catch {
            tick('x');
        }
        if (i % 80 === 0) nl();
        await sleep(15);
    }

    nl();
    console.log(`\n  ✓ Sent ${t3_total} requests in ${Date.now() - t0} ms`);
    console.log('  ✓ Watch backend for: [DDoS ALERT] Subnet Volumetric Attack');
    console.log(`  ✓ Verify: netsh advfirewall firewall show rule name="Apache-Sentinel-Block-List"`);
    console.log(`           → RemoteIP should include ${subnet}.0/24`);
    console.log(`  ✓ Auto-unblock after: ${ddos.SUBNET_BLOCK_BASE_TTL_MS/1000} s`);
}

/**
 * TEST 4 — Per-IP DoS Regression  (DoS detector)
 *
 * Sends t4_total requests from a single IP in a tight 5 ms burst.
 * Anomaly score spikes to 1.0 → trust penalty applied every check.
 * Trust degrades: 50 → 35 → 20 → 5 (<20) → BLOCKED.
 *
 * Math:
 *   anomalyScoreToPenalize = 0.7  (hard-coded in detector)
 *   trustPenaltyOnAnomaly  = 15
 *   initialTrustScore      = 50
 *   blockTrustThreshold    = 20
 *   Penalties to block     = ceil((50-20)/15) = 2 → fires on 3rd anomaly
 */
async function test4_DosRegression(p) {
    const { t4_total, dos } = p;
    const ip = '10.0.0.99';

    console.log('\n  ════════════════════════════════════════════════════════════');
    console.log('  TEST 4 — Per-IP DoS Regression  (Single-IP Trust Degradation)');
    console.log('  ════════════════════════════════════════════════════════════');
    console.log(`  Strategy : ${t4_total} rapid requests from single IP ${ip}  (5 ms burst)`);
    console.log(`  Threshold: dos.THRESHOLD (baseThreshold) = ${dos.THRESHOLD} req / ${dos.WINDOW_MS/1000} s`);
    console.log(`  Sends    : ${t4_total} req  →  ${(t4_total/dos.THRESHOLD).toFixed(1)}× threshold`);
    console.log('  Expected : trust 50 → 35 → 20 → 5  →  [DoS] 10.0.0.99 BLOCKED');
    console.log('             Windows Firewall rule added for this IP');
    console.log('');

    const t0 = Date.now();
    for (let i = 1; i <= t4_total; i++) {
        try {
            const code = await postLog(makeLogLine(ip, 'GET', '/api/user/profile', 200));
            tick(code === 200 ? '.' : 'B');
        } catch {
            tick('x');
        }
        if (i % 80 === 0) nl();
        await sleep(5);
    }

    nl();
    console.log(`\n  ✓ Sent ${t4_total} requests in ${Date.now() - t0} ms`);
    console.log(`  ✓ Watch backend for: [DoS] ${ip} BLOCKED`);
}

// ─── Sequential run ────────────────────────────────────────────────────────

async function runAll(p) {
    const step = async (fn) => {
        await fn(p);
        console.log('\n  → Resetting server state...');
        const code = await resetServer();
        console.log(`  → Reset: HTTP ${code}`);
        await sleep(1200);
    };
    await step(test4_DosRegression);
    await step(test1_GlobalFlood);
    await step(test2_CoordinatedBotnet);
    await test3_SubnetBlocking(p);
}

// ─── Interactive Menu ──────────────────────────────────────────────────────

function printBanner(cfg, p) {
    console.clear();
    console.log('');
    console.log('  ╔══════════════════════════════════════════════════════════╗');
    console.log('  ║     APACHE SENTINEL — ATTACK SIMULATOR  (config-aware)  ║');
    console.log('  ╠══════════════════════════════════════════════════════════╣');
    console.log(`  ║  env: ${cfg.env.padEnd(50)}║`);
    console.log(`  ║  target: http://${BACKEND.host}:${BACKEND.port}${' '.repeat(36 - BACKEND.host.length - String(BACKEND.port).length)}║`);
    console.log('  ╠══════════════════════════════════════════════════════════╣');
    console.log(`  ║  T-4  [1]  DoS  per-IP flood       sends ${String(p.t4_total).padEnd(6)}/ thr ${String(p.dos.THRESHOLD).padEnd(5)}║`);
    console.log(`  ║  T-1  [2]  DDoS global flood        sends ${String(p.t1_total).padEnd(6)}/ thr ${String(p.ddos.GLOBAL_RATE_THRESHOLD).padEnd(5)}║`);
    console.log(`  ║  T-2  [3]  DDoS coordinated botnet  sends ${String(p.t2_ips).padEnd(6)}/ thr ${String(p.ddos.COORDINATED_DISTINCT_IP_THRESHOLD).padEnd(5)}║`);
    console.log(`  ║  T-3  [4]  DDoS subnet /24 attack   sends ${String(p.t3_total).padEnd(6)}/ thr ${String(p.ddos.SUBNET_RATE_THRESHOLD).padEnd(5)}║`);
    console.log('  ╠══════════════════════════════════════════════════════════╣');
    console.log('  ║  [5]  Run ALL  [r]  Reset server  [c]  Calibration      ║');
    console.log('  ║  [q]  Quit                                               ║');
    console.log('  ╚══════════════════════════════════════════════════════════╝');
    console.log('');
}

async function interactive(cfg, p) {
    printBanner(cfg, p);

    const rl  = readline.createInterface({ input: process.stdin, output: process.stdout });
    const ask = () => rl.question('  > ', async (input) => {
        const choice = input.trim().toLowerCase();
        try {
            switch (choice) {
                case '1': await test4_DosRegression(p);     break;
                case '2': await test1_GlobalFlood(p);       break;
                case '3': await test2_CoordinatedBotnet(p); break;
                case '4': await test3_SubnetBlocking(p);    break;
                case '5': await runAll(p);                  break;
                case 'c': printCalibrationTable(cfg, p);    break;
                case 'r': {
                    const code = await resetServer();
                    console.log(`\n  Server reset → HTTP ${code}`);
                    break;
                }
                case 'q':
                    console.log('\n  Exiting.\n');
                    rl.close();
                    process.exit(0);
                default:
                    console.log('\n  Unknown option. Choose 1–5, c, r, or q.');
            }
        } catch (err) {
            console.error('\n  [!] Error:', err.message);
            console.error(`  [!] Is the backend running at http://${BACKEND.host}:${BACKEND.port}?`);
        }
        console.log('');
        printBanner(cfg, p);
        ask();
    });
    ask();
}

// ─── Entry point ────────────────────────────────────────────────────────────

(async () => {
    // 1. Fetch live thresholds from the running backend
    console.log('\n  Connecting to backend...');
    const cfg = await fetchLiveConfig();
    const p   = buildParams(cfg);

    // 2. Always print the calibration table on startup so the user sees confirmation
    printCalibrationTable(cfg, p);

    // 3. CLI mode or interactive mode
    const args = process.argv.slice(2);
    if (args.includes('--test')) {
        const val = args[args.indexOf('--test') + 1];
        if      (val === '1') await test4_DosRegression(p);
        else if (val === '2') await test1_GlobalFlood(p);
        else if (val === '3') await test2_CoordinatedBotnet(p);
        else if (val === '4') await test3_SubnetBlocking(p);
        else if (val === 'all') await runAll(p);
        else { console.error('  Unknown test:', val); process.exit(1); }
        process.exit(0);
    } else {
        await interactive(cfg, p);
    }
})();
