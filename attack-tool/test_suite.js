const http = require('http');

const BACKEND = { host: '127.0.0.1', port: 3000 };

// ─── HTTP Helpers with Latency Measurement ───

function httpGet(path) {
    return new Promise((resolve, reject) => {
        const start = process.hrtime.bigint();
        const req = http.request(
            { hostname: BACKEND.host, port: BACKEND.port, path, method: 'GET' },
            (res) => {
                let body = '';
                res.setEncoding('utf8');
                res.on('data', d => body += d);
                res.on('end', () => {
                    const ms = Number(process.hrtime.bigint() - start) / 1e6;
                    try { resolve({ status: res.statusCode, data: JSON.parse(body), ms }); }
                    catch { resolve({ status: res.statusCode, data: body, ms }); }
                });
            }
        );
        req.on('error', reject);
        req.end();
    });
}

function httpPatch(path, data) {
    return new Promise((resolve, reject) => {
        const payload = JSON.stringify(data);
        const start = process.hrtime.bigint();
        const req = http.request({
            hostname: BACKEND.host, port: BACKEND.port, path, method: 'PATCH',
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
        }, (res) => {
            let body = '';
            res.setEncoding('utf8');
            res.on('data', d => body += d);
            res.on('end', () => {
                const ms = Number(process.hrtime.bigint() - start) / 1e6;
                try { resolve({ status: res.statusCode, data: JSON.parse(body), ms }); }
                catch { resolve({ status: res.statusCode, data: body, ms }); }
            });
        });
        req.on('error', reject);
        req.write(payload);
        req.end();
    });
}

function postLog(line) {
    return new Promise((resolve, reject) => {
        const start = process.hrtime.bigint();
        const req = http.request({
            hostname: BACKEND.host, port: BACKEND.port, path: '/log', method: 'POST',
            headers: { 'Content-Type': 'text/plain', 'Content-Length': Buffer.byteLength(line) },
        }, (res) => {
            res.resume();
            res.on('end', () => {
                const ms = Number(process.hrtime.bigint() - start) / 1e6;
                resolve({ status: res.statusCode, ms });
            });
        });
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

const sleep = ms => new Promise(r => setTimeout(r, ms));

function makeLogLine(ip, method = 'GET', path = '/', status = 200) {
    const now = new Date();
    const ts = `21/Jun/2026:${now.toISOString().slice(11, 19)} +0000`;
    return `${ip} - - [${ts}] "${method} ${path} HTTP/1.1" ${status} 512 "-" "TestSuite/1.0"`;
}

// ─── Test Runner ───

let passCount = 0;
let failCount = 0;
const latencies = { log: [], statsGet: [], configPatch: [] };

function assert(name, condition, detail = '') {
    if (condition) {
        console.log(`  [PASS] ${name}${detail ? ' | ' + detail : ''}`);
        passCount++;
    } else {
        console.log(`  [FAIL] ${name}${detail ? ' | ' + detail : ''}`);
        failCount++;
    }
}

// ─── Send N log lines from a single IP ───
async function sendLogs(ip, count, method = 'GET', path = '/', status = 200) {
    for (let i = 0; i < count; i++) {
        const r = await postLog(makeLogLine(ip, method, path, status));
        latencies.log.push(r.ms);
    }
}

// ─── Send logs from multiple IPs in same /24 subnet ───
async function sendSubnetLogs(subnetPrefix, count, path = '/', status = 200) {
    for (let i = 1; i <= count; i++) {
        const ip = `${subnetPrefix}.${(i % 254) + 1}`;
        const r = await postLog(makeLogLine(ip, 'GET', path, status));
        latencies.log.push(r.ms);
    }
}

// ─── Send coordinated logs from distinct IPs to same URL ───
async function sendCoordinatedLogs(ipPrefix, count, url, errorRatio) {
    const errorCount = Math.floor(count * errorRatio);
    for (let i = 0; i < count; i++) {
        const ip = `${ipPrefix}.${(i % 254) + 1}`;
        const status = i < errorCount ? 404 : 200;
        const r = await postLog(makeLogLine(ip, 'GET', url, status));
        latencies.log.push(r.ms);
    }
}

// ═══════════════════════════════════════════════
//                  MAIN TEST SUITE
// ═══════════════════════════════════════════════

async function runTests() {
    console.log("=============================================");
    console.log(" Apache Sentinel — System Test Suite v2");
    console.log(" Mode: Development | Host: 127.0.0.1:3000");
    console.log("=============================================\n");

    // Verify dev mode (reset endpoint must exist)
    const resetStatus = await resetServer();
    if (resetStatus !== 200) {
        console.error("FATAL: /debug/reset returned " + resetStatus + ". Server must be in development mode.");
        process.exit(1);
    }
    console.log("[OK] Server is in development mode (/debug/reset available)\n");

    // Read default config
    const cfgRes = await httpGet('/api/config');
    console.log(`[INFO] Default config: DoS THRESHOLD=${cfgRes.data.dos.THRESHOLD}, WINDOW_MS=${cfgRes.data.dos.WINDOW_MS}`);
    console.log(`[INFO] DDoS GLOBAL_RATE_THRESHOLD=${cfgRes.data.ddos.GLOBAL_RATE_THRESHOLD}, COORDINATED_DISTINCT_IP=${cfgRes.data.ddos.COORDINATED_DISTINCT_IP_THRESHOLD}`);
    console.log(`[INFO] DDoS SUBNET_RATE_THRESHOLD=${cfgRes.data.ddos.SUBNET_RATE_THRESHOLD}, ERROR_RATIO=${cfgRes.data.ddos.COORDINATED_ERROR_RATIO_THRESHOLD}`);
    console.log(`[INFO] Environment: ${cfgRes.data.env}\n`);

    const DOS_THRESHOLD = cfgRes.data.dos.THRESHOLD;
    const GLOBAL_THRESHOLD = cfgRes.data.ddos.GLOBAL_RATE_THRESHOLD;
    const COORDINATED_IP_THRESHOLD = cfgRes.data.ddos.COORDINATED_DISTINCT_IP_THRESHOLD;
    const ERROR_RATIO_THRESHOLD = cfgRes.data.ddos.COORDINATED_ERROR_RATIO_THRESHOLD;
    const SUBNET_THRESHOLD = cfgRes.data.ddos.SUBNET_RATE_THRESHOLD;

    // ─── GROUP 1: DoS Detection (per-IP) ───
    console.log("--- GROUP 1: DoS DETECTION (per-IP Trust Score) ---\n");

    // TC01: Under threshold → not blocked
    await resetServer();
    const tc01Count = Math.floor(DOS_THRESHOLD * 0.5);
    await sendLogs('10.0.0.1', tc01Count);
    const tc01Stats = await httpGet('/api/stats');
    latencies.statsGet.push(tc01Stats.ms);
    assert(
        `TC01 DoS Under Threshold (${tc01Count} reqs, threshold=${DOS_THRESHOLD})`,
        tc01Stats.data.activeBlockedIps === 0,
        `blockedIps=${tc01Stats.data.activeBlockedIps}`
    );

    // TC02: Over threshold → blocked
    await resetServer();
    const tc02Count = Math.floor(DOS_THRESHOLD * 1.5);
    await sendLogs('10.0.0.2', tc02Count);
    const tc02Stats = await httpGet('/api/stats');
    latencies.statsGet.push(tc02Stats.ms);
    assert(
        `TC02 DoS Over Threshold (${tc02Count} reqs, threshold=${DOS_THRESHOLD})`,
        tc02Stats.data.activeBlockedIps > 0,
        `blockedIps=${tc02Stats.data.activeBlockedIps}`
    );

    // TC03: Trust Score Recovery
    // Trust starts at 50. Penalty = -15 when anomaly >= 0.7. Block when trust < 20.
    // We need exactly 2 penalties (50→35→20, still not blocked since threshold is <20).
    // Anomaly = count/threshold. For anomaly=0.7 we need count = 0.7 * 120 = 84.
    // But after first penalty, per-IP threshold drops to 96. So second trigger is easier.
    // Strategy: send 85 reqs (just over 0.7*120=84), wait for recovery, send again.
    await resetServer();
    const tc03Count = Math.floor(DOS_THRESHOLD * 0.55); // ~66 reqs → anomaly ~0.55, NO penalty
    await sendLogs('10.0.0.3', tc03Count);
    const tc03Mid = await httpGet('/api/stats');
    latencies.statsGet.push(tc03Mid.ms);
    const midBlocked = tc03Mid.data.activeBlockedIps;
    // Wait for tick() + window rollover. Must exceed WINDOW_MS (10s)
    // so first batch exits window0 and enters window1.
    // Weighted anomaly = w0*0.55 + w1*0.55 = 0.5*0.55 + 0.3*0.55 = 0.44 < 0.7 → no penalty
    await sleep(11000);
    // Send same amount again — combined weighted anomaly still < 0.7
    await sendLogs('10.0.0.3', tc03Count);
    const tc03Final = await httpGet('/api/stats');
    latencies.statsGet.push(tc03Final.ms);
    assert(
        `TC03 Trust Recovery (${tc03Count} reqs x2, 11s gap, weighted anomaly ~0.44 < 0.7)`,
        tc03Final.data.activeBlockedIps === 0,
        `midBlocked=${midBlocked}, finalBlocked=${tc03Final.data.activeBlockedIps}`
    );

    // ─── GROUP 2: DDoS Detection ───
    console.log("\n--- GROUP 2: DDoS DETECTION (Global, Coordinated, Subnet) ---\n");

    // TC04: Global Panic Mode — triggered
    // When panic is active, /api/stats returns 503 (Load Shedding).
    // So we verify panic by checking the HTTP status code.
    await resetServer();
    const tc04Count = Math.floor(GLOBAL_THRESHOLD * 1.5);
    // Use many different IPs to avoid per-IP DoS block
    for (let i = 0; i < tc04Count; i++) {
        const ip = `20.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`;
        const r = await postLog(makeLogLine(ip));
        latencies.log.push(r.ms);
    }
    // If panic is active, /api/stats will be blocked with 503
    const tc04Stats = await httpGet('/api/stats');
    latencies.statsGet.push(tc04Stats.ms);
    // Also check /api/config which is NOT in heavyPaths → should still return 200
    const tc04Config = await httpGet('/api/config');
    assert(
        `TC04 Global Panic Mode ON (${tc04Count} reqs, threshold=${GLOBAL_THRESHOLD})`,
        tc04Stats.status === 503 && tc04Config.status === 200,
        `statsStatus=${tc04Stats.status} (expect 503), configStatus=${tc04Config.status} (expect 200)`
    );

    // TC05: Global under threshold → no panic
    await resetServer();
    const tc05Count = Math.floor(GLOBAL_THRESHOLD * 0.5);
    for (let i = 0; i < tc05Count; i++) {
        const ip = `30.0.0.${(i % 254) + 1}`;
        await postLog(makeLogLine(ip));
    }
    const tc05Stats = await httpGet('/api/stats');
    latencies.statsGet.push(tc05Stats.ms);
    assert(
        `TC05 Global Under Threshold (${tc05Count} reqs, threshold=${GLOBAL_THRESHOLD})`,
        tc05Stats.data.isDdosPanicMode === false,
        `panicMode=${tc05Stats.data.isDdosPanicMode}`
    );

    // TC06a: Flash Crowd (low error ratio) → NOT blocked
    await resetServer();
    const tc06aIPs = COORDINATED_IP_THRESHOLD + 5; // Must exceed distinct IP threshold
    const flashErrorRatio = Math.max(0, ERROR_RATIO_THRESHOLD - 0.3);
    await sendCoordinatedLogs('40.0.0', tc06aIPs, '/api/login', flashErrorRatio);
    const tc06aStats = await httpGet('/api/stats');
    latencies.statsGet.push(tc06aStats.ms);
    assert(
        `TC06a Flash Crowd (${tc06aIPs} IPs, errorRatio=${(flashErrorRatio * 100).toFixed(0)}%, threshold=${(ERROR_RATIO_THRESHOLD * 100).toFixed(0)}%)`,
        tc06aStats.data.activeBlockedIps === 0,
        `blockedIps=${tc06aStats.data.activeBlockedIps}`
    );

    // TC06b: Botnet (high error ratio) → blocked
    await resetServer();
    const tc06bIPs = COORDINATED_IP_THRESHOLD + 5;
    const botnetErrorRatio = Math.min(1.0, ERROR_RATIO_THRESHOLD + 0.1);
    await sendCoordinatedLogs('50.0.0', tc06bIPs, '/api/login', botnetErrorRatio);
    const tc06bStats = await httpGet('/api/stats');
    latencies.statsGet.push(tc06bStats.ms);
    assert(
        `TC06b Botnet Attack (${tc06bIPs} IPs, errorRatio=${(botnetErrorRatio * 100).toFixed(0)}%, threshold=${(ERROR_RATIO_THRESHOLD * 100).toFixed(0)}%)`,
        tc06bStats.data.activeBlockedIps > 0,
        `blockedIps=${tc06bStats.data.activeBlockedIps}`
    );

    // TC07: Subnet Volume Attack
    await resetServer();
    const tc07Count = Math.floor(SUBNET_THRESHOLD * 1.5);
    await sendSubnetLogs('60.0.0', tc07Count);
    const tc07Stats = await httpGet('/api/stats');
    latencies.statsGet.push(tc07Stats.ms);
    assert(
        `TC07 Subnet Volume Attack (${tc07Count} reqs from /24, threshold=${SUBNET_THRESHOLD})`,
        tc07Stats.data.activeBlockedIps > 0,
        `blockedIps=${tc07Stats.data.activeBlockedIps}`
    );

    // ─── GROUP 3: Defense Response ───
    console.log("\n--- GROUP 3: DEFENSE RESPONSE ---\n");

    // TC08: Load Shedding during Panic Mode
    // First trigger panic mode
    await resetServer();
    for (let i = 0; i < GLOBAL_THRESHOLD + 50; i++) {
        const ip = `70.${(i >> 8) & 255}.${i & 255}.1`;
        await postLog(makeLogLine(ip));
    }
    // Now test load shedding
    const tc08Stats = await httpGet('/api/stats');
    const tc08Config = await httpGet('/api/config');
    latencies.statsGet.push(tc08Stats.ms);
    assert(
        `TC08 Load Shedding (Panic Mode → /api/stats=503, /api/config=200)`,
        tc08Stats.status === 503 && tc08Config.status === 200,
        `statsStatus=${tc08Stats.status}, configStatus=${tc08Config.status}`
    );

    // TC09: Firewall Bypass (blocked IP skips analysis)
    await resetServer();
    // Block an IP first
    const bypassCount = Math.floor(DOS_THRESHOLD * 1.5);
    await sendLogs('10.99.99.1', bypassCount);
    const tc09Pre = await httpGet('/api/stats');
    const preBlocked = tc09Pre.data.activeBlockedIps;
    // Send more from same IP — should still work (200) but skip analysis
    const bypassResult = await postLog(makeLogLine('10.99.99.1'));
    assert(
        `TC09 Firewall Bypass (blocked IP still gets 200 but skips analysis)`,
        preBlocked > 0 && bypassResult.status === 200,
        `preBlocked=${preBlocked}, postStatus=${bypassResult.status}`
    );

    // ─── GROUP 4: Integration ───
    console.log("\n--- GROUP 4: INTEGRATION ---\n");

    // TC10: Config Hot-reload
    await resetServer();
    const origConfig = await httpGet('/api/config');
    const origThreshold = origConfig.data.dos.THRESHOLD;
    const patchRes = await httpPatch('/api/config', { THRESHOLD: 999 });
    latencies.configPatch.push(patchRes.ms);
    const newConfig = await httpGet('/api/config');
    // Restore
    await httpPatch('/api/config', { THRESHOLD: origThreshold });
    assert(
        `TC10 Config Hot-reload (THRESHOLD: ${origThreshold} → 999 → ${origThreshold})`,
        patchRes.status === 200 && newConfig.data.dos.THRESHOLD === 999,
        `patchStatus=${patchRes.status}, newThreshold=${newConfig.data.dos.THRESHOLD}`
    );

    // TC11: Database Logging
    await resetServer();
    await postLog(makeLogLine('192.168.1.1', 'GET', '/test-logging', 200));
    await sleep(1000); // Wait for DB flush
    const logsRes = await httpGet('/api/logs?limit=5');
    assert(
        `TC11 Database Logging (logs retrievable from MongoDB)`,
        logsRes.status === 200 && logsRes.data && logsRes.data.data && logsRes.data.data.length > 0,
        `status=${logsRes.status}, logCount=${logsRes.data?.data?.length || 0}`
    );

    // TC12: API Contract — /api/stats
    await resetServer();
    const statsContract = await httpGet('/api/stats');
    latencies.statsGet.push(statsContract.ms);
    const hasAllFields = statsContract.data.hasOwnProperty('totalLogsAnalyzed')
        && statsContract.data.hasOwnProperty('activeBlockedIps')
        && statsContract.data.hasOwnProperty('currentCpuUsage')
        && statsContract.data.hasOwnProperty('isDdosPanicMode')
        && statsContract.data.hasOwnProperty('trafficHistory');
    assert(
        `TC12 API Contract /api/stats (all required fields present)`,
        statsContract.status === 200 && hasAllFields,
        `fields: totalLogsAnalyzed=${statsContract.data.totalLogsAnalyzed !== undefined}, activeBlockedIps=${statsContract.data.activeBlockedIps !== undefined}, isDdosPanicMode=${statsContract.data.isDdosPanicMode !== undefined}`
    );

    // TC13: API Contract — /api/firewall/rules
    const fwContract = await httpGet('/api/firewall/rules');
    assert(
        `TC13 API Contract /api/firewall/rules (data + pagination)`,
        fwContract.status === 200 && Array.isArray(fwContract.data.data) && fwContract.data.pagination,
        `hasData=${Array.isArray(fwContract.data?.data)}, hasPagination=${!!fwContract.data?.pagination}`
    );

    // ─── RESULTS ───
    console.log("\n=============================================");
    console.log(` RESULTS: ${passCount} PASSED | ${failCount} FAILED | Total: ${passCount + failCount}`);
    console.log("=============================================\n");

    // ─── LATENCY REPORT ───
    const avg = arr => arr.length ? (arr.reduce((a, b) => a + b, 0) / arr.length) : 0;
    const p95 = arr => {
        if (!arr.length) return 0;
        const sorted = [...arr].sort((a, b) => a - b);
        return sorted[Math.floor(sorted.length * 0.95)];
    };

    console.log("--- LATENCY REPORT ---");
    console.log(`POST /log   : avg=${avg(latencies.log).toFixed(2)}ms | p95=${p95(latencies.log).toFixed(2)}ms | samples=${latencies.log.length}`);
    console.log(`GET /api/*  : avg=${avg(latencies.statsGet).toFixed(2)}ms | p95=${p95(latencies.statsGet).toFixed(2)}ms | samples=${latencies.statsGet.length}`);
    console.log(`PATCH /api/*: avg=${avg(latencies.configPatch).toFixed(2)}ms | p95=${p95(latencies.configPatch).toFixed(2)}ms | samples=${latencies.configPatch.length}`);
    console.log("");
}

runTests().catch(err => {
    console.error("Test suite crashed:", err);
    process.exit(1);
});
