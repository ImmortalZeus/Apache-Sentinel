/**
 * Apache Sentinel — Latency Tester v2
 *
 * Measures POST /log latency under varying concurrency levels.
 * Captures: throughput (req/sec), per-call latency (mean, P50, P95, P99, max).
 *
 * Usage:  node attack-tool/latency_tester.js [totalReq=5000] [maxConc=100]
 *
 * Sweeps concurrency at: 1, 10, 50, 100 (or up to maxConc)
 * Each level uses a distinct IP prefix so the DoS detector does not
 * accidentally block IPs mid-test.
 */

const http = require('http');

const BACKEND = { host: '127.0.0.1', port: 3000 };
const TOTAL = parseInt(process.argv[2] || '5000', 10);
const MAX_CONC = parseInt(process.argv[3] || '100', 10);

function makeLogLine(ip, i) {
    const t = new Date(Date.now() + i);
    const stamp = `21/Jun/2026:${t.toISOString().slice(11, 19)} +0000`;
    return `${ip} - - [${stamp}] "GET /lat HTTP/1.1" 200 512 "-" "LatencyTester/2.0"`;
}

function postLog(line) {
    return new Promise((resolve, reject) => {
        const start = process.hrtime.bigint();
        const req = http.request({
            hostname: BACKEND.host,
            port: BACKEND.port,
            path: '/log',
            method: 'POST',
            headers: {
                'Content-Type': 'text/plain',
                'Content-Length': Buffer.byteLength(line),
            },
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

function get(path) {
    return new Promise((resolve, reject) => {
        const start = process.hrtime.bigint();
        const req = http.request({
            hostname: BACKEND.host,
            port: BACKEND.port,
            path,
            method: 'GET',
        }, (res) => {
            let body = '';
            res.setEncoding('utf8');
            res.on('data', d => body += d);
            res.on('end', () => {
                const ms = Number(process.hrtime.bigint() - start) / 1e6;
                let data = body;
                try { data = JSON.parse(body); } catch {}
                resolve({ status: res.statusCode, ms, data });
            });
        });
        req.on('error', reject);
        req.end();
    });
}

function postReset() {
    return new Promise((resolve) => {
        const req = http.request({
            hostname: BACKEND.host,
            port: BACKEND.port,
            path: '/debug/reset',
            method: 'POST',
        }, (res) => { res.resume(); resolve(res.statusCode); });
        req.on('error', () => resolve(500));
        req.end();
    });
}

async function runConcurrencyLevel(concurrency, total) {
    const latencies = [];
    const statuses = {};
    const t0 = Date.now();

    // Maintain a pool of `concurrency` in-flight requests.
    let issued = 0;
    const workers = [];

    for (let w = 0; w < concurrency; w++) {
        workers.push((async () => {
            while (issued < total) {
                const myIdx = issued++;
                if (myIdx >= total) break;
                // Use a unique IP per request to avoid triggering the per-IP
                // DoS detector during the test. Encode concurrency level +
                // request index into the IP to guarantee uniqueness across
                // the entire run.
                const a = concurrency & 255;
                const b = w & 255;
                const c = (myIdx >> 8) & 255;
                const d = myIdx & 255;
                const ip = `200.${a}.${b}.${c}`;
                const r = await postLog(makeLogLine(ip, myIdx));
                latencies.push(r.ms);
                statuses[r.status] = (statuses[r.status] || 0) + 1;
            }
        })());
    }
    await Promise.all(workers);

    const t1 = Date.now();
    return {
        concurrency,
        total,
        wallMs: t1 - t0,
        throughput: total / Math.max(1, t1 - t0) * 1000,
        latencies,
        statuses,
    };
}

function percentile(arr, p) {
    if (!arr.length) return 0;
    const sorted = [...arr].sort((a, b) => a - b);
    return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
}

function summarize(level) {
    const lat = level.latencies;
    const mean = lat.length ? lat.reduce((a, b) => a + b, 0) / lat.length : 0;
    return {
        concurrency: level.concurrency,
        total: level.total,
        wallMs: level.wallMs,
        throughput: level.throughput,
        latency: {
            mean: mean,
            p50: percentile(lat, 0.50),
            p95: percentile(lat, 0.95),
            p99: percentile(lat, 0.99),
            max: lat.length ? Math.max(...lat) : 0,
        },
        statuses: level.statuses,
    };
}

async function main() {
    console.log('=============================================');
    console.log(' Apache Sentinel — Latency Tester v2');
    console.log(` Total per level: ${TOTAL} | Max concurrency: ${MAX_CONC}`);
    console.log('=============================================\n');

    // Verify dev mode
    const resetStatus = await postReset();
    if (resetStatus !== 200) {
        console.error(`FATAL: /debug/reset returned ${resetStatus}. Server must be in development mode.`);
        process.exit(1);
    }
    console.log('[OK] Server is in development mode\n');

    // Snapshot baseline
    const baseline = await get('/api/stats');
    console.log(`[BASELINE] blockedIps=${baseline.data?.activeBlockedIps} panic=${baseline.data?.isDdosPanicMode} cpu=${baseline.data?.currentCpuUsage}\n`);

    const levels = [1, 10, 50, 100].filter(c => c <= MAX_CONC);
    const summaries = [];

    for (const conc of levels) {
        await postReset();
        // Distinct IP base per concurrency level so we don't trigger DoS mid-test
        console.log(`--- Concurrency = ${conc} ---`);
        const result = await runConcurrencyLevel(conc, TOTAL);
        const sum = summarize(result);
        summaries.push(sum);
        const l = sum.latency;
        console.log(`  wall=${sum.wallMs}ms throughput=${sum.throughput.toFixed(0)} req/s`);
        console.log(`  latency mean=${l.mean.toFixed(2)}ms p50=${l.p50.toFixed(2)}ms p95=${l.p95.toFixed(2)}ms p99=${l.p99.toFixed(2)}ms max=${l.max.toFixed(2)}ms`);
        console.log(`  statuses: ${JSON.stringify(sum.statuses)}\n`);
    }

    // Final snapshot
    await postReset();
    const finalSnap = await get('/api/stats');

    // Summary table
    console.log('=============================================');
    console.log(' LATENCY SUMMARY');
    console.log('=============================================');
    console.log(['Conc', 'Wall(ms)', 'RPS', 'Mean', 'P50', 'P95', 'P99', 'Max'].map(s => s.padStart(10)).join(''));
    console.log('-'.repeat(90));
    for (const s of summaries) {
        const l = s.latency;
        console.log([
            s.concurrency,
            s.wallMs,
            s.throughput.toFixed(0),
            l.mean.toFixed(2),
            l.p50.toFixed(2),
            l.p95.toFixed(2),
            l.p99.toFixed(2),
            l.max.toFixed(2),
        ].map(c => String(c).padStart(10)).join(''));
    }
    console.log('-'.repeat(90));

    console.log('\n[JSON_RESULTS_BEGIN]');
    console.log(JSON.stringify({
        totalPerLevel: TOTAL,
        maxConcurrency: MAX_CONC,
        baseline: baseline.data,
        finalSnapshot: finalSnap.data,
        summaries,
    }, null, 2));
    console.log('[JSON_RESULTS_END]');
}

main().catch(err => {
    console.error('Latency tester crashed:', err);
    process.exit(1);
});