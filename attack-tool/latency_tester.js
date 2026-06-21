const http = require('http');

const host = '127.0.0.1';
const port = 3000;

function sendReq(path) {
    return new Promise((resolve) => {
        const start = process.hrtime.bigint();
        const req = http.request({ host, port, path, method: 'GET' }, (res) => {
            res.resume();
            res.on('end', () => {
                const end = process.hrtime.bigint();
                resolve({ status: res.statusCode, ms: Number(end - start) / 1000000 });
            });
        });
        req.on('error', () => {
            const end = process.hrtime.bigint();
            resolve({ status: 0, ms: Number(end - start) / 1000000 });
        });
        req.end();
    });
}

function postLog(ip) {
    return new Promise((resolve) => {
        const line = `${ip} - - [20/Jun/2026:10:00:00 +0000] "GET /api/data HTTP/1.1" 200 512 "-" "LatencyTester/1.0"`;
        const start = process.hrtime.bigint();
        const req = http.request({ host, port, path: '/log', method: 'POST', headers: {'Content-Length': line.length} }, (res) => {
            res.resume();
            res.on('end', () => {
                const end = process.hrtime.bigint();
                resolve({ status: res.statusCode, ms: Number(end - start) / 1000000 });
            });
        });
        req.on('error', () => resolve({ status: 0, ms: 0 }));
        req.write(line);
        req.end();
    });
}

async function run() {
    console.log("=== Apache Sentinel Production Latency Test ===");
    console.log("Testing environment API (/api/config)...");
    const cfgRes = await sendReq('/api/config');
    console.log(`Config API responded in ${cfgRes.ms.toFixed(2)} ms`);

    console.log("\n[Phase 1] Normal Load (Sequential)...");
    let sumNormal = 0;
    for(let i=0; i<50; i++) {
        const r = await postLog('192.168.1.100');
        sumNormal += r.ms;
    }
    console.log(`-> Avg latency (Normal): ${(sumNormal/50).toFixed(2)} ms`);

    console.log("\n[Phase 2] Attack Simulation (Burst of 100 requests to trigger analysis)...");
    let sumAtk = 0;
    for(let i=0; i<100; i++) {
        const r = await postLog(`10.0.0.${i}`);
        sumAtk += r.ms;
    }
    console.log(`-> Avg latency (Under Attack / Heavy RAM arrays): ${(sumAtk/100).toFixed(2)} ms`);

    console.log("\n[Phase 3] Panic Mode / Load Shedding (Burst to trigger Panic)...");
    // Trigger panic
    let triggerPromises = [];
    for(let i=0; i<500; i++) triggerPromises.push(postLog(`8.8.8.${i%250}`));
    await Promise.all(triggerPromises);
    
    // Now measure heavy API during panic
    let sumPanic = 0;
    for(let i=0; i<50; i++) {
        const r = await sendReq('/api/search'); // heavy API
        sumPanic += r.ms;
    }
    console.log(`-> Avg latency (Load Shedding 503 Fast Reject): ${(sumPanic/50).toFixed(2)} ms`);
}

run();
