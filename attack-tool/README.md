# Apache Sentinel — Attack & Test Tooling

This folder contains the complete testing, load-generation, and attack
toolkit for **Apache Sentinel** — a real-time DoS/DDoS detection and
mitigation system built on top of Apache + Node.js.

> **For academic / development validation only.**
> Run only against your own local Sentinel instance.

---

## Contents

| File | Type | Purpose |
|---|---|---|
| `test_suite.js` | Automated harness | 24 functional test cases driven by boundary-value analysis. Output is JSON for the project report. |
| `latency_tester.js` | Load generator | Concurrency sweep (1, 10, 50, 100) over 5,000 requests/level. Reports mean / P50 / P95 / P99 / max latency + throughput. |
| `attack_tool.js` | Interactive simulator | Node-based attack menu. Bypasses Apache, injects directly into `POST /log`. Config-aware (reads `/api/config` at startup). |
| `attack_tool.ps1` | Interactive simulator | PowerShell HTTP flood against Apache with spoofed `X-Forwarded-For` headers. Requires a running Apache. |
| `test_run.log` | Sample output | Reference output from a recent run of `test_suite.js` (24/24 PASS). |
| `latency_run.log` | Sample output | Reference output from a recent run of `latency_tester.js`. |

All Node tools use **zero external dependencies** — only the standard
library (`http`, `readline`, `process`, etc.). They talk directly to
the backend over plain HTTP.

---

## Prerequisites

### Backend must be running in Development mode

The automated harnesses (`test_suite.js`, `latency_tester.js`) require
`POST /debug/reset` to clear state between cases. This endpoint is only
registered when `NODE_ENV !== 'production'`. The interactive simulators
(`attack_tool.js`, `attack_tool.ps1`) work in either mode.

```powershell
# Terminal 1 — backend (Administrator — required for netsh advfirewall)
cd ..\backend
npm run dev
```

Wait for: `[Server] Sentinel is running on http://localhost:3000`

### Optional: Apache

Only `attack_tool.ps1` requires a running Apache instance (it floods
real HTTP endpoints with spoofed headers). The Node tools inject
directly into the backend's `/log` endpoint and skip Apache entirely.

---

## Tool 1 — `test_suite.js` (automated functional suite)

Runs 24 black-box test cases against the backend. Each case uses
boundary-value analysis (50% and 150% of the active threshold) and a
fresh `/debug/reset` between cases to prevent state contamination.

### Run

```powershell
node attack-tool/test_suite.js > test_run.log 2>&1
```

Console output includes per-test pass/fail lines, a summary table, and
a JSON block delimited by `[JSON_RESULTS_BEGIN]` / `[JSON_RESULTS_END]`
suitable for ingestion into the project report.

### Test matrix (24 cases across 4 groups)

| Group | Cases | What it covers |
|---|---|---|
| DoS detection | TC1–TC8 | Trust score, sliding window, penalty cascade, slow-drip evasion, tick recovery |
| DDoS detection | TC9–TC13 | Global volumetric, flash crowd vs botnet, subnet /24 |
| Defense response | TC14–TC19 | Load shedding, panic deactivation, blocked-IP bypass, manual block/unblock, subnet idempotency |
| Integration | TC20–TC24 | Config hot-reload, DB logging, API contracts, adaptive threshold |

Total runtime: ~4–5 min (TC7 ~20 s slow drip, TC15 ~65 s panic
deactivation, TC8 ~30 s tick recovery).

### Per-test metrics captured

- Wall-clock duration of the attack loop
- Effective throughput (req/sec)
- Blocked-IP count (`/api/stats`)
- Blocked-IP list (`/api/firewall/rules`)
- CPU, global threshold, panic mode state
- HTTP status codes for every call
- Per-call latency (`process.hrtime.bigint()`)

---

## Tool 2 — `latency_tester.js` (load + latency benchmark)

Measures `POST /log` latency under varying concurrency levels. All
requests use distinct IPs to avoid triggering the DoS detector mid-test.

### Run

```powershell
# Defaults: 5000 requests per level, max concurrency 100
node attack-tool/latency_tester.js

# Custom load
node attack-tool/latency_tester.js 10000 200    # 10k reqs, max conc 200
```

### Output

For each concurrency level (1, 10, 50, 100):

- Mean / P50 / P95 / P99 / max latency
- Throughput (req/sec)
- Status code distribution

At the end, a JSON block delimited by `[JSON_RESULTS_BEGIN]` /
`[JSON_RESULTS_END]` contains the same data plus baseline / final
snapshots of `/api/stats`.

### Typical results (single Node process, dev preset)

| Concurrency | Mean | P95 | P99 | Throughput |
|---|---|---|---|---|
| 1 | ~0.6 ms | ~0.8 ms | ~7 ms | ~1,500 req/s |
| 10 | ~2 ms | ~5 ms | ~10 ms | ~4,200 req/s |
| 50 | ~10 ms | ~16 ms | ~24 ms | ~4,700 req/s |
| 100 | ~19 ms | ~22 ms | ~32 ms | ~5,200 req/s |

Throughput plateaus around 5,000 req/s as single-process Node becomes
the limiting factor. P99 stays under 50 ms at all levels, supporting the
real-time claim in the project report.

---

## Tool 3 — `attack_tool.js` (interactive Node simulator)

Fetches live thresholds from `GET /api/config` at startup, then computes
every test's request count dynamically so tests fire regardless of
whether the backend is running in development or production mode.

### Run

```powershell
node attack-tool/attack_tool.js                # interactive menu
node attack-tool/attack_tool.js --test 1       # DoS regression
node attack-tool/attack_tool.js --test 2       # Global volumetric flood
node attack-tool/attack_tool.js --test 3       # Coordinated botnet
node attack-tool/attack_tool.js --test 4       # Subnet /24 attack
node attack-tool/attack_tool.js --test all     # all 4 in sequence
```

### Menu

```
[1]  Per-IP DoS Regression     → test4_DosRegression()
[2]  Global Volumetric Flood   → test1_GlobalFlood()
[3]  Coordinated Botnet        → test2_CoordinatedBotnet()
[4]  Subnet /24 Attack         → test3_SubnetBlocking()
[5]  Run ALL tests sequentially
[r]  Reset server state        → POST /debug/reset
[q]  Quit
```

### Per-test details

**Test 1 — Per-IP DoS Regression**

- **Target:** DoS detector (trust score engine)
- **Method:** 150 rapid requests from `10.0.0.99`
- **Expected:** Trust score falls below 20 → `[DoS] 10.0.0.99 BLOCKED` + firewall rule

**Test 2 — Global Volumetric Flood**

- **Target:** DDoS Strategy 1 (global rate tracker)
- **Method:** 150 requests from 50 distinct IPs (3 req/IP, all below per-IP threshold)
- **Expected:** `[!] DDoS ALERT: Global Volumetric Flood detected` → Panic Mode ON

**Test 3 — Coordinated Botnet**

- **Target:** DDoS Strategy 2 (coordinated pattern detector)
- **Method:** 15 IPs → `POST /login`, 12/15 returning HTTP 404 (80% error rate)
- **Expected:** `[!] DDoS ALERT: Coordinated attack on /login` → swarm block

**Test 4 — Subnet /24 Attack**

- **Target:** DDoS Strategy 3 (subnet volume tracker)
- **Method:** 60 requests from `192.168.100.1–60` (1 req per host)
- **Expected:** `[!] DDoS ALERT: Subnet Volumetric Attack from 192.168.100.0/24` → CIDR block

---

## Tool 4 — `attack_tool.ps1` (interactive PowerShell simulator)

Fires real HTTP requests with spoofed `X-Forwarded-For` headers directly
against Apache. Requires a running Apache that is forwarding requests
to the backend.

### Run

```powershell
# PowerShell (Administrator not required for the tool itself,
# but the backend it talks to must be running as Administrator)
.\attack-tool\attack_tool.ps1
```

### Scenarios

| # | Name | Type | Description |
|---|---|---|---|
| 0 | Configure Params | — | Set target URL, request count, delay |
| 1 | Normal Traffic | DoS | Legitimate browsing simulation (500 ms delay) |
| 2 | Flash Crowd | DoS | Hundreds of IPs hitting one URL simultaneously |
| 3 | HTTP Flood | DoS | Cache-busting with random `?q=` params |
| 4 | Global Volumetric Flood | DDoS | Random IPs from across the globe |
| 5 | Coordinated Botnet | DDoS | Multiple IPs targeting a non-existent URL (404 error ratio) |
| 6 | Subnet Attack | DDoS | Attack from a single `/24` subnet |

---

## Cleanup & Reset

### Reset server state mid-testing (dev only)

```powershell
Invoke-WebRequest -Method Post -Uri "http://localhost:3000/debug/reset"
# or via Node tool: press [r] in the interactive menu
```

This clears all blocked IPs, offense histories, Panic Mode state, and the
Windows Firewall rule.

### Manually remove firewall rules

```powershell
netsh advfirewall firewall delete rule name="Apache-Sentinel-Block-List"
```

### Verify firewall state

```powershell
netsh advfirewall firewall show rule name="Apache-Sentinel-Block-List"
```

---

## Configuration Reference

The backend reads `backend/src/config.json`. Key parameters:

```
dos.WINDOW_MS                                  (10 000 ms)   Per-IP sliding window
dos.THRESHOLD                                  (120 req)     Per-IP block threshold

ddos.COORDINATED_ERROR_RATIO_THRESHOLD         (0.8)         80 % errors = botnet
ddos.SUBNET_PREFIX_LENGTH                      (24)          /24 CIDR grouping

ddos.development.GLOBAL_RATE_THRESHOLD         (100 req)     Global flood trigger
ddos.development.GLOBAL_RATE_WINDOW_MS         (10 000 ms)   Global window
ddos.development.COORDINATED_DISTINCT_IP_THRESHOLD  (10)     Bot swarm trigger
ddos.development.SUBNET_RATE_THRESHOLD         (50 req)      Subnet flood trigger
ddos.development.SUBNET_BLOCK_BASE_TTL_MS      (60 000 ms)   Subnet block TTL (1 min)
ddos.development.PANIC_MODE_DURATION_MS        (60 000 ms)   Panic Mode duration (1 min)
ddos.development.PANIC_MODE_COOLDOWN_MS        (60 000 ms)   Cooldown before re-trigger

ddos.production.GLOBAL_RATE_THRESHOLD          (800 req)     Production global threshold
ddos.production.SUBNET_RATE_THRESHOLD          (120 req)     Production subnet threshold
ddos.production.SUBNET_BLOCK_BASE_TTL_MS       (900 000 ms)  15-minute subnet block
ddos.production.PANIC_MODE_DURATION_MS         (900 000 ms)  15-minute Panic Mode
```

The Node tools (`test_suite.js`, `attack_tool.js`) read live thresholds
from `GET /api/config` at startup, so they adapt automatically. The
PowerShell tool uses the fallback table above.

---

## Recommended Run Sequence

```powershell
# 1. Start backend (Administrator)
cd ..\backend && npm run dev

# 2. Run automated suite (~4-5 min)
node attack-tool\test_suite.js > test_run.log 2>&1

# 3. Run latency benchmark (~30 s)
node attack-tool\latency_tester.js > latency_run.log 2>&1

# 4. Optional: interactive exploration
node attack-tool\attack_tool.js
```

After step 2, `test_run.log` contains a JSON block that can be pasted
into `Report/content/Results.tex` placeholder cells.

---

## See also

- [`../README.md`](../README.md) — top-level project overview
- [`../backend/README.md`](../backend/README.md) — backend API + detection algorithm details
- [`../frontend/README.md`](../frontend/README.md) — dashboard docs
- [`../backend/docs/apache-setup-guide.md`](../backend/docs/apache-setup-guide.md) — Apache install + `CustomLog` pipe on Windows