# Apache Sentinel — Attack Simulator Tool

> **For academic / development validation only.**
> Run only against your own local Sentinel instance.

---

## Overview

This folder contains the complete attack simulation suite for **Apache Sentinel** — a real-time DoS/DDoS detection and mitigation system built on top of Apache + Node.js.

Two attack tools are provided:

| File | Runtime | Best for |
|---|---|---|
| `attack_tool.js` | Node.js (no extra deps) | Precise log-injection tests against the `/log` endpoint |
| `attack_tool.ps1` | Windows PowerShell | Live HTTP flood tests against Apache directly |

---

## Prerequisites

### 1. Start the Sentinel backend  *(as Administrator — required for Firewall access)*

```powershell
# Terminal 1 — backend (Administrator)
cd ..\backend
npm run dev
```

Wait for: `[Server] Sentinel is running on http://localhost:3000`

### 2. (Optional) Start Apache

```powershell
# Terminal 2 — Apache (only needed for PS1 tool)
./httpd.exe
```

---

## Tool 1 — `attack_tool.js`  (Node.js — Recommended)

Injects log lines directly into the backend's `/log` endpoint, bypassing Apache.
Accurately triggers each detection algorithm without needing a running Apache instance.

### Run (interactive menu)

```powershell
node attack_tool.js
```

### Run a specific test directly

```powershell
node attack_tool.js --test 1      # Per-IP DoS regression
node attack_tool.js --test 2      # Global volumetric flood
node attack_tool.js --test 3      # Coordinated botnet
node attack_tool.js --test 4      # Subnet /24 block
node attack_tool.js --test all    # Run all 4 in sequence (with resets)
```

### Menu options

```
[1]  Per-IP DoS Regression     → test4_DosRegression()
[2]  Global Volumetric Flood   → test1_GlobalFlood()
[3]  Coordinated Botnet        → test2_CoordinatedBotnet()
[4]  Subnet /24 Attack         → test3_SubnetBlocking()
[5]  Run ALL tests sequentially
[r]  Reset server state        → POST /debug/reset
[q]  Quit
```

---

## Tool 2 — `attack_tool.ps1`  (PowerShell — Live HTTP)

Fires real HTTP requests with spoofed `X-Forwarded-For` headers directly against Apache.
Requires Apache to be running and forwarding requests to the backend.

### Run

```powershell
# Open a new PowerShell terminal (does NOT need to be Administrator)
.\attack_tool.ps1
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

## Test Matrix — What each test validates

### Test 1 — Per-IP DoS Regression (`--test 1`)

- **Target**: DoS detector (trust score engine)
- **Method**: 150 rapid requests from `10.0.0.99`
- **Config**: `dos.THRESHOLD = 120`, `dos.WINDOW_MS = 10 000`
- **Expected outcome**: Trust score falls below block threshold (20) → `[DoS] 10.0.0.99 BLOCKED` + firewall rule

---

### Test 2 — Global Volumetric Flood (`--test 2`)

- **Target**: DDoS Strategy 1 — global rate tracker
- **Method**: 150 requests from 50 distinct IPs (3 req/IP, all below per-IP threshold)
- **Config**: `ddos.development.GLOBAL_RATE_THRESHOLD = 100`
- **Expected outcome**: `[!] DDoS ALERT: Global Volumetric Flood detected` → Panic Mode activated

---

### Test 3 — Coordinated Botnet (`--test 3`)

- **Target**: DDoS Strategy 2 — coordinated pattern detector
- **Method**: 15 IPs → `POST /login`, 12/15 returning HTTP 404 (80 % error rate)
- **Config**: `ddos.development.COORDINATED_DISTINCT_IP_THRESHOLD = 10`, `COORDINATED_ERROR_RATIO_THRESHOLD = 0.8`
- **Expected outcome**: `[!] DDoS ALERT: Coordinated attack on /login` → swarm block of all 15 IPs

---

### Test 4 — Subnet /24 Block (`--test 4`)

- **Target**: DDoS Strategy 3 — subnet volume tracker
- **Method**: 60 requests from `192.168.100.1–60` (1 req per host)
- **Config**: `ddos.development.SUBNET_RATE_THRESHOLD = 50`, `SUBNET_PREFIX_LENGTH = 24`
- **Expected outcome**: `[!] DDoS ALERT: Subnet Volumetric Attack from 192.168.100.0/24` → entire `/24` blocked via `netsh`
- **Verify**: `netsh advfirewall firewall show rule name="Apache-Sentinel-Block-List"` → look for `192.168.100.0/24`

---

## Cleanup / Reset

### Reset server state mid-testing *(dev only)*

```powershell
Invoke-WebRequest -Method Post -Uri "http://localhost:3000/debug/reset"
# or via Node tool: press [r] in the interactive menu
```

This clears all blocked IPs, offense histories, Panic Mode state, and Windows Firewall rules.

### Manually remove firewall rules

```powershell
netsh advfirewall firewall delete rule name="Apache-Sentinel-Block-List"
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

ddos.production.GLOBAL_RATE_THRESHOLD          (5 000 req)   Production global threshold
ddos.production.SUBNET_RATE_THRESHOLD          (500 req)     Production subnet threshold
ddos.production.SUBNET_BLOCK_BASE_TTL_MS       (900 000 ms)  15-minute subnet block
ddos.production.PANIC_MODE_DURATION_MS         (900 000 ms)  15-minute Panic Mode
```

See `implementation_plan.md` (in root) for the full config security analysis.
