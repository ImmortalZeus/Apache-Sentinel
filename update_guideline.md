# Apache Sentinel — Integration & Update Guide

> **Audience:** Team members merging the original `apache-sentinel-backend` (GitHub) with this new full-stack workspace.  
> **Date:** June 2026  
> **Project path:** `D:/works/university/ITE15/Project-2/`

---

## Table of Contents

1. [Functional & Non-Functional Requirements Summary](#1-requirements-summary)
2. [API Contract Reference](#2-api-contract-reference)
3. [Backend Requirements for Frontend Connectivity](#3-backend-requirements)
4. [Connection Setup Guide](#4-connection-setup-guide)
5. [Team Integration Guide (Merging Old GitHub → New Workspace)](#5-team-integration-guide)

---

## 1. Requirements Summary

### 1.1 Functional Requirements Implemented

| # | Feature | Status | Location |
|---|---------|--------|----------|
| FR-01 | Apache log ingestion via stdin pipe | ✅ | `backend/log-collector.cjs` → `POST /log/batch` |
| FR-02 | Per-IP DoS detection (trust score model) | ✅ | `backend/src/detectors/dos.detector.ts` |
| FR-03 | Global volumetric DDoS detection (Stage 1 — Panic Mode) | ✅ | `backend/src/detectors/ddos.detector.ts` |
| FR-04 | Coordinated botnet detection (Stage 2 — Swarm Block) | ✅ | `backend/src/detectors/ddos.detector.ts` |
| FR-05 | Subnet /24 flood detection (Stage 3 — Subnet Block) | ✅ | `backend/src/detectors/ddos.detector.ts` |
| FR-06 | Automated Windows Firewall blocking via `netsh advfirewall` | ✅ | `backend/src/services/firewall.service.ts` |
| FR-07 | Manual IP block / unblock via UI | ✅ | `POST /api/firewall/block` + `POST /api/firewall/unblock` |
| FR-08 | **Revoke All** firewall blocks in one click | ✅ | `POST /api/firewall/unblock-all` |
| FR-09 | Real-time dashboard metrics (CPU, blocked IPs, traffic history) | ✅ | `GET /api/stats` |
| FR-10 | Live log explorer with multi-filter (status / method / search) | ✅ | `GET /api/logs` + frontend filter UI |
| FR-11 | Live config reading in Settings UI | ✅ | `GET /api/config` |
| FR-12 | Runtime threshold hot-reload without server restart | ✅ | `PATCH /api/config` → `ConfigService.update()` |
| FR-13 | Attack simulator tool (DoS + 3 DDoS scenarios) | ✅ | `attack-tool/attack_tool.js` + `attack_tool.ps1` |
| FR-14 | Config-aware attack tool (reads live thresholds at startup) | ✅ | `attack_tool.js` `buildParams()` / PS1 `Get-LiveConfig` |
| FR-15 | MongoDB persistence for all ingested logs | ✅ | `backend/src/services/Log.service.ts` |
| FR-16 | Firewall state sync from OS on startup | ✅ | `firewallService.syncFromFirewall()` |
| FR-17 | Panic Mode visual alert in Dashboard | ✅ | Pulsing banner, red chart, blinking badges |
| FR-18 | Settings page — slider + numeric input for every threshold | ✅ | `frontend/src/pages/Settings/index.tsx` |
| FR-19 | Apache log piping to backend via `log-collector.cjs` | ✅ | `C:/Apache24/conf/httpd.conf` CustomLog directive |
| FR-20 | Debug reset endpoint (dev mode only) | ✅ | `POST /debug/reset` |

### 1.2 Non-Functional Requirements Implemented

| # | Requirement | Implementation |
|---|------------|----------------|
| NFR-01 | **Administrator privilege required** | `checkAdminPrivilege()` called at startup; process exits if not elevated |
| NFR-02 | **Zero-restart config updates** | `ConfigService` singleton holds live state; `PATCH /api/config` hot-reloads both detectors |
| NFR-03 | **CORS locked to frontend origin** | `cors({ origin: 'http://localhost:5173' })` |
| NFR-04 | **No cache on API responses** | `nocache()` middleware + `etag: false` |
| NFR-05 | **Dual environment config** | `config.json` has `development` and `production` ddos sub-objects selected by `NODE_ENV` |
| NFR-06 | **Graceful shutdown** | `SIGTERM`/`SIGINT` handlers in `server.ts`; DB flush before exit |
| NFR-07 | **DB write batching** | Logs buffered; batch flush every 5 s or 1 000 entries (`DB_BATCH_SIZE`, `DB_FLUSH_INTERVAL`) |
| NFR-08 | **Hacker / terminal UI theme** | JetBrains Mono font, dark bg, green-on-black palette, scanline overlay |
| NFR-09 | **Attack tool calibration** | Sends `ceil(threshold × 1.6)` requests to always exceed threshold regardless of environment |
| NFR-10 | **Apache X-Forwarded-For trust** | `mod_remoteip` loaded; `RemoteIPHeader X-Forwarded-For` set in `httpd.conf` |

---

## 2. API Contract Reference

**Base URL:** `http://localhost:3000`  
**Frontend origin:** `http://localhost:5173`  
**Content-Type:** `application/json` (unless noted)

---

### 2.1 Log Ingestion

#### `POST /log`
Receive a single Apache Combined Log Format line.

| | |
|--|--|
| **Body** | `text/plain` — one raw Apache log line |
| **Response 200** | `OK` |
| **Response 400** | `{ message: "Failed to parse log" }` |

**Log line format (Apache Combined):**
```
127.0.0.1 - - [12/Jun/2026:20:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"
```

#### `POST /log/batch`
Receive multiple log lines at once (used by `log-collector.cjs`).

| | |
|--|--|
| **Body** | `{ "lines": ["<line1>", "<line2>", ...] }` |
| **Response 200** | `OK` |

---

### 2.2 Dashboard Metrics

#### `GET /api/stats`
Returns system-wide metrics for the Dashboard page. Polled every **5 seconds** by the frontend.

**Response 200:**
```json
{
  "totalLogsAnalyzed": 7509,
  "activeBlockedIps":  3,
  "currentCpuUsage":   0.42,
  "isDosPanicMode":    false,
  "isDdosPanicMode":   true,
  "globalThreshold":   100.0,
  "trafficHistory": [
    { "time": "20:00:00", "requests": 12 },
    { "time": "20:00:05", "requests": 98 }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `totalLogsAnalyzed` | `number` | Total log entries in MongoDB |
| `activeBlockedIps` | `number` | Count of IPs in current OS firewall block rule |
| `currentCpuUsage` | `number` | CPU usage ratio `0.0–1.0` |
| `isDosPanicMode` | `boolean` | DoS panic mode active |
| `isDdosPanicMode` | `boolean` | DDoS panic mode active (`ddosDetector.isUnderAttack()`) |
| `globalThreshold` | `number` | Current effective DoS rate threshold |
| `trafficHistory` | `Array` | Rolling 60-second traffic array for the chart |

---

### 2.3 Logs Explorer

#### `GET /api/logs`
Returns the 100 most recent log entries. Polled every **5 seconds**.

**Response 200:**
```json
[
  {
    "id":         "6849ab12c3d...",
    "ip":         "10.0.0.99",
    "method":     "GET",
    "path":       "/api/user/profile",
    "statusCode": 200,
    "timestamp":  "2026-06-12T13:00:00.000Z",
    "userAgent":  "Mozilla/5.0 ..."
  }
]
```

| Field | Type | Source MongoDB field |
|-------|------|----------------------|
| `id` | `string` | `_id` |
| `ip` | `string` | `remoteIp` |
| `method` | `string` | `requestMethod` |
| `path` | `string` | `requestUrl` |
| `statusCode` | `number` | `responseStatusCode` |
| `timestamp` | `ISO string` | `time` |
| `userAgent` | `string` | `userAgent` |

---

### 2.4 Firewall Management

#### `GET /api/firewall/rules`
Returns all currently active block rules. Polled every **10 seconds**.

**Response 200:**
```json
[
  {
    "ip":        "10.0.0.99",
    "detector":  "DOS",
    "reason":    "Trust Score depleted (5)",
    "blockedAt": "2026-06-12T13:00:00.000Z",
    "trustScore": 5
  }
]
```

| `detector` value | Meaning |
|-----------------|---------|
| `"DOS"` | Blocked by DoS detector (IP profile exists) |
| `"DDOS"` | Blocked by DDoS detector event |
| `"MANUAL"` | Manually added via UI (no internal profile) |

#### `POST /api/firewall/unblock`
Unblock a single IP.

**Body:** `{ "ip": "10.0.0.99" }`  
**Response 200:** `OK`

#### `POST /api/firewall/unblock-all`
Revoke every active block rule at once.

**Body:** _(empty)_  
**Response 200:** `{ "revoked": 12 }`

#### `POST /api/firewall/block`
Manually block an IP.

**Body:** `{ "ip": "203.0.113.50", "reason": "Manual Override" }`  
**Response 200:** `OK`

---

### 2.5 Live Configuration

#### `GET /api/config`
Returns the current live threshold values.

**Response 200:**
```json
{
  "env": "development",
  "dos": {
    "WINDOW_MS":  10000,
    "THRESHOLD":  120
  },
  "ddos": {
    "GLOBAL_RATE_THRESHOLD":             100,
    "GLOBAL_RATE_WINDOW_MS":             10000,
    "COORDINATED_DISTINCT_IP_THRESHOLD": 10,
    "COORDINATED_ERROR_RATIO_THRESHOLD": 0.8,
    "SUBNET_PREFIX_LENGTH":              24,
    "SUBNET_RATE_THRESHOLD":             50,
    "SUBNET_BLOCK_BASE_TTL_MS":          60000,
    "PANIC_MODE_DURATION_MS":            60000,
    "PANIC_MODE_COOLDOWN_MS":            60000
  }
}
```

#### `PATCH /api/config`
Hot-reload threshold values at runtime. No server restart needed.

**Body** (any subset of the keys above):
```json
{ "THRESHOLD": 80, "GLOBAL_RATE_THRESHOLD": 60 }
```

**Rules:**
- All values must be positive numbers
- DoS changes applied immediately via `dosDetector.updateConfig()`
- DDoS changes take effect on next `check()` call

**Response 200:** Full updated config (same shape as `GET /api/config`)

---

### 2.6 Debug (Development Only)

#### `POST /debug/reset`
Resets all detector state, clears all block rules. Only available when `NODE_ENV=development`.

**Response 200:** `OK`

---

## 3. Backend Requirements for Frontend Connectivity

### 3.1 Required Middleware

```typescript
app.use(express.text());           // POST /log  (text/plain body)
app.use(express.json());           // all JSON endpoints
app.use(cors({ origin: 'http://localhost:5173' })); // MUST match Vite port
app.use(nocache());                // prevent browser caching
```

### 3.2 Required Service Methods

| Service | Method | Signature |
|---------|--------|-----------|
| `ConfigService` | `getAll()` | `(): LiveConfig` |
| `ConfigService` | `update(patch)` | `(Partial<LiveDosConfig & LiveDdosConfig>): LiveConfig` |
| `FirewallService` | `getBlockedIPs()` | `(): Array<{ ip: string }>` |
| `FirewallService` | `block(ip)` | `(string): Promise<void>` |
| `FirewallService` | `unblock(ip)` | `(string): Promise<void>` |
| `FirewallService` | `syncFromFirewall()` | `(): Promise<void>` |
| `DoSDetector` | `getProfile(ip)` | `(string): { trustScore: number } \| undefined` |
| `DoSDetector` | `getCPUUsage()` | `(): number` |
| `DoSDetector` | `getGlobalThreshold()` | `(): number` |
| `DoSDetector` | `updateConfig(patch)` | `({ windowMs?, baseThreshold? }): void` ← **NEW** |
| `DoSDetector` | `unblock(ip)` | `(string): void` |
| `DoSDetector` | `syncBlockedIPs(ips)` | `(string[]): void` |
| `DDoSDetector` | `isUnderAttack()` | `(): boolean` |
| `DDoSDetector` | `check(lineData)` | `(ParsedLog): void` |
| `LogService` | `getTotalCount()` | `(): Promise<number>` |
| `LogService` | `getRecentLogs(n)` | `(number): Promise<LogDocument[]>` |
| `LogService` | `getTrafficHistory()` | `(): Array<{ time: string; requests: number }>` |
| `LogService` | `add(log)` | `(ParsedLog): void` |

### 3.3 Environment Variables

```env
NODE_ENV=development        # selects ddos config block (development | production)
MONGO_URI=mongodb://localhost:27017/apache_sentinel
```

### 3.4 Startup Sequence (Order Matters)

```typescript
await dbService.connect();               // 1. DB first
await checkAdminPrivilege();             // 2. Verify admin (netsh needs elevation)
await firewallService.syncFromFirewall();// 3. Sync OS firewall → internal state
dosDetector.syncBlockedIPs(...);         // 4. Sync detector from firewall state
app.listen(port);                        // 5. Start HTTP server
```

### 3.5 Apache Log Forwarding Bridge

```
Apache httpd  →  stdout pipe  →  log-collector.cjs  →  POST /log/batch  →  backend
```

**`httpd.conf` directive:**
```apache
CustomLog "| D:/apps/NodeJS/node.exe D:/works/university/ITE15/Project-2/backend/log-collector.cjs" combined
```

`log-collector.cjs` uses only Node.js built-in `http` — no npm dependencies required.

---

## 4. Connection Setup Guide

### 4.1 Prerequisites

| Tool | Version | Check |
|------|---------|-------|
| Node.js | 18 LTS+ | `node -v` |
| MongoDB | 6.0+ | `mongod --version` |
| Apache httpd | 2.4 | `httpd -v` |
| PowerShell | 5.1+ | `$PSVersionTable` |
| **Admin privileges** | **Required** | Run terminal as Administrator |

### 4.2 Repository Structure

```
Project-2/
├── backend/
│   ├── src/
│   │   ├── server.ts          ← entry point + all routes
│   │   ├── config.json        ← threshold configuration
│   │   ├── log-collector.ts   ← stdin→batch (tsx version, dev use)
│   │   ├── detectors/
│   │   │   ├── dos.detector.ts
│   │   │   └── ddos.detector.ts
│   │   └── services/
│   │       ├── config.service.ts   ← LiveConfig singleton (NEW)
│   │       ├── firewall.service.ts
│   │       ├── Log.service.ts
│   │       ├── db.service.ts
│   │       └── notification.service.ts
│   ├── log-collector.cjs      ← plain JS pipe (used by Apache)
│   └── package.json
│
├── frontend/
│   ├── src/
│   │   ├── api/               ← axios API clients
│   │   │   ├── client.ts      ← baseURL: http://localhost:3000
│   │   │   ├── firewall.ts
│   │   │   └── config.ts
│   │   ├── hooks/             ← React Query polling hooks
│   │   │   ├── useMetrics.ts  ← polls /api/stats every 5s
│   │   │   ├── useLogs.ts     ← polls /api/logs every 5s
│   │   │   └── useFirewall.ts ← polls /api/firewall/rules every 10s
│   │   └── pages/
│   │       ├── Dashboard/     ← metrics + traffic chart + panic banner
│   │       ├── Logs/          ← log table with status/method filters
│   │       ├── Firewall/      ← quarantine list + revoke all + manual block
│   │       └── Settings/      ← live config sliders + numeric inputs
│   └── package.json
│
├── attack-tool/
│   ├── attack_tool.js         ← Node.js simulator (4 scenarios)
│   ├── attack_tool.ps1        ← PowerShell simulator (real HTTP)
│   └── README.md
│
└── update_guideline.md        ← this file
```

### 4.3 Step-by-Step Startup

```powershell
# 1. Install dependencies
cd D:\works\university\ITE15\Project-2\backend  && npm install
cd D:\works\university\ITE15\Project-2\frontend && npm install

# 2. Create .env in backend/
# NODE_ENV=development
# MONGO_URI=mongodb://localhost:27017/apache_sentinel

# 3. Start MongoDB (if not a Windows service)
mongod --dbpath C:\data\db

# 4. Start backend (AS ADMINISTRATOR)
cd D:\works\university\ITE15\Project-2\backend
npm run dev
# → ✅ MongoDB Connected
# → [Privilege] Running with Administrator privileges ✅
# → [Server] Sentinel is running on http://localhost:3000

# 5. Start frontend (separate terminal)
cd D:\works\university\ITE15\Project-2\frontend
npm run dev
# → http://localhost:5173

# 6. Restart Apache (AS ADMINISTRATOR) after httpd.conf changes
C:\Apache24\bin\httpd.exe -t   # must say "Syntax OK"
net stop Apache2.4 && net start Apache2.4
```

### 4.4 Verify the Pipeline

```powershell
# Send a test request to Apache
Invoke-WebRequest http://127.0.0.1/ -UseBasicParsing

# Backend console should show the log being processed
# Logs Explorer tab should show the entry within 5 seconds
```

---

## 5. Team Integration Guide

> **Scenario:** A team member worked on the original `apache-sentinel-backend` only. He wants to merge his backend changes with this full-stack workspace.

### 5.1 What Changed vs. Original GitHub Repository

| Area | Original (`apache-sentinel-backend`) | New Workspace |
|------|--------------------------------------|---------------|
| Frontend | ❌ None | ✅ React + Vite SPA |
| Config hot-reload | ❌ Static import at startup | ✅ `ConfigService` singleton + `PATCH /api/config` |
| `DoSDetector` | No `updateConfig()` | ✅ `updateConfig({ windowMs, baseThreshold })` |
| `DDoSDetector` | Reads config at construction | ✅ Reads `configService.ddos` on every `check()` |
| `/api/config` | ❌ Missing | ✅ `GET` + `PATCH` |
| `/api/firewall/unblock-all` | ❌ Missing | ✅ `POST /api/firewall/unblock-all` |
| Log collector | `log-collector.ts` (tsx required) | ✅ `log-collector.cjs` (plain Node.js, no tsx) |
| `httpd.conf` pipe target | Old `dist/log-collector.js` path | ✅ New `backend/log-collector.cjs` |
| Attack tool | Basic JS tests in `/tests` | ✅ Full simulator in `/attack-tool` |

### 5.2 Files Your Team Member Must Not Overwrite

> [!WARNING]
> These files have been significantly modified from the original. If your team member has changes to these, do a **manual diff** and merge carefully — do NOT blindly overwrite.

- `backend/src/server.ts` — has 9 new API routes
- `backend/src/detectors/dos.detector.ts` — has `updateConfig()` method
- `backend/src/detectors/ddos.detector.ts` — reads config via `cfg()` getter
- `C:/Apache24/conf/httpd.conf` — `CustomLog` directive path changed

### 5.3 New Files to Copy In

> [!IMPORTANT]
> These files are **brand new** and must be added from this workspace:

```
backend/src/services/config.service.ts   ← NEW: live config singleton
backend/log-collector.cjs               ← NEW: plain JS Apache pipe
frontend/                               ← NEW: entire frontend
attack-tool/                            ← NEW: attack simulator
```

### 5.4 Code Changes Required in Existing Files

#### `dos.detector.ts` — Add `updateConfig()` method

```typescript
updateConfig(patch: { windowMs?: number; baseThreshold?: number }) {
  if (patch.windowMs      !== undefined) this.windowMs      = patch.windowMs;
  if (patch.baseThreshold !== undefined) this.baseThreshold = patch.baseThreshold;
  this.ipProfiles.clear(); // apply immediately
  console.info('[DoS] Config updated:', patch);
}
```

#### `ddos.detector.ts` — Replace static config references

```typescript
// Import at top of file:
import { configService } from '../services/config.service';

// Add getter inside class:
private get cfg() { return configService.ddos; }

// Replace all static config usages:
// OLD: this.GLOBAL_RATE_THRESHOLD
// NEW: this.cfg.GLOBAL_RATE_THRESHOLD
```

#### `server.ts` — Add 3 new routes

Copy these from this workspace's `server.ts`:

```typescript
// After existing /api/firewall/unblock route:
app.post('/api/firewall/unblock-all', async (req, res) => { ... });

// At the end of the API routes section:
app.get('/api/config',   (_req, res) => res.json(configService.getAll()));
app.patch('/api/config', (req, res)  => { ... }); // hot-reload with validation
```

And add the import:
```typescript
import { configService } from './services/config.service';
```

### 5.5 Merge Checklist

```
[ ] Copied frontend/ into Project-2/
[ ] Copied attack-tool/ into Project-2/
[ ] Copied backend/log-collector.cjs
[ ] Copied backend/src/services/config.service.ts
[ ] Updated dos.detector.ts with updateConfig() method
[ ] Updated ddos.detector.ts to use cfg() getter from configService
[ ] Added 3 new routes to server.ts (unblock-all, GET/PATCH /api/config)
[ ] Added ConfigService import to server.ts
[ ] Updated httpd.conf CustomLog to point to log-collector.cjs
[ ] Ran `npm install` in both backend/ and frontend/
[ ] Verified Apache config syntax: httpd.exe -t
[ ] Restarted Apache as Administrator
[ ] Started backend as Administrator — saw "✅ MongoDB Connected"
[ ] Opened http://localhost:5173 — all 4 tabs load
[ ] Ran attack tool option [1] — saw DoS alert in backend console
```

### 5.6 Common Integration Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `CORS policy blocked` | Backend missing CORS | Add `app.use(cors({ origin: 'http://localhost:5173' }))` |
| `Cannot GET /api/config` | Route not added | Copy route from this `server.ts` |
| Dashboard shows `Failed to connect` | Backend on wrong port | Verify port 3000; check `frontend/src/api/client.ts` baseURL |
| Attack tool shows all `t` (timeout) | Apache not running or pipe broken | Verify `httpd.conf`, restart Apache as admin |
| Settings save does nothing | `PATCH /api/config` missing or ConfigService not imported | Add route; verify import |
| Revoke All does nothing | `unblockAll` not in hook or API | Copy new `useFirewall.ts` and `api/firewall.ts` |
| Logs never appear | Log collector pipe broken | Run: `echo 'test log line' \| node backend/log-collector.cjs` |
| `entry.ip is undefined` | `getBlockedIPs()` returns `string[]` not objects | In `unblock-all`: `for (const ip of blocked)` instead of `entry.ip` |
| `[Privilege] NOT running as Administrator` | Backend started without admin | Re-run terminal as Administrator |

### 5.7 Port & URL Reference

| Service | URL | Notes |
|---------|-----|-------|
| Backend API | `http://localhost:3000` | Express server |
| Frontend UI | `http://localhost:5173` | Vite dev server |
| Apache | `http://127.0.0.1:80` | Attack tool target |
| MongoDB | `mongodb://localhost:27017` | Default; override via `.env` |

---

*Generated from live codebase — Apache Sentinel, June 2026.*
