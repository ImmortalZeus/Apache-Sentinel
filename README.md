# Apache Sentinel

Real-time DoS/DDoS detection and blocking system for Apache HTTP Server on
Windows. Reads Apache Combined Log Format access logs, applies a per-IP
trust-score DoS detector and a three-strategy DDoS detector, and pushes
block decisions to the OS firewall via `netsh advfirewall`.

> **Project 2 — Hanoi University of Science and Technology, ITE Faculty.**
> Single-server Windows deployment. Backend in TypeScript (Node.js +
> Express), frontend in React + Vite, persistent storage in MongoDB.

---

## Repository layout

```
Code/
├── backend/                 # Node.js + Express + TypeScript API server
├── frontend/                # React 19 + Vite + TypeScript dashboard
├── attack-tool/             # Test harness and load generator (see below)
```

`backend/` and `frontend/` are independent submodules — each has its
own dependency lockfile, build pipeline, and `npm` scripts. Build them
independently.

---

## Architecture at a glance

```
Apache HTTP Server
       │  (CustomLog pipe — Combined Log Format)
       ▼
log-collector.ts (Node child process)
       │  POST /log
       ▼
Express server (server.ts)
       │
       ├──► DoSDetector          per-IP trust score + weighted 3-window anomaly
       ├──► DDoSDetector         global rate / coordinated pattern / subnet volume
       │           │
       │           └──► event: dos-block-ip | ddos-block-ip | ddos-block-subnet
       │                       │
       │                       ▼
       │                FirewallService  ── netsh advfirewall (single rule, /24 CIDR)
       │                       │
       │                       ▼
       │                NotificationService (Windows toast via node-notifier)
       │
       ├──► LogService            batched insertMany → MongoDB (every 5 s)
       ├──► AuthService           JWT in httpOnly cookies, bcrypt
       └──► REST API              /api/stats, /api/logs, /api/firewall/*, /api/config
                ▲
                │  (axios + React Query, JWT cookie)
                │
       React dashboard  (Dashboard / Logs / Firewall / Settings / Login)
```

---

## Prerequisites

| Component | Version |
|---|---|
| OS | Windows 10/11 or Windows Server 2016+ |
| Apache HTTP Server | 2.4.x (2.4.66 verified) |
| Node.js | 18 LTS or newer (24.15 verified) |
| MongoDB | Community Edition, default port 27017 |
| PowerShell | 5.1+ (used for the admin-privilege check) |

Administrator privileges are required for the backend process because
`netsh advfirefirewall` calls need elevation. The server refuses to
start without it.

---

## Quick start (development)

### 1. Start MongoDB

```powershell
net start MongoDB
# Or run mongod manually: mongod --dbpath D:/mongo-data
```

### 2. Start the backend

Open **PowerShell as Administrator**:

```powershell
cd backend
npm install
npm run dev
```

Wait for `[Server] Sentinel is running on http://localhost:3000`.

### 3. Start the frontend

In a regular terminal:

```powershell
cd frontend
npm install
npm run dev
```

Vite serves the dashboard at `http://localhost:5173`.

### 4. Log in

```
URL:      http://localhost:5173
Username: admin
Password: admin
```

Change the password immediately after first login in any deployment
beyond local development.

---

## Apache integration

Apache must forward access logs to the backend's `log-collector.ts`
via a `CustomLog` pipe. Add this to `httpd.conf`:

```apache
CustomLog "|C:/Program Files/nodejs/node.exe D:/apache-sentinel/backend/dist/log-collector.js" combined
```

Adjust the path to match your installation, then restart Apache.

For a step-by-step Windows setup walkthrough, see
[`backend/docs/apache-setup-guide.md`](backend/docs/apache-setup-guide.md).

---

## Configuration

The backend reads `backend/src/config.json`. Hot-reloadable via
`PATCH /api/config` from the Settings page — no restart needed.

Key parameters:

| Parameter | Default (dev) | Meaning |
|---|---|---|
| `dos.WINDOW_MS` | 10000 | Per-IP sliding window |
| `dos.THRESHOLD` | 120 | Per-IP block threshold (requests per window) |
| `ddos.development.GLOBAL_RATE_THRESHOLD` | 100 | Global flood trigger |
| `ddos.development.COORDINATED_DISTINCT_IP_THRESHOLD` | 10 | Bot swarm trigger |
| `ddos.development.COORDINATED_ERROR_RATIO_THRESHOLD` | 0.8 | Bot-vs-flash-crowd boundary |
| `ddos.development.SUBNET_RATE_THRESHOLD` | 50 | Subnet block trigger |
| `ddos.development.PANIC_MODE_DURATION_MS` | 60000 | Panic Mode duration |

Production preset values are larger (e.g. `GLOBAL_RATE_THRESHOLD = 800`,
`PANIC_MODE_DURATION_MS = 900000`); switch via `NODE_ENV=production`.

---

## Test harness

The `attack-tool/` folder contains the automated test suite:

```powershell
# Backend must be running in Development mode
node attack-tool/test_suite.js > test_run.log 2>&1
node attack-tool/latency_tester.js > latency_run.log 2>&1
```

| Tool | Purpose |
|---|---|
| `attack-tool/test_suite.js` | 24 functional test cases (DoS detection, DDoS detection, defense response, integration). Boundary value analysis on every threshold. |
| `attack-tool/latency_tester.js` | Concurrency sweep (1, 10, 50, 100) over 5000 requests/level. Reports mean / P50 / P95 / P99 / max latency. |
| `attack-tool/attack_tool.js` | Interactive Node-based attack simulator. Bypasses Apache, injects directly into `POST /log`. |
| `attack-tool/attack_tool.ps1` | PowerShell HTTP flood against Apache with spoofed `X-Forwarded-For` headers. |

Test output is JSON-delimited (`[JSON_RESULTS_BEGIN]` / `[JSON_RESULTS_END]`)
for easy parsing into the report.

---