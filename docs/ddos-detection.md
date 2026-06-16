# DDoS Detection

## Overview

The DDoS detector protects against distributed attacks from multiple IPs. Unlike DoS (single source), DDoS attacks involve many sources making coordinated requests. The detector uses **three strategies** working together:

1. **Global Volumetric** - Detects total server overload
2. **Coordinated Botnet** - Detects attacking patterns per URL
3. **Subnet Blocking** - Blocks entire /24 subnets when needed

## Strategy 1: Global Volumetric Flood

Detects when total requests across all IPs exceed a threshold.

```
Incoming Request
       │
       ▼
┌──────────────────────────┐
│ Add timestamp to         │
│ globalTimestamps[]       │
└──────────────────────────┘
       │
       ▼
┌──────────────────────────┐
│ Remove timestamps older  │
│ than GLOBAL_RATE_WINDOW  │
└──────────────────────────┘
       │
       ▼
globalTimestamps.length > GLOBAL_RATE_THRESHOLD?
       │
  ┌────┴────┐
  │yes      │no
  ▼         ▼
TRIGGER    Continue
PANIC MODE
```

**Configuration:**
- `GLOBAL_RATE_WINDOW_MS`: Sliding window (default: 2000ms)
- `GLOBAL_RATE_THRESHOLD`: Requests in window to trigger (default: 500)

## Strategy 2: Coordinated Botnet

Detects when a single URL receives requests from many distinct IPs with high error rate (distinguishes botnets from flash crowds).

```
Request to /api/resource from IP
       │
       ▼
┌──────────────────────────┐
│ Normalize URL             │
│ /api/resource?id=123     │
│     → /api/resource       │
└──────────────────────────┘
       │
       ▼
┌──────────────────────────┐
│ Track per-URL:           │
│ - timestamps[]           │
│ - errorTimestamps[]      │
│ - ipLastSeen (Map)       │
└──────────────────────────┘
       │
       ▼
distinct IPs > COORDINATED_DISTINCT_IP_THRESHOLD?
       │
  ┌────┴────┐
  │yes      │no
  ▼         ▼
Calc error  Continue
ratio
  │
  ▼
errorRatio >= 0.8 (80%)?
  │
 ┌─┴─┐
 │yes│no
 ▼   ▼
BLOCK Flash
ALL IPs crowd
```

**Key Insight**: Flash crowds (legitimate high traffic) have low error rates. Botnets generating attack traffic often get high error rates (targeted URLs don't exist, etc.)

**Configuration:**
- `COORDINATED_DISTINCT_IP_THRESHOLD`: IPs to trigger (default: 10)
- `COORDINATED_ERROR_RATIO_THRESHOLD`: 0.8 (80%)

## Strategy 3: Subnet Blocking

Blocks entire /24 subnets when traffic exceeds thresholds.

```
Incoming Request from 192.168.1.50
       │
       ▼
┌──────────────────────────┐
│ Extract subnet:          │
│ 192.168.1.0/24          │
└──────────────────────────┘
       │
       ▼
┌──────────────────────────┐
│ Track per-subnet:        │
│ - timestamps[]           │
│ - ipLastSeen (Map)       │
└──────────────────────────┘
       │
       ▼
timestamps > SUBNET_RATE_THRESHOLD
  AND
distinct IPs >= SUBNET_DISTINCT_IP_THRESHOLD?
       │
  ┌────┴────┐
  │yes      │no
  ▼         ▼
BLOCK    Continue
SUBNET
```

**TTL-based Auto-Unblock:**
- First offense: 15 minutes
- Second offense: 1 hour
- Third offense: 4 hours
- Fourth offense: 16 hours
- Max: 24 hours

**Configuration:**
- `SUBNET_RATE_THRESHOLD`: Requests to trigger (default: 100)
- `SUBNET_DISTINCT_IP_THRESHOLD`: Minimum unique IPs (default: 5)
- `SUBNET_PREFIX_LENGTH`: 24 (IPv4 /24)
- `SUBNET_BLOCK_BASE_TTL_MS`: 900000 (15 min)

## Panic Mode

When Global Volumetric Flood is detected, system enters **Panic Mode**:

### Effects

1. **Load Shedding**: Heavy API endpoints return 503
   - `/api/stats` disabled
   - `/api/export` disabled  
   - `/api/search` disabled

2. **Aggressive DoS Thresholds**: DoS detector uses stricter thresholds
   - Trusted IPs: 80% of base threshold
   - Others: 20% of base threshold

3. **Reduced Global Threshold**: DoS global threshold * 0.7

### Duration

- `PANIC_MODE_DURATION_MS`: Default 5 minutes
- `PANIC_MODE_COOLDOWN_MS`: Default 5 minutes (prevents rapid re-trigger)

## Event Flow

```
Incoming Log
     │
     ├──────────────────┐
     ▼                  ▼
checkGlobalRate()  checkCoordinatedPattern()
     │                  │
     │            (if triggers)
     │                  ▼
     │            Block all IPs
     │            emit('ddos-block-ip', ip)
     │                  │
     ▼                  ▼
checkSubnetVolume()
     │
     (if triggers)
     ▼
Block subnet
emit('ddos-block-subnet', subnet)
```

## Events

| Event | Description |
|-------|--------------|
| `ddos-block-ip` | Block single IP |
| `ddos-block-subnet` | Block /24 subnet |
| `ddos-unblock-ip` | Unblock IP (manual) |
| `ddos-unblock-subnet` | Unblock subnet (manual) |

## Server Integration

```typescript
// Block individual IPs
ddosDetector.on('ddos-block-ip', async (ip) => {
    await firewallService.block(ip);
});

// Block subnets
ddosDetector.on('ddos-block-subnet', async (subnet) => {
    await firewallService.blockSubnet(subnet);
});

// Load shedding middleware
app.use((req, res, next) => {
    if (ddosDetector.isUnderAttack()) {
        const heavyPaths = ['/api/stats', '/api/export', '/api/search'];
        if (heavyPaths.some(p => req.path.startsWith(p))) {
            res.status(503).send({ message: "Panic Mode" });
            return;
        }
    }
    next();
});
```

## Detection Comparison

| Strategy | Target | Trigger | Mitigation |
|----------|--------|---------|-------------|
| Global Volumetric | Total server | >500 req/2s | Panic mode |
| Coordinated Botnet | Per-URL | >10 IPs + 80% errors | Block IPs |
| Subnet | Subnet /24 | >100 req + 5 IPs | Block subnet (TTL) |

## Configuration Summary

| Parameter | Default | Description |
|-----------|---------|-------------|
| `GLOBAL_RATE_WINDOW_MS` | 2000 | Global sliding window |
| `GLOBAL_RATE_THRESHOLD` | 500 | Global trigger threshold |
| `COORDINATED_DISTINCT_IP_THRESHOLD` | 10 | IPs per URL to trigger |
| `COORDINATED_ERROR_RATIO_THRESHOLD` | 0.8 | Error ratio for botnet |
| `SUBNET_RATE_THRESHOLD` | 100 | Requests per subnet |
| `SUBNET_DISTINCT_IP_THRESHOLD` | 5 | Unique IPs per subnet |
| `PANIC_MODE_DURATION_MS` | 300000 | 5 minutes |
| `SUBNET_BLOCK_BASE_TTL_MS` | 900000 | 15 minutes |