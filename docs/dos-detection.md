# DoS Detection

## Overview

The DoS (Denial of Service) detector protects against individual IPs flooding the server. It uses a **trust score system** that tracks each IP's behavior over time and blocks malicious actors when their trust score drops below a threshold.

## Trust Score System

Each IP has a profile with:
- **Trust Score**: Starts at 50, ranges 0-100
- **Request Timestamps**: Recent request times for rate analysis
- **Per-IP Threshold**: Dynamically adjusted based on behavior
- **Blocked Status**: Whether the IP is currently blocked

### Trust Score Rules

| Score Range | Behavior |
|------------|----------|
| 70-100 | Trusted - higher request threshold |
| 40-69 | Neutral - normal threshold |
| 20-39 | Suspicious - lowered threshold |
| 0-19 | Blocked - requests denied |

### Score Adjustments

- **Penalty**: -15 points per anomalous request (high request rate)
- **Reward**: +1 point per normal request (reward for good behavior)

## Request Processing Flow

```
Incoming Request (IP)
         │
         ▼
┌─────────────────────┐
│ Check if IP blocked │──yes──► Skip processing
└─────────────────────┘
         │ no
         ▼
┌─────────────────────┐
│ Record timestamp    │
│ Update lastSeen     │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ Calculate threshold  │◄── Based on trust score + CPU
│ (calcEffectiveThreshold)
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ Calculate anomaly    │
│ score (0.0 - 1.0)   │
└─────────────────────┘
         │
         ▼
    anomalyScore >= 0.7?
         │
    ┌────┴────┐
    │yes      │no
    ▼         ▼
- Trust drops   Request
- Threshold    allowed
  lowers
    │
    ▼
trustScore < 20?
    │
┌──┴──┐
│yes  │no
▼     ▼
BLOCK continue
```

## Anomaly Score Calculation

Uses a weighted sliding window across 3 time periods:

```
Window 0 (last 10s): weight 0.5
Window 1 (10-20s):  weight 0.3  
Window 2 (20-30s): weight 0.2
```

Formula:
```
anomalyScore = ratio0 * 0.5 + ratio1 * 0.3 + ratio2 * 0.2
```
Where `ratio` = actual requests / threshold (capped at 1.0)

## CPU-Aware Thresholds

The detector adjusts thresholds based on server CPU usage:

| CPU Level | Threshold Adjustment |
|-----------|---------------------|
| >90% critical | Base * 0.2 |
| >80% high | Base * 0.9 |
| 30-80% normal | Base * 1.0 |
| <30% low | Base + auto-increase |

## Configuration

All configurable via `config.json` or API:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `WINDOW_MS` | 10,000 | Sliding window size (10s) |
| `THRESHOLD` | 100 | Base requests per window |
| `initialTrustScore` | 50 | Starting trust for new IPs |
| `trustPenaltyOnAnomaly` | 15 | Points lost per anomaly |
| `trustRewardOnNormal` | 1 | Points gained per normal request |
| `blockTrustThreshold` | 20 | Trust score to trigger block |
| `inactiveTimeoutMs` | 30 min | Remove IP after inactivity |

Hot-reload via `PATCH /api/config`.

## Events

| Event | Description |
|-------|--------------|
| `dos-block-ip` | Emitted when IP is blocked |
| `dos-unblock-ip` | Emitted when IP is unblocked |

## Integration

Server listens for events:
```typescript
dosDetector.on('dos-block-ip', async (ip) => {
    await firewallService.block(ip);
    notificationService.notify(ip);
});
```

## Debugging

Check IP profile:
```typescript
const profile = dosDetector.getProfile('192.168.1.1');
console.log(profile.trustScore, profile.isBlocked);
```

View all blocked IPs:
```typescript
const blocked = firewallService.getBlockedIPs();
```