# Firewall Integration

## Overview

Apache Sentinel integrates with **Windows Firewall** (netsh advfirewall) to block malicious IPs at the OS level. All blocked IPs are enforced by the firewall, not just at the application level.

## Architecture

```
┌─────────────────────────┐
│  DoS/DDoS Detectors     │
│  (Application Layer)    │
└───────────┬─────────────┘
            │ events
            ▼
┌─────────────────────────┐
│  Firewall Service      │
│  (manages block list)   │
└───────────┬─────────────┘
            │ netsh commands
            ▼
┌─────────────────────────┐
│  Windows Firewall       │
│  (OS Level)             │
└─────────────────────────┘
```

## Windows Firewall Rule

All blocked IPs are managed under a single rule:

- **Name**: `Apache-Sentinel-Block-List`
- **Direction**: Inbound
- **Action**: Block
- **Protocol**: Any
- **RemoteIP**: Comma-separated list of blocked IPs/subnets

## Core Operations

### Block IP

```typescript
await firewallService.block('192.168.1.100');
```

Process:
1. Add IP to internal `blockedIPs` Set
2. Call `syncRule()` to update firewall

Netsh command created:
```
netsh advfirewall firewall add rule name="Apache-Sentinel-Block-List" dir=in action=block protocol=any remoteip=192.168.1.100
```

### Unblock IP

```typescript
await firewallService.unblock('192.168.1.100');
```

Process:
1. Remove IP from internal Set
2. Call `syncRule()` to update firewall

Netsh command created:
```
netsh advfirewall firewall set rule name="Apache-Sentinel-Block-List" new remoteip=<remaining-ips>
```

If no IPs remain, rule is deleted:
```
netsh advfirewall firewall delete rule name="Apache-Sentinel-Block-List"
```

### Block Subnet

```typescript
await firewallService.blockSubnet('192.168.1.0/24');
```

Process:
1. Calculate exponential backoff TTL
2. Add subnet to blocked set
3. Schedule auto-unblock after TTL

### Check if Blocked

```typescript
const isBlocked = firewallService.isBlocked('192.168.1.100');
```

### Get All Blocked IPs

```typescript
const blocked = firewallService.getBlockedIPs();
```

## Sync on Startup

When server starts, it synchronizes with existing firewall rules:

```typescript
await firewallService.syncFromFirewall();
```

Process:
1. Query existing rule via `netsh advfirewall firewall show rule`
2. Parse RemoteIP list
3. Populate internal `blockedIPs` Set

This ensures blocked IPs persist across server restarts.

## Race Condition Prevention

Multiple detectors may trigger blocks simultaneously. The service uses a **Mutex** to prevent race conditions:

```typescript
private syncMutex = new Mutex();

private async syncRuleSafe(): Promise<void> {
    const unlock = await this.syncMutex.lock();
    try {
        await this.syncRule();
    } finally {
        unlock();
    }
}
```

## Subnet TTL (Time-To-Live)

Subnets are blocked temporarily with exponential backoff:

| Offense | TTL |
|--------|-----|
| 1st | 15 minutes |
| 2nd | 1 hour |
| 3rd | 4 hours |
| 4th | 16 hours |
| 5th+ | 24 hours (max) |

Implementation:

```typescript
const baseTtl = 900000; // 15 min
const multiplier = Math.pow(4, history.count - 1);
const ttlMs = Math.min(baseTtl * multiplier, 86400000);

// Schedule auto-unblock
setTimeout(() => {
    this.unblockSubnet(cidr);
}, ttlMs);
```

## Offense History

Tracks subnet offenses for exponential backoff:

```typescript
// Purged every 48 hours
if (now - history.lastBlocked > 172800000) {
    history.count = 0;
}
```

## Admin Privilege Check

Firewall operations require **Administrator** privileges. Server checks on startup:

```typescript
await checkAdminPrivilege();
```

If not admin, server logs warning but continues (firewall operations will fail).

## Event Listeners

Server connects detector events to firewall:

```typescript
// DoS - individual IP block
dosDetector.on('dos-block-ip', async (ip) => {
    await firewallService.block(ip);
});

// DDoS - IP block
ddosDetector.on('ddos-block-ip', async (ip) => {
    await firewallService.block(ip);
});

// DDoS - subnet block
ddosDetector.on('ddos-block-subnet', async (subnet) => {
    await firewallService.blockSubnet(subnet);
});
```

## Manual Operations

### Manual Block via API

```bash
POST /api/firewall/block
{ "ip": "192.168.1.100" }
```

### Manual Unblock via API

```bash
POST /api/firewall/unblock
{ "ip": "192.168.1.100" }
```

### Unblock All

```bash
POST /api/firewall/unblock-all
```

## Troubleshooting

### View Firewall Rule

```powershell
netsh advfirewall firewall show rule name="Apache-Sentinel-Block-List"
```

### Delete Rule Manually

```powershell
netsh advfirewall firewall delete rule name="Apache-Sentinel-Block-List"
```

### Check Admin Rights

Run PowerShell as Administrator, then start the server.

## Configuration

No specific config needed - uses Windows Firewall directly. Ensure:
- Server runs as Administrator
- Windows Firewall is enabled