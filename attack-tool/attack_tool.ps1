# =============================================================
# Apache Sentinel - Attack Simulator (PowerShell, config-aware)
# Fires real HTTP requests with spoofed X-Forwarded-For headers
# directly against Apache. Requires Apache running on targetUrl.
# Fetches live thresholds from /api/config so counts always fire.
# =============================================================

# --- Connection params ----------------------------------------
$script:backendUrl = "http://localhost:3000"
$script:targetUrl  = "http://127.0.0.1"
$script:delayMs    = 0

# --- Computed attack counts (set by Get-LiveConfig) -----------
$script:t_dos_count    = 0
$script:t_global_count = 0
$script:t_botnet_count = 0
$script:t_subnet_count = 0

# Headroom: sends = ceil(threshold * HEADROOM)
$HEADROOM = 1.6

# --- Fallback dev defaults (used if backend unreachable) ------
$script:dosThreshold    = 120
$script:globalThreshold = 100
$script:botnetThreshold = 10
$script:botnetErrRatio  = 0.8
$script:subnetThreshold = 50
$script:subnetTTL       = 60000
$script:panicDuration   = 60000
$script:panicCooldown   = 60000
$script:envName         = "development (fallback)"

# =============================================================
# Fetch live config from backend
# =============================================================
function Get-LiveConfig {
    try {
        $r = Invoke-RestMethod -Uri "$script:backendUrl/api/config" `
                -Method Get -TimeoutSec 4 -ErrorAction Stop

        $script:dosThreshold    = $r.dos.THRESHOLD
        $script:globalThreshold = $r.ddos.GLOBAL_RATE_THRESHOLD
        $script:botnetThreshold = $r.ddos.COORDINATED_DISTINCT_IP_THRESHOLD
        $script:botnetErrRatio  = $r.ddos.COORDINATED_ERROR_RATIO_THRESHOLD
        $script:subnetThreshold = $r.ddos.SUBNET_RATE_THRESHOLD
        $script:subnetTTL       = $r.ddos.SUBNET_BLOCK_BASE_TTL_MS
        $script:panicDuration   = $r.ddos.PANIC_MODE_DURATION_MS
        $script:panicCooldown   = $r.ddos.PANIC_MODE_COOLDOWN_MS
        $script:envName         = $r.env

        Write-Host "  Connected to backend. Environment: $($r.env)" -ForegroundColor Green
    }
    catch {
        Write-Host "  WARNING: Cannot reach $script:backendUrl/api/config" -ForegroundColor Yellow
        Write-Host "  Using hardcoded development defaults." -ForegroundColor Yellow
    }

    $script:t_dos_count    = [int][Math]::Ceiling($script:dosThreshold    * 2.0)
    $script:t_global_count = [int][Math]::Ceiling($script:globalThreshold * $HEADROOM)
    $script:t_botnet_count = [int][Math]::Ceiling($script:botnetThreshold * $HEADROOM)
    $script:t_subnet_count = [int][Math]::Ceiling($script:subnetThreshold * $HEADROOM)
}

# =============================================================
# Calibration table
# =============================================================
function Show-CalibrationTable {
    Write-Host ""
    Write-Host "  CALIBRATION TABLE  -  live thresholds vs attack volumes" -ForegroundColor Cyan
    Write-Host "  Environment: $script:envName" -ForegroundColor DarkGray
    Write-Host "  ------------------------------------------------------------------"
    Write-Host "  Test    Parameter                         Threshold   Sends   Margin"
    Write-Host "  ------------------------------------------------------------------"

    $rows = @(
        @("T4 [1]", "dos  THRESHOLD",                $script:dosThreshold,    $script:t_dos_count),
        @("T1 [2]", "ddos GLOBAL_RATE_THRESHOLD",    $script:globalThreshold, $script:t_global_count),
        @("T2 [3]", "ddos COORDINATED_IP_THRESHOLD", $script:botnetThreshold, $script:t_botnet_count),
        @("T3 [4]", "ddos SUBNET_RATE_THRESHOLD",    $script:subnetThreshold, $script:t_subnet_count)
    )

    foreach ($row in $rows) {
        $test      = $row[0].PadRight(8)
        $param     = $row[1].PadRight(36)
        $threshold = "$($row[2])".PadLeft(9)
        $sends     = "$($row[3])".PadLeft(7)
        $pct       = [int](($row[3] / $row[2] - 1) * 100)
        $margin    = "+$pct%".PadLeft(7)
        $ok        = if ($row[3] -gt $row[2]) { "OK" } else { "FAIL" }
        $color     = if ($row[3] -gt $row[2]) { "Green" } else { "Red" }
        Write-Host "  $test $param $threshold $sends $margin  $ok" -ForegroundColor $color
    }

    Write-Host "  ------------------------------------------------------------------"
    Write-Host "  All OK  =>  every test WILL trigger detection" -ForegroundColor Green
    Write-Host ""
}

# =============================================================
# Intro banner
# =============================================================
function Show-Intro {
    Clear-Host
    Write-Host ""
    Write-Host "    Apache Sentinel - Attack Simulator  (PS, config-aware)" -ForegroundColor Yellow
    Write-Host "    ========================================================" -ForegroundColor DarkGray
    Write-Host "    Fires real HTTP with spoofed X-Forwarded-For headers." -ForegroundColor White
    Write-Host "    Requires Apache running and forwarding logs to backend." -ForegroundColor White
    Write-Host "    ========================================================" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    Fetching thresholds from $script:backendUrl/api/config ..."
    Write-Host ""
    Get-LiveConfig
    Show-CalibrationTable
}

# =============================================================
# Random IP helper
# =============================================================
function Get-RandomIP {
    $a = Get-Random -Minimum 1 -Maximum 254
    $b = Get-Random -Minimum 1 -Maximum 254
    $c = Get-Random -Minimum 1 -Maximum 254
    $d = Get-Random -Minimum 1 -Maximum 254
    return "$a.$b.$c.$d"
}

# =============================================================
# HTTP sender  (Invoke-WebRequest, 5-second timeout)
# Gives Apache enough time to write the log line and the
# backend enough time to process it before the next request.
# =============================================================
function Send-Fast {
    param(
        [string]$Url,
        [string]$FakeIp = ""
    )
    try {
        $headers = @{}
        if ($FakeIp -ne "") {
            $headers["X-Forwarded-For"] = $FakeIp
        }
        $resp = Invoke-WebRequest -Uri $Url `
            -Headers $headers `
            -UseBasicParsing `
            -TimeoutSec 5 `
            -ErrorAction SilentlyContinue
        return "ok"
    }
    catch [System.Net.WebException] {
        # 4xx / 5xx still count as a delivered request
        if ($null -ne $_.Exception.Response) {
            return "err"
        }
        return "timeout"
    }
    catch {
        return "timeout"
    }
}

# =============================================================
# Scenario 0 - Normal Traffic
# =============================================================
function Send-Normal {
    Write-Host ""
    Write-Host "  Normal Traffic - 20 legit requests, 500 ms delay" -ForegroundColor Green
    for ($i = 1; $i -le 20; $i++) {
        $result = Send-Fast -Url "$script:targetUrl/"
        if ($result -eq "ok") { Write-Host -NoNewline "." } else { Write-Host -NoNewline "!" }
        Start-Sleep -Milliseconds 500
    }
    Write-Host ""
    Write-Host "  Done."
}

# =============================================================
# Scenario 1 - Per-IP HTTP Flood  (DoS)
# =============================================================
function Send-HTTPFlood {
    $count = $script:t_dos_count
    $thr   = $script:dosThreshold

    Write-Host ""
    Write-Host "  [1] Per-IP HTTP Flood (DoS)" -ForegroundColor Yellow
    Write-Host "      Sends : $count requests from this machine (single real IP)"
    Write-Host "      Target: dos.THRESHOLD = $thr req/window  ->  sends $count  (+$([int](($count/$thr-1)*100))%)"
    Write-Host "      Expect: trust 50->35->20->5  ->  IP BLOCKED by firewall"
    Write-Host ""

    for ($i = 1; $i -le $count; $i++) {
        $randStr = -join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
        $url     = "$script:targetUrl/?q=$randStr"
        $result  = Send-Fast -Url $url
        if ($result -eq "ok")      { Write-Host -NoNewline "." }
        elseif ($result -eq "err") { Write-Host -NoNewline "!" }
        else                       { Write-Host -NoNewline "t" }
        if ($i % 80 -eq 0)        { Write-Host "" }
        if ($script:delayMs -gt 0) { Start-Sleep -Milliseconds $script:delayMs }
    }
    Write-Host ""
    Write-Host "  Done. Watch backend for: [DoS] BLOCKED"
}

# =============================================================
# Scenario 2 - Global Volumetric Flood  (DDoS Stage 1)
# =============================================================
function Send-GlobalFlood {
    $count  = $script:t_global_count
    $thr    = $script:globalThreshold
    $reqPer = 3
    $numIPs = [int][Math]::Ceiling($count / $reqPer)

    Write-Host ""
    Write-Host "  [2] Global Volumetric Flood (DDoS Stage 1)" -ForegroundColor Red
    Write-Host "      Sends : $count requests from $numIPs spoofed IPs ($reqPer req/IP)"
    Write-Host "      Target: GLOBAL_RATE_THRESHOLD = $thr  ->  sends $count  (+$([int](($count/$thr-1)*100))%)"
    Write-Host "      Expect: PANIC MODE activated"
    Write-Host ""

    $sent = 0
    for ($ip_i = 0; ($ip_i -lt $numIPs) -and ($sent -lt $count); $ip_i++) {
        $fakeIp = Get-RandomIP
        for ($j = 0; ($j -lt $reqPer) -and ($sent -lt $count); $j++) {
            $result = Send-Fast -Url "$script:targetUrl/" -FakeIp $fakeIp
            if ($result -eq "ok")      { Write-Host -NoNewline "G" }
            elseif ($result -eq "err") { Write-Host -NoNewline "g" }
            else                       { Write-Host -NoNewline "t" }
            $sent++
            if ($sent % 80 -eq 0)     { Write-Host "" }
            if ($script:delayMs -gt 0) { Start-Sleep -Milliseconds $script:delayMs }
        }
    }
    Write-Host ""
    Write-Host "  Done. Watch backend for: [DDoS ALERT] Global Volumetric Flood"
}

# =============================================================
# Scenario 3 - Coordinated Botnet  (DDoS Stage 2)
# =============================================================
function Send-CoordinatedBotnet {
    $count     = $script:t_botnet_count
    $thr       = $script:botnetThreshold
    $errTarget = $script:botnetErrRatio + 0.05
    $errCount  = [int][Math]::Ceiling($count * $errTarget)
    $actualPct = [int]($errCount / $count * 100)
    $threshPct = [int]($script:botnetErrRatio * 100)

    Write-Host ""
    Write-Host "  [3] Coordinated Botnet (DDoS Stage 2)" -ForegroundColor Magenta
    Write-Host "      Sends : $count distinct IPs -> /non-existent-login-path"
    Write-Host "      IPs   : $count  >  threshold $thr  (+$([int](($count/$thr-1)*100))%)"
    Write-Host "      Errors: $errCount/$count = $actualPct%  (threshold: $threshPct%)"
    Write-Host "      Expect: Swarm Block of all $count attacker IPs"
    Write-Host ""

    for ($i = 1; $i -le $count; $i++) {
        $fakeIp = Get-RandomIP
        if ($i -le $errCount) {
            $url = "$script:targetUrl/non-existent-login-path"
        } else {
            $url = "$script:targetUrl/"
        }
        $result = Send-Fast -Url $url -FakeIp $fakeIp
        if ($result -eq "ok")      { Write-Host -NoNewline "." }
        elseif ($result -eq "err") { Write-Host -NoNewline "E" }
        else                       { Write-Host -NoNewline "t" }
        if ($i % 80 -eq 0)        { Write-Host "" }
        if ($script:delayMs -gt 0) { Start-Sleep -Milliseconds $script:delayMs }
    }
    Write-Host ""
    Write-Host "  Done. Watch backend for: [DDoS ALERT] Coordinated attack"
}

# =============================================================
# Scenario 4 - Subnet Attack  (DDoS Stage 3)
# =============================================================
function Send-SubnetAttack {
    $count      = $script:t_subnet_count
    $thr        = $script:subnetThreshold
    $subnetBase = "10.0.50"
    $ttlSec     = [int]($script:subnetTTL / 1000)

    Write-Host ""
    Write-Host "  [4] Subnet /24 Attack (DDoS Stage 3)" -ForegroundColor Magenta
    Write-Host "      Sends : $count requests from $subnetBase.0/24  (random hosts)"
    Write-Host "      Target: SUBNET_RATE_THRESHOLD = $thr  ->  sends $count  (+$([int](($count/$thr-1)*100))%)"
    Write-Host "      Expect: entire /24 blocked for $ttlSec s"
    Write-Host ""

    for ($i = 1; $i -le $count; $i++) {
        $host4   = Get-Random -Minimum 1 -Maximum 254
        $fakeIp  = "$subnetBase.$host4"
        $randStr = -join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
        $result  = Send-Fast -Url "$script:targetUrl/?q=$randStr" -FakeIp $fakeIp
        if ($result -eq "ok")      { Write-Host -NoNewline "S" }
        elseif ($result -eq "err") { Write-Host -NoNewline "s" }
        else                       { Write-Host -NoNewline "t" }
        if ($i % 80 -eq 0)        { Write-Host "" }
        if ($script:delayMs -gt 0) { Start-Sleep -Milliseconds $script:delayMs }
    }
    Write-Host ""
    Write-Host "  Done. Watch backend for: [DDoS ALERT] Subnet Volumetric Attack"
    Write-Host "  Verify: netsh advfirewall firewall show rule name=Apache-Sentinel-Block-List"
}

# =============================================================
# Configure params
# =============================================================
function Set-Params {
    Write-Host ""
    Write-Host "  --- CONFIGURE PARAMS ---" -ForegroundColor Cyan

    $newBackend = Read-Host "  Backend URL  [$script:backendUrl]  (Enter to keep)"
    if (-not [string]::IsNullOrWhiteSpace($newBackend)) {
        $script:backendUrl = $newBackend
        Write-Host "  Re-fetching config..." -ForegroundColor DarkGray
        Get-LiveConfig
        Show-CalibrationTable
    }

    $newTarget = Read-Host "  Apache target URL  [$script:targetUrl]  (Enter to keep)"
    if (-not [string]::IsNullOrWhiteSpace($newTarget)) {
        $script:targetUrl = $newTarget
    }

    $newDelay = Read-Host "  Delay between requests ms  [$script:delayMs]  (Enter to keep)"
    if (-not [string]::IsNullOrWhiteSpace($newDelay)) {
        $script:delayMs = [int]$newDelay
    }

    Write-Host "  Params updated." -ForegroundColor Green
}

# =============================================================
# Main menu
# =============================================================
Show-Intro

do {
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " target: $script:targetUrl   env: $script:envName   delay: $($script:delayMs)ms" -ForegroundColor DarkGray
    Write-Host "------------------------------------------------------------"
    Write-Host " [1]  Per-IP HTTP Flood         (DoS)   sends=$script:t_dos_count  / thr=$script:dosThreshold"
    Write-Host " [2]  Global Volumetric Flood   (DDoS)  sends=$script:t_global_count / thr=$script:globalThreshold"
    Write-Host " [3]  Coordinated Botnet        (DDoS)  sends=$script:t_botnet_count / thr=$script:botnetThreshold"
    Write-Host " [4]  Subnet /24 Attack         (DDoS)  sends=$script:t_subnet_count / thr=$script:subnetThreshold"
    Write-Host " [5]  Normal Traffic            (legit, no attack)"
    Write-Host " [0]  Configure params  (backend URL / target / delay)"
    Write-Host " [c]  Show calibration table"
    Write-Host " [q]  Exit"
    Write-Host "============================================================" -ForegroundColor Cyan

    $choice = Read-Host " Select"

    switch ($choice.Trim().ToLower()) {
        "0" { Set-Params }
        "1" { Send-HTTPFlood }
        "2" { Send-GlobalFlood }
        "3" { Send-CoordinatedBotnet }
        "4" { Send-SubnetAttack }
        "5" { Send-Normal }
        "c" { Show-CalibrationTable }
        "q" { Write-Host "Exiting." -ForegroundColor DarkGray }
        default { Write-Host "  Invalid choice." -ForegroundColor Red }
    }
} while ($choice.Trim().ToLower() -ne "q")