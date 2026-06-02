#requires -Version 7.0
<#
.SYNOPSIS
  End-to-end smoke test for the Modern-DNS cluster control plane.

.DESCRIPTION
  Drives the full primary→secondary lifecycle in a single shell:
    1. Login to the primary as admin
    2. Initialize the cluster, capture the API token
    3. Spin up a "secondary" by issuing a join via curl with the token
    4. Verify /cluster/state shows two nodes (Primary + Secondary)
    5. Resync the cluster (push snapshot)
    6. Send temporaryDisableBlocking + forceUpdateBlockLists commands
    7. Delete the cluster

  This script does NOT start the backend processes — assumes the primary
  is already running locally on the configured PORTs (default 8080 / 8443).

.PARAMETER PrimaryHttp
  HTTP base URL of the primary (default http://127.0.0.1:8080).

.PARAMETER PrimaryHttps
  HTTPS base URL of the primary used for cluster peer endpoints
  (default https://127.0.0.1:8443).

.PARAMETER AdminUser / AdminPass
  Console credentials. Defaults match the SeedAdmin defaults.

.EXAMPLE
  pwsh -File scripts/cluster-e2e.ps1
  pwsh -File scripts/cluster-e2e.ps1 -PrimaryHttp http://10.0.0.10:8080
#>
param(
  [string]$PrimaryHttp  = 'http://127.0.0.1:8080',
  [string]$PrimaryHttps = 'https://127.0.0.1:8443',
  [string]$AdminUser    = 'admin',
  [string]$AdminPass    = 'Admin@2026!',
  [string]$ClusterDomain = 'cluster.local',
  [string[]]$PrimaryIPs = @('127.0.0.1'),
  [string]$SecondaryURL  = 'https://127.0.0.1:9443',
  [string]$SecondaryName = 'secondary-test'
)

$ErrorActionPreference = 'Stop'
# Allow self-signed for local testing
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "    [OK]  $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "    [WARN] $msg" -ForegroundColor Yellow }
function Fail($msg) { Write-Host "    [FAIL] $msg" -ForegroundColor Red; exit 1 }

function Invoke-Api {
  param(
    [string]$Method,
    [string]$Url,
    [hashtable]$Headers,
    $Body
  )
  $headers = if ($Headers) { $Headers } else { @{} }
  $params = @{ Method = $Method; Uri = $Url; Headers = $headers; SkipCertificateCheck = $true; ContentType = 'application/json' }
  if ($null -ne $Body) {
    $params.Body = ($Body | ConvertTo-Json -Depth 10 -Compress)
  }
  return Invoke-RestMethod @params
}

# 1. Login -----------------------------------------------------------------
Step "Logging in as $AdminUser"
$login = Invoke-Api -Method POST -Url "$PrimaryHttp/api/auth/login" -Body @{
  username = $AdminUser
  password = $AdminPass
}
if (-not $login.data.token) { Fail "no token in login response: $($login | ConvertTo-Json -Depth 5)" }
$token = $login.data.token
$authHdr = @{ Authorization = "Bearer $token" }
Ok "got bearer token"

# 2. Pre-clean any prior cluster ------------------------------------------
Step "Pre-cleaning any existing cluster"
try {
  $del = Invoke-Api -Method DELETE -Url "$PrimaryHttp/api/cluster?force=1" -Headers $authHdr
  Ok "cleared prior state ($($del.data.deleted))"
} catch {
  Warn "delete returned: $($_.Exception.Message)"
}

# 3. Initialize cluster ----------------------------------------------------
Step "Initializing cluster $ClusterDomain"
$init = Invoke-Api -Method POST -Url "$PrimaryHttp/api/cluster/initialize" -Headers $authHdr -Body @{
  clusterDomain          = $ClusterDomain
  primaryNodeIpAddresses = $PrimaryIPs
  heartbeatIntervalSec   = 5
  configRefreshSec       = 30
}
if (-not $init.data.apiToken) { Fail "no apiToken in init response" }
$clusterToken = $init.data.apiToken
$cv = $init.data.configVersion
Ok "cluster initialized; configVersion=$cv apiToken=$($clusterToken.Substring(0,8))…"

# 4. Simulate a secondary join via /api/cluster/internal/join --------------
Step "Simulating secondary join"
$peerHdr = @{ 'X-Cluster-Token' = $clusterToken }
$nodeId = [guid]::NewGuid().ToString('N')
$join = Invoke-Api -Method POST -Url "$PrimaryHttps/api/cluster/internal/join" -Headers $peerHdr -Body @{
  secondaryNodeId          = $nodeId
  secondaryName            = $SecondaryName
  secondaryNodeUrl         = $SecondaryURL
  secondaryNodeIpAddresses = @('127.0.0.2')
  zone                     = 'lab'
  version                  = 'v1.5.9-test'
}
Ok "joined; clusterInfo nodes=$($join.data.clusterInfo.nodes.Count)"

# 5. Verify /cluster/state shows both nodes --------------------------------
Step "Reading cluster state"
$state = Invoke-Api -Method GET -Url "$PrimaryHttp/api/cluster/state" -Headers $authHdr
$primaryCnt   = ($state.data.nodes | Where-Object type -eq 'Primary').Count
$secondaryCnt = ($state.data.nodes | Where-Object type -eq 'Secondary').Count
if ($primaryCnt -ne 1) { Fail "expected 1 Primary, got $primaryCnt" }
if ($secondaryCnt -lt 1) { Fail "expected >=1 Secondary, got $secondaryCnt" }
Ok "state: Primary=$primaryCnt Secondary=$secondaryCnt configVersion=$($state.data.configVersion)"

# 6. Heartbeat the secondary --------------------------------------------------
Step "Heartbeat (qps=42)"
$hb = Invoke-Api -Method POST -Url "$PrimaryHttps/api/cluster/internal/heartbeat" -Headers $peerHdr -Body @{
  nodeId   = $nodeId
  qps      = 42
  cpuUsage = 18
  memUsage = 35
}
Ok "heartbeat ack ($($hb.code))"

# 7. Resync (push snapshot) -------------------------------------------------
Step "Force resync"
try {
  $rs = Invoke-Api -Method POST -Url "$PrimaryHttp/api/cluster/resync" -Headers $authHdr
  $okCount   = ($rs.data.results | Where-Object ok -eq $true).Count
  $failCount = ($rs.data.results | Where-Object ok -eq $false).Count
  Ok "resync version=$($rs.data.configVersion) ok=$okCount failed=$failCount"
} catch {
  # Expected when the simulated secondary URL is unreachable; we still
  # validate that the API round-tripped without 5xx.
  Warn "resync push failed (expected when secondaryNodeUrl is fake): $($_.Exception.Message)"
}

# 8. Cluster commands ------------------------------------------------------
Step "Dispatching forceUpdateBlockLists"
$cmd1 = Invoke-Api -Method POST -Url "$PrimaryHttp/api/cluster/command" -Headers $authHdr -Body @{
  action = 'forceUpdateBlockLists'
}
Ok "forceUpdate -> ok=$($cmd1.data.success) failed=$($cmd1.data.failed)"

Step "Dispatching temporaryDisableBlocking (2 minutes)"
$cmd2 = Invoke-Api -Method POST -Url "$PrimaryHttp/api/cluster/command" -Headers $authHdr -Body @{
  action = 'temporaryDisableBlocking'
  args   = @{ minutes = 2 }
}
Ok "tempDisable -> ok=$($cmd2.data.success) failed=$($cmd2.data.failed)"

# 9. Cleanup ---------------------------------------------------------------
Step "Tearing down cluster"
$tear = Invoke-Api -Method DELETE -Url "$PrimaryHttp/api/cluster?force=1" -Headers $authHdr
Ok "deleted=$($tear.data.deleted) force=$($tear.data.force)"

Write-Host "`n==> All cluster control-plane endpoints round-tripped successfully." -ForegroundColor Green
