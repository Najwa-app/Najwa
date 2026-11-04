<#
.SYNOPSIS
    Najwa Mailbox Server — Server Hardening (Windows PowerShell)

.DESCRIPTION
    Hardens a remote Linux server before mailbox deployment, or audits
    the hardening state. Executes harden-server.sh on the target via SSH.

    This script is a Windows-native wrapper — the actual hardening logic
    lives in harden-server.sh (Linux). This script handles:
      - Uploading harden-server.sh to the remote server
      - Running it with the appropriate flags
      - Displaying the audit/fix results locally

.PARAMETER Target
    SSH target (e.g. root@myserver.com). Required for remote mode.
    If omitted, runs against a local Docker container (if running).
    Alias: -Host.

.PARAMETER Check
    Audit only — report issues without making changes.

.PARAMETER Yes
    Skip confirmation prompts (non-interactive).

.EXAMPLE
    .\harden-server.ps1 -Target root@myserver.com                # Interactive hardening
    .\harden-server.ps1 -Target root@myserver.com -Check          # Audit only
    .\harden-server.ps1 -Target root@myserver.com -Yes            # Non-interactive
    .\harden-server.ps1 -Target root@myserver.com -Check -Yes     # Silent audit
#>

param(
    # Not named $Host: that is PowerShell's read-only automatic variable.
    [Parameter(Position = 0)]
    [Alias("Host")]
    [string]$Target,

    [Alias("c")]
    [switch]$Check,

    [Alias("y")]
    [switch]$Yes
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$HardenScript = Join-Path $ScriptDir "harden-server.sh"

function Write-Info  { param($Msg) Write-Host "[INFO]  $Msg" -ForegroundColor Cyan }
function Write-Ok    { param($Msg) Write-Host "[OK]    $Msg" -ForegroundColor Green }
function Write-Warn  { param($Msg) Write-Host "[WARN]  $Msg" -ForegroundColor Yellow }
function Write-Err   { param($Msg) Write-Host "[ERROR] $Msg" -ForegroundColor Red }

function Test-Command {
    param($Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

# ---------------------------------------------------------------------------
# Build the flags for harden-server.sh
# ---------------------------------------------------------------------------

function Get-HardenFlags {
    $flags = @()
    if ($Check) { $flags += "--check" }
    if ($Yes)   { $flags += "--yes" }
    return ($flags -join " ")
}

# ---------------------------------------------------------------------------
# Remote hardening via SSH
# ---------------------------------------------------------------------------

function Invoke-RemoteHarden {
    if (-not (Test-Command "ssh")) {
        Write-Err "ssh not found. Enable OpenSSH in Windows Settings > Apps > Optional Features."
        exit 1
    }

    if (-not (Test-Path $HardenScript)) {
        Write-Err "harden-server.sh not found at: $HardenScript"
        exit 1
    }

    $flags = Get-HardenFlags
    $modeLabel = if ($Check) { "AUDIT" } else { "HARDEN" }

    Write-Host ""
    Write-Host "  Najwa Mailbox Server - Remote Server $modeLabel" -ForegroundColor White
    Write-Host "  Target: $Target" -ForegroundColor White
    Write-Host ""

    # Test SSH
    Write-Info "Testing SSH connection..."
    $test = ssh -o ConnectTimeout=10 -o BatchMode=yes $Target "echo ok" 2>$null
    if ($test -ne "ok") {
        Write-Err "Cannot SSH to $Target"
        exit 1
    }
    Write-Ok "SSH connected"

    # Check if already present on remote
    $remoteExists = ssh $Target "test -f /tmp/najwa-harden.sh && echo yes || echo no" 2>$null
    
    # Upload script
    $remotePath = "/tmp/najwa-harden-$PID.sh"
    Write-Info "Uploading harden-server.sh..."
    scp -q $HardenScript "${Target}:${remotePath}"
    Write-Ok "Script uploaded"

    # Execute
    Write-Info "Running hardening ($modeLabel mode)..."
    Write-Host ""

    ssh -t $Target "sudo bash $remotePath $flags; rm -f $remotePath"

    Write-Host ""
    if ($Check) {
        Write-Ok "Audit complete. Review findings above."
        Write-Info "To apply fixes: .\harden-server.ps1 -Target $Target"
    } else {
        Write-Ok "Hardening complete."
        Write-Info "Next: install the mailbox server (docs/server/deployment.md section 3 onward)"
    }
}

# ---------------------------------------------------------------------------
# Local Docker container hardening audit
# ---------------------------------------------------------------------------

function Invoke-DockerHarden {
    if (-not (Test-Command "docker")) {
        Write-Err "No -Target specified and Docker not available."
        Write-Err "Usage: .\harden-server.ps1 -Target user@server"
        exit 1
    }

    # Check if mailbox container is running
    $container = docker ps --filter "name=najwa-mailbox" --format "{{.Names}}" 2>$null
    if (-not $container) {
        Write-Err "No running najwa-mailbox container found."
        Write-Err "Usage: .\harden-server.ps1 -Target user@server"
        exit 1
    }

    Write-Info "=== Docker Container Security Audit ==="
    Write-Host ""

    # Run basic security checks inside the container
    Write-Info "Checking container: $container"
    Write-Host ""

    # User check
    $user = docker exec $container whoami 2>$null
    if ($user -eq "najwa" -or $user -eq "nobody") {
        Write-Ok "Running as unprivileged user: $user"
    } else {
        Write-Warn "Running as: $user (should be unprivileged)"
    }

    # Read-only filesystem check
    $roTest = docker exec $container sh -c "touch /tmp/.write-test 2>/dev/null && rm /tmp/.write-test && echo writable || echo readonly" 2>$null
    Write-Info "/tmp is: $roTest"

    # No outbound network: network_mode "none", or every attached network is
    # Docker-internal. Read from the configuration rather than probed, so an
    # offline host cannot make a bridged container pass.
    $netMode = docker inspect $container --format '{{.HostConfig.NetworkMode}}'
    $nets = @(docker inspect $container --format '{{range $k, $v := .NetworkSettings.Networks}}{{println $k}}{{end}}' | Where-Object { $_ })
    $external = @($nets | Where-Object { (docker network inspect $_ --format '{{.Internal}}') -ne "true" })
    if ($netMode -eq "none" -or ($nets.Count -gt 0 -and $external.Count -eq 0)) {
        Write-Ok "No outbound internet access (internal network)"
    } else {
        Write-Err "FAIL: container has outbound internet access (network mode '$netMode'; non-internal networks: $($external -join ', '))"
    }

    # Capabilities
    Write-Info "Container capabilities:"
    docker inspect $container --format '{{.HostConfig.CapAdd}}' 2>$null | Write-Host -ForegroundColor Gray
    docker inspect $container --format '{{.HostConfig.CapDrop}}' 2>$null | Write-Host -ForegroundColor Gray

    # Health
    $health = docker inspect $container --format '{{.State.Health.Status}}' 2>$null
    if ($health -eq "healthy") {
        Write-Ok "Health check: $health"
    } else {
        Write-Warn "Health check: $health"
    }

    Write-Host ""
    Write-Ok "Docker audit complete."
    Write-Info "For full OS-level hardening, deploy to a Linux server:"
    Write-Info "  .\harden-server.ps1 -Target user@server"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if ($Target) {
    Invoke-RemoteHarden
} else {
    Invoke-DockerHarden
}
