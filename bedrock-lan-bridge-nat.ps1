# Bedrock LAN Bridge Portproxy Manager
# Run this script in a powershell terminal with Administrator privileges.
# Usage:
#   .\bedrock-lan-bridge-nat.ps1 enable
#   .\bedrock-lan-bridge-nat.ps1 enable -config "myconfig.json"
#   .\bedrock-lan-bridge-nat.ps1 disable
#   .\bedrock-lan-bridge-nat.ps1 status

# --- SCRIPT PARAMETERS ---
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("enable", "disable", "status")]
    [string]$action,

    [string]$config = "config.json"
)

function Invoke-Netsh {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Arguments,

        [string]$ErrorHint = ""
    )

    $output = & netsh @Arguments 2>&1
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        $detail = ($output | Out-String).Trim()

        if ($detail -match "The parameter is incorrect") {
            $detail += "`n`nMost Windows releases only support TCP entries in netsh portproxy. " +
                       "UDP forwarding requires Windows 11 24H2 (build 26100+) or a newer Insider build."
        }

        if ($ErrorHint) {
            $detail = "$ErrorHint`n$detail"
        }

        throw "netsh failed (exit $exitCode)`n$detail"
    }

    return $output
}

function Load-Config($path) {
    $cfg = @{
        lanBroadcastPort = 19132
        localProxyPort   = 19134
    }

    if (Test-Path $path) {
        try {
            $json = Get-Content $path -Raw | ConvertFrom-Json

            if ($json.lanBroadcastPort) { $cfg.lanBroadcastPort = $json.lanBroadcastPort }
            if ($json.localProxyPort)   { $cfg.localProxyPort   = $json.localProxyPort }

        } catch {
            Write-Error "Failed to parse config: $path"
            exit 1
        }
    }

    return $cfg
}

function Show-Status($listenPort) {
    $result = Invoke-Netsh -Arguments @("interface", "portproxy", "show", "v4tov4") |
        Select-String "$listenPort"
    if ($result) {
        Write-Host "Portproxy is ENABLED."
    } else {
        Write-Host "Portproxy is DISABLED."
    }
}

function Enable-Rule($listenPort, $proxyPort) {
    Write-Host "Enabling NAT (UDP $listenPort -> $proxyPort)..."

    Invoke-Netsh -Arguments @(
        "interface", "portproxy", "add", "v4tov4",
        "protocol=udp",
        "listenaddress=0.0.0.0", "listenport=$listenPort",
        "connectaddress=127.0.0.1", "connectport=$proxyPort"
    ) -ErrorHint "Failed to add the UDP portproxy entry."

    Invoke-Netsh -Arguments @(
        "advfirewall", "firewall", "add", "rule",
        "name=Bedrock LAN Bridge", "dir=in", "action=allow",
        "protocol=UDP", "localport=$listenPort,$proxyPort"
    ) -ErrorHint "Failed to open the firewall ports."

    Write-Host "Enabled."
}

function Disable-Rule($listenPort) {
    Write-Host "Disabling NAT..."

    Invoke-Netsh -Arguments @(
        "interface", "portproxy", "delete", "v4tov4",
        "protocol=udp",
        "listenaddress=0.0.0.0", "listenport=$listenPort"
    ) -ErrorHint "Failed to remove the UDP portproxy entry."

    Invoke-Netsh -Arguments @(
        "advfirewall", "firewall", "delete", "rule",
        "name=Bedrock LAN Bridge"
    ) -ErrorHint "Failed to remove the firewall rule."

    Write-Host "Disabled."
}

# ---- MAIN EXECUTION ----
$cfg = Load-Config $config

$listenPort = $cfg.lanBroadcastPort
$proxyPort  = $cfg.localProxyPort

Write-Host "Using ports: listen=$listenPort proxy=$proxyPort"

switch ($action) {
    "enable"  { Enable-Rule $listenPort $proxyPort }
    "disable" { Disable-Rule $listenPort }
    "status"  { Show-Status $listenPort }
}
