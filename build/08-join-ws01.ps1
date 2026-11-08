# Runs INSIDE WS01 (Windows 11) via guestcontrol.
# Sets static IP + DNS to the DC, waits until the domain resolves, then joins soclab.local. Reboots.
# Domain-admin password is passed in env var DJ_PW by the caller.
$ErrorActionPreference = 'Stop'
if (-not $env:DJ_PW) { throw 'DJ_PW env var must be set.' }

$if = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
# (Re)apply static addressing; ignore "already exists".
if (-not (Get-NetIPAddress -InterfaceIndex $if.ifIndex -IPAddress 10.10.10.20 -ErrorAction SilentlyContinue)) {
    Get-NetIPAddress -InterfaceIndex $if.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -like '10.*' } | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceIndex $if.ifIndex -IPAddress 10.10.10.20 -PrefixLength 24 -DefaultGateway 10.10.10.1 -ErrorAction SilentlyContinue | Out-Null
}
Set-DnsClientServerAddress -InterfaceIndex $if.ifIndex -ServerAddresses 10.10.10.10
Clear-DnsClientCache

# Wait until the DC is reachable and the domain resolves (up to ~2 min).
$resolved = $false
for ($i = 0; $i -lt 24; $i++) {
    if (Test-Connection 10.10.10.10 -Count 1 -Quiet) {
        try { Resolve-DnsName -Name soclab.local -Type A -Server 10.10.10.10 -ErrorAction Stop | Out-Null; $resolved = $true; break } catch {}
    }
    Start-Sleep 5
}
Write-Output "domain reachable: $resolved (DNS=$((Get-DnsClientServerAddress -InterfaceIndex $if.ifIndex -AddressFamily IPv4).ServerAddresses -join ','))"

$sec  = ConvertTo-SecureString $env:DJ_PW -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('SOCLAB\Administrator', $sec)
Add-Computer -DomainName 'soclab.local' -Credential $cred -Restart -Force
