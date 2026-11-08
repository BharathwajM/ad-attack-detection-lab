# Runs INSIDE a Windows guest (DC01 or WS01) via guestcontrol.
# Expects these files already copied to C:\lab on the guest:
#   Sysmon64.exe, sysmonconfig.xml, splunkforwarder.msi
# Installs Sysmon with the sysmon-modular config and the Splunk Universal Forwarder,
# then configures the forwarder to send the lab's event channels to SPLUNK01:9997.
$ErrorActionPreference = 'Stop'
$lab = 'C:\lab'

# --- Sysmon ---
& "$lab\Sysmon64.exe" -accepteula -i "$lab\sysmonconfig.xml"

# --- Universal Forwarder (silent, no login, deploy as a service) ---
$msi = "$lab\splunkforwarder.msi"
Start-Process msiexec.exe -Wait -ArgumentList @(
  '/i', "`"$msi`"", 'AGREETOLICENSE=Yes',
  'RECEIVING_INDEXER=10.10.10.30:9997',
  'LAUNCHSPLUNK=1', 'SERVICESTARTTYPE=auto',
  '/quiet'
)

$ufx = 'C:\Program Files\SplunkUniversalForwarder'
$inputs = @"
[WinEventLog://Security]
disabled = 0
index = winlogs

[WinEventLog://System]
disabled = 0
index = winlogs

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = 1
index = winlogs

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = winlogs
"@
$dir = "$ufx\etc\system\local"
New-Item -ItemType Directory -Force $dir | Out-Null
Set-Content "$dir\inputs.conf" $inputs -Encoding ASCII

& "$ufx\bin\splunk.exe" restart

Write-Output "Sysmon + UF installed; forwarding Security/System/Sysmon/PowerShell to 10.10.10.30:9997."
