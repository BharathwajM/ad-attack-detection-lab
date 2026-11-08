# Host-side orchestrator: pushes 04-splunk-server-setup.sh into SPLUNK01 and runs it as root via guestcontrol.
# Reads the root (linux) and Splunk-web passwords from lab-credentials.local.txt; never prints them.
$ErrorActionPreference = 'Stop'
$vbm  = "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe"
$lab  = Split-Path $PSScriptRoot -Parent
$cred = "$lab\lab-credentials.local.txt"

function Get-Secret($label) {
    $l = Get-Content $cred | Where-Object { $_ -like "$label*" } | Select-Object -First 1
    if (-not $l) { throw "no credential line for '$label'" }
    if ($l -match ' / ') { ($l -split ' / ',2)[1].Trim() } else { ($l -split ': ',2)[1].Trim() }
}

$rootpw   = Get-Secret 'SPLUNK01 linux user:'
$splunkpw = Get-Secret 'Splunk web admin'

$pf = New-TemporaryFile
[IO.File]::WriteAllText($pf.FullName, $rootpw)
$envf = New-TemporaryFile
[IO.File]::WriteAllText($envf.FullName, "export SPLUNK_PW='$splunkpw'`n")

try {
    & $vbm guestcontrol SPLUNK01 copyto --username root --passwordfile $pf.FullName `
        "$PSScriptRoot\04-splunk-server-setup.sh" /root/setup.sh
    & $vbm guestcontrol SPLUNK01 copyto --username root --passwordfile $pf.FullName `
        $envf.FullName /root/.labenv
    & $vbm guestcontrol SPLUNK01 run --username root --passwordfile $pf.FullName `
        --exe /bin/bash -- -c '. /root/.labenv && bash /root/setup.sh > /root/setup.log 2>&1; rm -f /root/.labenv; echo DONE rc=$?'
}
finally {
    Remove-Item $pf.FullName, $envf.FullName -Force -ErrorAction SilentlyContinue
}
