# Unattended Ubuntu Server 24.04 install for SPLUNK01 (VirtualBox).
# Reads the lab password from lab-credentials.local.txt (never printed), writes it to a temp file
# for VBoxManage, starts the install headless, then deletes the temp file.
$ErrorActionPreference = 'Stop'
$vbm  = "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe"
$lab  = Split-Path $PSScriptRoot -Parent
$iso  = 'C:\Users\bhara\Downloads\ISOs\ubuntu-24.04.5-live-server-amd64.iso'

$line = Get-Content "$lab\lab-credentials.local.txt" | Where-Object { $_ -like 'SPLUNK01 linux user:*' }
$pw   = ($line -split ' / ', 2)[1].Trim()
$tmp  = New-TemporaryFile
try {
    [IO.File]::WriteAllText($tmp.FullName, $pw)
    & $vbm unattended install SPLUNK01 `
        --iso=$iso `
        --user=labadmin --full-user-name="Lab Admin" `
        --user-password-file=$($tmp.FullName) --admin-password-file=$($tmp.FullName) `
        --hostname=splunk01.soclab.local `
        --locale=en_US --country=AU --time-zone=UTC `
        --install-additions `
        --start-vm=headless
    # Give VBoxManage time to read the file before it is removed.
    Start-Sleep -Seconds 20
}
finally {
    Remove-Item $tmp.FullName -Force -ErrorAction SilentlyContinue
}
