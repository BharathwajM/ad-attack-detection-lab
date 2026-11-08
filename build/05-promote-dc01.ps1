# Runs INSIDE DC01 (Windows Server 2025) via VBoxManage guestcontrol.
# Sets a static IP, installs AD DS, and promotes the box to a new forest soclab.local.
# The DSRM password is passed in as the env var DSRM_PW by the caller (never hard-coded here).
# After this runs the VM reboots itself to finish promotion.
$ErrorActionPreference = 'Stop'

if (-not $env:DSRM_PW) { throw 'DSRM_PW env var must be set by the caller.' }

# --- Static IP 10.10.10.10 ---
$if = (Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1)
New-NetIPAddress -InterfaceIndex $if.ifIndex -IPAddress 10.10.10.10 -PrefixLength 24 -DefaultGateway 10.10.10.1 -ErrorAction SilentlyContinue | Out-Null
Set-DnsClientServerAddress -InterfaceIndex $if.ifIndex -ServerAddresses 127.0.0.1

# --- AD DS role ---
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null

# --- Promote to new forest soclab.local ---
$dsrm = ConvertTo-SecureString $env:DSRM_PW -AsPlainText -Force
Import-Module ADDSDeployment
Install-ADDSForest `
    -DomainName 'soclab.local' `
    -DomainNetbiosName 'SOCLAB' `
    -ForestMode 'WinThreshold' -DomainMode 'WinThreshold' `
    -InstallDns `
    -SafeModeAdministratorPassword $dsrm `
    -NoRebootOnCompletion:$false `
    -Force
