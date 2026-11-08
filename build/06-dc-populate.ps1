# Runs INSIDE DC01 after promotion (via guestcontrol, as SOCLAB\Administrator).
# Builds a small, realistic domain: an OU of users, a Kerberoastable service account with an SPN,
# and the audit policy that makes the planned detections visible in the Security log / Sysmon.
# Passwords are passed in as env vars by the caller; nothing secret is hard-coded here.
#   SVC_PW   - weak-ish password for the SQL service account (Kerberoasting target)
#   USER_PW  - shared starting password for the ordinary user accounts
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

if (-not $env:SVC_PW)  { throw 'SVC_PW env var must be set.' }
if (-not $env:USER_PW) { throw 'USER_PW env var must be set.' }

$ou = 'OU=Lab,DC=soclab,DC=local'
if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ou'" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name 'Lab' -Path 'DC=soclab,DC=local' -ProtectedFromAccidentalDeletion $false
}

# --- Ordinary users (targets for password spraying / account discovery) ---
$users = @(
  @{s='jsmith';  n='John Smith'},    @{s='agarcia'; n='Ana Garcia'},
  @{s='bchen';   n='Bai Chen'},      @{s='dkumar';  n='Dev Kumar'},
  @{s='efoster'; n='Erin Foster'},   @{s='mokafor'; n='Mary Okafor'},
  @{s='pnguyen'; n='Phuc Nguyen'},   @{s='rlopez';  n='Rosa Lopez'},
  @{s='twilson'; n='Tom Wilson'},    @{s='ysato';   n='Yuki Sato'}
)
$upw = ConvertTo-SecureString $env:USER_PW -AsPlainText -Force
foreach ($u in $users) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.s)'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name $u.n -SamAccountName $u.s `
            -UserPrincipalName "$($u.s)@soclab.local" -Path $ou `
            -AccountPassword $upw -Enabled $true `
            -ChangePasswordAtLogon $false -PasswordNeverExpires $true
    }
}

# --- Kerberoastable service account: SPN set, so any domain user can request its TGS (T1558.003) ---
$spw = ConvertTo-SecureString $env:SVC_PW -AsPlainText -Force
if (-not (Get-ADUser -Filter "SamAccountName -eq 'svc_sql'" -ErrorAction SilentlyContinue)) {
    New-ADUser -Name 'svc_sql' -SamAccountName 'svc_sql' `
        -UserPrincipalName 'svc_sql@soclab.local' -Path $ou `
        -AccountPassword $spw -Enabled $true -PasswordNeverExpires $true `
        -ServicePrincipalNames 'MSSQLSvc/dc01.soclab.local:1433'
}

# --- Audit policy: make the detections possible ---
# Kerberos service tickets (4769 -> Kerberoasting), logon (4624/4625 -> spraying),
# DS replication access (4662 -> DCSync), process creation with command line (4688, 1 -> all).
$cats = @(
  'Kerberos Service Ticket Operations',
  'Logon', 'Account Lockout',
  'Directory Service Access', 'Directory Service Changes',
  'Process Creation', 'Process Termination'
)
foreach ($c in $cats) { auditpol /set /subcategory:"$c" /success:enable /failure:enable | Out-Null }
# Include the command line in 4688 events.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentControlSet\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f 2>$null
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /f 2>$null | Out-Null
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord

Write-Output "Domain populated: $($users.Count) users + svc_sql (SPN MSSQLSvc). Audit policy set."
