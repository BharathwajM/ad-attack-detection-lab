# Runs INSIDE WS01 as local admin. Grants "Log on as a batch job" (SeBatchLogonRight) to SOCLAB\jsmith
# so the attack techniques can be run as that standard domain user via a scheduled task.
$ErrorActionPreference = 'Stop'
$acct = 'SOCLAB\jsmith'
$sid  = (New-Object System.Security.Principal.NTAccount($acct)).Translate([System.Security.Principal.SecurityIdentifier]).Value

$inf = 'C:\lab\sec-export.inf'
$db  = 'C:\lab\sec.sdb'
$new = 'C:\lab\sec-new.inf'
secedit /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null

$lines = Get-Content $inf
$found = $false
$out = foreach ($l in $lines) {
    if ($l -match '^SeBatchLogonRight\s*=') {
        $found = $true
        if ($l -notmatch [regex]::Escape($sid)) { "$($l.TrimEnd()),*$sid" } else { $l }
    } else { $l }
}
if (-not $found) {
    # insert under [Privilege Rights]
    $out = foreach ($l in $out) {
        $l
        if ($l -match '^\[Privilege Rights\]') { "SeBatchLogonRight = *$sid" }
    }
}
Set-Content $new $out -Encoding Unicode
secedit /configure /db $db /cfg $new /areas USER_RIGHTS /quiet
Remove-Item $inf,$new,$db -Force -ErrorAction SilentlyContinue
Write-Output "Granted SeBatchLogonRight to $acct ($sid)"
