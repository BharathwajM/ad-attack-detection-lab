# Create WS01 (Windows 11 Enterprise Evaluation) with EFI, Secure Boot and a virtual TPM 2.0, then start an
# unattended install. The local labadmin password is generated once into lab-credentials.local.txt and never printed.
$ErrorActionPreference = 'Stop'
$vbm = "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe"
$lab = Split-Path $PSScriptRoot -Parent
$cred = "$lab\lab-credentials.local.txt"
$iso = 'C:\Users\bhara\Downloads\ISOs\Win11_Enterprise_EVAL_26H2_x64_en-us.iso'
$vm  = 'WS01'
$dir = "C:\Users\bhara\VirtualBox VMs\$vm"

if (-not (Select-String -Path $cred -Pattern '^WS01 local admin' -Quiet)) {
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
    $rnd = -join (1..14 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    Add-Content $cred "WS01 local admin (labadmin): $rnd#7"
}

if (-not ((& $vbm list vms) -match "`"$vm`"")) {
    & $vbm createvm --name $vm --ostype Windows11_64 --register | Out-Null
    & $vbm modifyvm $vm --memory 6144 --cpus 4 --firmware efi --tpm-type 2.0 --nic1 natnetwork --nat-network1 ADLab `
        --graphicscontroller vboxsvga --vram 128 --audio-enabled off --clipboard-mode disabled --drag-and-drop disabled
    & $vbm createmedium disk --filename "$dir\$vm.vdi" --size 81920 --variant Standard | Out-Null
    & $vbm storagectl $vm --name SATA --add sata --controller IntelAhci --portcount 3
    & $vbm storageattach $vm --storagectl SATA --port 0 --device 0 --type hdd --medium "$dir\$vm.vdi"
    & $vbm modifynvram $vm inituefivarstore
    & $vbm modifynvram $vm enrollmssignatures
    & $vbm modifynvram $vm enrollorclpk
}

$line = Get-Content $cred | Where-Object { $_ -like 'WS01 local admin*' }
$pw   = ($line -split ': ', 2)[1].Trim()
$tmp  = New-TemporaryFile
try {
    [IO.File]::WriteAllText($tmp.FullName, $pw)
    & $vbm unattended install $vm `
        --iso=$iso --image-index=1 `
        --user=labadmin --full-user-name="Lab Admin" `
        --user-password-file=$($tmp.FullName) --admin-password-file=$($tmp.FullName) `
        --hostname=WS01.soclab.local `
        --locale=en_US --country=AU --time-zone="AUS Eastern Standard Time" `
        --install-additions `
        --start-vm=headless
    Start-Sleep -Seconds 20
}
finally {
    Remove-Item $tmp.FullName -Force -ErrorAction SilentlyContinue
}
