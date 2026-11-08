# Create DC01 (Windows Server 2025 Standard Evaluation, Desktop Experience) and start an unattended install.
# The local Administrator password (which becomes SOCLAB\Administrator after promotion) is read from
# lab-credentials.local.txt, passed via a temp file, and never printed.
$ErrorActionPreference = 'Stop'
$vbm = "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe"
$lab = Split-Path $PSScriptRoot -Parent
$iso = 'C:\Users\bhara\Downloads\ISOs\WinServer2025_EVAL_x64_en-us.iso'
$vm  = 'DC01'
$dir = "C:\Users\bhara\VirtualBox VMs\$vm"

if (-not ((& $vbm list vms) -match "`"$vm`"")) {
    & $vbm createvm --name $vm --ostype Windows2022_64 --register | Out-Null
    & $vbm modifyvm $vm --memory 4096 --cpus 2 --firmware efi --nic1 natnetwork --nat-network1 ADLab `
        --graphicscontroller vboxsvga --vram 128 --audio-enabled off --clipboard-mode disabled --drag-and-drop disabled
    & $vbm createmedium disk --filename "$dir\$vm.vdi" --size 61440 --variant Standard | Out-Null
    & $vbm storagectl $vm --name SATA --add sata --controller IntelAhci --portcount 3
    & $vbm storageattach $vm --storagectl SATA --port 0 --device 0 --type hdd --medium "$dir\$vm.vdi"
}

$line = Get-Content "$lab\lab-credentials.local.txt" | Where-Object { $_ -like 'Domain admin*' }
$pw   = ($line -split ': ', 2)[1].Trim()
$tmp  = New-TemporaryFile
try {
    [IO.File]::WriteAllText($tmp.FullName, $pw)
    & $vbm unattended install $vm `
        --iso=$iso --image-index=2 `
        --user=labadmin --full-user-name="Lab Admin" `
        --user-password-file=$($tmp.FullName) --admin-password-file=$($tmp.FullName) `
        --hostname=DC01.soclab.local `
        --locale=en_US --country=AU --time-zone="AUS Eastern Standard Time" `
        --install-additions `
        --start-vm=headless
    Start-Sleep -Seconds 20
}
finally {
    Remove-Item $tmp.FullName -Force -ErrorAction SilentlyContinue
}
