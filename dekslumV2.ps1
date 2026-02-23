#Requires -RunAsAdministrator
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# ================================
# SECURE LICENSE (KEY + SID + HASH)
# ================================

$secret = "MyPrivateSecret2026"

$licenses = @{
    "dev" = "B3C10CF54C7C7D955E8824652B7E074300AB2ABBC85C706F669C924264FD9073"
}

$inputKey = Read-Host "Enter License Key"

if (-not $licenses.ContainsKey($inputKey)) {
    Write-Host "Invalid License Key!" -ForegroundColor Red
    Start-Sleep 1
    exit
}

$currentSID = (whoami /user | Select-String "S-1-").ToString().Split()[-1]
$data = $currentSID + $secret
$bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
$hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
$generatedHash = [BitConverter]::ToString($hash) -replace "-",""

if ($licenses[$inputKey] -ne $generatedHash) {
    Write-Host "This key is not valid for this user!" -ForegroundColor Red
    Start-Sleep 1
    exit
}

Write-Host "License Verified!" -ForegroundColor Green
Start-Sleep 1
Clear-Host

# ================================
# NETWORK OPTIMIZE (REALTEK 2.5G)
# ================================

function Optimize-Network {

    $adapterName = "Ethernet"

    Write-Host "Optimizing Network..." -ForegroundColor Cyan

    Set-NetAdapterAdvancedProperty -Name $adapterName -DisplayName "Speed & Duplex" -DisplayValue "2.5 Gbps Full Duplex"

    "Advanced EEE","Energy-Efficient Ethernet","Green Ethernet","Gigabit Lite","Power Saving Mode" |
    ForEach-Object {
        Set-NetAdapterAdvancedProperty -Name $adapterName -DisplayName $_ -DisplayValue "Disabled"
    }

    Set-NetAdapterAdvancedProperty -Name $adapterName -DisplayName "Flow Control" -DisplayValue "Disabled"
    Set-NetAdapterAdvancedProperty -Name $adapterName -DisplayName "Interrupt Moderation" -DisplayValue "Disabled"

    Set-NetAdapterAdvancedProperty -Name $adapterName -DisplayName "Receive Side Scaling" -DisplayValue "Enabled"
    Set-NetAdapterAdvancedProperty -Name $adapterName -DisplayName "Maximum Number of RSS Queues" -DisplayValue "4"

    Set-NetAdapterAdvancedProperty -Name $adapterName -DisplayName "Receive Buffers" -DisplayValue "512"
    Set-NetAdapterAdvancedProperty -Name $adapterName -DisplayName "Transmit Buffers" -DisplayValue "512"

    "IPv4 Checksum Offload",
    "TCP Checksum Offload (IPv4)",
    "TCP Checksum Offload (IPv6)",
    "UDP Checksum Offload (IPv4)",
    "UDP Checksum Offload (IPv6)",
    "Large Send Offload v2 (IPv4)",
    "Large Send Offload v2 (IPv6)",
    "ARP Offload",
    "NS Offload" |
    ForEach-Object {
        Set-NetAdapterAdvancedProperty -Name $adapterName -DisplayName $_ -DisplayValue "Disabled"
    }

    Disable-NetAdapter -Name $adapterName -Confirm:$false
    Start-Sleep 2
    Enable-NetAdapter -Name $adapterName -Confirm:$false

    Write-Host "Network Optimized!" -ForegroundColor Green
}

function Reset-Network {
    $adapterName = "Ethernet"
    Set-NetAdapterAdvancedProperty -Name $adapterName -DisplayName "Speed & Duplex" -DisplayValue "Auto Negotiation"
    Enable-NetAdapter -Name $adapterName -Confirm:$false
}

# ================================
# CACHE CLEANER
# ================================

function Remove-Files($path) {
    if (Test-Path $path) {
        Get-ChildItem $path -Recurse -Force | Remove-Item -Recurse -Force
    }
}

function Run-Cleaner {
    Remove-Files "$env:TEMP"
    Remove-Files "C:\Windows\Temp"
    Remove-Files "$env:LOCALAPPDATA\Temp"
}

# ================================
# BOOST MODE
# ================================

function Run-Boost {

    Clear-Host
    Write-Host "Applying Boost..." -ForegroundColor Yellow

    $baseGUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    $planName = "Performance Dekslum"

    $duplicateOutput = powercfg -duplicatescheme $baseGUID
    $newGUID = ($duplicateOutput -split '\s+')[3]

    powercfg -changename $newGUID $planName
    powercfg /setacvalueindex $newGUID sub_processor PROCTHROTTLEMIN 100
    powercfg /setacvalueindex $newGUID sub_processor PROCTHROTTLEMAX 100
    powercfg -setactive $newGUID

    bcdedit /set disabledynamictick yes
    bcdedit /set tscsyncpolicy Enhanced

    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 0xffffffff /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f

    netsh int tcp set global rss=enabled

    Optimize-Network
    Run-Cleaner

    Write-Host ""
    Write-Host "BOOST COMPLETE!" -ForegroundColor Green
    Read-Host "Press Enter"
    exit
}

# ================================
# RESET MODE
# ================================

function Reset-Default {

    Clear-Host
    Write-Host "Resetting System..." -ForegroundColor Yellow

    powercfg -setactive SCHEME_BALANCED
    bcdedit /deletevalue disabledynamictick
    bcdedit /deletevalue tscsyncpolicy
    netsh int tcp reset

    Reset-Network

    Write-Host ""
    Write-Host "RESET COMPLETE!" -ForegroundColor Green
    Read-Host "Press Enter"
    exit
}

# ================================
# MENU
# ================================

Write-Host "1 : Install Dekslum"
Write-Host "2 : Uninstall Dekslum"
Write-Host ""

$choice = Read-Host "Select (1/2)"

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

switch ($choice) {
    "1" { Run-Boost }
    "2" { Reset-Default }
    default {
        Write-Host "Invalid Selection" -ForegroundColor Red
        Start-Sleep 2
    }
}
