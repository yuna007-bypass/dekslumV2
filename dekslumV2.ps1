#Requires -RunAsAdministrator

# ================================
# SECURE LICENSE (KEY + SID + HASH)
# ================================

# 🔐 Secret ของคุณ (ห้ามบอกใคร และอย่าเปลี่ยนทีหลัง)
$secret = "MyPrivateSecret2026"

# 🔑 License Database (เก็บค่า Hash เท่านั้น)
$licenses = @{
    "dev" = "B3C10CF54C7C7D955E8824652B7E074300AB2ABBC85C706F669C924264FD9073"
    "dekslumV2-Q8T4M1" = "HASH1"
    "dekslumV2-L2X9R7" = "HASH2"
    "dekslumV2-V7K3P6" = "HASH3"
    "dekslumV2-N5Z8F2" = "HASH4"
    "dekslumV2-H9M4T7" = "HASH5"
    "dekslumV2-R3L6X8" = "HASH6"
    "dekslumV2-P1Q7Z4" = "HASH7"
    "dekslumV2-T6V2K9" = "HASH8"
    "dekslumV2-M8F3L5" = "HASH9"
    "dekslumV2-Z4R9X1" = "HASH10"
}

# รับคีย์
$inputKey = Read-Host "Enter License Key"

if (-not $licenses.ContainsKey($inputKey)) {
    Write-Host "Invalid License Key!" -ForegroundColor Red
    Start-Sleep -Seconds 1
    exit
}

# ดึง SID ปัจจุบัน
$currentSID = (whoami /user | Select-String "S-1-").ToString().Split()[-1]

# สร้าง Hash จาก SID + Secret
$data = $currentSID + $secret
$bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
$hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
$generatedHash = [BitConverter]::ToString($hash) -replace "-",""

# ตรวจสอบ
if ($licenses[$inputKey] -ne $generatedHash) {
    Write-Host "This key is not valid for this user!" -ForegroundColor Red
    Start-Sleep -Seconds 1
    exit
}

Write-Host "License Verified!" -ForegroundColor Green
Start-Sleep -Seconds 1

Clear-Host

Write-Host "1 : Install Dekslum"
Write-Host "2 : Uninstall Dekslum"
Write-Host ""

$choice = Read-Host "Select (1/2)"

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ================================
# EXTREME CACHE CLEANER (SILENT)
# ================================

function Remove-Files($path) {
    if (Test-Path $path) {
        try {
            Get-ChildItem $path -Recurse -Force -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "CLEANED: $path" -ForegroundColor Green
        } catch {
            Write-Host "SKIPPED: $path" -ForegroundColor Yellow
        }
    }
}

function Scan-And-Clean($basePath) {
    if (Test-Path $basePath) {
        Get-ChildItem $basePath -Directory -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.Name -match '(?i)cache|temp|logs') -and
             ($_.FullName -notmatch '(?i)userdata|content|projects|profiles')
        } |
        ForEach-Object {
            try {
                Get-ChildItem $_.FullName -Recurse -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "AUTO CLEANED: $($_.FullName)" -ForegroundColor DarkGreen
            } catch {
                 Write-Host "SKIPPED: $($_.FullName)" -ForegroundColor Yellow
            }
        }
    }
}

function Run-Boost {
# ----------------
# Windows TEMP
# ----------------
    Remove-Files "$env:TEMP"
    Remove-Files "C:\Windows\Temp"
    Remove-Files "C:\Windows\Prefetch"
# ----------------
# User Cache
# ----------------
    Remove-Files "$env:LOCALAPPDATA\Temp"
    Remove-Files "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"
    Remove-Files "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
    Remove-Files "$env:LOCALAPPDATA\CrashDumps"
# --------------------
# Windows Update Cache
# --------------------
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    Remove-Files "C:\Windows\SoftwareDistribution\Download"
    Start-Service wuauserv -ErrorAction SilentlyContinue
# ----------------
# GPU Shader Cache
# ----------------
    Remove-Files "$env:LOCALAPPDATA\NVIDIA\DXCache"
    Remove-Files "$env:LOCALAPPDATA\NVIDIA\GLCache"
    Remove-Files "$env:LOCALAPPDATA\AMD\DxCache"
    Remove-Files "$env:LOCALAPPDATA\AMD\GLCache"
    Remove-Files "$env:LOCALAPPDATA\D3DSCache"
# ----------------
# Browser Cache
# ----------------
    Remove-Files "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
    Remove-Files "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
# ----------------
# FiveM Cache
# ----------------
    Remove-Files "$env:LOCALAPPDATA\FiveM\FiveM.app\data\cache"
    Remove-Files "$env:LOCALAPPDATA\FiveM\FiveM.app\data\server-cache"
    Remove-Files "$env:LOCALAPPDATA\FiveM\FiveM.app\data\server-cache-priv"
# ----------------
# Discord Cache
# ---------------
    #Remove-Files "$env:APPDATA\discord\Cache"
    #Remove-Files "$env:APPDATA\discord\Code Cache"
    #Remove-Files "$env:APPDATA\discord\GPUCache"
# ----------------
# Windows Error Logs
# ----------------
    Remove-Files "C:\ProgramData\Microsoft\Windows\WER"

    Scan-And-Clean "$env:LOCALAPPDATA"
    Scan-And-Clean "$env:APPDATA"
}
# =========================
# APPLY MODE
# =========================
function Run-Boost {

    Write-Host "Applying Network Tuning..." -ForegroundColor Yellow

    $settings = @{
        "Speed & Duplex"                   = "Auto Negotiation"
        "Advanced EEE"                     = "Disabled"
        "Energy-Efficient Ethernet"        = "Disabled"
        "Green Ethernet"                   = "Disabled"
        "Gigabit Lite"                     = "Disabled"
        "Power Saving Mode"                = "Disabled"
        "Flow Control"                     = "Disabled"
        "Interrupt Moderation"             = "Disabled"
        "Receive Side Scaling"             = "Enabled"
        "Maximum Number of RSS Queues"     = "4"
        "Receive Buffers"                  = "32"
        "Transmit Buffers"                 = "64"
        "Jumbo Frame"                      = "9014 Bytes"
        "IPv4 Checksum Offload"            = "Disabled"
        "TCP Checksum Offload (IPv4)"      = "Disabled"
        "TCP Checksum Offload (IPv6)"      = "Disabled"
        "UDP Checksum Offload (IPv4)"      = "Disabled"
        "UDP Checksum Offload (IPv6)"      = "Disabled"
        "Large Send Offload v2 (IPv4)"     = "Disabled"
        "Large Send Offload v2 (IPv6)"     = "Disabled"
        "ARP Offload"                      = "Disabled"
        "NS Offload"                       = "Disabled"
        "Priority & VLAN"                  = "Priority & VLAN Disabled"
        "VLAN ID"                          = "0"
        "Shutdown Wake-On-Lan"             = "Disabled"
        "Wake on Magic Packet"             = "Disabled"
        "Wake on pattern match"            = "Disabled"
    }

    foreach ($item in $settings.GetEnumerator()) {
        Set-NetAdapterAdvancedProperty -Name $adapterName `
            -DisplayName $item.Key `
            -DisplayValue $item.Value `
            -ErrorAction SilentlyContinue
    }

    Restart-Adapter
    Write-Host "Tuning Applied Successfully!" -ForegroundColor Green
}

# =========================
# RESET MODE
# =========================
function Reset-Default {

    Write-Host "Restoring Adapter Defaults..." -ForegroundColor Yellow

    # คืนค่า Advanced Property ทั้งหมดเป็นค่า Driver Default
    Get-NetAdapterAdvancedProperty -Name $adapterName | ForEach-Object {
        Set-NetAdapterAdvancedProperty -Name $adapterName `
            -RegistryKeyword $_.RegistryKeyword `
            -RegistryValue $_.DefaultRegistryValue `
            -ErrorAction SilentlyContinue
    }

    Restart-Adapter
    Write-Host "Adapter Restored to Default!" -ForegroundColor Green
}

# =========================
# RESTART FUNCTION
# =========================
function Restart-Adapter {
    Write-Host "Restarting Adapter..."
    Disable-NetAdapter -Name $adapterName -Confirm:$false
    Start-Sleep -Seconds 3
    Enable-NetAdapter -Name $adapterName -Confirm:$false
}

# ================================
# OPTION 1 : BOOST + CLEAN
# ================================

function Run-Boost {

    Clear-Host
    Write-Host "Processing..." -ForegroundColor Yellow

# =========================================
# Power Plan - Dekslum (High Perf Base)
# =========================================

$baseGUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"  # High Performance
$planName = "Performance Dekslum"

# ลบของเก่าถ้ามี
$existing = powercfg -l | Select-String $planName
if ($existing) {
    $oldGUID = ($existing -split '\s+')[3]
    powercfg -delete $oldGUID | Out-Null
}

# Clone High Performance
$duplicateOutput = powercfg -duplicatescheme $baseGUID
$newGUID = ($duplicateOutput -split '\s+')[3]

# ตั้งชื่อ
powercfg -changename $newGUID $planName "Dekslum Custom Performance Plan" | Out-Null

# บังคับ CPU 100%
powercfg /setacvalueindex $newGUID sub_processor PROCTHROTTLEMIN 100
powercfg /setacvalueindex $newGUID sub_processor PROCTHROTTLEMAX 100

# เปิดใช้งาน
powercfg -setactive $newGUID | Out-Null

    # Boot Config
    bcdedit /set disabledynamictick yes | Out-Null
    bcdedit /set tscsyncpolicy Enhanced | Out-Null
    bcdedit /deletevalue useplatformclock | Out-Null

    # Registry
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 0xffffffff /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f | Out-Null

    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Priority /t REG_DWORD /d 6 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d High /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d High /f | Out-Null

    reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f | Out-Null

    # Network
    netsh int tcp set global autotuninglevel=normal | Out-Null
    netsh int tcp set global rss=enabled | Out-Null
    netsh int tcp set global ecncapability=disabled | Out-Null
    netsh int tcp set global timestamps=disabled | Out-Null

    # Run Cache Cleaner 
    Run-Cleaner

    Clear-Host

Write-Host "1 : Install Demoshop"
Write-Host "2 : Uninstall Demoshop"
Write-Host ""
Write-Host "Select (1/2): 1"
Write-Host ""
Write-Host "Successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Press Enter to continue..." -ForegroundColor Gray

Read-Host
exit
}

# ================================
# OPTION 2 : RESET
# ================================

function Reset-Default {

    Clear-Host
    Write-Host "Resetting..." -ForegroundColor Yellow

    powercfg -setactive SCHEME_BALANCED | Out-Null

    bcdedit /deletevalue disabledynamictick | Out-Null
    bcdedit /deletevalue tscsyncpolicy | Out-Null
    bcdedit /set useplatformclock true | Out-Null

    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 10 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 20 /f | Out-Null

    netsh int tcp reset | Out-Null

    Clear-Host

Write-Host "1 : Install Demoshop"
Write-Host "2 : Uninstall Demoshop"
Write-Host ""
Write-Host "Select (1/2): 2"
Write-Host ""
Write-Host "Successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Press Enter to continue..." -ForegroundColor Gray

Read-Host
exit
}

# ================================
# MENU
# ================================

switch ($choice) {

    "1" { Run-Boost }

    "2" { Reset-Default }

    default {
        Write-Host "Invalid Selection" -ForegroundColor Red
        Start-Sleep 2
    }

}


