#Requires -RunAsAdministrator

# ================================
# SECURE LICENSE (KEY + SID + HASH)
# ================================

# 🔐 Secret ของคุณ (ห้ามบอกใคร และอย่าเปลี่ยนทีหลัง)
$secret = "MyPrivateSecret2026"

# 🔑 License Database (เก็บค่า Hash เท่านั้น)
$licenses = @{
    "dev" = "B3C10CF54C7C7D955E8824652B7E074300AB2ABBC85C706F669C924264FD9073"
    "dekslumV2-Q8T4M1" = "B3C10CF54C7C7D955E8824652B7E074300AB2ABBC85C706F669C924264FD9073"
    "dekslumV2-L2X9R7" = "1CDD809C18B8C0FBEDD358F0675AE4893AAA4CDA84D16B18BE9C30DC7FD30CF2"
    "dekslumV2-V7K3P6" = "B3C10CF54C7C7D955E8824652B7E074300AB2ABBC85C706F669C924264FD9073"
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
        } catch {}
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
            } catch {}
        }
    }
}

function Run-CacheCleaner {
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
    Remove-Files "C:\Windows\Softwaretribution\Download"
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
# cord Cache
# ---------------
    #Remove-Files "$env:APPDATA\cord\Cache"
    #Remove-Files "$env:APPDATA\cord\Code Cache"
    #Remove-Files "$env:APPDATA\cord\GPUCache"
# ----------------
# Windows Error Logs
# ----------------
    Remove-Files "C:\ProgramData\Microsoft\Windows\WER"

    Scan-And-Clean "$env:LOCALAPPDATA"
    Scan-And-Clean "$env:APPDATA"
}

$adapterName = "Ethernet"

#Write-Host "Tuning adapter: $adapterName"

# ============================
# Network Advanced Properties
# ============================

$BoostSettings = @{
    # ===== Speed =====
    "Speed & Duplex" = "Auto Negotiation"

    # ===== Power Saving =====
    "Advanced EEE" = "abled"
    "Energy-Efficient Ethernet" = "abled"
    "Green Ethernet" = "Disabled"
    "Gigabit Lite" = "Disabled"
    "Power Saving Mode" = "Disabled"

    # ===== Latency Optimize =====
    "Flow Control" = "Disabled"
    "Interrupt Moderation" = "Disabled"

    # ===== RSS =====
    "Receive Side Scaling" = "Enabled"
    "Maximum Number of RSS Queues" = "4"

    # ===== Buffers =====
    "Receive Buffers" = "32"
    "Transmit Buffers" = "64"

    # ===== Jumbo Frame =====
    "Jumbo Frame" = "9014 Bytes"

    # ===== Offloads =====
    "IPv4 Checksum Offload" = "Disabled"
    "TCP Checksum Offload (IPv4)" = "Disabled"
    "TCP Checksum Offload (IPv6)" = "Disabled"
    "UDP Checksum Offload (IPv4)" = "Disabled"
    "UDP Checksum Offload (IPv6)" = "Disabled"
    "Large Send Offload v2 (IPv4)" = "Disabled"
    "Large Send Offload v2 (IPv6)" = "Disabled"
    "ARP Offload" = "Disabled"
    "NS Offload" = "Disabled"

    # ===== VLAN =====
    "Priority & VLAN" = "Priority & VLAN Disabled"
    "VLAN ID" = "0"

    # ===== Wake =====
    "Shutdown Wake-On-Lan" = "Disabled"
    "Wake on Magic Packet" = "Disabled"
    "Wake on pattern match" = "Disabled"
}

# ================================
# OPTION 1 : BOOST + CLEAN
# ================================

function Run-Boost {
    #Write-Host "Success" -ForegroundColor Green
# ============================
# Apply Settings
# ============================

foreach ($item in $BoostSettings.GetEnumerator()) {
    try {
        Set-NetAdapterAdvancedProperty `
            -Name $adapterName `
            -DisplayName $item.Key `
            -DisplayValue $item.Value `
            -ErrorAction SilentlyContinue
    } catch {}
}

# Restart Adapter
#Write-Host "Restarting adapter..."
Disable-NetAdapter -Name $adapterName -Confirm:$false
Start-Sleep -Seconds 3
Enable-NetAdapter -Name $adapterName -Confirm:$false

#Write-Host "Complete."
    # Run Cache Cleaner 
    Run-CacheCleaner

    #Clear-Host
    #Write-Host "Processing..." -ForegroundColor Yellow

# =========================================
# Power Plan - Dekslum (High Perf Base)
# =========================================

$baseGUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"  # High Performance
$planName = "Performance Dekslum"

# ลบของเก่าถ้ามี
$existing = powercfg -l | Select-String $planName
if ($existing) {
    $oldGUID = ($existing -split '\s+')[3]

    # ถ้าแผนนี้กำลัง Active อยู่ ให้สลับไป Balanced ก่อน
    $active = powercfg -getactivescheme
    if ($active -match $oldGUID) {
        powercfg -setactive SCHEME_BALANCED | Out-Null
        Start-Sleep -Milliseconds 500
    }

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


    # Network
    netsh int tcp set global autotuninglevel=normal | Out-Null
    netsh int tcp set global rss=enabled | Out-Null
    netsh int tcp set global ecncapability=disabled | Out-Null
    netsh int tcp set global timestamps=disabled | Out-Null

# ============================================ # GhostBoost Clean Edition (Safe Tweaks) # ============================================
# 1️⃣ Enable Hardware GPU Scheduling
New-ItemProperty `
-Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" `
-Name "HwSchMode" `
-PropertyType DWord `
-Value 2 `
-Force | Out-Null

# 2️⃣ Disable Mouse Acceleration
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Value "0"
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Value "0"
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Value "0"

# 3️⃣ Enable Game Mode
New-ItemProperty `
-Path "HKCU:\Software\Microsoft\GameBar" `
-Name "AllowAutoGameMode" `
-PropertyType DWord `
-Value 1 `
-Force | Out-Null

# 4️⃣ Disable Game DVR
New-ItemProperty `
-Path "HKCU:\System\GameConfigStore" `
-Name "GameDVR_Enabled" `
-PropertyType DWord `
-Value 0 `
-Force | Out-Null


# ========================= Stop Xbox Services =========================

Stop-Service XblGameSave -Force -ErrorAction SilentlyContinue
Stop-Service XboxGipSvc -Force -ErrorAction SilentlyContinue
Stop-Service XboxNetApiSvc -Force -ErrorAction SilentlyContinue

# FiveM Priority = High (ถาวรทุกครั้งที่เปิดเกม)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FiveM_GTAProcess.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 3 /f | Out-Null

# Disable Background Apps (Global)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BackgroundAppGlobalToggle /t REG_DWORD /d 0 /f | Out-Null


    # ==== หน้าจอแบบในรูป ====
    Write-Host ""
    Write-Host "Successfully" -ForegroundColor Green
    Write-Host "Press Enter to continue..." -ForegroundColor White
    Read-Host
}

# ================================
# OPTION 2 : RESET
# ================================
# ============================
# RESET SETTINGS (DEFAULT)
# ============================

$ResetDefault = @{

    # Speed (Auto Negotiation)
    "Speed & Duplex" = "Auto Negotiation"

    # Power Saving
    "Advanced EEE" = "Enabled"
    "Energy-Efficient Ethernet" = "Enabled"
    "Green Ethernet" = "Enabled"
    "Gigabit Lite" = "Enabled"
    "Power Saving Mode" = "Enabled"

    # Latency
    "Flow Control" = "Rx & Tx Enabled"
    "Interrupt Moderation" = "Enabled"

    # RSS
    "Receive Side Scaling" = "Enabled"
    "Maximum Number of RSS Queues" = "2"

    # Buffers (ค่าทั่วไป)
    "Receive Buffers" = "256"
    "Transmit Buffers" = "512"

    # Jumbo
    "Jumbo Frame" = "Disabled"

    # Offloads
    "IPv4 Checksum Offload" = "Rx & Tx Enabled"
    "TCP Checksum Offload (IPv4)" = "Rx & Tx Enabled"
    "TCP Checksum Offload (IPv6)" = "Rx & Tx Enabled"
    "UDP Checksum Offload (IPv4)" = "Rx & Tx Enabled"
    "UDP Checksum Offload (IPv6)" = "Rx & Tx Enabled"
    "Large Send Offload v2 (IPv4)" = "Enabled"
    "Large Send Offload v2 (IPv6)" = "Enabled"
    "ARP Offload" = "Enabled"
    "NS Offload" = "Enabled"

    # VLAN
    "Priority & VLAN" = "Priority & VLAN Enabled"
    "VLAN ID" = "0"

    # Wake
    "Shutdown Wake-On-Lan" = "Enabled"
    "Wake on Magic Packet" = "Enabled"
    "Wake on pattern match" = "Enabled"
}

# ============================
# FUNCTION
# ============================

function Apply-Settings($settings) {

    #Write-Host "Tuning adapter: $adapterName"

    foreach ($item in $settings.GetEnumerator()) {
        try {
            Set-NetAdapterAdvancedProperty `
                -Name $adapterName `
                -DisplayName $item.Key `
                -DisplayValue $item.Value `
                -ErrorAction SilentlyContinue
        } catch {}
    }

    #Write-Host "Restarting adapter..."
    Disable-NetAdapter -Name $adapterName -Confirm:$false
    Start-Sleep -Seconds 3
    Enable-NetAdapter -Name $adapterName -Confirm:$false

    #Write-Host "Success" -ForegroundColor Green
    Start-Sleep -Seconds 1
}
function Reset-Default {
    
    Apply-Settings $ResetDefault
    
    #Clear-Host
    #Write-Host "Resetting..." -ForegroundColor Yellow

    powercfg -setactive SCHEME_BALANCED | Out-Null
        # ลบ Performance Dekslum ถ้ามี
    $planName = "Performance Dekslum"
    $existing = powercfg -l | Select-String $planName
    if ($existing) {
        $oldGUID = ($existing -split '\s+')[3]
        powercfg -delete $oldGUID | Out-Null
    }

    bcdedit /deletevalue disabledynamictick | Out-Null
    bcdedit /deletevalue tscsyncpolicy | Out-Null
    bcdedit /deletevalue useplatformclock | Out-Null

    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 10 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 20 /f | Out-Null

    netsh int tcp reset | Out-Null
    
    #Write-Host "Success" -ForegroundColor Green

# ============================================ # RESET GhostBoost Safe Tweaks # ============================================

# 1️⃣ Disable Hardware GPU Scheduling (กลับเป็นค่า default)
New-ItemProperty `
-Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" `
-Name "HwSchMode" `
-PropertyType DWord `
-Value 1 `
-Force | Out-Null

# 2️⃣ Enable Mouse Acceleration (ค่า Windows ปกติ)
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Value "1"
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Value "6"
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Value "10"

# 3️⃣ Disable Game Mode (ค่า default)
New-ItemProperty `
-Path "HKCU:\Software\Microsoft\GameBar" `
-Name "AllowAutoGameMode" `
-PropertyType DWord `
-Value 0 `
-Force | Out-Null

# 4️⃣ Enable Game DVR (กลับค่าเดิม)
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 1 /f | Out-Null


# ลบ Priority ที่ตั้งไว้
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FiveM_GTAProcess.exe" /f | Out-Null

# Enable Background Apps (Default)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BackgroundAppGlobalToggle /t REG_DWORD /d 1 /f | Out-Null


    # ==== หน้าจอแบบในรูป ====
    Write-Host ""
    Write-Host "Successfully" -ForegroundColor Green
    Write-Host "Press Enter to continue..." -ForegroundColor White
    Read-Host
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


                                                                                  ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗   ██╗███╗   ███╗
                                                                                  ██╔══██╗██╔════╝██║ ██╔╝██╔════╝██║     ██║   ██║████╗ ████║
                                                                                  ██║  ██║█████╗  █████╔╝ ███████╗██║     ██║   ██║██╔████╔██║
                                                                                  ██║  ██║██╔══╝  ██╔═██╗ ╚════██║██║     ██║   ██║██║╚██╔╝██║
                                                                                  ██████╔╝███████╗██║  ██╗███████║███████╗╚██████╔╝██║ ╚═╝ ██║
                                                                                  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝
                                                                                 ═══════════════════════════════════════════════════════════════
                                                                                            Gamer Performance Acceleration System v2.0
                                                                                 ═══════════════════════════════════════════════════════════════



