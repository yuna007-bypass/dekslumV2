#Requires -RunAsAdministrator

Clear-Host
Write-Host "1 : Install Dekslum"
Write-Host "2 : Uninstall Dekslum"
Write-Host ""
$choice = Read-Host "Select (1/2)"

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# -------- OPTION 1 : BOOST --------
function Run-Boost {

    Write-Host "Applying Windows Core Boost..." -ForegroundColor Yellow

    powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
    $ultimate = powercfg -l | Select-String "Ultimate Performance"
    if ($ultimate) {
        $guid = ($ultimate -split '\s+')[3]
        powercfg -setactive $guid
    }

    bcdedit /set disabledynamictick yes
    bcdedit /set tscsyncpolicy Enhanced

    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f

    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Priority /t REG_DWORD /d 6 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d High /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d High /f

    reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f

    netsh int tcp set global autotuninglevel=normal
    netsh int tcp set global rss=enabled
    netsh int tcp set global ecncapability=disabled
    netsh int tcp set global timestamps=disabled

    bcdedit /deletevalue useplatformclock

    Write-Host ""
    Write-Host "Boost Applied Successfully!" -ForegroundColor Green
    Write-Host ">> Restart Computer <<" -ForegroundColor Magenta
}

# -------- OPTION 2 : RESET --------
function Reset-Default {

    Write-Host "Resetting System..." -ForegroundColor Yellow

    powercfg -setactive SCHEME_BALANCED

    bcdedit /deletevalue disabledynamictick
    bcdedit /deletevalue tscsyncpolicy
    bcdedit /set useplatformclock true

    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 10 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 20 /f

    netsh int tcp reset

    Write-Host ""
    Write-Host "System Restored to Default!" -ForegroundColor Green
    Write-Host ">> Restart Computer <<" -ForegroundColor Magenta
}

# -------- MENU CONTROL --------
switch ($choice) {
    "1" { Run-Boost }
    "2" { Reset-Default }
    default { Write-Host "Invalid Selection" -ForegroundColor Red }
}