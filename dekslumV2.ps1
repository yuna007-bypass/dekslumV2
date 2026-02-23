# 1. Windows Ultimate Performance
Write-Host "Enabling Ultimate Performance..." -ForegroundColor Cyan
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61

# 2. Disable Dynamic Tick & Set TSC Sync
Write-Host "Configuring Boot Settings (Dynamic Tick & HPET)..." -ForegroundColor Cyan
bcdedit /set disabledynamictick yes
bcdedit /set tscsyncpolicy Enhanced
bcdedit /deletevalue useplatformclock # Disable HPET

# 3. Registry Gaming Priority & System Profile
Write-Host "Optimizing Registry for Gaming..." -ForegroundColor Cyan
$Paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
    "HKCU:\System\GameConfigStore"
)

foreach ($Path in $Paths) { if (!(Test-Path $Path)) { New-Item -Path $Path -Force } }

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Value 8 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Value 6 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Value "High"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Value "High"
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord

# 4. Network Optimization
Write-Host "Optimizing Network Settings..." -ForegroundColor Cyan
netsh int tcp set global autotuninglevel=normal
netsh int tcp set global rss=enabled
netsh int tcp set global ecncapability=disabled
netsh int tcp set global timestamps=disabled

Write-Host "Done! Please restart your computer for all changes to take effect." -ForegroundColor Green