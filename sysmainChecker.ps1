# Custom Response Header
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "      SYSTEM AUDIT: SYSMAIN ACTIVITY (30 DAYS)      " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# 1. Immediate Status Check
$currentStatus = Get-Service SysMain -ErrorAction SilentlyContinue
if ($currentStatus) {
    $color = if ($currentStatus.Status -eq 'Running') { "Green" } else { "Red" }
    Write-Host "[*] Current SysMain Status: $($currentStatus.Status)" -ForegroundColor $color
    Write-Host "[*] Current Startup Type  : $($currentStatus.StartType)" -ForegroundColor $color
} else {
    Write-Host "[!] SysMain service not found on this system." -ForegroundColor Red
}
Write-Host "----------------------------------------------------"

# 2. Log Audit
$StartTime = (Get-Date).AddDays(-30)

# Query 7040 (Type Change) and 7036 (Start/Stop)
try {
    $Events = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = 7040, 7036
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*SysMain*" }

    if ($Events) {
        foreach ($Event in $Events) {
            $Time = $Event.TimeCreated
            $UserSID = $Event.UserId
            
            # Resolve User
            $UserAccount = "SYSTEM/Service Control Manager"
            if ($UserSID) {
                try { $UserAccount = (New-Object System.Security.Principal.SecurityIdentifier($UserSID)).Translate([System.Security.Principal.NTAccount]).Value } catch {}
            }

            Write-Host "[!] Event Found: $($Time)" -ForegroundColor Yellow
            Write-Host "    Details: $($Event.Message)"
            Write-Host "    Triggered By: $UserAccount"
            Write-Host "----------------------------------------------------"
        }
    } else {
        Write-Host "[-] No logs found for SysMain in the last 30 days." -ForegroundColor Gray
        Write-Host "    Note: If service is disabled but logs are empty, "
        Write-Host "    logs may have been cleared or modified via Registry." -ForegroundColor Yellow
    }
} catch {
    Write-Host "[X] Access Denied. Please run as Administrator." -ForegroundColor Red
}
