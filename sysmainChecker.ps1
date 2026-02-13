Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "      SYSTEM LOG AUDIT: SYSMAIN (SUPERFETCH)        " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$StartTime = (Get-Date).AddDays(-30)

$Events = Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 7040
    StartTime = $StartTime
} -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*SysMain*" }

if ($Events) { 
    foreach ($Event in $Events) {
        $Time = $Event.TimeCreated
        $User = $Event.UserId # This identifies the SID or User Account
        $Message = $Event.Message

        Write-Host "[!] Change Detected" -ForegroundColor Yellow
        Write-Host "Date/Time : $Time"
        Write-Host "Action    : $Message"
        
        try {
            $Account = (New-Object System.Security.Principal.SecurityIdentifier($User)).Translate([System.Security.Principal.NTAccount])
            Write-Host "Changed By: $Account" -ForegroundColor White
        } catch {
            Write-Host "Changed By: SYSTEM/Unknown" -ForegroundColor Gray
        }
        Write-Host "----------------------------------------------------"
    }
} else {
    Write-Host "[+] No SysMain changes found in the last 30 days." -ForegroundColor Green
}
