# ==============================
# SysMain Status & Change Audit
# ==============================

$serviceName = "SysMain"
$daysBack = 30
$startDate = (Get-Date).AddDays(-$daysBack)

Write-Host "====================================="
Write-Host " Current SysMain Service Status"
Write-Host "====================================="

try {
    $service = Get-Service -Name $serviceName -ErrorAction Stop
    $startType = (Get-CimInstance Win32_Service -Filter "Name='$serviceName'").StartMode

    Write-Host "Service Name : $($service.Name)"
    Write-Host "Status       : $($service.Status)"
    Write-Host "Startup Type : $startType"
}
catch {
    Write-Host "SysMain service not found."
    exit
}

Write-Host "`n====================================="
Write-Host " SysMain Changes (Last $daysBack Days)"
Write-Host "====================================="

# Get Service Control Manager events
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ProviderName = 'Service Control Manager'
    Id = 7040,7036
    StartTime = $startDate
} | Where-Object {
    $_.Message -match $serviceName
}

if (!$events) {
    Write-Host "No SysMain changes found in the last $daysBack days."
    exit
}

foreach ($event in $events) {

    Write-Host "`n-------------------------------------"
    Write-Host "Time      : $($event.TimeCreated)"
    Write-Host "Event ID  : $($event.Id)"

    if ($event.Id -eq 7040) {
        Write-Host "Type      : Startup Type Change"
    }
    elseif ($event.Id -eq 7036) {
        Write-Host "Type      : Service State Change"
    }

    Write-Host "Details   :"
    Write-Host $event.Message

    # Attempt correlation with Security log
    $timeWindowStart = $event.TimeCreated.AddMinutes(-2)
    $timeWindowEnd   = $event.TimeCreated.AddMinutes(2)

    $securityEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        StartTime = $timeWindowStart
        EndTime = $timeWindowEnd
    } -ErrorAction SilentlyContinue

    $possibleUsers = $securityEvents | Where-Object {
        $_.Id -in 4688,4670,4697
    }

    if ($possibleUsers) {
        Write-Host "`nPossible Responsible User(s):"
        foreach ($sec in $possibleUsers) {
            Write-Host " - $($sec.Properties[1].Value) (Event ID: $($sec.Id))"
        }
    }
    else {
        Write-Host "`nUser info: Not available (Advanced auditing may not be enabled)."
    }
}

Write-Host "`n====================================="
Write-Host " Audit Complete"
Write-Host "====================================="
