Clear-Host

$serviceName = "SysMain"
$daysBack = 30
$startDate = (Get-Date).AddDays(-$daysBack)

function Section($text) {
    Write-Host ""
    Write-Host "====================================================" -ForegroundColor DarkGray
    Write-Host " $text" -ForegroundColor Cyan
    Write-Host "====================================================" -ForegroundColor DarkGray
}

function Good($t){ Write-Host $t -ForegroundColor Green }
function Bad($t){ Write-Host $t -ForegroundColor Red }
function Warn($t){ Write-Host $t -ForegroundColor Yellow }
function Info($t){ Write-Host $t -ForegroundColor Gray }

# ================= CURRENT STATUS =================
Section "Current SysMain Status"

$svc = Get-Service $serviceName -ErrorAction SilentlyContinue
$wmi = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"

if (!$svc) {
    Bad "SysMain service not found."
    exit
}

Write-Host "Status       : " -NoNewline
if ($svc.Status -eq "Running") { Good "Running" } else { Bad $svc.Status }

Write-Host "Startup Type : " -NoNewline
if ($wmi.StartMode -eq "Disabled") { Bad "Disabled" }
elseif ($wmi.StartMode -eq "Auto") { Good "Automatic" }
else { Warn $wmi.StartMode }

# ================= CHANGE EVENTS =================
Section "Startup Type Changes (Event ID 7040) - Last $daysBack Days"

$events = Get-WinEvent -FilterHashtable @{
    LogName='System'
    ProviderName='Service Control Manager'
    Id=7040
    StartTime=$startDate
} | Where-Object { $_.Message -match $serviceName }

if (!$events) {
    Warn "No startup type changes found."
    exit
}

foreach ($event in $events) {

    Write-Host ""
    Write-Host "Time        : " -NoNewline
    Write-Host $event.TimeCreated -ForegroundColor Magenta

    if ($event.Message -match "disabled") {
        Bad "Action      : DISABLED"
    }
    elseif ($event.Message -match "auto") {
        Good "Action      : Set to AUTOMATIC"
    }
    elseif ($event.Message -match "demand") {
        Warn "Action      : Set to MANUAL"
    }

    # ==== Determine Who / Source ====
    $windowStart = $event.TimeCreated.AddMinutes(-3)
    $windowEnd   = $event.TimeCreated.AddMinutes(3)

    $procEvents = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        Id=4688
        StartTime=$windowStart
        EndTime=$windowEnd
    } -ErrorAction SilentlyContinue

    $sourceType = "Unknown"
    $userFound = $null

    foreach ($p in $procEvents) {

        $msg = $p.Message

        if ($msg -match "sc.exe" -or $msg -match "powershell.exe") {
            $sourceType = "Manual (User Command)"
            $userFound = $p.Properties[1].Value
        }

        if ($msg -match "TrustedInstaller.exe" -or $msg -match "TiWorker.exe") {
            $sourceType = "System / Windows Update"
            $userFound = "NT AUTHORITY\SYSTEM"
        }
    }

    Write-Host "Source      : " -NoNewline
    if ($sourceType -match "Manual") { Warn $sourceType }
    elseif ($sourceType -match "System") { Good $sourceType }
    else { Info "Could not determine (Auditing may be disabled)" }

    if ($userFound) {
        Write-Host "User        : " -NoNewline
        Write-Host $userFound -ForegroundColor Yellow
    }

    Write-Host ""
    Info "Raw Event Message:"
    Write-Host $event.Message -ForegroundColor DarkGray
    Write-Host "----------------------------------------------------" -ForegroundColor DarkGray
}

Section "Service State Changes (Event ID 7036)"

$stateEvents = Get-WinEvent -FilterHashtable @{
    LogName='System'
    ProviderName='Service Control Manager'
    Id=7036
    StartTime=$startDate
} | Where-Object { $_.Message -match $serviceName }

foreach ($s in $stateEvents) {
    Write-Host ""
    Write-Host "Time   : " -NoNewline
    Write-Host $s.TimeCreated -ForegroundColor Magenta
    Info $s.Message
}

Section "Audit Complete"
