Clear-Host

$serviceName = "SysMain"
$daysBack = 30
$startDate = (Get-Date).AddDays(-$daysBack)

function Write-Section($text) {
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor DarkGray
    Write-Host " $text" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor DarkGray
}

function Write-Good($text) { Write-Host $text -ForegroundColor Green }
function Write-Bad($text)  { Write-Host $text -ForegroundColor Red }
function Write-Warn($text) { Write-Host $text -ForegroundColor Yellow }

# =========================
# Current Status
# =========================
Write-Section "Current SysMain Service Status"

try {
    $service = Get-Service -Name $serviceName -ErrorAction Stop
    $wmi = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"

    Write-Host "Service Name : " -NoNewline
    Write-Host $service.Name -ForegroundColor White

    Write-Host "Status       : " -NoNewline
    if ($service.Status -eq "Running") {
        Write-Good "Running"
    } else {
        Write-Bad $service.Status
    }

    Write-Host "Startup Type : " -NoNewline
    if ($wmi.StartMode -eq "Disabled") {
        Write-Bad "Disabled"
    } elseif ($wmi.StartMode -eq "Auto") {
        Write-Good "Automatic"
    } else {
        Write-Warn $wmi.StartMode
    }
}
catch {
    Write-Bad "SysMain service not found."
    exit
}

# =========================
# Change History
# =========================
Write-Section "SysMain Changes (Last $daysBack Days)"

$events = Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ProviderName = 'Service Control Manager'
    Id = 7040
    StartTime = $startDate
} | Where-Object { $_.Message -match $serviceName }

if (!$events) {
    Write-Warn "No startup type changes found."
} else {

    foreach ($event in $events) {

        Write-Host ""
        Write-Host "Time : " -NoNewline
        Write-Host $event.TimeCreated -ForegroundColor Magenta

        if ($event.Message -match "disabled") {
            Write-Bad "Action : Service was DISABLED"
        }
        elseif ($event.Message -match "auto") {
            Write-Good "Action : Service set to AUTOMATIC"
        }
        elseif ($event.Message -match "demand") {
            Write-Warn "Action : Service set to MANUAL"
        }
        $windowStart = $event.TimeCreated.AddMinutes(-3)
        $windowEnd   = $event.TimeCreated.AddMinutes(3)

        $procEvents = Get-WinEvent -FilterHashtable @{
            LogName='Security'
            Id=4688
            StartTime=$windowStart
            EndTime=$windowEnd
        } -ErrorAction SilentlyContinue

        $matches = $procEvents | Where-Object {
            $_.Message -match "sc.exe" -or
            $_.Message -match "powershell.exe" -or
            $_.Message -match "services.exe"
        }

        if ($matches) {
            foreach ($m in $matches) {
                $user = ($m.Properties[1].Value)
                Write-Host "Possible User : " -NoNewline
                Write-Host $user -ForegroundColor Yellow
            }
        } else {
            Write-Warn "User info not available (Auditing likely disabled at time of change)."
        }

        Write-Host "---------------------------------------------" -ForegroundColor DarkGray
    }
}

Write-Section "Audit Complete"
