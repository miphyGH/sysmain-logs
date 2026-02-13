Clear-Host
$serviceName = "SysMain"

function Section($text) {
    Write-Host ""
    Write-Host "==================================================" -ForegroundColor DarkGray
    Write-Host " $text" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor DarkGray
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

# ================= STARTUP TYPE CHANGES =================
Section "Startup Type Change History (Event ID 7040)"

$events = Get-WinEvent -FilterHashtable @{
    LogName='System'
    ProviderName='Service Control Manager'
    Id=7040
} -ErrorAction SilentlyContinue |
Where-Object { $_.Message -match $serviceName }

if (!$events) {
    Warn "No startup type change events found."
}
else {
    foreach ($event in $events) {

        Write-Host ""
        Write-Host "Time        : " -NoNewline
        Write-Host $event.TimeCreated -ForegroundColor Magenta

        # Determine change direction
        if ($event.Message -match "to disabled") {
            Bad "Action      : Service DISABLED"
        }
        elseif ($event.Message -match "to auto") {
            Good "Action      : Set to AUTOMATIC"
        }
        elseif ($event.Message -match "to demand") {
            Warn "Action      : Set to MANUAL"
        }
        else {
            Info "Action      : Startup type modified"
        }

        # Try to determine source
        $windowStart = $event.TimeCreated.AddMinutes(-2)
        $windowEnd   = $event.TimeCreated.AddMinutes(2)

        $procEvents = Get-WinEvent -FilterHashtable @{
            LogName='Security'
            Id=4688
            StartTime=$windowStart
            EndTime=$windowEnd
        } -ErrorAction SilentlyContinue

        $source = "Unknown"
        foreach ($p in $procEvents) {
            $msg = $p.Message

            if ($msg -match "TrustedInstaller.exe" -or $msg -match "TiWorker.exe") {
                $source = "System (Windows Update)"
            }
            elseif ($msg -match "sc.exe" -or $msg -match "powershell.exe") {
                $source = "Manual (User Command)"
            }
        }

        Write-Host "Source      : " -NoNewline
        if ($source -match "System") { Good $source }
        elseif ($source -match "Manual") { Warn $source }
        else { Info "Unknown (Auditing likely disabled)" }

        Write-Host "--------------------------------------------------" -ForegroundColor DarkGray
    }
}

Section "Audit Complete"
