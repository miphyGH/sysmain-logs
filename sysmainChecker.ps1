Clear-Host

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

# ================= SYSMAIN STATUS =================
Section "SysMain Current Status"

$svc = Get-Service "SysMain" -ErrorAction SilentlyContinue
$wmi = Get-CimInstance Win32_Service -Filter "Name='SysMain'"

if (!$svc) {
    Bad "SysMain not found."
} else {
    Write-Host "Status       : " -NoNewline
    if ($svc.Status -eq "Running") { Good "Running" } else { Bad $svc.Status }

    Write-Host "Startup Type : " -NoNewline
    if ($wmi.StartMode -eq "Disabled") { Bad "Disabled" }
    elseif ($wmi.StartMode -eq "Auto") { Good "Automatic" }
    else { Warn $wmi.StartMode }
}

# ================= SYSMAIN CHANGE HISTORY =================
Section "SysMain Startup Type Change History (Event 7040)"

$events = Get-WinEvent -FilterHashtable @{
    LogName='System'
    ProviderName='Service Control Manager'
    Id=7040
} -ErrorAction SilentlyContinue |
Where-Object { $_.Message -match "SysMain" }

if (!$events) {
    Warn "No change events found."
} else {
    foreach ($event in $events) {

        Write-Host ""
        Write-Host "Time   : " -NoNewline
        Write-Host $event.TimeCreated -ForegroundColor Magenta

        if ($event.Message -match "to disabled") {
            Bad "Action : DISABLED"
        }
        elseif ($event.Message -match "to auto") {
            Good "Action : AUTOMATIC"
        }
        elseif ($event.Message -match "to demand") {
            Warn "Action : MANUAL"
        }
        else {
            Info "Action : Modified"
        }

        Write-Host "--------------------------------------------------" -ForegroundColor DarkGray
    }
}

# ================= PREFETCH DETAILED ANALYSIS =================
Section "Java / Minecraft Prefetch Analysis"

$prefetchPath = "$env:SystemRoot\Prefetch"

if (!(Test-Path $prefetchPath)) {
    Bad "Prefetch folder not accessible."
    exit
}

$pfFiles = Get-ChildItem $prefetchPath -ErrorAction SilentlyContinue |
Where-Object {
    $_.Name -match "JAVA" -or
    $_.Name -match "MINECRAFT"
}

if (!$pfFiles) {
    Warn "No Java or Minecraft related prefetch files found."
} else {

    foreach ($pf in $pfFiles) {

        Write-Host ""
        Write-Host "Prefetch File : " -NoNewline
        Write-Host $pf.Name -ForegroundColor Yellow

        Write-Host "Full Path     : $($pf.FullName)"
        Write-Host "File Size     : $([Math]::Round($pf.Length/1KB,2)) KB"
        Write-Host "Last Modified : $($pf.LastWriteTime)"

        # Try to extract executable name from filename
        $exeName = ($pf.Name -split "-")[0]
        Write-Host "Executable    : $exeName"

        # Attempt basic run count extraction (best effort)
        try {
            $bytes = [System.IO.File]::ReadAllBytes($pf.FullName)
            $runCount = [BitConverter]::ToInt32($bytes, 0xD0)
            Write-Host "Run Count     : $runCount"
        }
        catch {
            Write-Host "Run Count     : Unable to parse"
        }

        Write-Host "--------------------------------------------------" -ForegroundColor DarkGray
    }
}

Section "Scan Complete"
