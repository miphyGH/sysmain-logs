<# 
  mc_ghost_scanner_fixed.ps1
  - Fixed Join-Path / array issues
  - Shows progress
  - Scans: .minecraft, Downloads, Desktop, Documents, Temp, AppData, Prefetch
  - Prints results to console (no JSON by default)
#>

[CmdletBinding()]
param()

function G($t){ Write-Host $t -ForegroundColor Green }
function Y($t){ Write-Host $t -ForegroundColor Yellow }
function R($t){ Write-Host $t -ForegroundColor Red }
function I($t){ Write-Host $t -ForegroundColor Gray }

# Ensure elevated
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { R "`n[!] Run PowerShell as Administrator and re-run the script."; exit 1 }

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "        Minecraft Ghost Client Scanner"
Write-Host "==============================================" -ForegroundColor Cyan

# build scan root paths safely with Join-Path
$user = $env:USERPROFILE
$pathsToScan = @()
$pathsToScan += (Join-Path $user ".minecraft")
$pathsToScan += (Join-Path $user "Downloads")
$pathsToScan += (Join-Path $user "Desktop")
$pathsToScan += (Join-Path $user "Documents")
$pathsToScan += $env:TEMP
$pathsToScan += (Join-Path $user "AppData")

# Prefetch folder (scan separately)
$prefetchFolder = Join-Path $env:WINDIR "Prefetch"

# detection regex — targeted + generic (case-insensitive)
$targetNames = @('doomsday','vape','vape-lite','vapev4','vapelite','slinky')
$genericPatterns = @('ghost','client','cheat','inject','javaagent','loader','autoclick')
$targetRegex = ('(?i)(' + ($targetNames + $genericPatterns | Sort-Object -Unique | ForEach-Object { [regex]::Escape($_) }) -join '|' + ')')

# helper: extract prefetch strings (UTF-16 then ASCII fallback)
function Extract-PrefetchStrings {
    param([string]$Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
    } catch { return @() }
    $results = @()

    try {
        $utf16 = [System.Text.Encoding]::Unicode.GetString($bytes) -split "`0"
        $results += ($utf16 | Where-Object { $_.Trim().Length -gt 2 })
    } catch {}

    if ($results.Count -eq 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($b in $bytes) {
            if ($b -ge 32 -and $b -le 126) { [void]$sb.Append([char]$b) } else { [void]$sb.Append(' ') }
        }
        $asciiParts = $sb.ToString() -split '\s+' | Where-Object { $_.Length -gt 2 }
        $results += $asciiParts
    }

    return ($results | Sort-Object -Unique)
}

# helper: inspect zip/jar for matching entries
function Find-InZip {
    param([string]$ZipPath, [string]$Regex)
    $found = @()
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
        foreach ($entry in $zip.Entries) {
            if ($entry.FullName -match $Regex) { $found += $entry.FullName }
        }
        $zip.Dispose()
    } catch {}
    return $found
}

# scan running java/javaw processes
Write-Host "`n[1] Checking running java/javaw processes..." -ForegroundColor Cyan
$javaProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(java|javaw)(\.exe)?$' }

if (-not $javaProcs -or $javaProcs.Count -eq 0) {
    I "No java/javaw processes found."
} else {
    foreach ($p in $javaProcs) {
        $pid = $p.ProcessId
        $cmd = $p.CommandLine
        $exe = $p.ExecutablePath
        $owner = try { ($p | Invoke-CimMethod -MethodName GetOwner).User } catch { "Unknown" }
        $susp = if ($cmd -and ($cmd -match $targetRegex)) { "[SUSPICIOUS]" } else { "[OK]" }
        if ($susp -eq "[SUSPICIOUS]") { Y "$susp PID $pid $($p.Name) Owner:$owner" } else { G "$susp PID $pid $($p.Name) Owner:$owner" }
        I "    Path: $exe"
        I "    Cmd : $cmd`n"
    }
}

# file extensions to check
$extensions = @('*.jar','*.zip','*.exe')

# scan each folder with progress
Write-Host "`n[2] Scanning folders (progress shown)..." -ForegroundColor Cyan
foreach ($root in $pathsToScan) {
    if (-not (Test-Path $root)) { I "Folder not found: $root"; continue }
    Write-Host "`nScanning: $root" -ForegroundColor Gray

    # gather candidate files (this may take time)
    try {
        $files = Get-ChildItem -Path $root -Recurse -Force -ErrorAction SilentlyContinue |
                 Where-Object { -not $_.PSIsContainer -and ($_.Extension -in '.jar','.zip','.exe') }
    } catch {
        I "  Unable to scan $root: $($_.Exception.Message)"
        continue
    }

    $total = $files.Count
    if ($total -eq 0) { I "  No candidate files found in $root"; continue }

    $index = 0
    foreach ($file in $files) {
        $index++
        $percent = [int](($index / $total) * 100)
        Write-Progress -Activity "Scanning files in $root" -Status "$index of $total" -PercentComplete $percent

        $name = $file.Name
        $full = $file.FullName
        $flagged = $false
        $matches = @()

        if ($name -match $targetRegex) { $matches += "NameMatch"; $flagged = $true }

        if ($file.Extension -match '\.jar|\.zip') {
            $inner = Find-InZip -ZipPath $full -Regex $targetRegex
            if ($inner.Count -gt 0) { $matches += ($inner | ForEach-Object { "Inner:$_" }); $flagged = $true }
        }

        if ($flagged) {
            Y ("[FLAG] {0}  ({1})" -f $name, $full)
            foreach ($m in $matches) { I ("       {0}" -f $m) }
        } else {
            G ("{0} (ok)" -f $name)
        }
    }

    Write-Progress -Activity "Scanning files in $root" -Completed
}

# Prefetch scan
Write-Host "`n[3] Scanning Prefetch for Java/Minecraft traces..." -ForegroundColor Cyan
if (Test-Path $prefetchFolder) {
    $pfList = Get-ChildItem -Path $prefetchFolder -Filter "*.pf" -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -match 'MINECRAFT|JAVA|JAVAW' }
    $totalPf = $pfList.Count
    if ($totalPf -eq 0) { I "  No java/minecraft prefetch files found." } else {
        $i = 0
        foreach ($pf in $pfList) {
            $i++
            Write-Progress -Activity "Parsing prefetch files" -Status "$i of $totalPf" -PercentComplete ([int](($i/$totalPf)*100))
            I ("Parsing: {0}" -f $pf.Name)
            $strings = Extract-PrefetchStrings -Path $pf.FullName
            $hits = $strings | Where-Object { $_ -match $targetRegex }
            if ($hits.Count -gt 0) {
                foreach ($h in $hits | Select-Object -Unique) { Y ("  Prefetch hit: {0}" -f $h) }
            } else {
                G "  No suspicious strings found in $($pf.Name)"
            }
        }
        Write-Progress -Activity "Parsing prefetch files" -Completed
    }
} else {
    I "Prefetch folder not found: $prefetchFolder"
}

Write-Host "`nScan complete." -ForegroundColor Cyan
