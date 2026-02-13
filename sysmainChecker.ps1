[CmdletBinding()]
param()

function G($t){ Write-Host $t -ForegroundColor Green }
function Y($t){ Write-Host $t -ForegroundColor Yellow }
function R($t){ Write-Host $t -ForegroundColor Red }
function I($t){ Write-Host $t -ForegroundColor Gray }

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { R "`n[!] Run PowerShell as Administrator."; exit 1 }

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "        Minecraft Ghost Client Scanner"
Write-Host "==============================================" -ForegroundColor Cyan

$user = $env:USERPROFILE

$pathsToScan = @(
    (Join-Path $user ".minecraft")
    (Join-Path $user "Downloads")
    (Join-Path $user "Desktop")
    (Join-Path $user "Documents")
    (Join-Path $user "AppData")
    $env:TEMP
)

$prefetchFolder = Join-Path $env:WINDIR "Prefetch"

$targetNames = @('doomsday','vape','vape-lite','vapev4','vapelite','slinky')
$genericPatterns = @('autoclick','ghost','client','cheat','inject','javaagent','loader','autoclicker','injector')

$allTargets = ($targetNames + $genericPatterns) | Sort-Object -Unique
$escapedTargets = $allTargets | ForEach-Object { [regex]::Escape($_) }
$targetRegex = '(?i)(' + ($escapedTargets -join '|') + ')'

function Extract-PrefetchStrings {
    param([string]$Path)

    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
    } catch {
        return @()
    }

    $results = @()

    try {
        $utf16 = [System.Text.Encoding]::Unicode.GetString($bytes) -split "`0"
        $results += ($utf16 | Where-Object { $_.Trim().Length -gt 2 })
    } catch {}

    if ($results.Count -eq 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($b in $bytes) {
            if ($b -ge 32 -and $b -le 126) {
                [void]$sb.Append([char]$b)
            } else {
                [void]$sb.Append(' ')
            }
        }
        $asciiParts = $sb.ToString() -split '\s+' | Where-Object { $_.Trim().Length -gt 2 }
        $results += $asciiParts
    }

    return ($results | Sort-Object -Unique)
}

function Find-InZip {
    param([string]$ZipPath, [string]$Regex)

    $found = @()

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)

        foreach ($entry in $zip.Entries) {
            if ($entry.FullName -match $Regex) {
                $found += $entry.FullName
            }
        }

        $zip.Dispose()
    } catch {}

    return $found
}

Write-Host "`n[1] Checking running java/javaw processes..." -ForegroundColor Cyan

$javaProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
Where-Object {
    $_.Name -match '^(java|javaw)(\.exe)?$' -or
    ($_.CommandLine -and $_.CommandLine -match '(?i)minecraft')
}

if (-not $javaProcs) {
    I "No java/javaw processes found."
} else {
    foreach ($p in $javaProcs) {
        try {
            $pid = $p.ProcessId
            $cmd = $p.CommandLine
            $exe = $p.ExecutablePath
            $owner = try { ($p | Invoke-CimMethod -MethodName GetOwner).User } catch { "Unknown" }

            if ($cmd -and ($cmd -match $targetRegex)) {
                Y "[SUSPICIOUS] PID $pid $($p.Name) Owner:$owner"
            } else {
                G "[OK] PID $pid $($p.Name) Owner:$owner"
            }

            I "    Path: $exe"
            I "    Cmd : $cmd`n"
        } catch {
            I "Process read error."
        }
    }
}

Write-Host "`n[2] Scanning folders..." -ForegroundColor Cyan

foreach ($root in $pathsToScan) {

    if (-not (Test-Path $root)) { continue }

    Write-Host "`nScanning: $root" -ForegroundColor Gray

    $files = Get-ChildItem -Path $root -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { -not $_.PSIsContainer -and ($_.Extension -in '.jar','.zip','.exe') }

    $total = $files.Count
    if ($total -eq 0) { continue }

    $i = 0

    foreach ($file in $files) {
        $i++
        Write-Progress -Activity "Scanning $root" -Status "$i of $total" -PercentComplete ([int](($i/$total)*100))

        $flagged = $false
        $matches = @()

        if ($file.Name -match $targetRegex) {
            $flagged = $true
            $matches += "NameMatch"
        }

        if ($file.Extension -match '\.jar|\.zip') {
            $inner = Find-InZip -ZipPath $file.FullName -Regex $targetRegex
            if ($inner.Count -gt 0) {
                $flagged = $true
                $matches += $inner
            }
        }

        if ($flagged) {
            Y "[FLAG] $($file.FullName)"
            foreach ($m in $matches) { I "   $m" }
        }
    }

    Write-Progress -Activity "Scanning $root" -Completed
}

Write-Host "`n[3] Scanning Prefetch..." -ForegroundColor Cyan

if (Test-Path $prefetchFolder) {

    $pfList = Get-ChildItem $prefetchFolder -Filter "*.pf" |
    Where-Object { $_.Name -match 'MINECRAFT|JAVA|JAVAW' }

    foreach ($pf in $pfList) {

        I "Parsing: $($pf.Name)"

        $strings = Extract-PrefetchStrings $pf.FullName
        $hits = $strings | Where-Object { $_ -match $targetRegex }

        foreach ($h in $hits | Select-Object -Unique) {
            Y "  Prefetch hit: $h"
        }
    }
}

Write-Host "`nScan complete." -ForegroundColor Cyan
