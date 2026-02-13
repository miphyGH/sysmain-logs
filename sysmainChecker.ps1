# ==========================
# Minecraft Ghost Client Detector (Simplified)
# Only scans Minecraft-related folders
# ==========================

[CmdletBinding()]
param()

function G($t){ Write-Host $t -ForegroundColor Green }
function Y($t){ Write-Host $t -ForegroundColor Yellow }
function R($t){ Write-Host $t -ForegroundColor Red }
function I($t){ Write-Host $t -ForegroundColor Gray }

# Check Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    R "`n[!] Run as Administrator!"
    exit 1
}

# Paths to scan
$user = $env:USERPROFILE
$pathsToScan = @(
    "$user\.minecraft",
    "$user\Downloads",
    "$user\Desktop",
    "$env:TEMP"
)

# Detection patterns
$targetNames = @('doomsday','vape','vape-lite','vapev4','slinky')
$genericPatterns = @('ghost','client','cheat','inject','javaagent')
$targetRegex = ('(?i)(' + ($targetNames + $genericPatterns | Sort-Object -Unique | ForEach-Object { [regex]::Escape($_) }) -join '|' + ')')

# Prefetch helper
function ExtractPrefetchStrings([string]$pfPath){
    try {
        $bytes = [System.IO.File]::ReadAllBytes($pfPath)
        $utf16 = [System.Text.Encoding]::Unicode.GetString($bytes) -split "`0"
        return ($utf16 | Where-Object { $_.Trim().Length -gt 2 } | Sort-Object -Unique)
    } catch { return @() }
}

# ------------------------
Write-Host "=============================="
Write-Host " Minecraft Ghost Client Scan"
Write-Host "==============================" -ForegroundColor Cyan

# 1) Running Java Processes
Write-Host "`n[>] Checking running java/javaw processes..." -ForegroundColor Cyan
$javaProcs = Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(java|javaw)(\.exe)?$' }

if ($javaProcs.Count -eq 0) { I "No java/javaw processes found." } else {
    foreach ($p in $javaProcs) {
        try {
            $cmd = $p.CommandLine
            $exe = $p.ExecutablePath
            $owner = try { ($p | Invoke-CimMethod -MethodName GetOwner).User } catch { "Unknown" }
            $susp = if ($cmd -match $targetRegex) { "[SUSPICIOUS]" } else { "[OK]" }

            Write-Host "$susp PID $($p.ProcessId) $($p.Name) Owner:$owner"
            Write-Host "    Cmd: $cmd"
            Write-Host "    Path: $exe`n"
        } catch {}
    }
}

# 2) File System Scan (Minecraft / Downloads / Desktop / Temp)
Write-Host "`n[>] Scanning folders for suspicious files..." -ForegroundColor Cyan
$extensions = @('*.jar','*.zip','*.exe')
foreach ($root in $pathsToScan) {
    if (Test-Path $root) {
        I "Scanning: $root"
        foreach ($ext in $extensions) {
            Get-ChildItem -Path $root -Recurse -Include $ext -ErrorAction SilentlyContinue | ForEach-Object {
                $name = $_.Name
                $full = $_.FullName
                $matches = @()
                if ($name -match $targetRegex) { $matches += "NameMatch" }

                # Check inside zip/jar
                if ($_.Extension -match '\.jar|\.zip') {
                    try {
                        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
                        $zip = [System.IO.Compression.ZipFile]::OpenRead($full)
                        foreach ($entry in $zip.Entries) {
                            if ($entry.FullName -match $targetRegex) { $matches += "InnerZipMatch:$($entry.FullName)" }
                        }
                        $zip.Dispose()
                    } catch {}
                }

                if ($matches.Count -gt 0) {
                    Y "[FLAG] $name Path:$full"
                    foreach ($m in $matches) { I "       $m" }
                } else {
                    G "$name (OK)"
                }
            }
        }
    } else { R "Folder not found: $root" }
}

# 3) Prefetch scan for Java/Minecraft
Write-Host "`n[>] Checking Prefetch files..." -ForegroundColor Cyan
$pfFolder = "$env:WINDIR\Prefetch"
if (Test-Path $pfFolder) {
    Get-ChildItem -Path $pfFolder -Filter "*.pf" | Where-Object { $_.Name -match "MINECRAFT|JAVA|JAVAW" } | ForEach-Object {
        I "Parsing: $($_.Name)"
        $strings = ExtractPrefetchStrings $_.FullName
        $hits = $strings | Where-Object { $_ -match $targetRegex }
        if ($hits.Count -gt 0) {
            foreach ($h in $hits) { Y "  Prefetch hit: $h" }
        } else { G "  No suspicious strings found." }
    }
} else { R "Prefetch folder not found." }

Write-Host "`nScan Complete."
