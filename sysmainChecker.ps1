<#
mc_cheat_scanner.ps1
All-in-one Minecraft ghost client / injectable detector (local, read-only)

Run as Administrator.
Saves results to: C:\Temp\mc_cheat_scan_<timestamp>.json (and .csv)
#>

[CmdletBinding()]
param(
    [string]$OutputDir = "C:\Temp",
    [switch]$OnlyMinecraftFiles  # if set, only scan Minecraft-related locations
)

function Write-Section($t){ Write-Host ""; Write-Host "===================================================" -ForegroundColor DarkGray; Write-Host " $t" -ForegroundColor Cyan; Write-Host "===================================================" -ForegroundColor DarkGray }
function G($t){ Write-Host $t -ForegroundColor Green }
function Y($t){ Write-Host $t -ForegroundColor Yellow }
function R($t){ Write-Host $t -ForegroundColor Red }
function I($t){ Write-Host $t -ForegroundColor Gray }

# Check admin
$isAdmin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    R "`n╔══════════════════════════════════════════════════╗"
    R "║           ADMINISTRATOR PRIVILEGES REQUIRED       ║"
    R "║     Please run this script as Administrator!      ║"
    R "╚══════════════════════════════════════════════════╝`n"
    exit 1
}

# Ensure output dir
if (-not (Test-Path $OutputDir)) { New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null }
$ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
$outJson = Join-Path $OutputDir "mc_cheat_scan_$ts.json"
$outCsv  = Join-Path $OutputDir "mc_cheat_scan_$ts.csv"

# detection patterns — targeted + generic
$targetNames = @(
    'doomsday','vape','vape-lite','vapev4','vape_v4','vapev4','vapelite','slinky'
)
$genericPatterns = @(
    'ghost','client','cheat','inject','injection','killaura','aimbot','velocity','xray','autoclick','autoclicker','dllinject','loader','jar-inject','javaagent'
)
# combine into regex (case-insensitive)
$targetRegex = ('(?i)(' + ($targetNames + $genericPatterns | Sort-Object -Unique | ForEach-Object { [regex]::Escape($_) }) -join '|' + ')')

# locations to scan for files
$user = $env:USERPROFILE
$pathsToScan = @(
    Join-Path $user ".minecraft",
    Join-Path $user "Downloads",
    Join-Path $user "Desktop",
    "$env:TEMP",
    "$env:TEMP\..\Local\Temp"  # fallback
)
# also include Program Files, Program Files (x86), common browser download locations
$pathsToScan += @("C:\Program Files","C:\Program Files (x86)")

if ($OnlyMinecraftFiles) {
    $pathsToScan = $pathsToScan | Where-Object { $_ -match "\\\.minecraft|Downloads|Desktop|Temp" }
}

# helper functions
function Hash-FileSHA256($path){
    try { (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return $null }
}

function Find-InZip($zipPath, [string]$pattern){
    try {
        $matches = @()
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        foreach ($entry in $zip.Entries) {
            if ($entry.FullName -match $pattern) { $matches += $entry.FullName }
        }
        $zip.Dispose()
        return $matches
    } catch { return @() }
}

function ExtractPrefetchStrings([string]$pfPath){
    # robust extraction: try Section C (best), then UTF16 fallback then ASCII fallback
    $bytes = [System.IO.File]::ReadAllBytes($pfPath)
    $results = [System.Collections.Generic.List[string]]::new()

    # try section offsets heuristically
    try {
        $version = [BitConverter]::ToUInt32($bytes,0)
        switch ($version) {
            17 { $offC = [BitConverter]::ToUInt32($bytes,0x44); $lenC = [BitConverter]::ToUInt32($bytes,0x48) }
            23 { $offC = [BitConverter]::ToUInt32($bytes,0x50); $lenC = [BitConverter]::ToUInt32($bytes,0x54) }
            26 { $offC = [BitConverter]::ToUInt32($bytes,0x50); $lenC = [BitConverter]::ToUInt32($bytes,0x54) }
            30 { $offC = [BitConverter]::ToUInt32($bytes,0x50); $lenC = [BitConverter]::ToUInt32($bytes,0x54) }
            default { $offC = 0; $lenC = 0 }
        }
        if ($lenC -gt 0 -and ($offC + $lenC) -le $bytes.Length) {
            $section = $bytes[$offC..($offC + $lenC - 1)]
            $s = [System.Text.Encoding]::Unicode.GetString($section) -split "`0"
            foreach ($x in $s) { if ($x -and $x.Trim().Length -gt 2) { $results.Add($x.Trim()) } }
        }
    } catch {}

    if ($results.Count -eq 0) {
        # UTF-16LE full decode
        try {
            $utf16 = [System.Text.Encoding]::Unicode.GetString($bytes) -split "`0"
            foreach ($x in $utf16) { if ($x -and $x.Trim().Length -gt 2) { $results.Add($x.Trim()) } }
        } catch {}
    }

    if ($results.Count -eq 0) {
        # ascii fallback
        $sb = New-Object System.Text.StringBuilder
        foreach ($b in $bytes) {
            if ($b -ge 32 -and $b -le 126) { [void]$sb.Append([char]$b) } else { [void]$sb.Append(' ') }
        }
        $asciiParts = $sb.ToString() -split '\s+' | Where-Object { $_ -and $_.Length -gt 2 }
        foreach ($x in $asciiParts) { $results.Add($x.Trim()) }
    }

    return ($results | Sort-Object -Unique)
}

# collector
$Report = [ordered]@{
    ScanTime = (Get-Date).ToString("o")
    Hostname = $env:COMPUTERNAME
    User     = $env:USERNAME
    Findings = @()
    Summary  = @{}
}

Write-Section "Minecraft Ghost Client Scanner"
I "Scanning locations (this may take a few seconds)..."
I "Output will be saved to: $outJson"

# 1) Inspect running java/javaw processes (commandlines, javaagents, modules)
Write-Section "Running Java Processes"
$javaProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(java|javaw)(\.exe)?$' -or ($_.CommandLine -and $_.CommandLine -match '(?i)minecraft') }

if ($javaProcs.Count -eq 0) { I "No java/javaw processes found." } else {
    foreach ($p in $javaProcs) {
        try {
            $pid = $p.ProcessId
            $cmd = $p.CommandLine
            $exe = $p.ExecutablePath
            $owner = $null
            try { $owner = ($p | Invoke-CimMethod -MethodName GetOwner).User } catch {}

            $note = ""
            if ($cmd -match '(?i)-javaagent:([^\s]+)') {
                $note = "javaagent: $($matches[1])"
            }

            # check for suspicious tokens in commandline
            $susMatches = @()
            if ($cmd -and ($cmd -match $targetRegex)) { $susMatches += "CommandLineContainsTarget" }
            if ($cmd -and ($cmd -match '(?i)-javaagent|--tweakClass|-cp|classpath')) { $susMatches += "CustomJavaArgs" }

            # try to get module list (may require elevation)
            $modules = @()
            try {
                $gp = Get-Process -Id $pid -ErrorAction Stop
                foreach ($m in $gp.Modules) { $modules += $m.ModuleName }
            } catch {}

            $finding = [ordered]@{
                Type = "Process"
                Name = $p.Name
                PID  = $pid
                Executable = $exe
                CommandLine = $cmd
                Owner = $owner
                Modules = $modules
                Notes = $susMatches
                Timestamp = (Get-Date).ToString("o")
            }
            if ($susMatches.Count -gt 0) {
                $Report.Findings += $finding
                Y ("[SUSPICIOUS] PID $pid   $($p.Name)   Owner:$owner")
                Y ("  Cmd: $cmd")
            } else {
                G ("PID $pid   $($p.Name)   Owner:$owner")
                I ("  Cmd: $cmd")
            }
        } catch { R "Error reading process $($p.Name): $($_.Exception.Message)" }
    }
}

# 2) Scan Minecraft / Downloads / Desktop / Temp / Program Files for jars/zips/exes and inspect jars
Write-Section "File System Scan (Minecraft / Downloads / Temp / Desktop / Program Files)"

$extensions = @('*.jar','*.zip','*.exe','*.dll')
$foundFiles = @()

foreach ($root in $pathsToScan) {
    if (-not (Test-Path $root)) { continue }
    I "Scanning: $root"
    try {
        foreach ($ext in $extensions) {
            Get-ChildItem -Path $root -Include $ext -Recurse -ErrorAction SilentlyContinue -Force | ForEach-Object {
                # skip very large/excluded paths
                if ($_.Length -gt 1GB) { continue }
                $foundFiles += $_
            }
        }
    } catch {}
}

# dedupe
$foundFiles = $foundFiles | Sort-Object FullName -Unique

if ($foundFiles.Count -eq 0) { I "No candidate files found." } else {
    foreach ($f in $foundFiles) {
        $name = $f.Name
        $full = $f.FullName
        $hash = Hash-FileSHA256 $full
        $match = @()
        if ($name -match $targetRegex) { $match += "NameMatch" }
        # open jars and zip to check inner entries
        $innerMatches = @()
        if ($f.Extension -match '\.jar|\.zip') {
            try {
                $entries = Find-InZip $full $targetRegex
                if ($entries.Count -gt 0) { $innerMatches += $entries; $match += "ZipInnerMatch" }
                else {
                    # also attempt scanning entry names for generic suspicious libs/classes
                    $entries2 = Find-InZip $full '(?i)(client|cheat|vape|doomsday|slinky|inject|loader|autoclick)'
                    if ($entries2.Count -gt 0) { $innerMatches += $entries2; $match += "ZipInnerGeneric" }
                }
            } catch {}
        }

        # compute a confidence score
        $confidence = 0
        if ($match -contains "NameMatch") { $confidence += 60 }
        if ($match -contains "ZipInnerMatch") { $confidence += 80 }
        if ($match -contains "ZipInnerGeneric") { $confidence += 40 }
        # if located in .minecraft folder or Downloads, increase
        if ($full -match "\\.minecraft\\|Downloads\\|Desktop\\") { $confidence += 10 }
        if ($f.Extension -ieq ".dll" -or $f.Extension -ieq ".exe") { $confidence += 15 }

        $entry = [ordered]@{
            Type = "File"
            Path = $full
            Name = $name
            Extension = $f.Extension
            Size = $f.Length
            SHA256 = $hash
            Matches = ($match + $innerMatches) -join ';'
            Confidence = [math]::Min($confidence,100)
            Timestamp = $f.LastWriteTime.ToString("o")
        }

        if ($entry.Confidence -ge 50) {
            $Report.Findings += $entry
            Y ("[FLAG] $($entry.Name)   Confidence: $($entry.Confidence)%   Path: $($entry.Path)")
            if ($entry.Matches) { I ("  Matches: $($entry.Matches)") }
            I ("  SHA256: $($entry.SHA256)")
        } else {
            I ("$($entry.Name) (ok) - Confidence $($entry.Confidence)%")
        }
    }
}

# 3) Prefetch scan for Minecraft/Java/javaw entries and content
Write-Section "Prefetch / Execution Artifacts Scan"
$pfFolder = "$env:SystemRoot\Prefetch"
if (Test-Path $pfFolder) {
    $pfFiles = Get-ChildItem -Path $pfFolder -Filter "*.pf" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "MINECRAFT|JAVA|JAVAW" }
    if ($pfFiles.Count -eq 0) { I "No java/minecraft prefetch files found." } else {
        foreach ($pf in $pfFiles) {
            I "Parsing: $($pf.Name)"
            $strings = ExtractPrefetchStrings $pf.FullName
            $hits = $strings | Where-Object { $_ -match $targetRegex }
            if ($hits.Count -gt 0) {
                foreach ($h in $hits) {
                    $Report.Findings += [ordered]@{
                        Type = "PrefetchString"
                        File = $pf.Name
                        Match = $h
                        SourcePath = $pf.FullName
                        Timestamp = (Get-Date).ToString("o")
                    }
                }
                Y ("  Prefetch matches: " + ($hits | Select-Object -First 6 -Unique -Join ', '))
            } else {
                I "  No suspicious strings in $($pf.Name)"
            }
        }
    }
} else { I "Prefetch folder not present" }

# 4) Quick registry & scheduled task indicators (common persistence)
Write-Section "Quick Registry & Task Checks"
$regPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($rp in $regPaths) {
    try {
        $items = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
        if ($items) {
            foreach ($prop in $items.PSObject.Properties) {
                $val = $prop.Value.ToString()
                if ($val -match $targetRegex) {
                    $Report.Findings += [ordered]@{ Type="RegistryRun"; Path = $rp; Name=$prop.Name; Value=$val; Timestamp=(Get-Date).ToString("o") }
                    Y ("[REG RUN] $($prop.Name) -> $val")
                }
            }
        }
    } catch {}
}

# 5) Final Summary & Save
Write-Section "Summary"
$total = $Report.Findings.Count
if ($total -eq 0) {
    G "No high-confidence findings. Manual review recommended for any flagged files."
} else {
    Y "Total findings: $total"
    foreach ($f in $Report.Findings) {
        Write-Host ($f | ConvertTo-Json -Depth 2) -ForegroundColor Gray
    }
}

# save outputs
try {
    $Report | ConvertTo-Json -Depth 5 | Out-File -FilePath $outJson -Encoding UTF8
    # a simple CSV of findings for moderation
    $Report.Findings | Export-Csv -Path $outCsv -NoTypeInformation -Force
    I "Saved JSON -> $outJson"
    I "Saved CSV  -> $outCsv"
} catch {
    R "Failed to save output: $($_.Exception.Message)"
}

Write-Section "Notes & Next Steps"
I "This scanner uses filename, zip/jar inner entries, command-line and prefetch evidence to flag likely injectables."
I "No automated tool can be 100% accurate. Any flagged file should be manually inspected (SHA256, antivirus scan, and opening the jar contents)."
I "If you want, I can add:"
I " - A whitelist/ignore list to prevent repeating false positives"
I " - Additional known-hash lookups (if you can provide sample hashes or allow a known-good database)"
I " - Automatic upload of suspicious files' hashes to VirusTotal (requires API key and explicit permission)"

G "`nScan complete."
