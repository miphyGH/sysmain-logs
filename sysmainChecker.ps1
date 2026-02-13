<#
.SYNOPSIS
  Parse-Prefetch.ps1 - Lightweight Prefetch (.pf) parser that extracts:
    - exe name, version, hash
    - run count
    - last run times (where present)
    - filenames referenced (Section C)
    - volume summary (if available)

.NOTES
  - Supports PF versions: 17, 23, 26, 30 (best-effort)
  - Windows 10 PF files may be compressed; if parsing fails see PECmd/PECmd.exe (Eric Zimmerman)
  - Requires Administrator to read C:\Windows\Prefetch
  - Based on public PF format docs (forensics.wiki, libyal).
#>

[CmdletBinding()]
param (
    [string]$PrefetchPath = "$env:SystemRoot\Prefetch",
    [switch]$OnlyMinecraft   # when set, only parse files with MINECRAFT or JAVA in filename
)

function Read-UInt32([System.IO.BinaryReader]$br) {
    $bytes = $br.ReadBytes(4)
    [BitConverter]::ToUInt32($bytes, 0)
}
function Read-Int32([System.IO.BinaryReader]$br) {
    $bytes = $br.ReadBytes(4)
    [BitConverter]::ToInt32($bytes, 0)
}
function Read-Int64([System.IO.BinaryReader]$br) {
    $bytes = $br.ReadBytes(8)
    [BitConverter]::ToInt64($bytes, 0)
}
function Read-BytesAt([string]$file, [int]$offset, [int]$count) {
    $fs = [System.IO.File]::OpenRead($file)
    try {
        $fs.Position = $offset
        $br = New-Object System.IO.BinaryReader($fs)
        $br.ReadBytes($count)
    }
    finally { $fs.Close() }
}
function FileTimeToDate([long]$filetime) {
    try {
        if ($filetime -le 0) { return $null }
        [DateTime]::FromFileTimeUtc([Int64]$filetime)
    } catch { return $null }
}

if (!(Test-Path $PrefetchPath)) {
    Write-Error "Prefetch folder not found: $PrefetchPath"
    return
}

# gather PF files
$files = Get-ChildItem -Path $PrefetchPath -Filter '*.pf' -ErrorAction SilentlyContinue
if ($OnlyMinecraft) {
    $files = $files | Where-Object { $_.Name -match 'MINECRAFT' -or $_.Name -match 'JAVA' -or $_.Name -match 'JAVAWS' }
}

if (-not $files -or $files.Count -eq 0) {
    Write-Host "No prefetch files found matching criteria." -ForegroundColor Yellow
    return
}

foreach ($f in $files) {
    Write-Host "`n========================================================" -ForegroundColor DarkGray
    Write-Host "Prefetch: $($f.Name)" -ForegroundColor Cyan
    Write-Host "Path    : $($f.FullName)"
    Write-Host "Size    : $([math]::Round($f.Length/1KB,2)) KB"

    # read header area
    $fs = [System.IO.File]::OpenRead($f.FullName)
    try {
        $br = New-Object System.IO.BinaryReader($fs)

        # Header basics
        $fs.Position = 0
        $formatVersion = Read-UInt32 $br
        $fs.Position = 4
        $sigBytes = $br.ReadBytes(4)
        $signature = [System.Text.Encoding]::ASCII.GetString($sigBytes)
        $fs.Position = 0x0C
        $fileSizeFromHeader = Read-UInt32 $br

        # exe name field: 0x10 length 60 bytes, UTF-16LE
        $fs.Position = 0x10
        $nameBytes = $br.ReadBytes(60)
        $exeName = ([System.Text.Encoding]::Unicode.GetString($nameBytes)).Trim([char]0)
        $fs.Position = 0x4C
        $prefetchHash = Read-UInt32 $br

        Write-Host "Version    : $formatVersion"
        Write-Host "Signature  : $signature"
        Write-Host "ExeName    : $exeName"
        Write-Host "Hash       : $prefetchHash"
        Write-Host "HeaderSize : $fileSizeFromHeader"

        # Determine offsets from file information (version dependent)
        $infoOffset = 0x54
        $fs.Position = $infoOffset

        $supported = $true
        switch ($formatVersion) {
            17 {
                # version 17 file info layout
                $offsetA = Read-UInt32 $br
                $countA  = Read-UInt32 $br
                $offsetB = Read-UInt32 $br
                $countB  = Read-UInt32 $br
                $offsetC = Read-UInt32 $br
                $lenC    = Read-UInt32 $br
                $offsetD = Read-UInt32 $br
                $countD  = Read-UInt32 $br
                $lenD    = Read-UInt32 $br
                $fs.Position = 0x78
                $lastExecFiletime = Read-Int64 $br
                $fs.Position = 0x90
                $runCount = Read-Int32 $br
                $olderFileTimes = @()
            }
            23 {
                $offsetA = Read-UInt32 $br
                $countA  = Read-UInt32 $br
                $offsetB = Read-UInt32 $br
                $countB  = Read-UInt32 $br
                $offsetC = Read-UInt32 $br
                $lenC    = Read-UInt32 $br
                $offsetD = Read-UInt32 $br
                $countD  = Read-UInt32 $br
                $lenD    = Read-UInt32 $br
                $fs.Position = 0x80
                $lastExecFiletime = Read-Int64 $br
                $fs.Position = 0x98
                $runCount = Read-Int32 $br
                $olderFileTimes = @()
            }
            26 {
                $offsetA = Read-UInt32 $br
                $countA  = Read-UInt32 $br
                $offsetB = Read-UInt32 $br
                $countB  = Read-UInt32 $br
                $offsetC = Read-UInt32 $br
                $lenC    = Read-UInt32 $br
                $offsetD = Read-UInt32 $br
                $countD  = Read-UInt32 $br
                $lenD    = Read-UInt32 $br
                $fs.Position = 0x80
                $latestExecFiletime = Read-Int64 $br
                $olderFileTimes = @()
                for ($i=0; $i -lt 7; $i++) {
                    $olderFileTimes += (Read-Int64 $br)
                }
                $fs.Position = 0xD0
                $runCount = Read-Int32 $br
                $lastExecFiletime = $latestExecFiletime
            }
            30 {
                # Version 30 (Windows 10) - structure is similar but sometimes compressed.
                # We attempt to read offsets as version 26; if offsets look invalid we will bail.
                $offsetA = Read-UInt32 $br
                $countA  = Read-UInt32 $br
                $offsetB = Read-UInt32 $br
                $countB  = Read-UInt32 $br
                $offsetC = Read-UInt32 $br
                $lenC    = Read-UInt32 $br
                $offsetD = Read-UInt32 $br
                $countD  = Read-UInt32 $br
                $lenD    = Read-UInt32 $br
                # read candidate last exec times (try same layout)
                try {
                    $fs.Position = 0x80
                    $latestExecFiletime = Read-Int64 $br
                    $olderFileTimes = @()
                    for ($i=0; $i -lt 7; $i++) { $olderFileTimes += (Read-Int64 $br) }
                    $fs.Position = 0xD0
                    $runCount = Read-Int32 $br
                    $lastExecFiletime = $latestExecFiletime
                }
                catch {
                    # some Win10 prefetch files are compressed; fallback below
                    $runCount = $null
                    $lastExecFiletime = $null
                    $olderFileTimes = @()
                }
            }
            default {
                $supported = $false
            }
        }

        if (-not $supported) {
            Write-Host "This prefetch version ($formatVersion) is not supported by this parser." -ForegroundColor Yellow
            continue
        }

        # Basic sanity: ensure section C offset/len are inside file
        if ($offsetC -eq 0 -or $lenC -eq 0 -or ($offsetC + $lenC) -gt $fs.Length) {
            Write-Host "Prefetch file looks compressed/unsupported or section offsets invalid." -ForegroundColor Yellow
            Write-Host "Try a dedicated tool (PECmd/Prefetch viewers) for Windows 10 compressed PFs." -ForegroundColor Yellow
            continue
        }

        # run count & last run times
        if ($null -ne $runCount) { Write-Host "Run Count  : $runCount" } else { Write-Host "Run Count  : N/A" }
        if ($null -ne $lastExecFiletime) {
            $dt = FileTimeToDate $lastExecFiletime
            Write-Host "Last Run   : $dt (UTC)"
        } else {
            if ($olderFileTimes -and $olderFileTimes.Count -gt 0) {
                $times = $olderFileTimes | ForEach-Object { FileTimeToDate $_ } | Where-Object { $_ -ne $null }
                if ($times) {
                    Write-Host "Last Runs  :"
                    $times | ForEach-Object { Write-Host "  - $_ (UTC)" }
                } else {
                    Write-Host "Last Runs  : N/A"
                }
            } else {
                Write-Host "Last Run   : N/A"
            }
        }

        # Section C - filename strings (UTF-16LE list)
        $bytesC = Read-BytesAt -file $f.FullName -offset $offsetC -count $lenC
        $strC = [System.Text.Encoding]::Unicode.GetString($bytesC)
        # split on null char
        $names = $strC -split "`0" | Where-Object { $_ -ne '' } | ForEach-Object { $_.Trim() }

        Write-Host ""
        Write-Host "Referenced Filenames (Section C):" -ForegroundColor Cyan
        if ($names.Count -eq 0) {
            Write-Host "  (none found in Section C)" -ForegroundColor Yellow
        } else {
            # display many lines but limit to avoid overwhelming
            $names | ForEach-Object { Write-Host "  - $_" }
        }

        # Optional: try to parse Volume info summary (Section D) - best-effort
        if ($offsetD -gt 0 -and ($offsetD + $lenD) -le $fs.Length) {
            Write-Host ""
            Write-Host "Volume info (Section D) Summary:" -ForegroundColor Cyan
            $volBytes = Read-BytesAt -file $f.FullName -offset $offsetD -count $lenD
            # search for ASCII/UTF-16 substrings that look like \DEVICE\ or \??\ or drive letters
            $txt = ([System.Text.Encoding]::Unicode.GetString($volBytes)) -replace "`0", ''
            if ($txt -match "\\\\Device\\\\|\\\?\\\|[A-Z]:\\") {
                # print some matched substrings (best-effort)
                $matches = @()
                if ($txt -match "\\\\Device\\\\[^\\s]+") { $matches += $matches[0] } 
                Write-Host "  Raw volume strings found (partial):"
                # show trimmed preview
                $trimPreview = ($txt -split "[`r`n]") | Where-Object { $_ -and ($_.Length -gt 3) } | Select-Object -First 5
                foreach ($tp in $trimPreview) { Write-Host "    $tp" }
            } else {
                Write-Host "  (no human-readable volume strings detected)"
            }
        }

    } catch {
        Write-Host "Error parsing file: $($_.Exception.Message)" -ForegroundColor Red
    } finally {
        if ($br) { $br.Close() }
        if ($fs) { $fs.Close() }
    }
}
