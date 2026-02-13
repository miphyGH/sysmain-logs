<#
.SYNOPSIS
  Extract .exe / .jar / .zip entries from Minecraft/Java prefetch (.pf) files.
.DESCRIPTION
  Tries a safe header-based read of Section C for known PF versions.
  If that fails or yields nothing, falls back to scanning UTF-16LE and ASCII printable strings
  across the entire file to find .exe/.jar/.zip references (like Windows Prefetch Viewer).
.NOTES
  Run as Administrator to read C:\Windows\Prefetch.
#>

param(
    [string]$PrefetchPath = "$env:SystemRoot\Prefetch",
    [switch]$OnlyMinecraft    # when set, only check files with MINECRAFT or JAVA in name
)

function Read-UInt32([byte[]]$b, [int]$offset) {
    if ($offset + 4 -gt $b.Length) { return $null }
    return [BitConverter]::ToUInt32($b, $offset)
}

function Try-SectionC([byte[]]$bytes) {
    # Try to parse section C offsets for several known versions.
    # Return [pscustomobject] @{ Success = $true/$false; Content = string[]; Method = 'SectionC'/'HeaderFail' }
    $result = @{ Success = $false; Content = @(); Method = 'HeaderFail' }

    if ($bytes.Length -lt 8) { return $result }

    $version = Read-UInt32 $bytes 0
    # offsets used by community docs:
    # Versions 17: SectionC offset @ 0x44, len @ 0x48
    # Versions 23/26/30: SectionC offset @ 0x50, len @ 0x54
    switch ($version) {
        17 {
            $offC = Read-UInt32 $bytes 0x44
            $lenC = Read-UInt32 $bytes 0x48
        }
        23 { 
            $offC = Read-UInt32 $bytes 0x50
            $lenC = Read-UInt32 $bytes 0x54
        }
        26 {
            $offC = Read-UInt32 $bytes 0x50
            $lenC = Read-UInt32 $bytes 0x54
        }
        30 {
            $offC = Read-UInt32 $bytes 0x50
            $lenC = Read-UInt32 $bytes 0x54
        }
        default {
            # unknown version -> try common offsets heuristically
            $offC = Read-UInt32 $bytes 0x50
            $lenC = Read-UInt32 $bytes 0x54
        }
    }

    if ($offC -and $lenC -and ($offC + $lenC) -le $bytes.Length -and $lenC -gt 0) {
        try {
            $section = $bytes[$offC..($offC + $lenC - 1)]
            # decode section as UTF-16LE and split on NUL
            $s = [System.Text.Encoding]::Unicode.GetString($section)
            $parts = $s -split "`0" | Where-Object { $_ -and ($_.Length -ge 4) }
            $result.Success = $true
            $result.Content = $parts
            $result.Method = "SectionC(v$version)"
            return $result
        } catch {
            return $result
        }
    }

    return $result
}

function Extract-Utf16All([byte[]]$bytes, [int]$minLen = 4) {
    # Decode whole file as UTF-16LE then split on NUL to extract sequences
    try {
        $s = [System.Text.Encoding]::Unicode.GetString($bytes)
        return ($s -split "`0" | Where-Object { $_ -and ($_.Length -ge $minLen) })
    } catch {
        return @()
    }
}

function Extract-AsciiPrintable([byte[]]$bytes, [int]$minLen = 4) {
    # Convert non-printable bytes to spaces, then split
    $chars = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) {
        if ($b -ge 32 -and $b -le 126) { [void]$chars.Append([char]$b) } else { [void]$chars.Append(' ') }
    }
    $all = $chars.ToString() -split '\s+' | Where-Object { $_ -and ($_.Length -ge $minLen) }
    return $all
}

function Find-Targets([string[]]$strings) {
    if (-not $strings) { return @() }
    $regex = '(?i)([A-Za-z0-9_\\:\/\-\.\s]+?\.(exe|jar|zip))\b'
    $found = @()
    foreach ($s in $strings) {
        foreach ($m in [regex]::Matches($s, $regex)) {
            $val = $m.Groups[1].Value.Trim()
            if ($val -and $val.Length -ge 4) { $found += $val }
        }
    }
    return ($found | Sort-Object -Unique)
}

if (!(Test-Path $PrefetchPath)) {
    Write-Host "Prefetch folder not found: $PrefetchPath" -ForegroundColor Red
    return
}

$files = Get-ChildItem -Path $PrefetchPath -Filter '*.pf' -ErrorAction SilentlyContinue
if ($OnlyMinecraft) {
    $files = $files | Where-Object { $_.Name -match 'MINECRAFT' -or $_.Name -match 'JAVA' -or $_.Name -match 'JAVAW' }
}

if (-not $files -or $files.Count -eq 0) {
    Write-Host "No matching prefetch files found." -ForegroundColor Yellow
    return
}

foreach ($f in $files) {
    Write-Host ""
    Write-Host "================ $($f.Name) ================" -ForegroundColor DarkGray
    Write-Host "Path: $($f.FullName)"
    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)

    # 1) Try Section C parsing first
    $sec = Try-SectionC $bytes
    $results = @()
    if ($sec.Success) {
        $targets = Find-Targets $sec.Content
        if ($targets.Count -gt 0) {
            foreach ($t in $targets) { $results += [pscustomobject]@{ Item = $t; Source = $sec.Method } }
        }
    }

    # 2) If nothing found yet, do fallback: UTF-16 whole-file + ASCII
    if ($results.Count -eq 0) {
        $utf16 = Extract-Utf16All $bytes 4
        $ascii = Extract-AsciiPrintable $bytes 4

        $t1 = Find-Targets $utf16
        $t2 = Find-Targets $ascii

        foreach ($x in $t1) { $results += [pscustomobject]@{ Item = $x; Source = 'UTF16-Fallback' } }
        foreach ($x in $t2) { $results += [pscustomobject]@{ Item = $x; Source = 'ASCII-Fallback' } }

        # also attempt combined raw search: join bytes as ISO-8859-1 string then regex
        if ($results.Count -eq 0) {
            try {
                $iso = [System.Text.Encoding]::GetEncoding(28591).GetString($bytes)
                $rawFound = Find-Targets @($iso)
                foreach ($x in $rawFound) { $results += [pscustomobject]@{ Item = $x; Source = 'RAW-Fallback' } }
            } catch { }
        }
    }

    if ($results.Count -eq 0) {
        Write-Host "No .exe / .jar / .zip references found." -ForegroundColor Yellow
    } else {
        # print unique keeping source preference: SectionC first then others
        $results = $results | Sort-Object Item -Unique
        foreach ($r in $results) {
            $color = 'Green'
            if ($r.Source -match 'Fallback') { $color = 'Yellow' }
            Write-Host ("{0,-80} {1}" -f $r.Item, "[$($r.Source)]") -ForegroundColor $color
        }
    }
}

Write-Host "`nScan complete." -ForegroundColor Cyan
