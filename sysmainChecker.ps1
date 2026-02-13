Clear-Host

function Section($text) {
    Write-Host ""
    Write-Host "==================================================" -ForegroundColor DarkGray
    Write-Host " $text" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor DarkGray
}

function Good($t){ Write-Host $t -ForegroundColor Green }
function Warn($t){ Write-Host $t -ForegroundColor Yellow }

$prefetchPath = "$env:SystemRoot\Prefetch"

Section "Minecraft / Java Prefetch File Scan"

if (!(Test-Path $prefetchPath)) {
    Write-Host "Prefetch folder not found." -ForegroundColor Red
    exit
}

# Find Minecraft / Java prefetch files
$pfFiles = Get-ChildItem $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue |
Where-Object { $_.Name -match "MINECRAFT" -or $_.Name -match "JAVA" }

if (!$pfFiles) {
    Warn "No Minecraft or Java prefetch files found."
    exit
}

foreach ($pf in $pfFiles) {

    Section "Prefetch File: $($pf.Name)"

    # Read raw bytes
    $bytes = [System.IO.File]::ReadAllBytes($pf.FullName)

    # Convert to ASCII printable strings (length ≥4)
    $strings = -join ($bytes | ForEach-Object {
        if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { " " }
    }) -split '\s+'

    # Find .exe, .jar, .zip references
    $matches = $strings | Where-Object { $_ -match '\.exe$|\.jar$|\.zip$' } | Sort-Object -Unique

    if ($matches.Count -eq 0) {
        Warn "No .exe / .jar / .zip references found."
    } else {
        foreach ($item in $matches) {
            Good $item
        }
    }
}

Section "Scan Complete"
