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

Section "Minecraft / Java Prefetch Content Scan"

if (!(Test-Path $prefetchPath)) {
    Write-Host "Prefetch folder not found." -ForegroundColor Red
    exit
}

# Find Minecraft / Java related prefetch files
$pfFiles = Get-ChildItem $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue |
Where-Object {
    $_.Name -match "MINECRAFT" -or
    $_.Name -match "JAVA"
}

if (!$pfFiles) {
    Warn "No Minecraft or Java prefetch files found."
    exit
}

foreach ($pf in $pfFiles) {

    Section "Prefetch File: $($pf.Name)"

    # Read raw bytes
    $bytes = [System.IO.File]::ReadAllBytes($pf.FullName)

    # Extract readable Unicode strings
    $content = [System.Text.Encoding]::Unicode.GetString($bytes)

    # Find .exe, .jar, .zip references
    $matches = Select-String -InputObject $content -Pattern '\S+\.(exe|jar|zip)' -AllMatches

    if ($matches.Matches.Count -eq 0) {
        Warn "No .exe / .jar / .zip references found."
        continue
    }

    $found = @()

    foreach ($m in $matches.Matches) {
        $found += $m.Value
    }

    # Remove duplicates
    $unique = $found | Sort-Object -Unique

    foreach ($item in $unique) {
        Good $item
    }
}

Section "Scan Complete"
