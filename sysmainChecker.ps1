$prefetchPath = "$env:SystemRoot\Prefetch"
$pfFiles = Get-ChildItem $prefetchPath -Filter "*.pf" | Where-Object { $_.Name -match "JAVAW" }

foreach ($pf in $pfFiles) {
    Write-Host ""
    Write-Host "================ $($pf.Name) ================" -ForegroundColor DarkGray

    $bytes = [System.IO.File]::ReadAllBytes($pf.FullName)

    # --- Header info ---
    try {
        $version = [BitConverter]::ToUInt32($bytes,0)
        $lastRunCount = [BitConverter]::ToUInt32($bytes,0x18)
        $lastExecTime = [DateTime]::FromFileTime([BitConverter]::ToInt64($bytes,0x08))
        Write-Host ("Version: {0}, Last Run Count: {1}, Last Exec: {2}" -f $version, $lastRunCount, $lastExecTime) -ForegroundColor Cyan
    } catch { Write-Host "Could not parse header info" -ForegroundColor Red }

    # --- Section C (Referenced files) ---
    try {
        switch ($version) {
            17 { $offC = [BitConverter]::ToUInt32($bytes,0x44); $lenC = [BitConverter]::ToUInt32($bytes,0x48) }
            23 { $offC = [BitConverter]::ToUInt32($bytes,0x50); $lenC = [BitConverter]::ToUInt32($bytes,0x54) }
            26 { $offC = [BitConverter]::ToUInt32($bytes,0x50); $lenC = [BitConverter]::ToUInt32($bytes,0x54) }
            30 { $offC = [BitConverter]::ToUInt32($bytes,0x50); $lenC = [BitConverter]::ToUInt32($bytes,0x54) }
            default { $offC = 0; $lenC = 0 }
        }

        if ($lenC -gt 0 -and ($offC + $lenC) -le $bytes.Length) {
            $section = $bytes[$offC..($offC+$lenC-1)]
            $str = [System.Text.Encoding]::Unicode.GetString($section)
            $entries = $str -split "`0" | Where-Object { $_ -and $_.Trim() -ne "" }
            Write-Host "`nReferenced Files / Activity:" -ForegroundColor Cyan
            foreach ($e in $entries) { Write-Host "  $e" -ForegroundColor Green }
        } else {
            Write-Host "No Section C content found" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Error reading Section C: $($_.Exception.Message)" -ForegroundColor Red
    }
}
