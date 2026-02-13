$prefetchPath = "$env:SystemRoot\Prefetch"
$pfFiles = Get-ChildItem $prefetchPath -Filter "*.pf" | Where-Object { $_.Name -match "JAVAW|MINECRAFT|JAVA" }

foreach ($pf in $pfFiles) {
    Write-Host ""
    Write-Host "================ $($pf.Name) ================" -ForegroundColor DarkGray

    $bytes = [System.IO.File]::ReadAllBytes($pf.FullName)
    $found = @()

    # UTF-16LE scan
    try {
        $utf16 = [System.Text.Encoding]::Unicode.GetString($bytes) -split "`0"
        foreach ($s in $utf16) {
            if ($s -and $s.Trim() -ne "") { $found += [pscustomobject]@{ Item = $s.Trim(); Source = "UTF16" } }
        }
    } catch {}

    # ASCII scan
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) {
        if ($b -ge 32 -and $b -le 126) { [void]$sb.Append([char]$b) } else { [void]$sb.Append(" ") }
    }
    $asciiParts = $sb.ToString() -split "\s+" | Where-Object { $_ -and $_.Trim() -ne "" }
    foreach ($s in $asciiParts) { $found += [pscustomobject]@{ Item = $s.Trim(); Source = "ASCII" } }

    if ($found.Count -eq 0) {
        Write-Host "  No readable content found." -ForegroundColor Yellow
    } else {
        # Unique + sort
        $found = $found | Sort-Object Item -Unique
        foreach ($f in $found) {
            $color = if ($f.Source -eq "UTF16") { "Green" } else { "Yellow" }
            Write-Host ("  {0}" -f $f.Item) -ForegroundColor $color
        }
    }
}
