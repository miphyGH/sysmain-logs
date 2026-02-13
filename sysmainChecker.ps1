$prefetchPath = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchPath) {
    Write-Host "`nPREFETCH INTEGRITY & CONTENT" -ForegroundColor Cyan
    
    $files = Get-ChildItem -Path $prefetchPath -Filter *.pf -Force -ErrorAction SilentlyContinue
    if (-not $files) {
        Write-Host "  No prefetch files found." -ForegroundColor Yellow
    } else {
        foreach ($pf in $files) {
            # Only focus on Minecraft/Java/javaws for content extraction
            if ($pf.Name -match "MINECRAFT|JAVA|JAVAW") {
                Write-Host ""
                Write-Host "================ $($pf.Name) ================" -ForegroundColor DarkGray

                $bytes = [System.IO.File]::ReadAllBytes($pf.FullName)
                $found = @()

                # --- Section C Parsing (best attempt) ---
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
                        $section = $bytes[$offC..($offC+$lenC-1)]
                        $str = [System.Text.Encoding]::Unicode.GetString($section)
                        $parts = $str -split "`0" | Where-Object { $_ -match '\.exe$|\.jar$|\.zip$' }
                        foreach ($p in $parts) { $found += [pscustomobject]@{ Item = $p; Source = "SectionC(v$version)" } }
                    }
                } catch {}

                # --- Fallback UTF-16 scan ---
                if ($found.Count -eq 0) {
                    try {
                        $utf16 = [System.Text.Encoding]::Unicode.GetString($bytes) -split "`0"
                        foreach ($p in $utf16) {
                            if ($p -match '\.exe$|\.jar$|\.zip$') { $found += [pscustomobject]@{ Item = $p; Source = "UTF16-Fallback" } }
                        }
                    } catch {}
                }

                # --- Fallback ASCII scan ---
                if ($found.Count -eq 0) {
                    $sb = New-Object System.Text.StringBuilder
                    foreach ($b in $bytes) {
                        if ($b -ge 32 -and $b -le 126) { [void]$sb.Append([char]$b) } else { [void]$sb.Append(" ") }
                    }
                    $asciiParts = $sb.ToString() -split "\s+" | Where-Object { $_ -match '\.exe$|\.jar$|\.zip$' }
                    foreach ($p in $asciiParts) { $found += [pscustomobject]@{ Item = $p; Source = "ASCII-Fallback" } }
                }

                if ($found.Count -eq 0) {
                    Write-Host "  No .exe/.jar/.zip references found." -ForegroundColor Yellow
                } else {
                    $found = $found | Sort-Object Item -Unique
                    foreach ($f in $found) {
                        $color = if ($f.Source -match "Fallback") { "Yellow" } else { "Green" }
                        Write-Host ("    {0,-70} [{1}]" -f $f.Item, $f.Source) -ForegroundColor $color
                    }
                }
            }
        }
    }
} else {
    Write-Host "`nCould not find prefetch folder??" -ForegroundColor Red
}
