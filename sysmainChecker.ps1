$prefetchPath = "$env:SystemRoot\Prefetch"
$pfFiles = Get-ChildItem $prefetchPath -Filter "*.pf" | Where-Object { $_.Name -match "MINECRAFT|JAVA" }

foreach ($pf in $pfFiles) {
    Write-Host "`n================ $($pf.Name) ================"
    $bytes = [System.IO.File]::ReadAllBytes($pf.FullName)

    # Determine version (first 4 bytes)
    $version = [BitConverter]::ToUInt32($bytes,0)
    # Section C offset and length depend on version
    switch ($version) {
        17 { $offsetC = [BitConverter]::ToUInt32($bytes,0x44); $lenC = [BitConverter]::ToUInt32($bytes,0x48) }
        23 { $offsetC = [BitConverter]::ToUInt32($bytes,0x50); $lenC = [BitConverter]::ToUInt32($bytes,0x54) }
        26 { $offsetC = [BitConverter]::ToUInt32($bytes,0x50); $lenC = [BitConverter]::ToUInt32($bytes,0x54) }
        30 { $offsetC = [BitConverter]::ToUInt32($bytes,0x50); $lenC = [BitConverter]::ToUInt32($bytes,0x54) }
        default { Write-Host "Unsupported PF version $version"; continue }
    }

    if (($offsetC + $lenC) -gt $bytes.Length) { Write-Host "Invalid offsets"; continue }

    $sectionC = $bytes[$offsetC..($offsetC+$lenC-1)]
    # Decode UTF-16LE
    $str = [System.Text.Encoding]::Unicode.GetString($sectionC)
    # Split on nulls
    $paths = $str -split "`0" | Where-Object { $_ -match '\.exe$|\.jar$|\.zip$' } | Sort-Object -Unique

    if ($paths.Count -eq 0) { Write-Host "No .exe/.jar/.zip found" }
    else { $paths | ForEach-Object { Write-Host $_ } }
}
