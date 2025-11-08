Write-Output "=========================================="
Write-Output "=============== IPV4 HIDER ==============="
Write-Output "=========================================="

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8


if ($args.Count -eq 0) {
    Write-Output "Usage : ./IPV4_Hider.ps1 <file_to_parse>."
    exit 1
}

if (-not (Test-Path $args[0])) {
    Write-Output "File doesn't exist."
    exit 1
}

$file = $args[0]
$start = Select-String -Pattern '\b(?:\d{1,3}\.){3}\d{1,3}\b' -Path $file | Select-Object -First 1

if (-not $start) {
    Write-Output "No IPV4 address in this file."
    exit 1
}

Copy-Item -Path $file -Destination "$file.bak"
$incr = 0

while ($true) {
    $ipAddress = Select-String -Pattern '\b(?:\d{1,3}\.){3}\d{1,3}\b' -Path $file | Select-Object -First 1

    if ($ipAddress) {
        $ipAddress = $ipAddress.Matches.Value
        Write-Output "IP trouvée : $ipAddress"
        $motif = Read-Host "IP address will be replace by: "
        (Get-Content $file) -replace [regex]::Escape($ipAddress), $motif | Set-Content $file
        Write-Output "IP address $ipAddress replaced by $motif"
        Write-Output "-----------------------------------------------"
        $incr++
        Start-Sleep -Seconds 0.5
    } else {
        Write-Output "All IPV4 Addresses had been replaced. [$incr]"
        Write-Output "Backup file had been saved at $file.bak ."
        exit 1
    }
}
