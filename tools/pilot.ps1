#requires -Version 5.1
<#
Measure SOC viewer start/RAM and query time per case. Writes docs/pilot-results.json.
#>
param([int]$BasePort = 8404)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$php = if (Get-Command php -ErrorAction SilentlyContinue) { (Get-Command php).Source } else { 'C:\xampp\php\php.exe' }
$results = New-Object System.Collections.Generic.List[object]
$index = 0

foreach ($case in @('soc-1', 'soc-2', 'soc-3')) {
    $port = $BasePort + $index
    $index++
    $runDir = Join-Path $repo 'run'
    New-Item -ItemType Directory -Path $runDir -Force | Out-Null
    $pidFile = Join-Path $runDir "pilot-$case.pid"

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $proc = Start-Process -FilePath $php -ArgumentList @(
        '-d', 'display_errors=0',
        '-S', "127.0.0.1:$port",
        '-t', 'shared/public',
        'shared/public/router.php'
    ) -WorkingDirectory $repo -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $runDir "pilot-$case.out.log") `
        -RedirectStandardError (Join-Path $runDir "pilot-$case.err.log")
    Set-Content -Path $pidFile -Value $proc.Id -NoNewline

    $deadline = (Get-Date).AddSeconds(20)
    $healthy = $false
    while ((Get-Date) -lt $deadline) {
        try {
            $h = Invoke-RestMethod -Uri "http://127.0.0.1:$port/healthz" -TimeoutSec 2
            if ($h.status -eq 'ok') { $healthy = $true; break }
        } catch { Start-Sleep -Milliseconds 250 }
    }
    $sw.Stop()
    $startSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 2)

    $validateSw = [System.Diagnostics.Stopwatch]::StartNew()
    & $php (Join-Path $repo 'shared\bin\cli.php') validate --case $case | Out-Null
    $validateSw.Stop()

    $proc.Refresh()
    $datasetBytes = 0
    foreach ($split in @('train', 'holdout')) {
        $f = Join-Path $repo "data\$case\$split\events.jsonl"
        if (Test-Path $f) { $datasetBytes += (Get-Item $f).Length }
    }

    $results.Add([ordered]@{
        case = $case
        port = $port
        viewer_start_seconds = $startSeconds
        healthy = $healthy
        validate_seconds = [math]::Round($validateSw.Elapsed.TotalSeconds, 2)
        rss_mb = [math]::Round($proc.WorkingSet64 / 1MB, 1)
        private_mb = [math]::Round($proc.PrivateMemorySize64 / 1MB, 1)
        dataset_kb = [math]::Round($datasetBytes / 1KB, 1)
        host_ram_gb = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
    })

    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
}

$out = Join-Path $repo 'docs\pilot-results.json'
$results | ConvertTo-Json -Depth 5 | Set-Content -Path $out -Encoding UTF8
foreach ($r in $results) {
    Write-Output ("{0}: start={1}s validate={2}s rss={3}MB private={4}MB dataset={5}KB healthy={6}" -f `
        $r.case, $r.viewer_start_seconds, $r.validate_seconds, $r.rss_mb, $r.private_mb, $r.dataset_kb, $r.healthy)
}
Write-Output "written: $out"
