#requires -Version 5.1
<#
.SYNOPSIS
Build, validate, replay, evaluate, and package SOC cases on localhost.

.DESCRIPTION
Python-free SOC harness controller. Requires PHP 8.1+ (XAMPP PHP is detected).
The viewer binds to 127.0.0.1 only and needs no SIEM.

.EXAMPLE
.\tools\soc.ps1 -Action build
.\tools\soc.ps1 -Action start -Port 8091
.\tools\soc.ps1 -Action validate
.\tools\soc.ps1 -Action evaluate -Rule .\my-rule.json -Split train
.\tools\soc.ps1 -Action package
#>
param(
    [ValidateSet('build', 'validate', 'selfcheck', 'evaluate', 'freeze', 'package', 'start', 'stop', 'health', 'status')]
    [string]$Action = 'health',

    [string]$Case = 'soc-1',
    [string]$Rule = '',
    [ValidateSet('train', 'holdout')]
    [string]$Split = 'train',
    [switch]$Instructor,
    [int]$Port = 8091
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$isPackage = (Test-Path (Join-Path $repoRoot 'manifest-sha256.txt')) -and -not (Test-Path (Join-Path $repoRoot 'shared\bin\generate-soc1.php'))
$runDir = Join-Path $repoRoot 'run'
$pidFile = Join-Path $runDir 'viewer.pid'
$baseUrl = "http://127.0.0.1:$Port"

function Get-PhpPath {
    $cmd = Get-Command php -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($candidate in @('C:\xampp\php\php.exe', "$env:ProgramFiles\php\php.exe", "${env:ProgramFiles(x86)}\php\php.exe")) {
        if ($candidate -and (Test-Path $candidate)) { return $candidate }
    }
    throw 'PHP 8.1+ not found. Install PHP/XAMPP or add php.exe to PATH.'
}

function Invoke-Cli {
    param([string[]]$CliArgs)
    $php = Get-PhpPath
    & $php (Join-Path $repoRoot 'shared\bin\cli.php') @CliArgs
    if ($LASTEXITCODE -ne 0) { throw "cli.php exited with $LASTEXITCODE" }
}

function Get-RunningPid {
    if (-not (Test-Path $pidFile)) { return $null }
    $raw = (Get-Content $pidFile -Raw).Trim()
    if (-not $raw) { return $null }
    $proc = Get-Process -Id ([int]$raw) -ErrorAction SilentlyContinue
    if ($proc) { return [int]$raw }
    return $null
}

function Invoke-Start {
    if (Get-RunningPid) { Write-Output "Viewer already running at $baseUrl"; return }
    New-Item -ItemType Directory -Path $runDir -Force | Out-Null
    $php = Get-PhpPath
    $process = Start-Process -FilePath $php -ArgumentList @(
        '-d', 'display_errors=0',
        '-S', "127.0.0.1:$Port",
        '-t', 'shared/public',
        'shared/public/router.php'
    ) -WorkingDirectory $repoRoot `
        -RedirectStandardOutput (Join-Path $runDir 'viewer.out.log') `
        -RedirectStandardError (Join-Path $runDir 'viewer.err.log') `
        -WindowStyle Hidden -PassThru
    Set-Content -Path $pidFile -Value $process.Id -NoNewline
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        try {
            $health = Invoke-RestMethod -Uri "$baseUrl/healthz" -TimeoutSec 3
            if ($health.status -eq 'ok') {
                Write-Output "SOC viewer started (PID $($process.Id)) at $baseUrl"
                Write-Output "  datasets: $(($health.datasets.PSObject.Properties.Name) -join ', ')"
                return
            }
        } catch {
            Start-Sleep -Milliseconds 300
        }
    }
    throw "Viewer did not become healthy. See run\viewer.err.log."
}

function Invoke-Stop {
    $running = Get-RunningPid
    if (-not $running) { Write-Output 'Not running.'; return }
    Stop-Process -Id $running -Force
    Remove-Item $pidFile -Force
    Write-Output "Stopped PID $running"
}

switch ($Action) {
    'build' {
        Invoke-Cli @('generate')
        Invoke-Cli @('validate', '--case', $Case)
        Invoke-Cli @('selfcheck', '--case', $Case)
    }
    'validate' { Invoke-Cli @('validate', '--case', $Case) }
    'selfcheck' { Invoke-Cli @('selfcheck', '--case', $Case) }
    'evaluate' {
        if (-not $Rule) { throw 'Provide -Rule <path-to-rule.json>' }
        $rulePath = (Resolve-Path $Rule).Path
        $args = @('evaluate', '--case', $Case, '--rule', $rulePath, '--split', $Split)
        if ($Instructor) { $args += '--instructor' }
        Invoke-Cli $args
    }
    'freeze' {
        if (-not $Rule) { throw 'Provide -Rule <path-to-rule.json>' }
        $rulePath = (Resolve-Path $Rule).Path
        Invoke-Cli @('freeze', '--case', $Case, '--rule', $rulePath)
    }
    'package' { Invoke-Cli @('package', '--case', $Case) }
    'start' { Invoke-Start }
    'stop' { Invoke-Stop }
    'health' { Invoke-RestMethod -Uri "$baseUrl/healthz" -TimeoutSec 5 | ConvertTo-Json -Depth 5 }
    'status' {
        $running = Get-RunningPid
        if ($running) { Write-Output "Running (PID $running) at $baseUrl" } else { Write-Output 'Not running.' }
    }
}
