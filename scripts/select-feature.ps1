#requires -Version 5.1
<#
.SYNOPSIS
Select the active Spec Kit feature without Python.

.DESCRIPTION
Python-free equivalent of scripts/select_feature.py. Writes
.specify/feature.json as UTF-8 without BOM.

.EXAMPLE
.\scripts\select-feature.ps1 002-kampusmart-target
.\scripts\select-feature.ps1 --list
#>
param(
    [Parameter(Position = 0)]
    [string]$Feature
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$specs = Join-Path $root 'specs'
if (-not (Test-Path $specs)) { throw "No specs directory at $specs" }

$choices = Get-ChildItem $specs -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName 'spec.md') } |
    ForEach-Object { $_.Name } |
    Sort-Object

if ($Feature -eq '--list') {
    Write-Output 'Available features:'
    $choices | ForEach-Object { Write-Output "  $_" }
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Feature) -or $Feature -notin $choices) {
    Write-Output 'Usage: .\scripts\select-feature.ps1 <feature-name>'
    Write-Output 'Available features:'
    $choices | ForEach-Object { Write-Output "  $_" }
    exit 2
}

$target = Join-Path $root '.specify'
if (-not (Test-Path $target)) { New-Item -ItemType Directory -Path $target -Force | Out-Null }
$file = Join-Path $target 'feature.json'
$json = '{"feature_directory":"specs/' + $Feature + '"}' + "`n"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($file, $json, $utf8NoBom)
Write-Output "Active Spec Kit feature: $Feature"
