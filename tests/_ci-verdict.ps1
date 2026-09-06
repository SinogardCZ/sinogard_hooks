#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Spusti jednu sadu a verdikt vezme ze SOUHRNNEHO RADKU, ne z navratoveho kodu.

.DESCRIPTION
  Nalez Amber A6: CI cetla jen exit code. Sada, ktera spadne uprostred nebo
  neprovede ani jedno tvrzeni, umi skoncit nulou - `0 passed / 0 failed` by
  proslo zelene a README pritom slibuje, ze verdikt dava souhrnny radek.

  Selze, kdyz:
    - souhrnny radek chybi uplne  (sada spadla driv, nez ho stihla napsat),
    - failed > 0,
    - passed = 0                  (sada nic neovrila).

  Vystup sady se propousti beze zmeny, aby v logu CI zustal cely.

.EXAMPLE
  pwsh -NoProfile -File tests/_ci-verdict.ps1 -Suite gate -Interpreter powershell.exe
#>
param(
    [Parameter(Mandatory = $true)][string]$Suite,
    [string]$Interpreter = 'powershell.exe'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Nalez Amber J2: rezim sberu nespousti hook vubec. Kdyby ho nekdo mel v prostredi,
# sada by vydala nenulovy `passed` z bloku mimo pripadova pole a verdikt by byl zeleny
# nad necim, co se vubec nezmerilo. Sada uz to sama odmita; tady je druha zavora,
# protoze verdikt je posledni misto, kde se zelena vydava.
if ($env:SINOGARD_HOOKS_COLLECT -eq '1') {
    Write-Host ("VERDIKT {0}: SINOGARD_HOOKS_COLLECT=1 je v prostredi - rezim sberu nic nemeri" -f $Suite) -ForegroundColor Red
    exit 1
}

$suitePath = Join-Path $PSScriptRoot ($Suite + '.tests.ps1')
if (-not [System.IO.File]::Exists($suitePath)) {
    Write-Host ("VERDIKT {0}: sada {1} neexistuje" -f $Suite, $suitePath) -ForegroundColor Red
    exit 1
}

$output = & pwsh -NoProfile -File $suitePath -Interpreter $Interpreter 2>&1 | ForEach-Object { [string]$_ }
$suiteExit = $LASTEXITCODE
$output | ForEach-Object { Write-Host $_ }

$summary = $null
foreach ($line in $output) {
    $m = [regex]::Match($line, '(\d+)\s+passed\s*/\s*(\d+)\s+failed\s*/\s*(\d+)\s+skipped')
    if ($m.Success) { $summary = $m }
}

if ($null -eq $summary) {
    Write-Host ("VERDIKT {0}: souhrnny radek CHYBI - sada nedobehla (navratovy kod byl {1}, ale ten nic netvrdi)" `
                -f $Suite, $suiteExit) -ForegroundColor Red
    exit 1
}

$passed  = [int]$summary.Groups[1].Value
$failed  = [int]$summary.Groups[2].Value
$skipped = [int]$summary.Groups[3].Value

if ($failed -gt 0) {
    Write-Host ("VERDIKT {0}: {1} failed" -f $Suite, $failed) -ForegroundColor Red
    exit 1
}
if ($passed -eq 0) {
    Write-Host ("VERDIKT {0}: 0 passed - sada neoverila nic, zelena by byla lez" -f $Suite) -ForegroundColor Red
    exit 1
}

Write-Host ("VERDIKT {0}: OK ({1} passed / {2} failed / {3} skipped)" -f $Suite, $passed, $failed, $skipped) -ForegroundColor Green
exit 0
