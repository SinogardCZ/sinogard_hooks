#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Generator regresniho invariantu (tests/fixtures/invariants.json).

.DESCRIPTION
  Nalez Amber H2: soubor vznikl "generovano z pripadovych poli", ale generator
  v repu nebyl. Pri pristim rustu sady by ho nikdo nezopakoval, invariant by
  zkamenel na 142 radcich a prestal by delat to, kvuli cemu vznikl.

  Postup: sady se spusti v rezimu SBERU (SINOGARD_HOOKS_COLLECT=1) - pripady se
  jen ohlasi, hook se nespousti, takze to trva sekundy. Vysledek se PRIDA
  k existujicim radkum.

  Soubor je APPEND-ONLY. Generator existujici radky NIKDY nemeni ani neodebira -
  jen doplni ty, ktere v nem jeste nejsou. To je zamer: radek odsud odchazi jen
  s citovanym rozhodnutim, ne proto, ze se zmenilo pripadove pole.

  Radky prvniho vydani nemaji klice `hook` a `kind` - tehdy byl invariant jen pro
  branu nad prikazy. Chybejici klic proto znamena `gate` / `cmd` a dopisovat ho
  zpetne by znamenalo prepsat 142 radku, ktere prepsat nemam.

.EXAMPLE
  pwsh -NoProfile -File tests/_generate-invariants.ps1
  pwsh -NoProfile -File tests/_generate-invariants.ps1 -WhatIf
#>
param(
    [switch]$WhatIf,
    [string]$Interpreter = 'pwsh'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path $PSScriptRoot -Parent
$invPath = Join-Path $PSScriptRoot 'fixtures/invariants.json'
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Get-SuiteCases([string]$Suite) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Interpreter
    $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $PSScriptRoot ($Suite + '.tests.ps1')) + '"'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = $utf8
    $psi.WorkingDirectory = $repoRoot
    $psi.EnvironmentVariables['SINOGARD_HOOKS_COLLECT'] = '1'
    $p = [System.Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEnd()
    [void]$p.StandardError.ReadToEnd()
    $p.WaitForExit()

    $m = [regex]::Match($out, '<<<SINOGARD-CASES\s*(.*?)\s*SINOGARD-CASES>>>', 'Singleline')
    if (-not $m.Success) { throw ("Sada {0} nevydala sber pripadu." -f $Suite) }
    return @($m.Groups[1].Value | ConvertFrom-Json)
}

# Klic radku: hook + nastroj + doslovny prikaz/cesta. Ocekavani do klice NEPATRI -
# kdyby se zmenilo, ma to byt VIDET jako spor, ne se pridat jako druhy radek.
function Get-RowKey($Hook, $Tool, $Value) {
    # Oddelovac je znak, ktery se v prikazu nevyskytne. `u{...}` tu byt nemuze -
    # Windows PowerShell 5.1 ho nezna a skript ma bezet v obou interpretech.
    $sep = [string][char]1
    return ([string]$Hook + $sep + [string]$Tool + $sep + [string]$Value)
}

$doc = [System.IO.File]::ReadAllText($invPath, $utf8) | ConvertFrom-Json
$existing = @($doc.rows)

$seen = @{}
foreach ($row in $existing) {
    $hook = if ($row.PSObject.Properties['hook']) { [string]$row.hook } else { 'gate' }
    $seen[(Get-RowKey $hook $row.tool $row.cmd)] = [string]$row.expect
}

$added = New-Object System.Collections.ArrayList
$conflicts = New-Object System.Collections.ArrayList

foreach ($suite in @('gate', 'secrets')) {
    foreach ($c in (Get-SuiteCases $suite)) {
        $key = Get-RowKey $c.hook $c.tool $c.cmd
        if ($seen.ContainsKey($key)) {
            # Tyz tvar s JINYM ocekavanim = spor, ne novy radek. Rozhodnout ho musi
            # clovek: bud se zmenilo pravidlo (a patri to do hlaseni), nebo je chyba
            # v novem pripadu.
            if ($seen[$key] -ne [string]$c.expect) {
                [void]$conflicts.Add(("{0} / {1}: invariant rika {2}, sada {3}" -f $c.hook, $c.cmd, $seen[$key], $c.expect))
            }
            continue
        }
        $seen[$key] = [string]$c.expect
        $row = [ordered]@{ tool = [string]$c.tool; cmd = [string]$c.cmd
                           expect = [string]$c.expect; since = [string]$c.since }
        if ([string]$c.hook -ne 'gate') { $row['hook'] = [string]$c.hook }
        if ([string]$c.kind -ne 'cmd')  { $row['kind'] = [string]$c.kind }
        [void]$added.Add($row)
    }
}

if ($conflicts.Count -gt 0) {
    Write-Host 'SPOR - tvar uz v invariantu je, ale s jinym ocekavanim:' -ForegroundColor Red
    foreach ($c in $conflicts) { Write-Host ("  " + $c) -ForegroundColor Red }
    Write-Host 'Nic se nezapisuje. Rozhodnuti patri cloveku.' -ForegroundColor Red
    exit 1
}

Write-Host ("Existujicich radku: {0}" -f $existing.Count)
Write-Host ("Novych radku:       {0}" -f $added.Count)

if ($added.Count -eq 0) { Write-Host 'Neni co pridat.'; exit 0 }
if ($WhatIf) {
    foreach ($r in $added) { Write-Host ("  + [{0}] {1} -> {2}" -f $r.tool, $r.cmd, $r.expect) }
    exit 0
}

# Zapis: hlavicka a existujici radky se berou z puvodniho souboru DOSLOVA (append-only),
# nove se pripoji za ne. Cely soubor se neserializuje znovu - tim by se 142 radku
# prepsalo formatovanim, a to je presne to, co se tu delat nema.
$text = [System.IO.File]::ReadAllText($invPath, $utf8)
$lastBracket = $text.LastIndexOf(']')
if ($lastBracket -lt 0) { throw 'invariants.json nema uzavirajici zavorku pole.' }
$head = $text.Substring(0, $lastBracket).TrimEnd()
$tail = $text.Substring($lastBracket)

$sb = New-Object System.Text.StringBuilder
[void]$sb.Append($head)
foreach ($r in $added) {
    [void]$sb.Append(",`n    {`n")
    $keys = @($r.Keys)
    for ($i = 0; $i -lt $keys.Count; $i++) {
        $k = $keys[$i]
        $v = ConvertTo-Json ([string]$r[$k]) -Compress
        $comma = if ($i -lt $keys.Count - 1) { ',' } else { '' }
        [void]$sb.Append(("      `"{0}`": {1}{2}`n" -f $k, $v, $comma))
    }
    [void]$sb.Append('    }')
}
[void]$sb.Append("`n  " + $tail.TrimStart())

[System.IO.File]::WriteAllText($invPath, $sb.ToString(), $utf8)

# Kontrola, ze vysledek je porad platny JSON a ze radku PRIBYLO, ne ubylo.
$check = [System.IO.File]::ReadAllText($invPath, $utf8) | ConvertFrom-Json
$after = @($check.rows).Count
Write-Host ("Po zapisu radku:    {0}" -f $after)
if ($after -ne ($existing.Count + $added.Count)) {
    throw ("Pocet radku nesedi: cekano {0}, je {1}." -f ($existing.Count + $added.Count), $after)
}
