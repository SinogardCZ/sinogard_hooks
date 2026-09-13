#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Ctenar auditu brany (gate-audit.jsonl): rozpad radku per tvar a rozhodnuti.

.DESCRIPTION
  TASK-106 (vyrok 6 Amber 2026-09-12 v mandatu Toma): audit soubor mel 2026-09-12
  1 197 radku a NULA ctenaru - zadny kod ho necetl, zadny krok ho nespoustel. Log bez
  ctenare je "allow s mezikrokem", ne doklad. Tenhle skript je ten ctenar: vola ho krok
  uzavery session (GSD `.claude/skills/uzavera-session/SKILL.md`, krok 1) a kanarek na
  SessionStart hlasi prirustek radku od minuleho startu (resume-cost.ps1).

  Cte se UDALOST, ne obsah: radek nese ts, tool, shape, decision - text prikazu v auditu
  neni (zadani TASK-36 par. 4 bod 8). Skript nic nemeni; kdyz soubor chybi, rekne to
  a skonci nulou - chybejici audit je stav k ohlaseni, ne pad.

.PARAMETER Path
  Cesta k gate-audit.jsonl. Vychozi: $env:CLAUDE_PLUGIN_DATA\gate-audit.jsonl, a kdyz
  promenna neni (skript bezi mimo hook), datovy adresar pluginu v profilu uzivatele
  (~\.claude\plugins\data\sinogard-hooks-sinogard-hooks\gate-audit.jsonl).

.PARAMETER Since
  Jen radky s `ts` >= tento okamzik (napr. start session) - prirustek za session.

.PARAMETER Json
  Misto tabulky vypise souhrn jako JSON (pro stroje: kanarek, hlaseni).

.EXAMPLE
  pwsh -NoProfile -File tests/_audit-report.ps1
  pwsh -NoProfile -File tests/_audit-report.ps1 -Since '2026-09-12T20:00:00'
#>
param(
    [string]$Path = '',
    [string]$Since = '',
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Resolve-AuditPath([string]$Given) {
    if ($Given -ne '') { return $Given }
    $dir = $env:CLAUDE_PLUGIN_DATA
    if ([string]::IsNullOrWhiteSpace($dir)) {
        $dir = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.claude\plugins\data\sinogard-hooks-sinogard-hooks'
    }
    return (Join-Path $dir 'gate-audit.jsonl')
}

$auditPath = Resolve-AuditPath $Path
if (-not (Test-Path -LiteralPath $auditPath)) {
    if ($Json) { Write-Output (@{ path = $auditPath; exists = $false; rows = 0 } | ConvertTo-Json -Compress) }
    else { Write-Host ("audit: soubor neexistuje ({0}) - zadny radek, nic k cteni" -f $auditPath) }
    exit 0
}

$utf8 = New-Object System.Text.UTF8Encoding($false)
$lines = @([System.IO.File]::ReadAllLines($auditPath, $utf8) | Where-Object { $_.Trim() -ne '' })
$sinceTs = $null
if ($Since -ne '') { $sinceTs = [DateTimeOffset]::Parse($Since, [System.Globalization.CultureInfo]::InvariantCulture) }

$rows = New-Object System.Collections.ArrayList
$bad = 0
foreach ($l in $lines) {
    $o = $null
    try { $o = $l | ConvertFrom-Json } catch { $bad++; continue }
    if ($null -eq $o) { $bad++; continue }
    $ts = $null
    if ($o.PSObject.Properties['ts']) { try { $ts = [DateTimeOffset]::Parse([string]$o.ts, [System.Globalization.CultureInfo]::InvariantCulture) } catch { $ts = $null } }
    if ($null -ne $sinceTs -and ($null -eq $ts -or $ts -lt $sinceTs)) { continue }
    [void]$rows.Add([pscustomobject]@{
        ts       = $ts
        tool     = if ($o.PSObject.Properties['tool']) { [string]$o.tool } else { '' }
        shape    = if ($o.PSObject.Properties['shape']) { [string]$o.shape } else { '' }
        decision = if ($o.PSObject.Properties['decision']) { [string]$o.decision } else { '' }
    })
}

$byShape = @($rows | Group-Object shape, decision | Sort-Object Count -Descending | ForEach-Object {
    [pscustomobject]@{ shape = $_.Group[0].shape; decision = $_.Group[0].decision; count = $_.Count }
})
$byTool = @($rows | Group-Object tool | Sort-Object Count -Descending | ForEach-Object {
    [pscustomobject]@{ tool = $_.Name; count = $_.Count }
})
$stamps = @($rows | Where-Object { $null -ne $_.ts } | ForEach-Object { $_.ts } | Sort-Object)
$first = if ($stamps.Count -gt 0) { $stamps[0].ToString('o') } else { '' }
$last  = if ($stamps.Count -gt 0) { $stamps[$stamps.Count - 1].ToString('o') } else { '' }

if ($Json) {
    Write-Output (@{
        path = $auditPath; exists = $true; totalLines = $lines.Count; rows = $rows.Count
        invalid = $bad; since = $Since; first = $first; last = $last
        byShape = $byShape; byTool = $byTool
    } | ConvertTo-Json -Depth 4 -Compress)
    exit 0
}

Write-Host ("audit: {0}" -f $auditPath)
Write-Host ("radku v souboru: {0}   v rozsahu: {1}   nevalidnich: {2}" -f $lines.Count, $rows.Count, $bad)
if ($Since -ne '') { Write-Host ("od: {0}" -f $Since) }
if ($rows.Count -gt 0) { Write-Host ("prvni: {0}   posledni: {1}" -f $first, $last) }
Write-Host ''
Write-Host 'rozpad per tvar x rozhodnuti:'
foreach ($g in $byShape) { Write-Host ("  {0,6}  {1}  {2}" -f $g.count, $g.shape, $g.decision) }
Write-Host ''
Write-Host 'rozpad per nastroj:'
foreach ($g in $byTool) { Write-Host ("  {0,6}  {1}" -f $g.count, $g.tool) }
exit 0
