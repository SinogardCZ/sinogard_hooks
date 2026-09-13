#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Testy hlaseni ceny obnoveni a startovniho kanarka (hooks/scripts/resume-cost.ps1).

.EXAMPLE
  pwsh -NoProfile -File tests/resume-cost.tests.ps1
#>
param(
    [switch]$Full,
    [string]$Interpreter = 'powershell.exe'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot '_harness.ps1')
$script:Interpreter = $Interpreter
Assert-NoCollectEnv

if ($Full) {
    Write-Host ""
    Write-Host "resume-cost.ps1 - kanarek a cena resume   (interpret: $Interpreter)" -ForegroundColor Yellow
}

$cfg = [System.IO.File]::ReadAllText(
    (Join-Path $script:RepoRoot 'hooks/config/defaults.json'),
    ([System.Text.UTF8Encoding]::new($false))) | ConvertFrom-Json
$manifest = [System.IO.File]::ReadAllText(
    (Join-Path $script:RepoRoot '.claude-plugin/plugin.json'),
    ([System.Text.UTF8Encoding]::new($false))) | ConvertFrom-Json

function Get-SystemMessage($Result) {
    if ([string]::IsNullOrWhiteSpace($Result.Stdout)) { return '' }
    $obj = $Result.Stdout | ConvertFrom-Json
    $p = $obj.PSObject.Properties['systemMessage']
    if ($null -eq $p) { return '' }
    return [string]$p.Value
}

# ------------------------------------------------------- startup = kanarek ---

Start-Case 'startup -> kanarek se ctyrmi stavy a verzi (T36-N5)'
$json = New-HookInput 'sessionstart-startup' @{}
$r = Invoke-Hook -Script 'resume-cost.ps1' -InputJson $json
$msg = Get-SystemMessage $r

$expectedCanary = $cfg.texts.canary
$expectedCanary = $expectedCanary -replace '\{version\}', $manifest.version
$expectedCanary = $expectedCanary -replace '\{gate\}', $cfg.texts.canaryOk
$expectedCanary = $expectedCanary -replace '\{secrets\}', $cfg.texts.canaryOk
$expectedCanary = $expectedCanary -replace '\{resume\}', $cfg.texts.canaryOk
$expectedCanary = $expectedCanary -replace '\{notify\}', $cfg.texts.canaryOk

Assert-Equal 0 $r.Exit 'startup exit 0'
Assert-Equal $expectedCanary $msg 'startup systemMessage presne dle konfigurace'
Assert-True ($msg.Contains([string]$manifest.version)) 'kanarek nese verzi pluginu'

# 🔎 Kontrolni skupina: kanarek se POCITA. Kdyz se notify vypne, musi se to
# v nem projevit - konstantni "vse OK" by tenhle pripad neshodil.
Start-Case 'kanarek je pocitany, ne konstanta (kontrolni skupina)'
$overrideDir = Join-Path $script:TempDir 'projekt-canary/.claude'
[void][System.IO.Directory]::CreateDirectory($overrideDir)
[System.IO.File]::WriteAllText(
    (Join-Path $overrideDir 'sinogard-hooks.json'),
    '{"hooks":{"gate":true,"secrets":true,"resumeCost":true,"notify":false}}',
    ([System.Text.UTF8Encoding]::new($false)))
$r2 = Invoke-Hook -Script 'resume-cost.ps1' -InputJson $json -Environment @{
    CLAUDE_PROJECT_DIR = (Join-Path $script:TempDir 'projekt-canary')
}
$msg2 = Get-SystemMessage $r2
$expectedOff = $cfg.texts.canary
$expectedOff = $expectedOff -replace '\{version\}', $manifest.version
$expectedOff = $expectedOff -replace '\{gate\}', $cfg.texts.canaryOk
$expectedOff = $expectedOff -replace '\{secrets\}', $cfg.texts.canaryOk
$expectedOff = $expectedOff -replace '\{resume\}', $cfg.texts.canaryOk
$expectedOff = $expectedOff -replace '\{notify\}', $cfg.texts.canaryOff
Assert-Equal $expectedOff $msg2 'vypnuty notify je v kanarku videt'
Assert-True ($msg2 -ne $msg) 'kanarek se zmenil (jinak by nemohl selhat)'

# ------------------------------------------------------ resume s hodnotami ---

Start-Case 'resume s plnym vstupem -> cena + radek JSONL'
$dataDir = Join-Path $script:TempDir 'plugin-data'
[void][System.IO.Directory]::CreateDirectory($dataDir)
$json = New-HookInput 'sessionstart-resume' @{}
$r = Invoke-Hook -Script 'resume-cost.ps1' -InputJson $json -Environment @{ CLAUDE_PLUGIN_DATA = $dataDir }
$msg = Get-SystemMessage $r

# 5400 s = 90 min = 1 h 30 min
$expected = $cfg.texts.resumeMessage
$expected = $expected -replace '\{h\}', '1'
$expected = $expected -replace '\{m\}', '30'
$expected = $expected -replace '\{tokens\}', '182340'
$expected = $expected -replace '\{expired\}', $cfg.texts.resumeYes
$expected = $expected -replace '\{usd\}', '1.1396'

Assert-Equal 0 $r.Exit 'resume exit 0'
Assert-Equal $expected $msg 'resume systemMessage presne dle konfigurace (vc. ceskych znaku)'

$logPath = Join-Path $dataDir $cfg.resumeCost.logFile
Assert-True (Test-Path -LiteralPath $logPath) 'JSONL soubor vznikl'
if (Test-Path -LiteralPath $logPath) {
    $lines = @([System.IO.File]::ReadAllLines($logPath, ([System.Text.UTF8Encoding]::new($false))) |
               Where-Object { $_ -ne '' })
    Assert-Equal 1 $lines.Count 'JSONL ma prave jeden radek'
    $entry = $lines[0] | ConvertFrom-Json
    Assert-Equal 'test-session' $entry.session_id 'JSONL session_id'
    Assert-Equal 'resume' $entry.source 'JSONL source'
    Assert-Equal 5400 $entry.seconds 'JSONL seconds'
    Assert-Equal 182340 $entry.tokens 'JSONL tokens'
    Assert-Equal $true $entry.expired 'JSONL expired'
    Assert-Equal 1.1396 $entry.usd 'JSONL usd'
    # Tvrdi se BAJTY v souboru, ne $entry.ts - ConvertFrom-Json prevede ISO retezec
    # na DateTime a regex by pak meril jeho lokalni formatovani, ne to, co je zapsane.
    Assert-True ($lines[0] -match '"ts":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}') 'JSONL ts je ISO 8601 (v zapsanem textu)'
}

# JSONL se PRIPOJUJE, neprepisuje
Start-Case 'druhy resume pripoji dalsi radek (append, ne prepis)'
$r = Invoke-Hook -Script 'resume-cost.ps1' -InputJson $json -Environment @{ CLAUDE_PLUGIN_DATA = $dataDir }
$lines = @([System.IO.File]::ReadAllLines($logPath, ([System.Text.UTF8Encoding]::new($false))) |
           Where-Object { $_ -ne '' })
Assert-Equal 2 $lines.Count 'JSONL ma po druhem behu dva radky'

# -------------------------------------------- resume bez poli (starsi CLI) ---

Start-Case 'resume bez poli ceny -> jen kanarek, zadny pad'
$json = New-HookInput 'sessionstart-resume-minimal' @{}
$r = Invoke-Hook -Script 'resume-cost.ps1' -InputJson $json -Environment @{ CLAUDE_PLUGIN_DATA = $dataDir }
$msg = Get-SystemMessage $r
Assert-Equal 0 $r.Exit 'resume bez poli exit 0'
Assert-Equal $expectedCanary $msg 'resume bez poli vraci kanarek, ne cenu'

# --------------------------------------------------- nic neblokuje (Z6) ---

Start-Case 'vadny vstup hook nezastavi (opak fail-closed brany)'
foreach ($bad in @('', '{', '{"hook_event_name":"SessionStart"}')) {
    $r = Invoke-Hook -Script 'resume-cost.ps1' -InputJson $bad
    Assert-Equal 0 $r.Exit ("vadny vstup <{0}> konci exit 0" -f $bad)
}

Start-Case 'vypnuti hooku projektovym override'
$overrideDir = Join-Path $script:TempDir 'projekt-resume/.claude'
[void][System.IO.Directory]::CreateDirectory($overrideDir)
[System.IO.File]::WriteAllText(
    (Join-Path $overrideDir 'sinogard-hooks.json'),
    '{"hooks":{"gate":true,"secrets":true,"resumeCost":false,"notify":true}}',
    ([System.Text.UTF8Encoding]::new($false)))
$json = New-HookInput 'sessionstart-startup' @{}
$r = Invoke-Hook -Script 'resume-cost.ps1' -InputJson $json -Environment @{
    CLAUDE_PROJECT_DIR = (Join-Path $script:TempDir 'projekt-resume')
}
Assert-Equal '' (Get-SystemMessage $r) '[override] vypnuty hook nehlasi nic'
Assert-Equal 0 $r.Exit '[override] exit 0'

# ------------------------------------------------- D2: kanarek hlasi dry-run ---

# Nalez Amber D2: SINOGARD_HOOKS_DRYRUN je GLOBALNI promenna prostredi. Kdyby prosakla
# do produkce, upozorneni by tise prestala chodit a kanarek by dal hlasil notify jako
# zapnuty. Par musi izolovat prave tuhle jednu promennou - stejny vstup, jen s ni a bez ni.
Start-Case 'kanarek prizna dry-run rezim (a bez nej mlci)'
$json = New-HookInput 'sessionstart-startup' @{}

$rDry = Invoke-Hook -Script 'resume-cost.ps1' -InputJson $json -Environment @{ SINOGARD_HOOKS_DRYRUN = '1' }
$msgDry = Get-SystemMessage $rDry
Assert-True ($msgDry -match 'DRY-RUN') '[dry-run] kanarek rezim prizna'

$rNormal = Invoke-Hook -Script 'resume-cost.ps1' -InputJson $json
$msgNormal = Get-SystemMessage $rNormal
Assert-True ($msgNormal -notmatch 'DRY-RUN') '[bez dry-run] kanarek o nem mlci'
Assert-True ($msgNormal -ne '') '[bez dry-run] kanarek porad neco hlasi'

# ------------------------- TASK-106 vyrok 6 (0.2.0): kanarek hlasi prirustek auditu ---
#
# Audit brany mel 2026-09-12 1 197 radku a NULA ctenaru (hlaseni 01 §3). Vyrok 6 Amber
# (mandat Toma): kanarek na SessionStart vypise PRIRUSTEK radku od minuleho startu.
# Tvrdi se CISLO, ne pritomnost vety: prvni start nad 3 radky hlasi +3, po pripsani dvou
# radku druhy start hlasi +2 (ne +5) - znacka posledniho stavu se tedy zapsala a cetla.
# Mutant: zapomenout zapsat znacku -> druhy start hlasi +5 -> cervena.
# Kontrolni skupina: bez audit souboru se k kanarku NIC nepripoji (jinak by "+0" tvrdilo
# "audit se pise", i kdyz ho nikdo nepise).
Start-Case 'vyrok 6: kanarek hlasi prirustek radku auditu od minuleho startu'
$auditDataDir = Join-Path $script:TempDir 'plugin-data-audit'
[void][System.IO.Directory]::CreateDirectory($auditDataDir)
$auditFile = Join-Path $auditDataDir $cfg.gate.auditFile
$auditRow = '{"ts":"2026-09-12T20:00:00.0000000+02:00","tool":"Bash","shape":"opaque:variable","decision":"allow"}'
[System.IO.File]::WriteAllText($auditFile, ($auditRow + "`n") * 3, ([System.Text.UTF8Encoding]::new($false)))
$jsonStart = New-HookInput 'sessionstart-startup' @{}

$expectedA1 = $expectedCanary + (($cfg.texts.canaryAudit -replace '\{delta\}', '3') -replace '\{total\}', '3')
$rA1 = Invoke-Hook -Script 'resume-cost.ps1' -InputJson $jsonStart -Environment @{ CLAUDE_PLUGIN_DATA = $auditDataDir }
Assert-Equal 0 $rA1.Exit '[audit-kanarek] prvni start exit 0'
Assert-Equal $expectedA1 (Get-SystemMessage $rA1) '[audit-kanarek] prvni start: +3 (3 celkem)'
Assert-True (Test-Path -LiteralPath (Join-Path $auditDataDir 'audit-canary.json')) '[audit-kanarek] znacka posledniho stavu vznikla'

[System.IO.File]::AppendAllText($auditFile, ($auditRow + "`n") * 2, ([System.Text.UTF8Encoding]::new($false)))
$expectedA2 = $expectedCanary + (($cfg.texts.canaryAudit -replace '\{delta\}', '2') -replace '\{total\}', '5')
$rA2 = Invoke-Hook -Script 'resume-cost.ps1' -InputJson $jsonStart -Environment @{ CLAUDE_PLUGIN_DATA = $auditDataDir }
Assert-Equal $expectedA2 (Get-SystemMessage $rA2) '[audit-kanarek] druhy start: +2 (5 celkem), ne +5'

# resume s cenou nese prirustek taky - session obnovena pres --resume by jinak o auditu neslysela
$rA3 = Invoke-Hook -Script 'resume-cost.ps1' -InputJson (New-HookInput 'sessionstart-resume' @{}) -Environment @{ CLAUDE_PLUGIN_DATA = $auditDataDir }
$msgA3 = Get-SystemMessage $rA3
Assert-True ($msgA3.EndsWith((($cfg.texts.canaryAudit -replace '\{delta\}', '0') -replace '\{total\}', '5'))) ("[audit-kanarek] resume nese +0 (5 celkem): {0}" -f $msgA3)

# 🔴 kontrolni skupina: bez audit souboru zadna veta o auditu
$noAuditDir = Join-Path $script:TempDir 'plugin-data-noaudit'
[void][System.IO.Directory]::CreateDirectory($noAuditDir)
$rA4 = Invoke-Hook -Script 'resume-cost.ps1' -InputJson $jsonStart -Environment @{ CLAUDE_PLUGIN_DATA = $noAuditDir }
Assert-Equal $expectedCanary (Get-SystemMessage $rA4) '[audit-kanarek/kontrola] bez audit souboru je kanarek beze zmeny'

Write-TestSummary
if ($script:Fail -gt 0) { exit 1 }
exit 0
