#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Testy upozorneni (hooks/scripts/notify.ps1).

.DESCRIPTION
  Sada tvrdi TVAR vystupu, ne to, ze upozorneni doopravdy vyskocilo - to je
  pozorovatelne jen na obrazovce Toma a patri do hlaseni, ne do zelene sady.
  Kanaly `toast` a `messagebox` se testuji jen na "nic neblokuje a nic nevypise".

.EXAMPLE
  pwsh -NoProfile -File tests/notify.tests.ps1
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
    Write-Host "notify.ps1 - upozorneni   (interpret: $Interpreter)" -ForegroundColor Yellow
}

$cfg = [System.IO.File]::ReadAllText(
    (Join-Path $script:RepoRoot 'hooks/config/defaults.json'),
    ([System.Text.UTF8Encoding]::new($false))) | ConvertFrom-Json

$ESC = [char]27
$BEL = [char]7

function New-Override([string]$Name, [string]$Json) {
    $dir = Join-Path $script:TempDir ($Name + '/.claude')
    [void][System.IO.Directory]::CreateDirectory($dir)
    [System.IO.File]::WriteAllText((Join-Path $dir 'sinogard-hooks.json'), $Json,
        ([System.Text.UTF8Encoding]::new($false)))
    return (Join-Path $script:TempDir $Name)
}

function Get-TerminalSequence($Result) {
    if ([string]::IsNullOrWhiteSpace($Result.Stdout)) { return '' }
    $obj = $Result.Stdout | ConvertFrom-Json
    $p = $obj.PSObject.Properties['terminalSequence']
    if ($null -eq $p) { return '' }
    return [string]$p.Value
}

$matchers = @('permission_prompt', 'idle_prompt', 'agent_needs_input', 'elicitation_dialog')

# 🔴 Vychozi kanal je `toast` (volba z mereni prostredi, viz README), takze sekvenci OSC 9
# si sada musi ZAPNOUT prepnutim - jinak by tvrdila neco o jinem kanalu, nez ktery bezi.
$osc9Dir = New-Override 'projekt-notify-osc9' '{"notify":{"channel":"osc9","title":"Claude Code"}}'
$osc9Env = @{ CLAUDE_PROJECT_DIR = $osc9Dir }

Start-Case 'kanal osc9 -> platny JSON s OSC 9 a jmenem matcheru'
foreach ($m in $matchers) {
    $json = New-HookInput 'notification' @{ 'notification_type' = $m }
    $r = Invoke-Hook -Script 'notify.ps1' -InputJson $json -Environment $osc9Env
    Assert-Equal 0 $r.Exit ("[{0}] exit 0" -f $m)

    $seq = Get-TerminalSequence $r
    $expectedBody = $cfg.texts.notifyText -replace '\{matcher\}', $m
    Assert-Equal ($ESC + ']9;' + $expectedBody + $BEL) $seq ("[{0}] sekvence presne dle konfigurace" -f $m)
    Add-HookTime $r.Ms
    Assert-True ($r.Ms -lt (Get-HookCeilingMs)) ("[{0}] doba {1} ms < {2}" -f $m, $r.Ms, (Get-HookCeilingMs))
}

Start-Case 'sekvence nese jen povolene OSC (Claude Code jine zahodi)'
$json = New-HookInput 'notification' @{ 'notification_type' = 'permission_prompt' }
$r = Invoke-Hook -Script 'notify.ps1' -InputJson $json -Environment $osc9Env
$seq = Get-TerminalSequence $r
# povoleno: OSC 0/1/2/9/99/777 a BEL. Zadny jiny ESC nez uvodni uvod sekvence.
$escCount = ([regex]::Matches($seq, [regex]::Escape($ESC))).Count
Assert-Equal 1 $escCount 'sekvence obsahuje prave jeden ESC'
Assert-True ($seq.StartsWith($ESC + ']9;')) 'sekvence zacina OSC 9'
Assert-True ($seq.EndsWith($BEL)) 'sekvence konci BEL'
Assert-True ($seq.Substring(4, $seq.Length - 5) -notmatch '[\x00-\x1F\x7F]') 'telo nenese ridici znaky'

Start-Case 'ridici znaky ve vstupu se do sekvence nedostanou'
$json = New-HookInput 'notification' @{ 'notification_type' = "perm" + $ESC + "]0;zla sekvence" + $BEL }
$r = Invoke-Hook -Script 'notify.ps1' -InputJson $json -Environment $osc9Env
$seq = Get-TerminalSequence $r
Assert-Equal 1 (([regex]::Matches($seq, [regex]::Escape($ESC))).Count) 'vlozeny ESC byl odstranen'
Assert-Equal 1 (([regex]::Matches($seq, [regex]::Escape($BEL))).Count) 'vlozeny BEL byl odstranen'

Start-Case 'channel none -> zadny vystup'
$dir = New-Override 'projekt-notify-none' '{"notify":{"channel":"none","title":"Claude Code"}}'
$json = New-HookInput 'notification' @{ 'notification_type' = 'permission_prompt' }
$r = Invoke-Hook -Script 'notify.ps1' -InputJson $json -Environment @{ CLAUDE_PROJECT_DIR = $dir }
Assert-Equal 0 $r.Exit '[none] exit 0'
Assert-Equal '' $r.Stdout.Trim() '[none] zadny stdout'

# 🔴 SINOGARD_HOOKS_DRYRUN=1 je tu POVINNE, ne pohodli. Bez nej sada strilela skutecne
# toasty a modalni okna - Tom je videl jako "nekolik notifikaci jako Windows warning"
# a kazdy messagebox po sobe nechal viset skryty proces (nalez Amber B12).
# Skutecna notifikace patri sonde, kterou pousti clovek, ne sade.
$dryRun = @{ SINOGARD_HOOKS_DRYRUN = '1' }

Start-Case 'channel toast a messagebox nic neblokuji a nic nevypisou (dry-run)'
foreach ($ch in @('toast', 'messagebox')) {
    $dir = New-Override ('projekt-notify-' + $ch) ('{"notify":{"channel":"' + $ch + '","title":"Claude Code"}}')
    $json = New-HookInput 'notification' @{ 'notification_type' = 'permission_prompt' }
    $r = Invoke-Hook -Script 'notify.ps1' -InputJson $json -Environment ($dryRun + @{ CLAUDE_PROJECT_DIR = $dir })
    Assert-Equal 0 ($r.Exit) ("[{0}] exit 0" -f $ch)
    Assert-Equal '' ($r.Stdout.Trim()) ("[{0}] zadny stdout" -f $ch)
    Assert-True ($r.Stderr -match 'DRYRUN') ("[{0}] dry-run rekl, co by poslal" -f $ch)
    Assert-True ($r.Ms -lt ((Get-HookCeilingMs) + 3000)) ("[{0}] doba {1} ms - neblokuje" -f $ch, $r.Ms)
}

# Zadani par. 2.3: "Zvuk ne". Sablona ToastText02 ale zvuk HRAJE, dokud se
# `<audio silent="true"/>` nedoplni (nalez Amber A3). XML se proto sklada jako
# retezec - jinak by tohle tvrzeni neslo overit pod pwsh 7, kde WinRT neexistuje.
Start-Case 'toast je tichy - XML nese audio silent="true"'
$dir = New-Override 'projekt-notify-toast-tichy' '{"notify":{"channel":"toast","title":"Claude Code"}}'
$json = New-HookInput 'notification' @{ 'notification_type' = 'permission_prompt' }
$r = Invoke-Hook -Script 'notify.ps1' -InputJson $json -Environment ($dryRun + @{ CLAUDE_PROJECT_DIR = $dir })
Assert-True ($r.Stderr -match '<audio\s+silent="true"\s*/>') 'XML toastu vypina zvuk'
Assert-True ($r.Stderr -match 'ToastText02') 'XML toastu drzi puvodni sablonu'

Start-Case 'ridici a XML znaky ve jmene matcheru toast nerozbiji'
$dir = New-Override 'projekt-notify-toast-escape' '{"notify":{"channel":"toast","title":"Claude & <Code>"}}'
$json = New-HookInput 'notification' @{ 'notification_type' = 'perm<&>"x"' }
$r = Invoke-Hook -Script 'notify.ps1' -InputJson $json -Environment ($dryRun + @{ CLAUDE_PROJECT_DIR = $dir })
Assert-Equal 0 $r.Exit '[escape] exit 0'
$xml = ''
if ($r.Stderr -match '(<toast>.*</toast>)') { $xml = $Matches[1] }
Assert-True ($xml -ne '') '[escape] XML se naslo na stderr'
$parsed = $null
try { $parsed = [xml]$xml } catch { $parsed = $null }
Assert-True ($null -ne $parsed) '[escape] XML je porad platne (znaky jsou escapovane)'

Start-Case 'vadny vstup hook nezastavi'
foreach ($bad in @('', '{', '{"hook_event_name":"Notification"}')) {
    $r = Invoke-Hook -Script 'notify.ps1' -InputJson $bad
    Assert-Equal 0 $r.Exit ("vadny vstup <{0}> konci exit 0" -f $bad)
}

Start-Case 'vypnuti hooku projektovym override'
$dir = New-Override 'projekt-notify-off' '{"hooks":{"gate":true,"secrets":true,"resumeCost":true,"notify":false}}'
$json = New-HookInput 'notification' @{ 'notification_type' = 'permission_prompt' }
$r = Invoke-Hook -Script 'notify.ps1' -InputJson $json -Environment @{ CLAUDE_PROJECT_DIR = $dir }
Assert-Equal '' $r.Stdout.Trim() '[override] vypnuty notify nevypisuje nic'
Assert-Equal 0 $r.Exit '[override] exit 0'

Assert-TimingBudget

Write-TestSummary
if ($script:Fail -gt 0) { exit 1 }
exit 0
