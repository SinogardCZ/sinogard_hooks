#!/usr/bin/env pwsh
<#
.SYNOPSIS
  SessionStart: kanarek pri startu a cena obnoveni pri resume/fork.

.DESCRIPTION
  ASCII-ONLY zdroj; lidske texty jsou v hooks/config/defaults.json.

  Tenhle hook NIC NEBLOKUJE. Jeho fail-closed je opacny nez u brany: kdyz spadne,
  konci exit 0 a mlci - jinak by chyba v evidenci zastavila session.

  Kanarek (T36-N5) se POCITA, netiskne se konstanta: kazdy ze ctyr hooku dostane
  znacku podle toho, jestli jeho skript existuje A je zapnuty. Konstantni "vse OK"
  by byla kontrola, ktera nemuze selhat.
#>

trap { exit 0 }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '_common.ps1')

$PluginRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

function Get-PluginVersion([string]$Root) {
    $path = Join-Path $Root '.claude-plugin/plugin.json'
    if (-not (Test-Path -LiteralPath $path)) { return '?' }
    $manifest = ConvertFrom-Json (Read-Utf8File $path)
    return [string](Get-Field $manifest 'version' '?')
}

function Get-CanaryMessage($Config, [string]$Root) {
    $ok = Get-Text $Config 'canaryOk' 'ok'
    $off = Get-Text $Config 'canaryOff' '-'
    $map = @{ gate = 'gate.ps1'; secrets = 'secrets.ps1'; resumeCost = 'resume-cost.ps1'; notify = 'notify.ps1' }
    $state = @{}
    foreach ($key in $map.Keys) {
        $scriptPath = Join-Path $Root ('hooks/scripts/' + $map[$key])
        $live = (Test-Path -LiteralPath $scriptPath) -and (Test-HookEnabled $Config $key)
        $state[$key] = if ($live) { $ok } else { $off }
    }
    $text = Get-Text $Config 'canary' 'sinogard-hooks {version}'
    $text = $text -replace '\{version\}', (Get-PluginVersion $Root)
    $text = $text -replace '\{gate\}', $state['gate']
    $text = $text -replace '\{secrets\}', $state['secrets']
    $text = $text -replace '\{resume\}', $state['resumeCost']
    $text = $text -replace '\{notify\}', $state['notify']
    return $text
}

function Write-ResumeLog($Payload, [double]$Seconds, [double]$Tokens, [bool]$Expired, [double]$Usd, [string]$FileName) {
    $dir = $env:CLAUDE_PLUGIN_DATA
    if ([string]::IsNullOrWhiteSpace($dir)) { return }   # bez datoveho adresare se nic nezapisuje
    [void][System.IO.Directory]::CreateDirectory($dir)
    $line = [ordered]@{
        ts         = (Get-Date).ToString('o')
        session_id = [string](Get-Field $Payload 'session_id' '')
        source     = [string](Get-Field $Payload 'source' '')
        seconds    = $Seconds
        tokens     = $Tokens
        expired    = $Expired
        usd        = $Usd
    } | ConvertTo-Json -Depth 4 -Compress
    $path = Join-Path $dir $FileName
    $bytes = ([System.Text.UTF8Encoding]::new($false)).GetBytes($line + "`n")
    $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Dispose()
}

# ------------------------------------------------------------------ beh ---

$raw = Read-HookStdin
if ([string]::IsNullOrWhiteSpace($raw)) { exit 0 }

$payload = $null
try { $payload = $raw | ConvertFrom-Json } catch { $payload = $null }
if ($null -eq $payload) { exit 0 }

$cwd = [string](Get-Field $payload 'cwd' (Get-Location).Path)
$projectDir = $env:CLAUDE_PROJECT_DIR
if ([string]::IsNullOrWhiteSpace($projectDir)) { $projectDir = $cwd }

$config = Get-HookConfig $PluginRoot $projectDir
if (-not (Test-HookEnabled $config 'resumeCost')) { exit 0 }

$source = [string](Get-Field $payload 'source' 'startup')
$seconds = Get-Field $payload 'seconds_since_last_response' $null
$tokens  = Get-Field $payload 'context_tokens' $null
$expired = Get-Field $payload 'prompt_cache_likely_expired' $null
$usd     = Get-Field $payload 'estimated_cache_write_usd' $null

$hasCost = ($source -eq 'resume' -or $source -eq 'fork') -and
           ($null -ne $seconds) -and ($null -ne $tokens)

if (-not $hasCost) {
    $message = Get-CanaryMessage $config $PluginRoot
    Write-HookStdout (@{ systemMessage = $message } | ConvertTo-Json -Depth 3 -Compress)
    exit 0
}

$totalMinutes = [Math]::Floor([double]$seconds / 60)
$hours = [Math]::Floor($totalMinutes / 60)
$minutes = $totalMinutes - ($hours * 60)

$expiredText = if ([bool]$expired) { Get-Text $config 'resumeYes' 'ano' } else { Get-Text $config 'resumeNo' 'ne' }
$usdValue = 0.0
if ($null -ne $usd) { $usdValue = [double]$usd }

$message = Get-Text $config 'resumeMessage' 'Resume {h}:{m} {tokens} {expired} {usd}'
$message = $message -replace '\{h\}', ([string]$hours)
$message = $message -replace '\{m\}', ([string]$minutes)
$message = $message -replace '\{tokens\}', ([string]([long]$tokens))
$message = $message -replace '\{expired\}', $expiredText
$message = $message -replace '\{usd\}', ($usdValue.ToString('0.0000', [System.Globalization.CultureInfo]::InvariantCulture))

$logFile = [string](Get-Field (Get-Field $config 'resumeCost') 'logFile' 'resume-log.jsonl')
Write-ResumeLog $payload ([double]$seconds) ([double]$tokens) ([bool]$expired) $usdValue $logFile

Write-HookStdout (@{ systemMessage = $message } | ConvertTo-Json -Depth 3 -Compress)
exit 0
