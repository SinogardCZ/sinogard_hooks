#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Notification: upozorni, ze Claude Code na neco ceka.

.DESCRIPTION
  ASCII-ONLY zdroj; texty v hooks/config/defaults.json.

  Nic neblokuje - pri chybe konci exit 0 a mlci.

  Kanal je volba v konfiguraci (`notify.channel`):
    osc9       - terminalSequence OSC 9 (Windows Terminal, ConEmu, WezTerm, iTerm2)
    toast      - WinRT toast pres Windows.UI.Notifications
    messagebox - System.Windows.Forms.MessageBox v ODDELENEM procesu
                 (v tomhle nikdy - modalni okno by drzelo hook do timeoutu)
    none       - nedela nic

  Claude Code propousti jen OSC 0/1/2/9/99/777 a BEL; cokoli jineho pole zahodi.
  Text se proto zbavi ridicich znaku, nez se do sekvence vlozi.
#>

trap { exit 0 }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '_common.ps1')

$PluginRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

$ESC = [char]27
$BEL = [char]7

function Remove-ControlChar([string]$Text) {
    return ([regex]::Replace($Text, '[\x00-\x1F\x7F]', ' '))
}

function Send-Toast([string]$Title, [string]$Body) {
    # WinRT z PowerShellu bez modulu. Proveditelnost nebyla predem overena -
    # kdyz typ nejde nacist, hook mlci a vraci $false (kanal se pak nepouzije).
    try {
        [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(
            [Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        $texts = $template.GetElementsByTagName('text')
        $texts.Item(0).AppendChild($template.CreateTextNode($Title)) | Out-Null
        $texts.Item(1).AppendChild($template.CreateTextNode($Body)) | Out-Null
        $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
        $appId = 'Microsoft.WindowsTerminal_8wekyb3d8bbwe!App'
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
        return $true
    } catch {
        return $false
    }
}

function Send-MessageBox([string]$Title, [string]$Body) {
    # Modalni okno se spousti v ODDELENEM procesu a necekame na nej - jinak by
    # hook bezel, dokud ho nekdo neodklikne, a spadl by na timeout.
    try {
        $script = "Add-Type -AssemblyName System.Windows.Forms; " +
                  "[void][System.Windows.Forms.MessageBox]::Show('" + ($Body -replace "'", "''") + "','" +
                  ($Title -replace "'", "''") + "')"
        Start-Process -FilePath 'powershell.exe' `
                      -ArgumentList @('-NoProfile', '-WindowStyle', 'Hidden', '-Command', $script) `
                      -WindowStyle Hidden | Out-Null
        return $true
    } catch {
        return $false
    }
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
if (-not (Test-HookEnabled $config 'notify')) { exit 0 }

$notifyCfg = Get-Field $config 'notify'
$channel = [string](Get-Field $notifyCfg 'channel' 'osc9')
if ($channel -eq 'none') { exit 0 }

$matcher = [string](Get-Field $payload 'notification_type' '')
$title = [string](Get-Field $notifyCfg 'title' 'Claude Code')
$body = Remove-ControlChar ((Get-Text $config 'notifyText' '{matcher}') -replace '\{matcher\}', $matcher)
$title = Remove-ControlChar $title

switch ($channel) {
    'osc9' {
        $sequence = $ESC + ']9;' + $body + $BEL
        Write-HookStdout (@{ terminalSequence = $sequence } | ConvertTo-Json -Depth 3 -Compress)
        exit 0
    }
    'toast' {
        [void](Send-Toast $title $body)
        exit 0
    }
    'messagebox' {
        [void](Send-MessageBox $title $body)
        exit 0
    }
}

exit 0
