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

# XML se sklada jako RETEZEC a teprve pak se nacte. Dva duvody:
#   1. `<audio silent="true"/>` sablona ToastText02 neumi - zadani par. 2.3 rika "Zvuk ne"
#      a sablona ho hraje (nalez Amber A3).
#   2. Retezec jde zkontrolovat i tam, kde WinRT vubec neexistuje (pwsh 7), takze
#      tvrzeni "toast je tichy" umi overit sada na OBOU interpretech.
function Get-ToastXml([string]$Title, [string]$Body) {
    $t = [System.Security.SecurityElement]::Escape($Title)
    $b = [System.Security.SecurityElement]::Escape($Body)
    return '<toast><visual><binding template="ToastText02">' +
           '<text id="1">' + $t + '</text>' +
           '<text id="2">' + $b + '</text>' +
           '</binding></visual><audio silent="true"/></toast>'
}

function Send-Toast([string]$Title, [string]$Body) {
    # WinRT z PowerShellu bez modulu. Proveditelnost nebyla predem overena -
    # kdyz typ nejde nacist, hook mlci a vraci $false (kanal se pak nepouzije).
    try {
        [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        $xml = [Windows.Data.Xml.Dom.XmlDocument]::new()
        $xml.LoadXml((Get-ToastXml $Title $Body))
        $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
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
        # SINOGARD_HOOKS_DRYRUN=1: nic se neposila, jen se na stderr rekne, CO by se
        # poslalo. Sada tim prestala strilet skutecna okna - Tom videl "nekolik
        # notifikaci jako Windows warning" a byly to prave testy (nalez Amber B12).
        # stdout zustava prazdny, takze tvrzeni "kanal nic nevypise" plati dal.
        if ($env:SINOGARD_HOOKS_DRYRUN -eq '1') {
            Write-HookStderr ('DRYRUN toast ' + (Get-ToastXml $title $body))
            exit 0
        }
        [void](Send-Toast $title $body)
        exit 0
    }
    'messagebox' {
        if ($env:SINOGARD_HOOKS_DRYRUN -eq '1') {
            Write-HookStderr ('DRYRUN messagebox ' + $title + ' | ' + $body)
            exit 0
        }
        [void](Send-MessageBox $title $body)
        exit 0
    }
}

exit 0
