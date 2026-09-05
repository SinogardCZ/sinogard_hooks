#!/usr/bin/env pwsh
<#
.SYNOPSIS
  PreToolUse secrets guard: cteni, zapis i vypis souboru se secrets konci deny nebo ask.

.DESCRIPTION
  ASCII-ONLY zdroj (viz _common.ps1); lidske texty jsou v hooks/config/defaults.json.
  Fail-closed stejne jako gate.ps1: vyjimka, vadny vstup i neznamy nastroj = exit 2.

  Nelogujeme obsah nastroju ani promptu - do rozhodnuti jde jen cesta nebo prikaz,
  a ven jen duvod.
#>

$script:InternalMessage = 'secrets.ps1: internal error, blocked'
trap {
    try { Write-HookStderr $script:InternalMessage } catch { [Console]::Error.Write($script:InternalMessage) }
    exit 2
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '_common.ps1')

$PluginRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

$script:ReadTools  = @('Read')
$script:WriteTools = @('Edit', 'Write', 'MultiEdit', 'NotebookEdit')
$script:CmdTools   = @('Bash', 'PowerShell')

# ------------------------------------------------------------- pomocnici ---

function Test-AnyPattern([string]$Text, $Patterns) {
    foreach ($p in $Patterns) {
        if ([string]::IsNullOrWhiteSpace([string]$p)) { continue }
        if ([regex]::IsMatch($Text, [string]$p, 'IgnoreCase')) { return $true }
    }
    return $false
}

function Get-BaseName([string]$NormalPath) {
    $idx = $NormalPath.LastIndexOf('/')
    if ($idx -ge 0) { return $NormalPath.Substring($idx + 1) }
    return $NormalPath
}

# Je soubor verzovany gitem? Neznama odpoved je 'ne' - nikdy allow ze slabosti.
function Test-GitTracked([string]$RepoDir, [string]$RelativePath) {
    if ([string]::IsNullOrWhiteSpace($RepoDir)) { return $false }
    if (-not (Test-SafePath $RepoDir)) { return $false }
    try {
        $null = & git -C $RepoDir ls-files --error-unmatch -- $RelativePath 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Get-RelativeToCwd([string]$NormalPath, [string]$CwdNormal) {
    if ($NormalPath.StartsWith($CwdNormal + '/')) { return $NormalPath.Substring($CwdNormal.Length + 1) }
    return $NormalPath
}

# --------------------------------------------------------- pravidlo cesty ---

function Test-SecretPath([string]$Path, [bool]$IsWrite, $Config) {
    $sec = Get-Field $Config 'secrets'
    $shapes = Get-Field $sec 'shapes'
    $norm = ConvertTo-NormalPath $Path
    if ($norm -eq '') { return $null }
    $base = Get-BaseName $norm

    # Nalez Metis 21: `Get-Content .en?` shell rozvine na `.env`, ale kontrola vidi
    # `.en?`. Zastupny znak je neznamy cil -> Z3: ask. POZOR: ale NE u kazdeho globu:
    # `ls *.md` nebo `grep x *.ts` by se ptalo pokazde a takova brana se do tydne
    # vypne. Ptame se jen tehdy, kdyz ten glob DOKAZE padnout na chranene jmeno.
    if ($base -match '[\*\?]') {
        $globRegex = '^' + ([regex]::Escape($base) -replace '\\\*', '.*' -replace '\\\?', '.') + '$'
        foreach ($known in @(Get-Field $sec 'protectedBaseNames' @())) {
            if ([regex]::IsMatch([string]$known, $globRegex, 'IgnoreCase')) {
                return @{ Decision = 'ask'
                          Shape = ((Get-Field $shapes 'wildcardPath' '{path}') -replace '\{path\}', $Path) }
            }
        }
        return $null
    }

    # (1) soubory prostredi maji vlastni politiku - verzovany .env.<x> je legitimni
    $envCfg = Get-Field $sec 'envFile'
    # `^\.env($|\.)`, ne `^\.env` - jinak by sem spadl i `.envrc`, ktery ma vlastni
    # tvrde pravidlo, a skoncil by v mekci vetvi "trackovany? -> allow".
    if ($base -match '^\.env($|\.)') {
        if (Test-AnyPattern $base @(Get-Field $envCfg 'allowNames' @())) { return $null }
        if (Test-AnyPattern $base @(Get-Field $envCfg 'denyNames' @())) {
            return @{ Decision = 'deny'
                      Shape = ((Get-Field $shapes 'secretFile' '{path}') -replace '\{path\}', $Path) }
        }
        $rel = Get-RelativeToCwd $norm (ConvertTo-NormalPath $script:Cwd)
        if (Test-GitTracked $script:Cwd $rel) { return $null }
        return @{ Decision = 'ask'
                  Shape = ((Get-Field $shapes 'envFileUntracked' '{path}') -replace '\{path\}', $Path) }
    }

    # (2) tvrde zakazane tvary
    if (Test-AnyPattern $norm @(Get-Field $sec 'denyPathPatterns' @())) {
        return @{ Decision = 'deny'
                  Shape = ((Get-Field $shapes 'secretFile' '{path}') -replace '\{path\}', $Path) }
    }

    # (3) sebeochrana - soubory, kterymi se brana vypina (jen zapis)
    if ($IsWrite -and (Test-AnyPattern $norm @(Get-Field $sec 'selfProtectPathPatterns' @()))) {
        return @{ Decision = 'ask'
                  Shape = ((Get-Field $shapes 'selfProtect' '{path}') -replace '\{path\}', $Path) }
    }

    # (4) seda zona
    if (Test-AnyPattern $norm @(Get-Field $sec 'askPathPatterns' @())) {
        return @{ Decision = 'ask'
                  Shape = ((Get-Field $shapes 'settingsLocal' '{path}') -replace '\{path\}', $Path) }
    }

    return $null
}

# ------------------------------------------------------- pravidlo prikazu ---

# Vytahne z prikazu tokeny, ktere vypadaji jako cesta. Slovo bez lomitka a bez
# tecky na zacatku cestou neni - jinak by kazdy prepinac spustil falesny nalez.
function Get-PathCandidate([string]$Command) {
    $out = New-Object System.Collections.ArrayList

    # (a) Nalez Metis 23/24: cesta muze byt LITERAL uvnitr vyrazu
    # (`[IO.File]::ReadAllText('.env')`, `python -c "open('.env')"`). Kazdy retezec
    # v uvozovkach je proto kandidat. Vetsina jich nic nematchne - vyhodnoceni navic
    # nic nestoji, kdezto vynechany literal je dira.
    # Dva NEZAVISLE prubehy, ne jedna alternace: `python -c "open('.env')"` ma jednoduche
    # uvozovky UVNITR dvojitych, a jedna alternace by vnejsi retezec spotrebovala
    # a vnitrni uz nenasla.
    foreach ($pattern in @('"([^"]{1,260})"', '''([^'']{1,260})''')) {
        foreach ($m in [regex]::Matches($Command, $pattern)) {
            $value = $m.Groups[1].Value
            if ($value -ne '') { [void]$out.Add($value) }
        }
    }

    foreach ($token in (Expand-ColonParameter (Split-Arguments $Command))) {
        # (b) Nalez Metis 22: `cat<.env` - presmerovani nemusi mit kolem sebe mezery,
        # takze token muze nest prikaz i cestu naraz.
        foreach ($piece in ($token -split '[<>]')) {
            $t = $piece
            if ($t.StartsWith('-')) {
                $eq = $t.IndexOf('=')
                if ($eq -lt 0) { continue }
                $t = $t.Substring($eq + 1)
            }
            # git show <ref>:<cesta>  (ale ne disk C:\...)
            if ($t -notmatch '^[A-Za-z]:[\\/]' -and $t -match '^[^/\\]+:[^\\/:]') {
                $t = $t.Substring($t.LastIndexOf(':') + 1)
            }
            if ($t -eq '') { continue }
            # (c) Nalez Metis 2: `Get-Content id_rsa` - hole jmeno souboru bez lomitka
            # a bez tecky na zacatku se drive kandidatem nestalo, takze se vzor na
            # privatni klic vubec nevyhodnotil. Kandidatem je proto i jmeno s TECKOU
            # nebo s prefixem `id_`.
            if ($t.Contains('/') -or $t.Contains('\') -or
                $t.StartsWith('.') -or $t.StartsWith('~') -or $t.StartsWith('%') -or
                $t.Contains('.') -or $t -match '^id_' -or
                $t.Contains('*') -or $t.Contains('?')) {
                [void]$out.Add($t)
            }
        }
    }
    return ,@($out)
}

function Test-EnvironmentDump([string]$Command) {
    foreach ($sub in (Split-CommandLine $Command)) {
        $argv = Split-Arguments $sub
        if ($argv.Count -eq 0) { continue }
        $exe = Get-ExecutableName $argv[0]
        $rest = @()
        if ($argv.Count -gt 1) { $rest = @($argv[1..($argv.Count - 1)]) }
        $positional = @($rest | Where-Object { -not $_.StartsWith('-') -and -not $_.StartsWith('/') })

        if ($exe -eq 'printenv' -and $positional.Count -eq 0) { return $true }
        if ($exe -eq 'env' -and $positional.Count -eq 0) { return $true }
        if ($exe -eq 'set' -and $rest.Count -eq 0) { return $true }
        # Nalez councilu Metis 2026-09-05: `Get-Content Env:*` je taky vypis celeho
        # prostredi - vzor musi pripustit hvezdicku a seznam cmdletu i cteci cestu,
        # ne jen vypis polozek providera.
        if (@('get-childitem', 'gci', 'dir', 'ls', 'get-item', 'gi',
              'get-content', 'gc', 'cat', 'type') -contains $exe) {
            foreach ($a in $positional) { if ($a -match '^env:[\\/*]*$') { return $true } }
        }
    }
    return $false
}

function Get-SensitiveEnvName([string]$Command, [string]$NamePattern) {
    $patterns = @(
        '\$env:([A-Za-z_][A-Za-z0-9_]*)',
        '(?:^|[^A-Za-z0-9_])env:([A-Za-z_][A-Za-z0-9_]*)',
        '\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?',
        'getenvironmentvariable\s*\(\s*["'']([^"'']+)["'']',
        '%([A-Za-z_][A-Za-z0-9_]*)%'
    )
    foreach ($p in $patterns) {
        foreach ($m in [regex]::Matches($Command, $p, 'IgnoreCase')) {
            $name = $m.Groups[1].Value
            if ([regex]::IsMatch($name, $NamePattern, 'IgnoreCase')) { return $name }
        }
    }
    return ''
}

function Test-SecretCommand([string]$Command, $Config) {
    $sec = Get-Field $Config 'secrets'
    $shapes = Get-Field $sec 'shapes'
    $worst = $null

    # zapisove tvary v prikazu (presmerovani, Set-Content, ...) zapinaji sebeochranu
    $isWrite = ($Command -match '(>>?|\btee\b|\bset-content\b|\bout-file\b|\badd-content\b|\bsc\b)')

    foreach ($candidate in (Get-PathCandidate $Command)) {
        $r = Test-SecretPath $candidate $isWrite $Config
        if ($null -eq $r) { continue }
        if ($r.Decision -eq 'deny') { return $r }
        if ($null -eq $worst) { $worst = $r }
    }

    if (Test-EnvironmentDump $Command) {
        if ($null -eq $worst) {
            $worst = @{ Decision = 'ask'; Shape = (Get-Field $shapes 'envDump' 'env') }
        }
    }

    $namePattern = [string](Get-Field $sec 'envVarNamePattern' '(KEY|TOKEN|SECRET|PASSWORD|PWD|CREDENTIAL)')
    $name = Get-SensitiveEnvName $Command $namePattern
    if ($name -ne '') {
        if ($null -eq $worst) {
            $worst = @{ Decision = 'ask'
                        Shape = ((Get-Field $shapes 'envVarRead' '{name}') -replace '\{name\}', $name) }
        }
    }

    return $worst
}

# ------------------------------------------------------------------ beh ---

$raw = Read-HookStdin
if ([string]::IsNullOrWhiteSpace($raw)) { Write-HookStderr $script:InternalMessage; exit 2 }

$payload = $null
try { $payload = $raw | ConvertFrom-Json } catch { $payload = $null }
if ($null -eq $payload) { Write-HookStderr $script:InternalMessage; exit 2 }

$toolName = [string](Get-Field $payload 'tool_name' '')
$toolInput = Get-Field $payload 'tool_input'
$script:Cwd = [string](Get-Field $payload 'cwd' (Get-Location).Path)
$mode = [string](Get-Field $payload 'permission_mode' 'default')

$projectDir = $env:CLAUDE_PROJECT_DIR
if ([string]::IsNullOrWhiteSpace($projectDir)) { $projectDir = $script:Cwd }

$config = Get-HookConfig $PluginRoot $projectDir
$script:InternalMessage = Get-Text $config 'secretsInternalError' $script:InternalMessage

$known = @($script:ReadTools + $script:WriteTools + $script:CmdTools)
if ($known -notcontains $toolName) { Write-HookStderr $script:InternalMessage; exit 2 }

if (-not (Test-HookEnabled $config 'secrets')) { exit 0 }

$decision = $null
if ($script:CmdTools -contains $toolName) {
    $command = [string](Get-Field $toolInput 'command' '')
    if ([string]::IsNullOrWhiteSpace($command)) { Write-HookStderr $script:InternalMessage; exit 2 }
    $decision = Test-SecretCommand $command $config
} else {
    $path = [string](Get-Field $toolInput 'file_path' '')
    if ($path -eq '') { $path = [string](Get-Field $toolInput 'notebook_path' '') }
    if ($path -eq '') { $path = [string](Get-Field $toolInput 'path' '') }
    if ([string]::IsNullOrWhiteSpace($path)) { Write-HookStderr $script:InternalMessage; exit 2 }
    $decision = Test-SecretPath $path ($script:WriteTools -contains $toolName) $config
}

if ($null -eq $decision) { exit 0 }

$reason = (Get-Text $config 'gateReason' 'Brana par. 6: {shape}') -replace '\{shape\}', $decision.Shape

if ($decision.Decision -eq 'ask' -and $mode -eq 'bypassPermissions') {
    $reason = $reason + (Get-Text $config 'bypassSuffix' ' bypass')
    Write-DenyDecision $reason
}
if ($decision.Decision -eq 'deny') { Write-DenyDecision $reason }
Write-AskDecision $reason
