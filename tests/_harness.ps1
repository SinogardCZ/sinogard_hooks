#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Sdileny harness testovych sad sinogard-hooks - bez Pester.

.DESCRIPTION
  Prevzaty vzor z GSD `repo/tests/scripts/_harness.ps1` (rozhodnuti Toma 2026-08-11
  bod 4a: PowerShell moduly nemaji project scope). Dot-source sdili scope volajiciho,
  takze volajici sada musi mit PRED dot-source vlastni `param([switch]$Full, ...)`.

  Ticho je default: potlacuji se radky OK a hlavicky pripadu, NIKDY fail, souhrn,
  navratovy kod ani chyby behu. `skipped` pocita PRIPADY, `passed`/`failed` ASSERTY.

  Navic proti GSD: `Invoke-Hook` spousti skript hooku jako SKUTECNY PROCES pres
  hranici stdin/stdout - dot-source by ztratil navratovy kod i kodovani, tedy prave
  to, o cem sada tvrdi.
#>

$script:Pass = 0
$script:Fail = 0
$script:Skip = 0
# Pod StrictMode je cteni nenastavene promenne vyjimka - a ta by sadu shodila
# uprostred, tedy "nezmereno", ne cervena.
$script:BaselineMs = $null
$script:CurrentCase = ''
$script:CaseHeaderPrinted = $false

function Start-Case([string]$name) {
    $script:CurrentCase = $name
    $script:CaseHeaderPrinted = $false
    if ($Full) {
        Write-Host ""
        Write-Host "  $name" -ForegroundColor Cyan
        $script:CaseHeaderPrinted = $true
    }
}

function Write-CaseFailHeaderOnce {
    if (-not $script:CaseHeaderPrinted) {
        Write-Host ""
        Write-Host "  $script:CurrentCase" -ForegroundColor Cyan
        $script:CaseHeaderPrinted = $true
    }
}

function Assert-Equal($expected, $actual, [string]$what) {
    if ($expected -eq $actual) {
        $script:Pass++
        if ($Full) { Write-Host ("    OK   {0}: {1}" -f $what, $actual) -ForegroundColor DarkGray }
    } else {
        $script:Fail++
        if (-not $Full) { Write-CaseFailHeaderOnce }
        Write-Host ("    FAIL {0}: cekano <{1}>, dostano <{2}>" -f $what, $expected, $actual) -ForegroundColor Red
    }
}

function Assert-True([bool]$cond, [string]$what) {
    if ($cond) {
        $script:Pass++
        if ($Full) { Write-Host ("    OK   {0}" -f $what) -ForegroundColor DarkGray }
    } else {
        $script:Fail++
        if (-not $Full) { Write-CaseFailHeaderOnce }
        Write-Host ("    FAIL {0}" -f $what) -ForegroundColor Red
    }
}

function Write-TestSummary {
    $format = if ($Full) { "{0} passed / {1} failed / {2} skipped" }
              else       { "{0} passed / {1} failed / {2} skipped   (detail: -Full)" }
    Write-Host ""
    Write-Host "-------------------------------------------"
    Write-Host ($format -f $script:Pass, $script:Fail, $script:Skip) `
        -ForegroundColor $(if ($script:Fail) { 'Red' } else { 'Green' })
    Write-Host ""
}

# ------------------------------------------------------------ spousteni ---

$script:RepoRoot   = Split-Path $PSScriptRoot -Parent
$script:ScriptsDir = Join-Path $script:RepoRoot 'hooks/scripts'
$script:TempDir    = Join-Path ([System.IO.Path]::GetTempPath()) ("sinogard-hooks-tests-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
[void][System.IO.Directory]::CreateDirectory($script:TempDir)

# Zapise vstup hooku do docasneho souboru jako UTF-8 BEZ BOM (BOM by rozbil
# ConvertFrom-Json na strane hooku) a vrati cestu.
function New-FixtureFile([string]$Json, [string]$Name) {
    $path = Join-Path $script:TempDir ($Name + '.json')
    [System.IO.File]::WriteAllBytes($path, ([System.Text.UTF8Encoding]::new($false)).GetBytes($Json))
    return $path
}

# Nacte sablonu z tests/fixtures a dosadi do ni hodnoty.
function New-HookInput([string]$Template, [hashtable]$Values) {
    $path = Join-Path $PSScriptRoot ('fixtures/' + $Template + '.json')
    $text = [System.IO.File]::ReadAllText($path, ([System.Text.UTF8Encoding]::new($false)))
    $obj = $text | ConvertFrom-Json
    foreach ($key in $Values.Keys) {
        $parts = $key.Split('.')
        $node = $obj
        for ($i = 0; $i -lt $parts.Length - 1; $i++) { $node = $node.$($parts[$i]) }
        $leaf = $parts[$parts.Length - 1]
        if ($node.PSObject.Properties[$leaf]) { $node.PSObject.Properties.Remove($leaf) }
        $node | Add-Member -NotePropertyName $leaf -NotePropertyValue $Values[$key]
    }
    return ($obj | ConvertTo-Json -Depth 10)
}

# Spusti skript hooku jako skutecny proces. Vraci Exit / Stdout / Stderr / Ms.
# Vstup se zapisuje do BaseStream jako bajty - .NET Framework (PS 5.1) neumi
# StandardInputEncoding, takze jakykoli textovy zapis by prosel pres OEM stranku.
function Invoke-Hook {
    param(
        [Parameter(Mandatory = $true)][string]$Script,
        # Prazdny stdin je legitimni pripad brany (fail-closed), ne chyba volani.
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$InputJson,
        [string]$Interpreter = $script:Interpreter,
        [hashtable]$Environment = $null
    )

    $scriptPath = Join-Path $script:ScriptsDir $Script
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Interpreter
    $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $scriptPath + '"'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $psi.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
    $psi.WorkingDirectory = $script:RepoRoot
    if ($Environment) {
        foreach ($k in $Environment.Keys) { $psi.EnvironmentVariables[$k] = [string]$Environment[$k] }
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $proc = [System.Diagnostics.Process]::Start($psi)

    # Cteni se spousti PRED zapisem - jinak plny buffer roury zablokuje obe strany.
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()

    $bytes = ([System.Text.UTF8Encoding]::new($false)).GetBytes($InputJson)
    $proc.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
    $proc.StandardInput.BaseStream.Flush()
    $proc.StandardInput.Close()

    $proc.WaitForExit()
    $sw.Stop()

    return [pscustomobject]@{
        Exit   = $proc.ExitCode
        Stdout = $outTask.Result
        Stderr = $errTask.Result
        Ms     = $sw.ElapsedMilliseconds
    }
}

# Studeny start interpretu sam o sobe trva pres sekundu a na zatizenem stroji kolisa.
# Absolutni strop by proto meril ZATEZ STROJE, ne hook. Baseline je spusteni prazdneho
# skriptu tymz interpretem - rozdil proti nemu je vlastni naklad hooku, tedy prave to,
# o cem tvrzeni mluvi (pomale nacteni konfigurace).
function Measure-InterpreterBaseline {
    $noop = Join-Path $script:TempDir 'noop.ps1'
    [System.IO.File]::WriteAllText($noop, "exit 0`n", ([System.Text.UTF8Encoding]::new($false)))
    $times = @()
    for ($i = 0; $i -lt 3; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $script:Interpreter
        $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $noop + '"'
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        [void]$p.StandardOutput.ReadToEnd()
        [void]$p.StandardError.ReadToEnd()
        $p.WaitForExit()
        $sw.Stop()
        $times += $sw.ElapsedMilliseconds
    }
    return [int](($times | Measure-Object -Maximum).Maximum)
}

# 🔴 Proc MEDIAN a ne strop na kazde fixture:
#   Zadani chtelo "kazda fixture < 2 s". Zmereno: samotny studeny start interpretu je
#   ~336 ms, cely hook na NEZATIZENEM stroji 1,0-1,27 s (nejhorsi z peti), a behem
#   vlastni sady - 200 procesu za sebou - jednotlive behy vystoupaji pres 2,5 s.
#   Absolutni strop na 2 s by tedy meril ZATEZ STROJE, ne hook: cervena by prisla
#   podle toho, co zrovna bezi vedle, a takova brana se do tydne vypne.
#   Konstrukce je proto dvojdilna:
#     - TVRDY STROP na jednu fixture (HookCeilingMs) chyta beh, ktery se zasekl;
#       je hluboko pod `timeout: 10` z hooks.json, kde by uz slo o PROPUSTENI.
#     - MEDIAN pres vsechny fixtury chyta systematicke zpomaleni (pomale nacteni
#       konfigurace, pribyly modul) a jednotlivy vykyv ho nepohne.
#   Odchylka od zneni zadani je vedoma a doprovozena merenim, ne odhadem.
$script:HookCeilingMs = 5000
$script:Times = New-Object System.Collections.ArrayList

function Add-HookTime([int]$Ms) { [void]$script:Times.Add($Ms) }

function Get-HookCeilingMs { return $script:HookCeilingMs }

function Assert-TimingBudget {
    if ($script:Times.Count -eq 0) { return }
    if ($null -eq $script:BaselineMs) { $script:BaselineMs = Measure-InterpreterBaseline }
    $sorted = @($script:Times | Sort-Object)
    $median = $sorted[[int][Math]::Floor($sorted.Count / 2)]
    $budget = $script:BaselineMs + 1500
    Start-Case 'doba behu (T36-N4)'
    Assert-True ($median -lt $budget) (
        "median {0} ms < {1} ms (baseline interpretu {2} + 1500) pres {3} behu; nejhorsi {4} ms" -f
        $median, $budget, $script:BaselineMs, $sorted.Count, $sorted[$sorted.Count - 1])
}

# Vytahne permissionDecision z vystupu hooku; prazdny vystup = 'allow'
# (zadne rozhodnuti, plati normalni tok opravneni).
function Get-Decision($Result) {
    if ([string]::IsNullOrWhiteSpace($Result.Stdout)) { return 'allow' }
    try {
        $obj = $Result.Stdout | ConvertFrom-Json
    } catch {
        return 'INVALID-JSON'
    }
    $hso = $obj.PSObject.Properties['hookSpecificOutput']
    if ($null -eq $hso) { return 'NO-HOOKSPECIFICOUTPUT' }
    $pd = $hso.Value.PSObject.Properties['permissionDecision']
    if ($null -eq $pd) { return 'NO-DECISION' }
    return [string]$pd.Value
}
