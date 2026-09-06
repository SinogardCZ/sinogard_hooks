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

    # SINOGARD_HOOKS_DRYRUN se VZDY vynuluje, dokud si ho pripad sam nenastavi.
    # Je to globalni promenna prostredi a CI ji nastavuje pro celou ulohu, takze
    # kanarkove testy doma merily neco jineho nez na CI - proslo to jen proto, ze
    # muj shell ji nema. Test nesmi merit okolni prostredi; hodnotu si urcuje sam.
    $psi.EnvironmentVariables['SINOGARD_HOOKS_DRYRUN'] = ''

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

# ---------------------------------------------- sber pripadu a regresni invariant ---
#
# Nalez Amber H2: invariants.json vznikl "generovano z pripadovych poli", ale generator
# v repu nebyl - pri pristim rustu sady by ho nikdo nezopakoval a soubor by zkamenel.
# Sber jde pres tyhle dve funkce: sady, ktere vydavaji ROZHODNUTI o opravneni (gate,
# secrets), kazdy svuj pripad ohlasi. resume-cost a notify zadne rozhodnuti nevydavaji
# (SessionStart pridava kontext, Notification strili toast), takze pro ne invariant
# nema co drzet - to je duvod, ne opomenuti.
$script:CollectedCases = New-Object System.Collections.ArrayList

function Test-CollectOnly { return ($env:SINOGARD_HOOKS_COLLECT -eq '1') }

function Add-CollectedCase([string]$Hook, [string]$Kind, [string]$Tool, [string]$Value,
                           [string]$Expect, [string]$Since) {
    [void]$script:CollectedCases.Add([ordered]@{
        hook = $Hook; kind = $Kind; tool = $Tool; cmd = $Value; expect = $Expect; since = $Since
    })
}

# Vypis pro generator. Ohraniceny znackami, aby se dal vytahnout z vystupu sady.
function Write-CollectedCases {
    if (-not (Test-CollectOnly)) { return }
    Write-Host '<<<SINOGARD-CASES'
    Write-Host (($script:CollectedCases | ConvertTo-Json -Depth 5 -Compress))
    Write-Host 'SINOGARD-CASES>>>'
}

# Prehraje radky invariantu, ktere patri danemu hooku. Radek bez `hook`/`kind` je
# z prvniho vydani souboru - tehdy byl invariant jen pro branu nad prikazy.
function Invoke-InvariantRows([string]$HookName) {
    # V rezimu sberu se hook nespousti vubec - generator jen potrebuje seznam pripadu.
    if (Test-CollectOnly) { return }
    Start-Case ("regresni invariant (fixtures/invariants.json, hook {0})" -f $HookName)
    $invPath = Join-Path $PSScriptRoot 'fixtures/invariants.json'
    if (-not (Test-SafePath $invPath)) {
        $script:Skip++
        Write-Host '    SKIP invariants.json chybi' -ForegroundColor Yellow
        return
    }
    $invDoc = [System.IO.File]::ReadAllText($invPath, ([System.Text.UTF8Encoding]::new($false))) | ConvertFrom-Json
    $rowsProp = $invDoc.PSObject.Properties['rows']
    $all = if ($null -eq $rowsProp) { @() } else { @($rowsProp.Value) }

    $mine = New-Object System.Collections.ArrayList
    foreach ($row in $all) {
        $hook = if ($row.PSObject.Properties['hook']) { [string]$row.hook } else { 'gate' }
        if ($hook -eq $HookName) { [void]$mine.Add($row) }
    }
    Assert-True ($mine.Count -ge 1) ("invariantu pro {0} je {1}" -f $HookName, $mine.Count)

    foreach ($row in $mine) {
        $kind = if ($row.PSObject.Properties['kind']) { [string]$row.kind } else { 'cmd' }
        if ($kind -eq 'path') {
            $template = switch ([string]$row.tool) {
                'Write' { 'pretooluse-write' }
                'Edit'  { 'pretooluse-edit' }
                default { 'pretooluse-read' }
            }
            $json = New-HookInput $template @{ 'tool_input.file_path' = $row.cmd }
        } else {
            $template = if ([string]$row.tool -eq 'PowerShell') { 'pretooluse-powershell' } else { 'pretooluse-bash' }
            $json = New-HookInput $template @{ 'tool_input.command' = $row.cmd }
        }
        $r = Invoke-Hook -Script ($HookName + '.ps1') -InputJson $json
        Assert-Equal $row.expect (Get-Decision $r) ("[invariant/{0}] {1}" -f $row.since, $row.cmd)
    }
}

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
# Tyto dve funkce jsou ZAMERNE kopie tech z hooks/scripts/_common.ps1, ne dot-source:
# kdyby sada sdilela kod s tim, co meri, chyba v _common.ps1 by se schovala sama pred
# sebou. Duplicitu drzim vedome a je to par radku.
function Join-SafePath([string]$Base, [string]$Leaf) {
    if ([string]::IsNullOrWhiteSpace($Base)) { return $null }
    try { return [System.IO.Path]::Combine($Base, $Leaf) } catch { return $null }
}

function Test-SafePath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try { return [System.IO.File]::Exists($Path) -or [System.IO.Directory]::Exists($Path) }
    catch { return $false }
}

# Cesta na jednotce, ktera na tomhle stroji NEEXISTUJE. Presne to potkalo hook na CI:
# fixtures nesou cwd "W:/dev/gsd/repo", runner zadne W: nema, Join-Path/Test-Path
# resolvuji PSDrive a misto "neni" vyhodily vyjimku. Vraci $null, kdyz jsou vsechna
# pismena obsazena - pak se pripad PRESKOCI, nezezelena naprazdno.
function Get-MissingDrivePath([string]$Leaf = 'projekt') {
    $used = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() })
    foreach ($letter in [char[]]'QYXVUTSRPNMLKJIHGFE') {
        if ($used -notcontains ([string]$letter)) { return ([string]$letter + ':\' + $Leaf) }
    }
    return $null
}

function Get-Decision($Result) {
    if ([string]::IsNullOrWhiteSpace($Result.Stdout)) {
        # Prazdny stdout ma DVA vyznamy a sada je musela rozlisovat od zacatku:
        #   exit 0 = hook se nevyjadril, plati normalni tok opravneni (allow),
        #   exit != 0 = hook SPADL a fail-closed ho utnul.
        # Kdyz se oboji hlasilo jako 'allow', spadly hook vypadal jako propusteny
        # prikaz - presne tak se na CI schovala pricina za 44 radku "dostano allow".
        if ($Result.Exit -ne 0) {
            $why = ($Result.Stderr -replace '\s+', ' ').Trim()
            if ($why.Length -gt 300) { $why = $why.Substring(0, 300) }
            if ([string]::IsNullOrWhiteSpace($why)) { $why = '(bez stderr)' }
            return ("CRASH(exit={0}): {1}" -f $Result.Exit, $why)
        }
        return 'allow'
    }
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
