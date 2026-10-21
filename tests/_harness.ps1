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
$script:AskOutputs = New-Object System.Collections.ArrayList

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
    # V rezimu sberu se hook nespousti, takze souhrn NIC netvrdi. Musi to byt videt
    # v logu, ne jen v hlave toho, kdo sadu spoustel (nalez Amber J2).
    # Nalez Amber L3: varovani nestacilo. Souhrnny radek `N passed / M failed` se
    # tiskl dal a verdikt cte prave jeho - takze rezim, ktery nic nemeri, uměl
    # vydat zelenou. V rezimu sberu ten radek proto NEVZNIKNE a verdikt hlasi
    # "souhrnny radek CHYBI".
    if ($script:CollectMode) {
        Write-Host "REZIM SBERU (-Collect): hook se nespoustel, souhrnny radek se netiskne." -ForegroundColor Yellow
        Write-Host ("sebrano {0} pripadu" -f $script:CollectedCases.Count) -ForegroundColor Yellow
        Write-Host ""
        return
    }
    Write-TimingLine
    Write-Host ($format -f $script:Pass, $script:Fail, $script:Skip) `
        -ForegroundColor $(if ($script:Fail) { 'Red' } else { 'Green' })
    Write-Host ""
}

# Rozdeleni dob behu se tisklo jen v -Full, takze na CI nebylo videt NIKDY - a kdyz
# strop spadl, zbyl holy udaj "9001 ms" bez toho, jak vypadal zbytek behu. Tri cykly
# CI se hledala pricina, kterou mel rict prvni z nich. Tiskne se proto vzdycky.
# Tvar radku zamerne NEobsahuje "passed /" - to je vzorec, kterym _ci-verdict.ps1
# hleda souhrn, a druha shoda by mu podstrcila jina cisla.
function Write-TimingLine {
    if ($script:Times.Count -eq 0) { return }
    $sorted = @($script:Times | Sort-Object)
    $median = $sorted[[int][Math]::Floor($sorted.Count / 2)]
    $max = $sorted[$sorted.Count - 1]
    $slow = @($sorted | Where-Object { $_ -ge 3000 }).Count
    Write-Host ("doba hooku: median {0} ms, max {1} ms, nad 3000 ms: {2} z {3}, opakovani po prekroceni stropu: {4}" `
        -f $median, $max, $slow, $sorted.Count, $script:Retries) -ForegroundColor DarkGray
}

# ------------------------------------------------------------ spousteni ---

$script:RepoRoot   = Split-Path $PSScriptRoot -Parent
$script:ScriptsDir = Join-Path $script:RepoRoot 'hooks/scripts'
$script:TempDir    = Join-Path ([System.IO.Path]::GetTempPath()) ("sinogard-hooks-tests-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
[void][System.IO.Directory]::CreateDirectory($script:TempDir)
# Prazdny projekt (bez `.claude/sinogard-hooks.json`) - vychozi CLAUDE_PROJECT_DIR kazdeho behu hooku.
$script:EmptyProjectDir = Join-Path $script:TempDir 'prazdny-projekt'
[void][System.IO.Directory]::CreateDirectory($script:EmptyProjectDir)

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
# 🔴 ZMENA MIMO ROZSAH KOLA 5b - vynutilo si ji CI, viz hlaseni 07 §0.
#
# Tvrdy strop na jednu fixturu meril na CI ZATEZ RUNNERU, ne hook. Tri behy pwsh po
# sobe spadly, pokazde na jinem tvaru (9001 ms, 5015 ms), zatimco tyz tvar doma bezi
# 1,1 s a job powershell.exe byl zeleny pokazde. Presne pred tim varuje komentar
# u HookCeilingMs: absolutni strop meri stroj.
#
# Beh, ktery se SKUTECNE zasekl, se zasekne i podruhe; vykyv planovace ne. Opakuje
# se proto jednou a tvrdi se druhe mereni - ale do MEDIANU jde vzdycky mereni PRVNI,
# aby median zustal poctivym pozorovanim stroje. Opakovani znovu spousti hook: na CI
# je DRYRUN=1, takze je to neskodne; doma by opakovani u `notify` znamenalo druhy
# toast - k prekroceni stropu tam ale nedochazi.
function Invoke-Hook {
    param(
        [Parameter(Mandatory = $true)][string]$Script,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$InputJson,
        [string]$Interpreter = $script:Interpreter,
        [hashtable]$Environment = $null,
        # TASK-179 kolo 8 (K8-5): radek s vlastnim `maxMs` pod stropem se opakuje uz nad nim - jinak by ho jeden vykyv
        # planovace shodil, zatimco radek bez `maxMs` by tytez vykyv prezil.
        [int]$RetryAboveMs = 0,
        [switch]$FreshDataOnRetry
    )

    $limit = if ($RetryAboveMs -gt 0) { [Math]::Min($RetryAboveMs, [int]$script:HookCeilingMs) } else { [int]$script:HookCeilingMs }
    $first = Invoke-HookOnce -Script $Script -InputJson $InputJson -Interpreter $Interpreter -Environment $Environment
    # Do rozpoctu jde PRVNI mereni - jinak by median klesal prave o ty behy, kvuli
    # kterym se opakuje, a prestal by systematicke zpomaleni videt.
    Add-HookTime ([int]$first.Ms)
    if ($first.Ms -lt $limit) { return $first }

    # K8-5: s -FreshDataOnRetry pise druhy beh audit do NOVE slozky (volajici cte `CLAUDE_PLUGIN_DATA` z tehoz slovniku) -
    # jinak by radky auditu nesly oba behy a pocty (`auditShapeCount`) by vysly dvojnasobne. Jen na prani: sady, ktere
    # slozku sdileji pres vic volani (stav session), ji meni nechteji.
    if ($FreshDataOnRetry -and $null -ne $Environment -and $Environment.ContainsKey('CLAUDE_PLUGIN_DATA')) {
        $Environment['CLAUDE_PLUGIN_DATA'] = [string]$Environment['CLAUDE_PLUGIN_DATA'] + '-r2'
    }
    $script:Retries++
    $second = Invoke-HookOnce -Script $Script -InputJson $InputJson -Interpreter $Interpreter -Environment $Environment
    Add-Member -InputObject $second -NotePropertyName 'FirstMs' -NotePropertyValue ([int]$first.Ms)
    Add-Member -InputObject $second -NotePropertyName 'Retried' -NotePropertyValue $true
    return $second
}

function Invoke-HookOnce {
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
    # TASK-117 (0.3.0): tataz trida "hodnota z okoli" jeste dvakrat. Bez CLAUDE_PROJECT_DIR
    # bere hook projekt z `cwd` sablony (W:/dev/gsd/repo) a na stroji, kde GSD repo je, mlcky
    # platil jeho skutecny prepis (`gate.opaque.*` = audit) - sada merila konfiguraci GSD,
    # ne vychozi chovani (CI ten adresar nema, takze tam merila neco jineho). A od 0.3.0 hook
    # zapisuje audit i u `ask`/`deny` (H-b): zdedeny CLAUDE_PLUGIN_DATA by sada psala do
    # skutecneho auditu. Vychozi je proto prazdny projekt a zadny audit; pripad si oboji
    # urcuje sam parametrem -Environment.
    $psi.EnvironmentVariables['CLAUDE_PROJECT_DIR'] = $script:EmptyProjectDir
    $psi.EnvironmentVariables['CLAUDE_PLUGIN_DATA'] = ''

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

    # ZOPT-Q102 (Tom 2026-10-20, TASK-179 / 0.3.1): hook nesmi vratit `ask` NIKDY - kazdy beh kazde sady se pocita
    # (Assert-NoAskVerdict), ne jen radky, ktere ocekavani `ask` nesou.
    $stdoutText = $outTask.Result
    if ($stdoutText -match '"permissionDecision"\s*:\s*"ask"') { [void]$script:AskOutputs.Add($Script) }

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
# Kolikrat se beh po prekroceni tvrdeho stropu opakoval. Tiskne se v souhrnu -
# opakovani, o kterem se nevi, by z tvrdeho stropu udelalo mrtvou vetev.
$script:Retries = 0

function Add-HookTime([int]$Ms) { [void]$script:Times.Add($Ms) }

# ---------------------------------------------- sber pripadu a regresni invariant ---
#
# Nalez Amber H2: invariants.json vznikl "generovano z pripadovych poli", ale generator
# v repu nebyl - pri pristim rustu sady by ho nikdo nezopakoval a soubor by zkamenel.
# Sber jde pres tyhle dve funkce: sady, ktere vydavaji ROZHODNUTI o opravneni (gate,
# secrets), kazdy svuj pripad ohlasi. resume-cost a notify zadne rozhodnuti nevydavaji
# (SessionStart pridava kontext, Notification strili toast), takze pro ne invariant
# nema co drzet - to je duvod, ne opomenuti.
#
# Nalez Amber J2 (POTRETI tataz trida "hodnota z okoli" - po W: a po DRYRUN): rezim
# sberu se driv bral z promenne prostredi. Kdyby ji mel nekdo nastavenou globalne,
# sady by se vyprazdnily TISE - bloky mimo `Test-Cases` bezi dal, takze `passed`
# zustane nenulove, souhrn vyjde zeleny a NIC z ~1400 tvaru se nezmeri. Rezim je
# proto PARAMETR sady; promenna prostredi se jen kontroluje a odmita.
$script:CollectedCases = New-Object System.Collections.ArrayList
$script:CollectMode = $false

function Set-CollectMode([bool]$On) { $script:CollectMode = $On }

function Test-CollectOnly { return $script:CollectMode }

# Zavola se hned po dot-source. Promenna prostredi rezim NEZAPINA - kdyz ji nekdo
# ma nastavenou, sada skonci nenulove misto toho, aby tise nezmerila nic.
function Assert-NoCollectEnv {
    if ($env:SINOGARD_HOOKS_COLLECT -eq '1') {
        Write-Host ''
        Write-Host 'CHYBA: SINOGARD_HOOKS_COLLECT=1 je v prostredi.' -ForegroundColor Red
        Write-Host 'Rezim sberu se zapina parametrem -Collect, ne promennou prostredi.' -ForegroundColor Red
        Write-Host 'Sada konci, aby nevydala zelenou nad nezmerenymi tvary.' -ForegroundColor Red
        exit 1
    }
}

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
    # TASK-117: pripad s typografickou uvozovkou (M25, U+201C) prosel konzoli
    # powershell.exe pres OEM stranku a "best fit" z U+201C udelal `"` - JSON se rozbil a generator
    # spadl. Mimo-ASCII znaky se proto vypisuji jako \uXXXX (uvnitr retezce JSON je to tyz znak).
    $jsonCases = ($script:CollectedCases | ConvertTo-Json -Depth 5 -Compress)
    $jsonCases = [regex]::Replace($jsonCases, '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
    Write-Host $jsonCases
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

# TASK-117 (0.3.0): pripady v datovem souboru tests/fixtures/task117-<hook>.json. Radek nese
# tool, cmd, expect (nebo expectNot), volitelne mode (permission_mode), override (text
# projektoveho prepisu; `@<klic>` = hodnota `_override<Klic>` z tehoz souboru), reasonContains,
# audit (auditShape regex, auditDecision, auditNotContains) a faze. Radek s `faze` vetsi nez
# `$script:Task117Faze` ceka na schvaleny navrh a pocita se jako PRESKOCENY - ne zeleny.
$script:Task117Faze = 2
# TASK-179 (0.3.1): tentyz format radku nese i tests/fixtures/task179-<hook>.json - `$Fixture` je predpona souboru.
function Invoke-Task117Rows([string]$HookName, [string]$Fixture = 'task117') {
    $path = Join-Path $PSScriptRoot ('fixtures/' + $Fixture + '-' + $HookName + '.json')
    $doc = [System.IO.File]::ReadAllText($path, ([System.Text.UTF8Encoding]::new($false))) | ConvertFrom-Json
    $rows = @($doc.rows)
    Assert-True ($rows.Count -ge 1) ("[{0}/{1}] fixture nese pripady: {2}" -f $Fixture, $HookName, $rows.Count)
    foreach ($row in $rows) {
        $faze = if ($row.PSObject.Properties['faze']) { [int]$row.faze } else { 1 }
        $expect = if ($row.PSObject.Properties['expect']) { [string]$row.expect } else { '' }
        $label = ("[{0}/{1}/{2}] {3}" -f $Fixture, $row.group, $row.name, (([string]$row.cmd) -replace '\r?\n', ' / '))
        # Faze se kontroluje PRED sberem: radek, ktery ceka na schvaleny navrh, do invariantu
        # nepatri - generator by z nej udelal tvrzeni, ktere zadna sada nemerila.
        if ($faze -gt $script:Task117Faze) {
            if (Test-CollectOnly) { continue }
            $script:Skip++
            if ($Full) { Write-Host ("    SKIP {0} (faze {1})" -f $label, $faze) -ForegroundColor Yellow }
            continue
        }
        # Radek s projektovym prepisem nebo rezimem meri JINY stav nez invariant (ten bezi
        # bez prepisu a v `default`) - do invariantu by prisel s chybnym ocekavanim. Radek s `{REP}` / `{REP2}` (K8-9) nese
        # nerozvinuty zastupny text - pozna se podle presneho zastupce, tymz kriteriem jako rozvinuti nize (K9-7: predpona `{REP`
        # by vyradila i literal jako `{REPO}`; K10-4: vlastnost `repText` by nepoznala radek jen s `{REP2}`).
        $cmdRaw = [string]$row.cmd
        if ($expect -ne '' -and -not $row.PSObject.Properties['override'] -and -not $row.PSObject.Properties['mode'] -and
            -not $row.PSObject.Properties['cwd'] -and -not $cmdRaw.Contains('{PLUGIN_ROOT}') -and
            -not $cmdRaw.Contains('{REP}') -and -not $cmdRaw.Contains('{REP2}')) {
            $kind = if (@('Write', 'Edit', 'Read') -contains [string]$row.tool) { 'path' } else { 'cmd' }
            Add-CollectedCase $HookName $kind ([string]$row.tool) ([string]$row.cmd) $expect ([string]$row.name)
        }
        if (Test-CollectOnly) { continue }
        # Z117-Q23: radek muze byt i nastroj nad souborem (Write/Edit/Read - `cmd` je cesta) a nest vlastni `cwd`.
        # `{PLUGIN_ROOT}` = koren pluginu, ze ktereho sada hooky spousti (= "prave bezici plugin", R2 kolo 2).
        $rootFwd = ([string]$script:RepoRoot).Replace('\', '/')
        $cmdText = ([string]$row.cmd).Replace('{PLUGIN_ROOT}', $rootFwd)
        # TASK-179 kolo 6 (K6-4): `{REP}` = `repText` opakovany `repCount`krat (patologicky dlouhy prikaz bez tisicu znaku ve fixture).
        if ($cmdText.Contains('{REP}')) { $cmdText = $cmdText.Replace('{REP}', ([string]$row.repText * [int]$row.repCount)) }
        # K7-1 (kolo 7): druhe opakovani (`{REP2}`) pro vnorene UZAVRENE zavorky - otviraci v `{REP}`, zaviraci v `{REP2}`.
        if ($cmdText.Contains('{REP2}')) { $cmdText = $cmdText.Replace('{REP2}', ([string]$row.repText2 * [int]$row.repCount2)) }
        $tool = [string]$row.tool
        $values = @{}
        if (@('Write', 'Edit', 'Read') -contains $tool) {
            $template = 'pretooluse-' + $tool.ToLowerInvariant()
            $values['tool_input.file_path'] = $cmdText
        } else {
            $template = if ($tool -eq 'PowerShell') { 'pretooluse-powershell' } else { 'pretooluse-bash' }
            $values['tool_input.command'] = $cmdText
        }
        if ($row.PSObject.Properties['mode']) { $values['permission_mode'] = [string]$row.mode }
        if ($row.PSObject.Properties['cwd']) { $values['cwd'] = ([string]$row.cwd).Replace('{PLUGIN_ROOT}', $rootFwd) }
        $json = New-HookInput $template $values
        # Bez vlastniho CLAUDE_PROJECT_DIR by hook vzal projekt z `cwd` sablony (W:/dev/gsd/repo)
        # a na stroji, kde GSD repo je, by mlcky platil jeho skutecny prepis (`gate.opaque.*`
        # = audit) - sada by merila konfiguraci GSD, ne vychozi chovani. Prazdny projekt proto vzdy.
        $envh = @{ 'CLAUDE_PROJECT_DIR' = (Join-Path $script:TempDir ('t117p-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))) }
        [void][System.IO.Directory]::CreateDirectory($envh['CLAUDE_PROJECT_DIR'])
        if ($row.PSObject.Properties['override']) {
            $ov = [string]$row.override
            if ($ov.StartsWith('@')) {
                $key = '_override' + $ov.Substring(1, 1).ToUpperInvariant() + $ov.Substring(2)
                $ov = [string]$doc.PSObject.Properties[$key].Value
            }
            $dir = Join-Path $script:TempDir ('t117-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
            [void][System.IO.Directory]::CreateDirectory((Join-Path $dir '.claude'))
            [System.IO.File]::WriteAllText((Join-Path $dir '.claude/sinogard-hooks.json'), $ov, ([System.Text.UTF8Encoding]::new($false)))
            $envh['CLAUDE_PROJECT_DIR'] = $dir
        }
        $auditDir = Join-Path $script:TempDir ('t117a-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
        $envh['CLAUDE_PLUGIN_DATA'] = $auditDir
        $retryAbove = if ($row.PSObject.Properties['maxMs']) { [int]$row.maxMs } else { 0 }
        $r = Invoke-Hook -Script ($HookName + '.ps1') -InputJson $json -Environment $envh -RetryAboveMs $retryAbove -FreshDataOnRetry
        # K8-5: po opakovani je audit druheho behu v nove slozce.
        $auditDir = [string]$envh['CLAUDE_PLUGIN_DATA']
        $decision = Get-Decision $r
        if ($expect -ne '') { Assert-Equal $expect $decision $label }
        if ($row.PSObject.Properties['expectNot']) {
            Assert-True ($decision -ne [string]$row.expectNot) ("{0}: nesmi byt <{1}>, dostano <{2}>" -f $label, $row.expectNot, $decision)
        }
        if ($row.PSObject.Properties['reasonContains']) {
            $reason = ''
            if (-not [string]::IsNullOrWhiteSpace($r.Stdout)) { $reason = [string]($r.Stdout | ConvertFrom-Json).hookSpecificOutput.permissionDecisionReason }
            Assert-True ($reason.Contains([string]$row.reasonContains)) ("{0}: duvod nese <{1}>: {2}" -f $label, $row.reasonContains, $reason)
        }
        $auditPath = Join-Path $auditDir 'gate-audit.jsonl'
        $lines = @()
        if ([System.IO.File]::Exists($auditPath)) {
            $lines = @([System.IO.File]::ReadAllLines($auditPath, ([System.Text.UTF8Encoding]::new($false))) | Where-Object { $_ -ne '' })
        }
        # TASK-179 kolo 6 (K6-5): tvar, ktery v auditu byt NESMI (allow radek u tehoz listu, ktery konci ask).
        if ($row.PSObject.Properties['auditAbsentShape']) {
            # K7-9 (kolo 7): bez jedineho radku auditu by tvrzeni "tvar tam neni" proslo naprazdno (audit se vubec nezapsal).
            Assert-True ($lines.Count -ge 1) ("{0}: audit nese aspon jeden radek (auditAbsentShape)" -f $label)
            foreach ($l in $lines) {
                $o = $l | ConvertFrom-Json
                $bad = [string]$o.shape -match [string]$row.auditAbsentShape -and
                       (-not $row.PSObject.Properties['auditAbsentDecision'] -or [string]$o.decision -eq [string]$row.auditAbsentDecision)
                Assert-True (-not $bad) ("{0}: audit NEnese shape~<{1}>; radky: {2}" -f $label, $row.auditAbsentShape, ($lines -join ' || '))
            }
        }
        # TASK-179 kolo 6 (K6-4): doba jednoho behu hooku (patologicky dlouhy prikaz nesmi narazit na timeout hooku).
        # K7-7/K8-5 (kola 7 a 8): Invoke-Hook beh nad `maxMs` (nejvys HookCeilingMs) jednou opakuje a vraci druhe mereni -
        # jeden vykyv stroje radek neshodi. `maxMs` nad stropem se na strop zkrati: strop je absolutni mez jednoho behu sady.
        if ($row.PSObject.Properties['maxMs']) {
            $maxMs = [Math]::Min([int]$row.maxMs, [int]$script:HookCeilingMs)
            Assert-True ([int]$r.Ms -lt $maxMs) ("{0}: hook do {1} ms, dostano {2} ms" -f $label, $maxMs, $r.Ms)
        }
        if ($row.PSObject.Properties['auditShape']) {
            $hit = $null
            $hits = 0
            foreach ($l in $lines) {
                $o = $l | ConvertFrom-Json
                if ([string]$o.shape -match [string]$row.auditShape -and
                    (-not $row.PSObject.Properties['auditDecision'] -or [string]$o.decision -eq [string]$row.auditDecision)) {
                    if ($null -eq $hit) { $hit = $l }
                    $hits++
                }
            }
            Assert-True ($null -ne $hit) ("{0}: radek auditu shape~<{1}> decision=<{2}>; radky: {3}" -f $label, $row.auditShape, $row.auditDecision, ($lines -join ' || '))
            # TASK-179 kolo 6 (K6-6): kazde cteni obalu nesmi zapsat tutez udalost znovu.
            if ($row.PSObject.Properties['auditShapeCount']) {
                Assert-Equal ([int]$row.auditShapeCount) $hits ("{0}: pocet radku auditu shape~<{1}>" -f $label, $row.auditShape)
            }
            if ($row.PSObject.Properties['auditNotContains']) {
                foreach ($l in $lines) {
                    Assert-True (-not $l.Contains([string]$row.auditNotContains)) ("{0}: audit NEnese text prikazu <{1}>" -f $label, $row.auditNotContains)
                }
            }
        }
    }
}

function Get-HookCeilingMs { return $script:HookCeilingMs }

# Jen pro test opakovani (kolo 5b): sada si strop docasne snizi, aby se opakovani
# vubec spustilo, a pak ho vrati. V bezne sade se tohle nevola.
function Set-HookCeilingMs([int]$Ms) { $script:HookCeilingMs = $Ms }
function Get-HookRetryCount { return $script:Retries }
function Get-HookTimeCount { return $script:Times.Count }

# ZOPT-Q102 (0.3.1): ocekavani `audit` v tabulkach pripadu = hook MLCI (rozhodnuti allow) A zapise radek auditu sede zony
# (`gate:<id>`, `opaque:<pricina>`, `secrets:<id>`) s rozhodnutim allow. Bez toho by kontrolni skupiny "tohle je citlive"
# a "tohle ne" (byvale ask x allow) od 0.3.1 obe koncily allow a sada by rozdil prestala merit. Jmenujici tvary
# (`secrets:nameOnly*`, `secrets:wildcardName`) a SQL ze souboru/roury nejsou seda zona - jsou to zaznamy tichych tvaru 0.3.0.
function New-AuditEnvironment {
    $dir = Join-Path $script:TempDir ('aud-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    return @{ 'CLAUDE_PLUGIN_DATA' = $dir }
}

function Test-GreyZoneAudit([string]$AuditDir) {
    $path = Join-Path $AuditDir 'gate-audit.jsonl'
    if (-not [System.IO.File]::Exists($path)) { return $false }
    foreach ($l in [System.IO.File]::ReadAllLines($path, ([System.Text.UTF8Encoding]::new($false)))) {
        if ($l -eq '') { continue }
        $o = $l | ConvertFrom-Json
        $shape = [string]$o.shape
        if ([string]$o.decision -notmatch '^allow') { continue }
        if ($shape -notmatch '^(gate:|opaque:|secrets:)') { continue }
        if ($shape -match '^secrets:(nameOnly|wildcardName)') { continue }
        return $true
    }
    return $false
}

# ZOPT-Q102 (Tom 2026-10-20, A179-O2): zadny verdikt `ask` nikde v pluginu (gate i secrets). Strukturni test ve dvou vrstvach:
# (1) zadny beh hooku v cele sade nevydal `ask` (pocita Invoke-HookOnce); (2) zdroj hooku nema zapisovac `ask` ani konstrukci
# verdiktu `ask` a vychozi konfigurace nema hodnotu `ask` - cesta kodu, kterou zadna fixtura nepotka, se tak chyti taky.
function Assert-NoAskVerdict {
    Start-Case 'ZOPT-Q102: zadny verdikt ask'
    $byScript = @($script:AskOutputs | Group-Object | ForEach-Object { '{0} {1}x' -f $_.Name, $_.Count })
    Assert-Equal 0 $script:AskOutputs.Count ('[ask/beh] behu hooku s permissionDecision ask ({0})' -f ($byScript -join ', '))
    foreach ($f in @(Get-ChildItem -Path $script:ScriptsDir -Filter '*.ps1' -File)) {
        $src = [System.IO.File]::ReadAllText($f.FullName)
        $writer = [regex]::Matches($src, '\bWrite-AskDecision\b').Count
        $verdict = [regex]::Matches($src, '(?i)Decision\s*=\s*''ask''').Count
        Assert-Equal 0 $writer ('[ask/zdroj] {0}: vyskytu Write-AskDecision' -f $f.Name)
        Assert-Equal 0 $verdict ('[ask/zdroj] {0}: konstrukci verdiktu ask' -f $f.Name)
    }
    $defaults = ConvertFrom-Json ([System.IO.File]::ReadAllText((Join-Path $script:ScriptsDir '..\config\defaults.json')))
    $askPaths = New-Object System.Collections.ArrayList
    $stack = New-Object System.Collections.Stack
    $stack.Push(@('', $defaults))
    while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        $path = [string]$item[0]; $node = $item[1]
        if ($node -is [System.Management.Automation.PSCustomObject]) {
            foreach ($p in $node.PSObject.Properties) {
                if ($p.Name.StartsWith('_')) { continue }
                $stack.Push(@(($path + '.' + $p.Name), $p.Value))
            }
        } elseif ($node -is [System.Array]) {
            for ($i = 0; $i -lt $node.Count; $i++) { $stack.Push(@(($path + '[' + $i + ']'), $node[$i])) }
        } elseif ($node -is [string] -and $node -ceq 'ask') {
            [void]$askPaths.Add($path)
        }
    }
    Assert-Equal 0 $askPaths.Count ('[ask/konfigurace] defaults.json: hodnot ask ({0})' -f (@($askPaths | Sort-Object) -join ', '))
}

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
    # 🔴 Nalez Ady N46 (0.1.11): `allow` v sade znamena JEDNU vec - hook MLCI, tedy
    # plati normalni tok opravneni Claude Code. Plugin zadny allow writer nema
    # (`_common.ps1`: jen Write-DenyDecision / Write-AskDecision), takze KAZDY
    # radek `allow` v invariantu je tvrzeni o TICHU. Kdyby hook zacal vydavat
    # `permissionDecision: allow`, tu vrstvu by PRESKOCIL - a do 0.1.10 to sada
    # nepoznala, protoze obe veci vracela jako retezec 'allow'.
    #
    # Slovo `silent` se schvalne nezavadi: jeden slovnik, dva vyznamy se rozlisi tady.
    # `DECISION-ALLOW` se nerovna zadnemu ocekavani v zadne fixture, takze takovy hook
    # zcervena na KAZDEM radku, ne jen tam, kde si toho nekdo vsimne.
    if (([string]$pd.Value) -eq 'allow') { return 'DECISION-ALLOW' }
    return [string]$pd.Value
}
