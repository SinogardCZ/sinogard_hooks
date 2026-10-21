#!/usr/bin/env pwsh
<#
.SYNOPSIS
  PreToolUse brana par. 6: destruktivni git a DB operace konci deny; seda zona audit (hook mlci).

.DESCRIPTION
  ASCII-ONLY zdroj (viz _common.ps1). Vsechny lidske texty jsou v
  hooks/config/defaults.json.

  Fail-closed: jakakoli vyjimka, nevalidni nebo prazdny vstup, chybejici prikaz
  i neznamy nastroj konci exit 2. Ukazkovy validator Anthropicu tohle nedela
  (exit 1 = fail-open); lisime se vedome.

  deny = JSON permissionDecision "deny" + exit 2 + tyz duvod na stderr.
  jinak = exit 0 bez vystupu (zadne rozhodnuti, plati normalni tok opravneni); seda zona navic zapise radek auditu.
  ZOPT-Q102 (Tom 2026-10-20, 0.3.1): hook nevraci `ask` nikdy - kazde byvale `ask` ma politiku `audit` nebo `deny`
  (gate.decisions, gate.opaque, gate.dbDestroyLocal v defaults.json; A179-O3).
#>

# Trap MUSI byt drive nez dot-source: kdyby _common.ps1 chybelo nebo bylo vadne,
# neodchycena chyba by skoncila exit 1, tedy fail-OPEN.
$script:InternalMessage = 'gate.ps1: internal error, blocked'
trap {
    $msg = $script:InternalMessage
    # Diagnostika je opt-in a NEOSLABUJE fail-closed: blokuje se dal, jen se navic
    # rekne proc. Bez prepinace se detail nikam nedostane (mohl by nest cizi text).
    if ($env:SINOGARD_HOOKS_DEBUG -eq '1') {
        $msg = $msg + " [debug] " + $_.Exception.Message + " @ " + $_.InvocationInfo.PositionMessage
    }
    try { Write-HookStderr $msg } catch { [Console]::Error.Write($msg) }
    exit 2
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '_common.ps1')

$PluginRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

# Vychozi hodnota MUSI stat driv, nez ji nekdo precte: pod Set-StrictMode je cteni
# nenastavene promenne vyjimka, a v tele Write-GateAudit by ji spolkl jeho `catch`
# (evidence je fail-OPEN) - audit by tise prestal chodit.
$script:PermissionMode = 'default'

# TASK-106 bod 15 (0.2.0): rozbor vnitrku obalu, ktery text SPOUSTI (`bash -c`, `pwsh
# -Command`, `cmd /c`, `eval`, `iex`, `Start-Process`). Uvnitr nej je promenna v HLAVE
# statementu obsah, ktery se spusti - tedy `invoked`, ne `variable`. Priznak se nese
# script-scope, protoze Get-CommandLeaf konfiguraci ani kontext parametrem nedostava
# (refaktor podpisu je mimo rozsah, zadani par. 6 bod 5).
$script:InvokedContext = $false
$script:InvokedAssigned = $null

# ------------------------------------------------------------- pomocne ---

# List je hashtable a ne kazdy nese kazdy klic. Pod StrictMode je pristup k chybejicimu
# klici hazardni, takze se cte pres ContainsKey.
function Get-LeafField($Leaf, [string]$Name, $Default = '') {
    if ($null -eq $Leaf) { return $Default }
    if (-not $Leaf.ContainsKey($Name)) { return $Default }
    if ($null -eq $Leaf[$Name]) { return $Default }
    return $Leaf[$Name]
}

# Rozhodnuti Toma 2026-09-07/T36-O5 = A: "nerozebratelne" prestalo byt jednou tridou.
# Do 0.1.9 skoncil KAZDY takovy list na `ask` - a nad realnymi cisly to znamenalo
# 45 dotazu ze 46 pri dvou skutecnych zasazich par. 6. List proto nese PRICINU (`Why`)
# a politiku k ni urcuje konfigurace (`gate.opaque`). Bez `Why` by se nedalo odlisit
# `& $cmd` (obsah se SPUSTI - zustava ask) od `"EXIT=$code"` (retezec s promennou).
#
# `Body` nese jen pricina `interpreter`: je to kod, ktery se spusti a rozebrat ho neumime,
# ale JMENO volani v nem videt je - a to je jediny signal, ktery mame (viz 1C).
function New-OpaqueLeaf([string]$Raw, [string]$Why, [string]$Body = '') {
    return @{ Kind = 'opaque'; Raw = $Raw; Why = $Why; Body = $Body }
}

# Mazani volanim .NET / VB tridy. Dva vzory nad TYMZ vyctem jmen, aby se nemohly
# rozejit: prvni jen POZNA, ze jde o mazani (Get-CommandLeaf), druhy z nej vytahne
# LITERALNI cil (Test-RecursiveDeleteRule). Cil v promenne druhy vzor nenajde -
# a prave to je rozdil mezi `deny` a `ask` (nalez Amber A1).
$script:NetDeleteCallHeads = '(?:\[(?:System\.)?IO\.(?:Directory|File)\]::Delete|\[Microsoft\.VisualBasic\.FileIO\.FileSystem\]::Delete(?:Directory|File))'
$script:NetDeleteCallPattern   = $script:NetDeleteCallHeads + '\('
$script:NetDeleteTargetPattern = $script:NetDeleteCallHeads + '\(\s*[''"]([^''"]+)[''"]'

# Jmeno spustitelneho souboru PO rozbaleni obalu.
#
# Nalez Amber C4: `sudo -u postgres psql <<SQL` a `docker exec -i db psql <<SQL` davaly
# OuterExe `sudo` resp. `docker`, ty nejsou v sqlClients, telo heredocu se proto vubec
# nectlo jako SQL a destruktivni operace propadla na allow. Rozbaleni obalu uz umi
# Get-CommandLeaf, takze se pouzije ono a vezme se posledni list.

# Get-WrapperTail a jeho tabulka obalu ziji od 0.3.0 v _common.ps1 - sdili je secrets.ps1 (Z117-Q27, A117-N16).

# Jmeno spustitelneho souboru PO rozbaleni obalu.
#
# Nalez Amber C4: `sudo -u postgres psql <<SQL` a `docker exec -i db psql <<SQL` davaly
# OuterExe `sudo` resp. `docker`, ty nejsou v sqlClients, telo heredocu se proto vubec
# nectlo jako SQL a destruktivni operace propadla na allow.
function Get-UnwrappedExe([string]$Command) {
    # K2-9 (kolo 2 /code-review): jen pruchod obaly - volaji ho clanky roury PRED klientem, kde se hleda jen echo/printf.
    if ([string]::IsNullOrWhiteSpace($Command)) { return '' }
    $tail = Get-WrapperTail (Split-Arguments $Command)
    if ($tail.Count -eq 0) { return '' }
    return (Get-ExecutableName ([string]$tail[0]))
}

# TASK-179 (0.3.1): uvozujici prikaz tela heredocu a cil roury. Pruchod obaly (Get-WrapperTail) zustava, jak byl - jeho verdikty
# (vcetne shellu v kontejneru, `docker exec -i c sh <<EOF`) se nemeni (AOPT-O25). Kdyz ale NEnajde SQL klienta ani shell a prikaz
# je kontejnerovy obal, rozhodne rozbor obalu (Get-ContainerCommand): `podman --connection x exec -i c psql <<SQL` daval do 0.3.0
# jako klienta jmeno kontejneru a telo se necetlo jako SQL. Pak je hostitelsky text VNITRNI prikaz + promenne prostredi obalu
# (AOPT-O26, ne volby obalu) a telo nese priznak Container (jen DB pravidlo, nikdy `allow` z gate.dbDestroyLocal).
# K2-1 (kolo 2): totez pro shell v kontejneru (`docker compose exec -T db bash <<EOF`) - telo se rozebere, ale jen DB pravidlem.
# K2-5 (kolo 2): obal kontejneru muze stat az v ocasu starsiho pruchodu (`env -S "docker ... exec -i db psql" <<SQL`).
# K3-2/K3-3/K3-9 (kolo 3): i kdyz klienta nebo shell najde STARSI pruchod (tvar 0.3.0, vsechna pravidla), je to porad tvar
# v kontejneru: telo nese NoAllow (zadne `allow` z gate.dbDestroyLocal, AOPT-O26) a ContainerEnv (promenne `-e` obalu,
# ktere starsi pruchod zahodil). ContainerEnv nese JEN promenne obalu, ne argumenty vnitrniho prikazu (K3-5).
# K5-1/K5-3/K5-4 (kolo 5): vysledek nese i `Alt` = dalsi cteni obalu (jiny klient, shell nebo interpret). Telo heredocu
# a roura se pak posoudi pro KAZDE cteni a plati nejhorsi verdikt: starsi pruchod muze obal precist spatne (`--entrypoint`,
# `--detach-keys` nezna) a nezname volby davaji dve cteni - zadne z nich nesmi vyhrat jen proto, ze prislo prvni.
# Interpret nalezeny starsim pruchodem (`docker exec -i app python3 <<EOF`) zustava na ceste 0.3.0 (verdikt beze zmeny).
function Get-UnwrappedCommand([string]$Command) {
    $res = @{ Exe = ''; Outer = $Command; Container = $false; NoAllow = $false; ContainerEnv = ''; Alt = @() }
    if ([string]::IsNullOrWhiteSpace($Command)) { return $res }
    $argv = Split-Arguments $Command
    $tail = Get-WrapperTail $argv
    if ($tail.Count -gt 0) { $res.Exe = Get-ExecutableName ([string]$tail[0]) }
    $oldExe = $res.Exe.ToLowerInvariant()
    $cargv = $null
    if ($oldExe -match $script:ContainerCli) { $cargv = @($tail) }
    else {
        $ci = Get-ContainerIndex $argv
        if ($ci -ge 0) { $cargv = @($argv[$ci..($argv.Count - 1)]) }
    }
    $cc = if ($null -ne $cargv) { Get-ContainerCommand $cargv } else { $null }
    $envText = if ($null -ne $cc) { Resolve-ContainerEnv $cc.Env } else { '' }
    # Cteni rozboru obalu: klient, shell nebo interpret (K4-3) v kontejneru - telo posoudi Test-ContainerLeaf.
    $hits = New-Object System.Collections.ArrayList
    if ($null -ne $cc) {
        $keys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        foreach ($t0 in $cc.Tails) {
            # Bez `@()` kolem volani: Get-WrapperTail vraci `,@(...)` (N-H10).
            $t = Get-WrapperTail @($t0)
            if ($t.Count -eq 0) { continue }
            $exe = Get-ExecutableName ([string]$t[0])
            $lx = $exe.ToLowerInvariant()
            $rank = if (@($script:SqlClients) -ccontains $lx) { 0 } elseif (@($script:ShellInterpreters) -ccontains $lx) { 1 } elseif (@($script:CodeInterpreters) -ccontains $lx) { 2 } else { -1 }
            if ($rank -lt 0) { continue }
            $outer = ((Join-Argument @($t0)) + ' ' + $envText).Trim()
            if (-not $keys.Add($lx + '|' + $outer)) { continue }
            [void]$hits.Add(@{ Exe = $exe; Outer = $outer; Container = $true; NoAllow = $true; ContainerEnv = $envText; Rank = $rank })
        }
    }
    if ((@($script:SqlClients) -ccontains $oldExe) -or (@($script:ShellInterpreters) -ccontains $oldExe) -or (@($script:CodeInterpreters) -ccontains $oldExe)) {
        if ($null -ne $cc) {
            $res.NoAllow = $true; $res.ContainerEnv = $envText
            # K5-3: cteni rozboru obalu s JINYM programem nez starsi pruchod (ten treba vzal hodnotu `--entrypoint` za kontejner).
            $res.Alt = @($hits | Where-Object { $_.Exe.ToLowerInvariant() -cne $oldExe })
        }
        return $res
    }
    if ($hits.Count -eq 0) { return $res }
    # K5-4: poradi klient > shell > interpret jen urcuje hlavni cteni; ostatni jdou do Alt a posoudi se taky.
    # Bez Sort-Object: Windows PowerShell 5.1 nema -Stable a poradi cteni ma zustat.
    $sorted = @(foreach ($rk in 0, 1, 2) { foreach ($h in $hits) { if ($h.Rank -eq $rk) { $h } } })
    $main = $sorted[0]
    $main['Alt'] = @(if ($sorted.Count -gt 1) { $sorted[1..($sorted.Count - 1)] })
    return $main
}

# K6-10 (kolo 6): vsechna cteni vysledku Get-UnwrappedCommand (hlavni + Alt) z jednoho mista - spotrebitel, ktery by Alt
# zapomnel rozbalit, by posoudil jen prvni cteni (trida K5-3/K5-4).
function Get-UnwrappedReadings($Unwrapped) {
    return ,@(@($Unwrapped) + @($Unwrapped.Alt))
}

# K7-3/K7-4 (kolo 7): kazdy vyskyt obalu s vic ctenimi (telo heredocu a roury pro kazde cteni, kandidati vnitrniho prikazu
# kontejneru) dostane vlastni skupinu; list nese ReadingGroup a Reading (poradi cteni). Write-GateAudit pak za skupinu zapise
# udalost jen tolikrat, kolikrat ji nese nejbohatsi cteni - ruzne vyskyty se navzajem nepotlacuji. Vnoreny vyskyt si
# skupinu necha (nejvnitrnejsi vyhrava, Set-LeafReading).
# K8-1 (kolo 8): telo obalu se rozebira znovu PRI VERDIKTU kazdeho cteni (Test-ContainerLeaf -> Get-NestedShellLeaf). Skupina
# zalozena v takovem rozboru je proto `<skupina vnejsiho cteni>.<poradi v nem>` - n-ta skupina tela ma v kazdem vnejsim cteni
# tyz klic a Invoke-LeafVerdict ji vede pod cestou vnejsiho cteni. Jinak by kazde vnejsi cteni zalozilo novou skupinu
# a udalost tela by se zapsala tolikrat, kolik cteni ma vnejsi obal.
# K9-2/K9-3 (kolo 9, zamitnuto): poradi je pozicni - lisi-li se vnejsi cteni POCTEM listu, ktere telo rozebiraji znovu,
# muze se udalost zapsat vickrat (soucet maxim po pozicich >= maximum souctu). Jen nadpocet, nikdy chybejici radek; verdikt beze zmeny.
$script:ReadingGroupSeq = 0
$script:ReadingGroupLocal = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::Ordinal)
function New-ReadingGroup {
    $ctx = $script:AuditReading
    if ($null -eq $ctx) {
        $script:ReadingGroupSeq++
        return [string]$script:ReadingGroupSeq
    }
    $key = [string]$ctx.G + '|' + [string]$ctx.R
    $n = 1
    if ($script:ReadingGroupLocal.ContainsKey($key)) { $n += $script:ReadingGroupLocal[$key] }
    $script:ReadingGroupLocal[$key] = $n
    return ([string]$ctx.G + '.' + $n)
}
function Set-LeafReading($Leaf, [string]$Group, [int]$Reading) {
    if ([string](Get-LeafField $Leaf 'ReadingGroup' '') -ne '') { return }
    $Leaf['ReadingGroup'] = $Group
    $Leaf['Reading'] = $Reading
}

# Hodnoty `-e/--env` obalu kontejneru jako text pro Get-DbHosts. CR-3 (kolo 1 /code-review): pruchozi `-e PGHOST` (bez `=`)
# preda vnitrnimu prikazu hodnotu z prostredi hostitele - stoji-li v TEMZE prikazu (`PGHOST=x docker ...`, `export PGHOST=x; ...`,
# `$env:PGHOST = 'x'; ...`), vezme se odtud. Jinak hodnotu nevidime -> hostitel neznamy = mistni (`ask`, ne ticho);
# totez `--env-file` (obsah souboru v prikazu neni, README omezeni 11).
# K8-6/K8-7 (kolo 8): tytez promenne tehoz obalu se ptaji vickrat (vetev prefixu, Get-ContainerLeaves, Get-UnwrappedCommand) -
# vysledek plati, dokud nepribude rozebirany text.
$script:ContainerEnvCache = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::Ordinal)
function Resolve-ContainerEnv($Envs) {
    $cacheKey = [string]$script:ParsedTexts.Count + [char]0 + (@($Envs | ForEach-Object { [string]$_ }) -join [string][char]0)
    if ($script:ContainerEnvCache.ContainsKey($cacheKey)) { return $script:ContainerEnvCache[$cacheKey] }
    # K7-2 (kolo 7): prirazeni se hleda ve VSECH textech, ktere beh rozebira (Register-ParsedText) - dekodovany
    # `-EncodedCommand` v $script:FullCommand neni a vzdaleny hostitel by se tam cetl jako neznamy (mistni, `ask`).
    # K8-6: hlavni prikaz je mezi nimi (Get-CommandLineLeaves ho zapise prvni); samostatne jen pred prvnim rozborem.
    $texts = @(foreach ($pt in $script:ParsedTexts) { [string]$pt.Text })
    if ($texts.Count -eq 0) { $texts = @([string]$script:FullCommand) }
    $out = New-Object System.Collections.ArrayList
    foreach ($e in @($Envs)) {
        $v = [string]$e
        if ($v -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { [void]$out.Add($v); continue }
        $n = [regex]::Escape($v)
        $val = '("[^"]*"|''[^'']*''|[^\s;&|]+)'
        foreach ($text in $texts) {
            # K2-4 (kolo 2): prirazeni muze stat i hned za uvozovkou tela obalu (`bash -c "PGHOST=x docker ..."`).
            foreach ($m in [regex]::Matches($text, ('(?:^|[\s;&|("''])(?:export\s+)?' + $n + '=' + $val))) {
                [void]$out.Add($v + '=' + $m.Groups[1].Value.Trim('"').Trim("'"))
            }
            foreach ($m in [regex]::Matches($text, ('\$env:' + $n + '\s*=\s*' + $val), 'IgnoreCase')) {
                [void]$out.Add($v + '=' + $m.Groups[1].Value.Trim('"').Trim("'"))
            }
        }
    }
    $res = (@($out | Select-Object -Unique) -join ' ')
    $script:ContainerEnvCache[$cacheKey] = $res
    return $res
}

# TASK-179 (0.3.1): listy VNITRNIHO prikazu kontejneroveho obalu (Get-ContainerCommand v _common.ps1). List obalu samotny
# (`Exe = docker`) vznika dal beze zmeny, takze vsechna pravidla nad nim maji dnesni verdikt. Vnitrni listy nesou priznak
# Container: Test-Leaf na ne pousti JEN DB pravidlo (AOPT-O25 - cesty a git v obrazu zustavaji README omezenim 11)
# a `gate.dbDestroyLocal = allow` se jich nikdy netyka (AOPT-O26). Hostitel = vnitrni prikaz + promenne prostredi,
# ktere obal predava (`-e PGHOST=...`), nikdy volby obalu (`-H` enginu, `run -h` hostname kontejneru).
function Get-ContainerLeaves($Argv, [int]$Depth, [string]$SkipTail = '', $Parsed = $null, [string]$Group = '') {
    $out = New-Object System.Collections.ArrayList
    # K4-8 (kolo 4): vetev prefixu rozbor uz ma - podruhe se nepocita.
    $cc = if ($null -ne $Parsed) { $Parsed } else { Get-ContainerCommand $Argv }
    if ($null -eq $cc) { return $out }
    $envText = Resolve-ContainerEnv $cc.Env
    # K7-3 (kolo 7): kandidati vnitrniho prikazu (surove a slepene ARGV, obe cteni nezname volby) jsou cteni TEHOZ obalu -
    # jedna skupina pro audit. Cteni 0 je list starsiho pruchodu ve vetvi prefixu (ta skupinu predava v $Group).
    $grp = if ($Group -ne '') { $Group } else { New-ReadingGroup }
    $ti = 0
    foreach ($t0 in $cc.Tails) {
        $t = @($t0)
        $ti++
        if ($t.Count -eq 0) { continue }
        # CR-5: vnitrni prikaz, ktery uz rozebral pruchod prefixovym obalem (vsemi pravidly), se podruhe nerozebira. Promenne
        # obalu (`-e PGHOST=...`, K2-2) a zakaz `allow` nese od K3-6 rovnou ten starsi list (vetev prefixu v Get-CommandLeaf).
        if ($SkipTail -ne '' -and (Join-Argument $t) -ceq $SkipTail) { continue }
        foreach ($l in (Get-CommandLeaf (Join-Argument $t) ($Depth + 1))) {
            $l['Container'] = $true
            Set-LeafReading $l $grp $ti
            # K4-2 (kolo 4): pripojit, ne prepsat - vnoreny obal (`docker exec outer docker exec -e PGHOST=... inner`) uz svou
            # promennou do listu zapsal a vnejsi vrstva by ji jinak smazala.
            Add-LeafContainerEnv $l $envText
            [void]$out.Add($l)
        }
    }
    return $out
}

# Test-ParameterPrefix a Test-EncodedCommandFlag ziji od 0.3.0 v _common.ps1 (Z117-Q27, A117-N16).

# Test-HeredocOutsideQuotes a $script:HeredocPattern ziji od 0.2.0 v _common.ps1 (sdili je secrets.ps1).

# Roura, jejimz POSLEDNIM clankem je SQL klient.
#
# Nalez Amber C1 - regrese, kterou zavedla oprava B4: `echo "DROP TABLE users" | psql -h db`
# se delilo na dva listy. `echo` neni SQL klient, takze se jeho argument necetl jako SQL;
# `psql` uz zadne SQL nemel. Vysledek allow, pritom pred B4 to byl ask.
#
# Vraci @{ Rest = prikazy bez techto rour; Bodies = @(...) } ve stejnem tvaru jako
# Split-Heredoc: bud list typu 'heredoc' s literalnim SQL, nebo priznak, ze obsah
# neni videt (pak plati Z3 -> ask).
function Split-SqlPipeline([string]$Command, $SqlClients) {
    $bodies = New-Object System.Collections.ArrayList

    if ([string]::IsNullOrWhiteSpace($Command) -or $Command -notmatch '\|') {
        return @{ Rest = $Command; Bodies = @() }
    }

    # Nalez Amber E1: driv se tu delilo `[regex]::Split`, ktery neumi uvozovky, takze
    # `echo "DROP TABLE users;" | psql -h db` se rozpadlo UPROSTRED retezce a destruktivni
    # prikaz propadl na allow. Deli se jedinym skenerem z _common.ps1.
    foreach ($stmt in (Split-Statement $Command)) {
        if ([string]::IsNullOrWhiteSpace($stmt)) { continue }
        # POZOR: bez `@()`. Split-Pipe uz vraci `,@(...)`, aby se jednoprvkovy vysledek
        # nerozbalil na skalar; dalsi `@()` kolem toho by pole zabalilo JESTE JEDNOU
        # a Count by byl 1 misto poctu clanku. Presne na tom tahle oprava poprve spadla.
        # `@(...)` je tu POVINNE, ne kosmetika (nalez Hestia N23): jednoclankovy vysledek
        # se z funkce vraci jako RETEZEC a `.Count` nad nim pod StrictMode shodi hook.
        # Stavalo se to vzdycky, kdyz jedina roura v prikazu stala v uvozovkach -
        # tedy u `bash -c 'git log | head'`, coz je uplne bezna prace.
        $stages = @(Split-Pipe $stmt)
        if ($stages.Count -lt 2) { continue }

        $sink = $stages[$stages.Count - 1]
        $sinkU0 = Get-UnwrappedCommand $sink
        # K5-3/K5-4: klient muze byt i jen v dalsim cteni obalu (Alt) - telo roury se posoudi pro kazde cteni s klientem.
        # Bez `@()` kolem volani a ne primo do roury: Get-UnwrappedReadings vraci `,@(...)` (N-H10).
        $sinkReadings = Get-UnwrappedReadings $sinkU0
        $sinks = @($sinkReadings | Where-Object { $SqlClients -ccontains ([string]$_.Exe).ToLowerInvariant() })
        if ($sinks.Count -eq 0) { continue }

        $literal = New-Object System.Collections.ArrayList
        $opaque = $false
        for ($i = 0; $i -lt $stages.Count - 1; $i++) {
            $up = $stages[$i].Trim()
            $upExe = Get-UnwrappedExe $up
            if ($upExe -match '^(echo|printf|write-output|write-host)$') {
                foreach ($m in [regex]::Matches($up, '"([^"]*)"|''([^'']*)''')) {
                    foreach ($g in 1, 2) { if ($m.Groups[$g].Success) { [void]$literal.Add($m.Groups[$g].Value) } }
                }
            } else {
                # `cat drop.sql | psql`, `Get-Content x | psql`, `$sql | psql` - obsah
                # neni v prikazu videt, takze rozsah nezname. Plati Z3.
                $opaque = $true
            }
        }

        # K6-6/K7-4: cteni tehoz obalu jsou jedna skupina - do auditu jde udalost jednou (New-ReadingGroup, Write-GateAudit).
        $grp = New-ReadingGroup
        for ($si = 0; $si -lt $sinks.Count; $si++) {
            $sinkU = $sinks[$si]
            $sinkExe = [string]$sinkU.Exe
            if ($opaque) {
                [void]$bodies.Add(@{ Outer = $sinkU.Outer; OuterExe = $sinkExe; Body = ''; Opaque = $true; Container = [bool]$sinkU.Container
                                     NoAllow = [bool]$sinkU.NoAllow; ContainerEnv = [string]$sinkU.ContainerEnv; ReadingGroup = $grp; Reading = $si })
            } elseif ($literal.Count -gt 0) {
                [void]$bodies.Add(@{ Outer = $sinkU.Outer; OuterExe = $sinkExe; Body = ($literal -join ' ; '); Opaque = $false; Container = [bool]$sinkU.Container
                                     NoAllow = [bool]$sinkU.NoAllow; ContainerEnv = [string]$sinkU.ContainerEnv; ReadingGroup = $grp; Reading = $si })
            }
        }
    }

    # Rest se NEPREPISUJE. Sink i upstream clanky projdou normalni cestou pres
    # Split-CommandLine, takze roura nic neschovava. Tim se navic sam opravil nalez E6:
    # substituce v upstream clanku prijde jako dalsi podprikaz a skonci deny, ne ask.
    return @{ Rest = $Command; Bodies = @($bodies) }
}

# Split-Pipe a Split-Statement zijou v _common.ps1 - jeden skener pro vsechna deleni.

# Heredoc: telo je SQL, ale hostitel DB stoji v uvozujicim prikazu PRED `<<`.
# Split-CommandLine deli i na konci radku, takze by se telo stalo samostatnym
# podprikazem BEZ hosta - a `psql -h db.firma.cz <<SQL / DROP TABLE x / SQL`
# by skoncilo jako lokalni operace (ask) misto vzdalene (deny). Nalez Amber A4.
#
# Vraci @{ Rest = prikaz bez tel heredocu; Bodies = @(@{ Outer; OuterExe; Body }) }.

function Split-Heredoc([string]$Command) {
    $heredocPattern = $script:HeredocPattern
    $bodies = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Command)) {
        return @{ Rest = $Command; Bodies = @(); Unterminated = $false }
    }
    if ($Command -notmatch '<<') { return @{ Rest = $Command; Bodies = @(); Unterminated = $false } }

    # Nalez Amber E2: `<<` se hledalo regexem nad radkem, takze `echo "<<x>>"` zacalo
    # heredoc uvnitr retezce a zbytek prikazu se spolkl jako telo. Uvod heredocu se
    # proto hleda kvotove korektne - jen `<<` MIMO uvozovky a ne `<<<` (here-string).
    # Nalez Amber G9: radky se deli regexem a to je tu SPRAVNE - telo heredocu konci
    # radkem, ktery se PRESNE rovna delimiteru, takze linky musi zustat, jak jsou.
    # Chybelo neco jineho: pokracovani radku spojuje dva radky v JEDEN prikaz. Bez toho
    # stalo `psql -h prod \` a `  <<SQL` na dvou radcich, uvozujici prikaz vysel prazdny
    # a telo se necetlo jako SQL -> allow.
    # Spojuje se i uvnitr uvozovek a uvnitr tel, kde to Bash nedela vzdy. Je to smerem
    # k prisnosti: telo, jehoz radek konci escapem, se slepi s delimiterem, heredoc
    # zustane neukonceny a plati Z3 -> ask.
    $joined = [regex]::Replace($Command, [regex]::Escape((Get-ScannerEscape)) + '\r?\n', ' ')
    $lines = [regex]::Split($joined, '\r?\n')
    $keep = New-Object System.Collections.ArrayList
    $unterminated = $false
    $i = 0
    while ($i -lt $lines.Count) {
        $line = $lines[$i]
        if (-not (Test-HeredocOutsideQuotes $line)) { [void]$keep.Add($line); $i++; continue }
        # `<<EOF`, `<<-EOF`, `<<'EOF'`, `<<"EOF"` - ne `<<<` (here-string) a ne `<`.
        # Nalez Amber C1: kotva `\s*$` na konci znamenala, ze `<<SQL 2>&1` ani
        # `<<SQL > out.log` se za heredoc nepovazovaly, telo se rozpadlo na radky
        # a vzdalena destruktivni operace propadla na allow. Kotva je pryc; co je
        # za delimiterem, zustava soucasti uvozujiciho prikazu (a nese tam hostitele).
        # `\` pred delimiterem (`<<\SQL`) je treti zpusob, jak potlacit expanzi -
        # vedle `'SQL'` a `"SQL"`. Bez nej se telo nevytahlo (nalez Metis 2, kolo 2).
        $m = [regex]::Match($line, $heredocPattern)
        if (-not $m.Success) {
            [void]$keep.Add($line); $i++; continue
        }
        # Nalez Metis 6 (kolo 2): na jednom radku muze byt heredocu VIC
        # (`cat <<IGNORE && psql -h prod <<SQL`) a tela se ctou v poradi uvedeni.
        # Driv se bral jen prvni a telo toho druheho propadlo mimo SQL kontext.
        $delims = New-Object System.Collections.ArrayList
        $outerBuf = New-Object System.Text.StringBuilder
        $pos = 0
        foreach ($mm in [regex]::Matches($line, $heredocPattern)) {
            foreach ($g in 1, 2, 3) { if ($mm.Groups[$g].Success) { [void]$delims.Add($mm.Groups[$g].Value) } }
            if ($mm.Index -ge $pos) {
                [void]$outerBuf.Append($line.Substring($pos, $mm.Index - $pos))
                [void]$outerBuf.Append(' ')
                $pos = $mm.Index + $mm.Length
            }
        }
        [void]$outerBuf.Append($line.Substring($pos))
        $outer = $outerBuf.ToString().Trim()
        [void]$keep.Add($outer)

        # Uvozujici prikaz pro KAZDE telo je ten clanek, ve kterem jeho `<<` stalo.
        $outerStages = @(Split-Statement $outer)
        $j = $i + 1
        for ($d = 0; $d -lt $delims.Count; $d++) {
            $delim = [string]$delims[$d]
            $bodyLines = New-Object System.Collections.ArrayList
            while ($j -lt $lines.Count -and $lines[$j].Trim() -ne $delim) {
                [void]$bodyLines.Add($lines[$j]); $j++
            }
            if ($j -ge $lines.Count) { $unterminated = $true }
            $myOuter = if ($d -lt $outerStages.Count) { [string]$outerStages[$d] } else { $outer }
            $myU0 = Get-UnwrappedCommand $myOuter
            # K5-3/K5-4: telo se posoudi pro kazde cteni obalu (Alt) - plati nejhorsi verdikt.
            $readings = Get-UnwrappedReadings $myU0
            $grp = New-ReadingGroup
            for ($ri = 0; $ri -lt $readings.Count; $ri++) {
                $myU = $readings[$ri]
                [void]$bodies.Add(@{ Outer = $myU.Outer; OuterExe = [string]$myU.Exe; Container = [bool]$myU.Container
                                     NoAllow = [bool]$myU.NoAllow; ContainerEnv = [string]$myU.ContainerEnv
                                     Body = ($bodyLines -join "`n"); ReadingGroup = $grp; Reading = $ri })
            }
            $j++   # radek s ukoncovacim delimiterem se zahazuje
        }

        $i = $j
    }
    return @{ Rest = ($keep -join "`n"); Bodies = @($bodies); Unterminated = $unterminated }
}

# ------------------------------------------------------------- pravidla ---

# Globalni prepinace gitu pred podprikazem. Hodnota: kolik tokenu se preskoci.
$script:GitGlobalWithValue = @('-c', '-C', '--git-dir', '--work-tree', '--namespace',
                               '--exec-path', '--config-env', '--super-prefix')
$script:GitGlobalNoValue   = @('-p', '--paginate', '--no-pager', '--bare', '--no-replace-objects',
                               '--literal-pathspecs', '--glob-pathspecs', '--noglob-pathspecs',
                               '--icase-pathspecs', '--no-optional-locks')

function Remove-GitGlobalOption($Tokens) {
    $out = New-Object System.Collections.ArrayList
    $i = 0
    while ($i -lt $Tokens.Count) {
        $t = $Tokens[$i]
        if ($t.StartsWith('-')) {
            $name = $t
            $eq = $t.IndexOf('=')
            if ($eq -ge 0) { $name = $t.Substring(0, $eq) }
            if ($script:GitGlobalWithValue -contains $name) {
                if ($eq -ge 0) { $i += 1 } else { $i += 2 }
                continue
            }
            if ($script:GitGlobalNoValue -contains $name) { $i += 1; continue }
        }
        # prvni token, ktery neni globalni prepinac, je podprikaz
        for ($j = $i; $j -lt $Tokens.Count; $j++) { [void]$out.Add($Tokens[$j]) }
        break
    }
    return ,@($out)
}

function Get-RestTokens($Tokens) {
    if ($null -eq $Tokens) { return ,@() }
    $arr = @($Tokens)
    if ($arr.Count -le 1) { return ,@() }
    return ,@($arr[1..($arr.Count - 1)])
}

# Rozebere text, ktery spusti JINY shell, nez ze ktereho prisel prikaz.
#
# Nalez Amber I2: escape znak se pri sestupu neprepnul, takze
#   z Bash nastroje  `pwsh -c 'echo <zpetny apostrof>" ; git reset --hard'`
#   z PS nastroje    `bash -c 'echo \" ; git reset --hard'`
# se rozebiraly pravidly VNEJSIHO shellu a oba propadly na allow. Znak se proto na
# dobu rozboru prepne a pak vrati zpatky - `finally`, aby ho nezmenila ani vyjimka.
function Get-NestedShellLeaf([string]$Inner, [string]$ShellTool, [int]$Depth) {
    $out = New-Object System.Collections.ArrayList
    $prev = Get-ScannerEscape
    Set-ScannerEscape $ShellTool
    try {
        foreach ($l in (Get-CommandLineLeaves $Inner ($Depth + 1))) { [void]$out.Add($l) }
    } finally {
        Set-ScannerEscapeChar $prev
    }
    return $out
}

# TASK-106 bod 15 (gamma, 0.2.0): vnitrek obalu, ktery text SPOUSTI. Do 0.1.11 stal pred
# rozborem `if (Test-Unexpandable $inner) -> invoked` nad CELYM vnitrkem, takze promenna
# KDEKOLI v tele (`pwsh -Command "git status; Write-Host $x"`) udelala z obalu spusteni
# promenne. Mereni faze 1 (2026-09-12): 44 dotazu `invoked`, 41 tohoto tvaru, pravych 0.
# Vnitrek se proto rozebira tymz retezem jako hlavni beh a `invoked` je jen statement,
# jehoz HLAVA je promenna nebo substituce (obsah se spusti) - to drzi Get-CommandLeaf
# pres $script:InvokedContext. `bash -c "$x"`, `pwsh -c "$x"`, `cmd /c %X%`, `eval $cmd`
# i `bash -c "$(cat cmd.txt)"` zustavaji ask (kontrolni skupina v sade).
# `$ShellTool` prazdny = tyz shell jako hostitel (cmd /c, eval, iex, Start-Process).
function Get-InvokedLeaves([string]$Inner, [string]$ShellTool, [int]$Depth) {
    $out = New-Object System.Collections.ArrayList
    # Vnejsi shell escapovany dolar ROZBALI, nez text preda dal: `pwsh -Command "... `$env:X = 1 ..."`
    # psane z PowerShellu prijde vnitrnimu pwsh jako `$env:X = 1` (prirazeni), z Bashe
    # `bash -c "echo \$HOME"` jako `echo $HOME`. Split-Arguments escapovanou dvojici schvalne
    # nechava celou (kvuli `C:\src`), takze by tu `$` zustal za escapem a prirazeni by se
    # cetlo jako promenna v hlave -> `invoked`. Zmereno nad vzorkem faze 1: bez tohoto kroku
    # zustalo 42 ze 44 dotazu `invoked` dotazem i po zuzeni. Rozbaluje se JEN dolar.
    $Inner = $Inner.Replace((Get-ScannerEscape) + '$', '$')
    # Promenna, kterou vnitrni text SAM PRIRAZUJE (`$e = $null; ...; $e | Select-Object`), neni
    # obsah rozbaleny vnejsim shellem - je to lokalni promenna vnitrniho skriptu, a ta se
    # v hlave statementu nespousti (PowerShell hodnotu vypise, nespusti). Jmena se sesbiraji
    # predem a Get-CommandLeaf je necha jako `variable` (audit). Promenna bez prirazeni
    # v hlave (`bash -c "$cmd arg"`, `pwsh -c "$x"`) zustava `invoked`. Zmereno nad vzorkem:
    # 13 ze 44 dotazu `invoked` melo presne tenhle tvar (`$e | ...` po `[ref]$e`).
    $prevAssigned = $script:InvokedAssigned
    $assigned = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($m in [regex]::Matches($Inner, '(?:^|[;\n{(|])\s*\$(?:env:|script:|global:|local:)?([A-Za-z_][A-Za-z0-9_]*)\s*[+\-*/]?=(?!=)')) {
        [void]$assigned.Add($m.Groups[1].Value)
    }
    foreach ($m in [regex]::Matches($Inner, '\[ref\]\s*\$([A-Za-z_][A-Za-z0-9_]*)')) { [void]$assigned.Add($m.Groups[1].Value) }
    $script:InvokedAssigned = $assigned
    $prev = $script:InvokedContext
    $script:InvokedContext = $true
    try {
        if ($ShellTool -eq '') {
            foreach ($l in (Get-CommandLineLeaves $Inner ($Depth + 1))) { [void]$out.Add($l) }
        } else {
            foreach ($l in (Get-NestedShellLeaf $Inner $ShellTool $Depth)) { [void]$out.Add($l) }
        }
    } finally {
        $script:InvokedContext = $prev
        $script:InvokedAssigned = $prevAssigned
    }
    return $out
}

# Nalez Ada N19: hlavni beh proustel prikaz TREMI pruchody - Split-Heredoc,
# Split-SqlPipeline a teprve pak Split-CommandLine. Rekurze (bash -c, cmd /c, eval,
# telo bloku, telo heredocu do shellu) volala JEN posledni clanek, takze dva
# specialni pruchody se v zanoreni nespoustely:
#   bash -c 'echo "DROP TABLE users" | psql -h prod'   -> allow (hole = deny)
#   sh -c "psql -h prod <<SQL ... SQL"                 -> allow
# Vzdaleny DROP nema zalozni siet v `permissions.deny` - prefixove pravidlo rouru
# neumi - takze ho drzel jen hook. Retez proto zije v JEDINE funkci a volaji ji
# obe strany; kdyz pribude ctvrty pruchod, prijde do zanoreni sam od sebe.
function Get-CommandLineLeaves([string]$Text, [int]$Depth) {
    $out = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Text)) { return $out }
    # K6-1/K6-2 (TASK-179, kolo 6): text a jeho escape pro spojeni substituci v rozboru kontejneroveho obalu (_common.ps1);
    # K7-2: i pro prirazeni promennych pruchozich `-e VAR` (Resolve-ContainerEnv).
    Register-ParsedText $Text
    # CR-S4 (TASK-179, kolo 3): text, ktery se prave rozebira - holy `iex` v nem hleda literaly roury (Get-CommandLeaf).
    $prevLineText = $script:LineText
    $script:LineText = $Text

    # Tela heredocu se vytahnou PRED delenim - jinak by se telo stalo samostatnym
    # podprikazem bez hosta a vzdalena operace by se cetla jako lokalni (Amber A4).
    $hd = Split-Heredoc $Text
    # Roura do SQL klienta se resi az nad zbytkem - heredoc uz je z nej pryc (Amber C1).
    $pl = Split-SqlPipeline $hd.Rest $script:SqlClients

    # `&` si vyzadame ZPATKY: je to operator SPUSTENI, ne oddelovac, a bez nej se
    # `& $cmd` neda odlisit od `$cmd`. Do 0.1.9 to nevadilo (oboji koncilo ask),
    # od 0.1.10 je `invoked` jedina trida, ktera se ptat NEPRESTALA.
    foreach ($sub in (Split-CommandLine $pl.Rest @('&'))) {
        foreach ($l in (Get-CommandLeaf $sub $Depth)) { [void]$out.Add($l) }
    }
    # CR-V2 (TASK-179, kolo 6): statement, ktery zacina VYRAZEM (`[Environment]::X(...) + (psql ...)`), Get-CommandLeaf
    # nerozebira (Test-ExpressionStatement) - prikaz v zavorce se nespustil pres zadne pravidlo (i v 0.3.0). V PowerShellu
    # proto rozhoduje i parser PowerShellu: kazdy prikaz (CommandAst), jehoz text zadny list nema, se rozebere navic.
    # Prikaz s blokem skriptu (`& { ... }`, `ForEach-Object { ... }`) se preskoci - jeho vnitrni prikazy jsou vlastni
    # CommandAst a blok uz rozebral Get-CommandLeaf.
    if ((Get-ScannerEscape) -eq '`') {
        $raws = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        foreach ($l in $out) { [void]$raws.Add(([string]$l.Raw).Trim()) }
        $tk = $null; $pe = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($pl.Rest, [ref]$tk, [ref]$pe)
        $cmds = @($ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true))
        foreach ($ca in $cmds) {
            $ct = $ca.Extent.Text.Trim()
            if (-not $raws.Add($ct)) { continue }
            if ($null -ne $ca.Find({ param($a) $a -is [System.Management.Automation.Language.ScriptBlockExpressionAst] }, $true)) { continue }
            foreach ($l in (Get-CommandLeaf $ct ($Depth + 1))) { [void]$out.Add($l) }
        }
    }
    foreach ($b in $hd.Bodies) {
        [void]$out.Add(@{ Kind = 'heredoc'; Exe = 'heredoc'; Args = @(); Raw = $b.Body
                          Text = $b.Body; Outer = $b.Outer; OuterExe = $b.OuterExe; GitConfig = @(); Container = [bool]$b.Container
                          NoAllow = [bool]$b.NoAllow; ContainerEnv = [string]$b.ContainerEnv; ReadingGroup = [string]$b.ReadingGroup; Reading = [int]$b.Reading })
    }
    # Neukonceny heredoc: nevime, kde telo konci, takze nevime, co se spusti.
    if ($hd.Unterminated) {
        [void]$out.Add((New-OpaqueLeaf $Text 'heredocUnterminated'))
    }
    foreach ($b in $pl.Bodies) {
        if ($b.Opaque) {
            [void]$out.Add(@{ Kind = 'sqlPipeOpaque'; Exe = 'sql-pipe'; Args = @(); Raw = $b.Outer
                              Text = $b.Outer; Outer = $b.Outer; OuterExe = $b.OuterExe; GitConfig = @(); Container = [bool]$b.Container
                          NoAllow = [bool]$b.NoAllow; ContainerEnv = [string]$b.ContainerEnv; ReadingGroup = [string]$b.ReadingGroup; Reading = [int]$b.Reading })
        } else {
            [void]$out.Add(@{ Kind = 'heredoc'; Exe = 'heredoc'; Args = @(); Raw = $b.Body
                              Text = $b.Body; Outer = $b.Outer; OuterExe = $b.OuterExe; GitConfig = @(); Container = [bool]$b.Container
                          NoAllow = [bool]$b.NoAllow; ContainerEnv = [string]$b.ContainerEnv; ReadingGroup = [string]$b.ReadingGroup; Reading = [int]$b.Reading })
        }
    }
    $script:LineText = $prevLineText
    return $out
}

# TASK-117 H-a (0.3.0, Z117-Q17 = A, Tom 2026-10-08 = varianta 1 navrhu `01-navrh-allow-list.md`
# par. 2): `invoked` vznikal JEN tim, ze hlava byla promenna - `$m = "C:\...\mutant.ps1"; & $m`
# se ptalo, kdezto tentyz skript volany literalne (`& "C:\...\mutant.ps1"`) mlcel uz v 0.2.0
# (README omezeni 1). Allow-list cest by proto nepokryl nic (N-A). Hlava, jejiz KAZDA promenna
# ma v TEMZE prikazu DRIV prirazeni LITERALEM, se nahradi tim literalem a statement se rozebere
# znovu - presne tak, jako by ho autor napsal bez promenne. Zaroven to zavira N-B:
# `$x = 'git'; & $x reset --hard` je rozbalene `git reset --hard` -> deny (pod zuzenim GSD bylo
# ticho). Literal = retezec bez promenne; jedina vyjimka je `$env:` z pevne mnoziny neutajenych
# adresaru (LOCALAPPDATA, TEMP, TMP, USERPROFILE, APPDATA, HOME). Nerozbaluje se:
#   - promenna prirazena vic nez jednou KDEKOLI v prikazu (i v bloku, `[ref]`, `-OutVariable`,
#     `foreach`), nebo kdyz prikaz pouziva Set-Variable / New-Variable,
#   - prirazeni uvnitr bloku nebo podminky (jen statement nejvyssi urovne),
#   - kdyz prikaz v temze statementu, ktery promennou nebo literal jmenuje, ZAPISUJE (TOCTOU:
#     `Set-Content $p ...; & $p` by zmenil soubor po kontrole),
#   - uvnitr obalu, ktery text spousti (`bash -c`, `pwsh -c`, `iex`, `Start-Process`).
# Jen PowerShell nastroj - tvar `invoked` se ve vzorku vyskytl jen tam.
$script:LiteralAssign = @{}
$script:FullCommand = ''
$script:LineText = ''
$script:IexLiteralScan = $false
$script:AllLeaves = @()
$script:EnvLiteralNames = '(?:LOCALAPPDATA|TEMP|TMP|USERPROFILE|APPDATA|HOME)'

function Get-LiteralAssignment([string]$Command) {
    $result = @{}
    if ([string]::IsNullOrWhiteSpace($Command)) { return $result }
    # CR-P2 (/code-review): promennou meni i `Set-Item variable:x`, `(Get-Variable x).Value = ...`, `Clear-Variable`,
    # `$ExecutionContext.SessionState.PSVariable.Set(...)` a vicenasobne prirazeni `$a, $x = ...` - kterykoli z nich
    # v prikazu rozbaleni vypne CELE (zustava `invoked` = ask). Kolo 2: `variable:` jen jako cesta providera, ne
    # konec spolecneho parametru `-ErrorVariable:e` / `-OutVariable:x`.
    if ([regex]::IsMatch($Command, '(?i)\b(set-variable|new-variable|sv|nv|get-variable|gv|clear-variable|clv|remove-variable|rv)\b|(^|[^\w-])variable:|psvariable|sessionstate')) { return $result }
    if ([regex]::IsMatch($Command, '(\$\{?[\w:]+\}?\s*,\s*)+\$\{?[\w:]+\}?\s*=(?!=)')) { return $result }
    $counts = @{}
    $assignPatterns = @(
        '\$\{?(?:script:|global:|local:|private:)?([A-Za-z_][A-Za-z0-9_]*)\}?\s*(?:[+\-*/%]|\?\?)?=(?!=)',
        '\[ref\]\s*\$([A-Za-z_][A-Za-z0-9_]*)',
        '(?i)-(?:outvariable|ov|pipelinevariable|pv|errorvariable|ev|warningvariable|wv|informationvariable|iv)\s*[:\s]\s*[''"]?\+?([A-Za-z_][A-Za-z0-9_]*)',
        '(?i)foreach\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s+in\b'
    )
    foreach ($p in $assignPatterns) {
        foreach ($m in [regex]::Matches($Command, $p)) {
            $k = $m.Groups[1].Value.ToLowerInvariant()
            $counts[$k] = 1 + [int]$(if ($counts.ContainsKey($k)) { $counts[$k] } else { 0 })
        }
    }
    $literalRx = '^\s*\$(?:script:|global:|local:)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:"((?:[^"`$]|\$env:' + $script:EnvLiteralNames + '(?![A-Za-z0-9_]))*)"|''([^'']*)'')\s*$'
    $writeRx = '(?i)(^|[\s;|&({])(set-content|sc|add-content|ac|out-file|tee-object|tee|copy-item|cp|copy|cpi|move-item|mv|move|mi|new-item|ni|rename-item|ren|rni|remove-item|ri|del|rm)(\s|$)|\[(system\.)?io\.file\]::(write|append|copy|move|create|open|replace|delete)|>'
    $statements = @(Split-Statement $Command)
    $pos = 0
    foreach ($st in $statements) {
        $at = $Command.IndexOf($st, $pos)
        if ($at -ge 0) { $pos = $at + $st.Length }
        $m = [regex]::Match($st, $literalRx)
        if (-not $m.Success) { continue }
        $name = $m.Groups[1].Value
        if ([int]$counts[$name.ToLowerInvariant()] -ne 1) { continue }
        $value = if ($m.Groups[2].Success) { $m.Groups[2].Value } else { $m.Groups[3].Value }
        $result[$name.ToLowerInvariant()] = @{ Value = $value; End = $pos; Start = $at }
    }
    # TOCTOU: statement, ktery ZAPISUJE a jmenuje promennou nebo jeji literal, rozbaleni rusi.
    foreach ($st in $statements) {
        $clean = [regex]::Replace($st, '[0-9*]?>{1,2}\s*(?:&[0-9]|\$null|nul)\b', ' ')
        # Zapis se hleda MIMO retezce - `-Expect 'NFD->lower'` ani `-Old '... -> ...'` nic nezapisuji
        # (zmereno nad populaci: 4 z 16 zbylych dotazu byly `->` v textu argumentu).
        $unquoted = [regex]::Replace($clean, '"(?:[^"`]|`.)*"|''[^'']*''', '""')
        if (-not [regex]::IsMatch($unquoted, $writeRx)) { continue }
        foreach ($k in @($result.Keys)) {
            $v = [string]$result[$k].Value
            $leaf = ($v -replace '\\', '/').Split('/')[-1]
            if ([regex]::IsMatch($clean, ('(?i)\$\{?' + [regex]::Escape($k) + '(?![A-Za-z0-9_])')) -or
                ($v -ne '' -and $clean.IndexOf($v, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -or
                ($leaf -ne '' -and $clean.IndexOf($leaf, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)) {
                $result.Remove($k)
            }
        }
    }
    return $result
}

# Rozbali promenne v hlave (`$m`, `${m}`, `"$sp\x.ps1"`) literalem; $null = neslo.
function Expand-LiteralHead([string]$Head, [string]$Raw) {
    if ($Head -match '\$\(' -or $Head -match '%') { return $null }
    $refs = [regex]::Matches($Head, '\$\{?([A-Za-z_][A-Za-z0-9_]*)(:[A-Za-z_])?\}?')
    if ($refs.Count -eq 0) { return $null }
    # CR-P7 (/code-review): rozhoduje PRVNI vyskyt pouziti - stejny text pred prirazenim i po nem by s LastIndexOf
    # rozbalil i pouziti, ktere bezi s jinou hodnotou (`. .\init.ps1; & $m; $m = '...'; & $m`).
    # Vyskyt textu pouziti, ktery lezi uvnitr prirazeni nektere promenne hlavy (`$m = ...` obsahuje `$m`), pouzitim neni.
    $use = -1
    $from = 0
    while ($true) {
        $p = $script:FullCommand.IndexOf($Raw, $from)
        if ($p -lt 0) { break }
        $inside = $false
        foreach ($a0 in $script:LiteralAssign.Values) { if ($p -ge [int]$a0.Start -and $p -lt [int]$a0.End) { $inside = $true; break } }
        if (-not $inside) { $use = $p; break }
        $from = $p + 1
    }
    $out = $Head
    foreach ($r in $refs) {
        if ($r.Groups[2].Success) { return $null }   # `$env:X` primo v hlave - neprirazena promenna
        $k = $r.Groups[1].Value.ToLowerInvariant()
        if (-not $script:LiteralAssign.ContainsKey($k)) { return $null }
        $a = $script:LiteralAssign[$k]
        if ($use -lt 0 -or [int]$a.End -gt $use) { return $null }
        $lit = [regex]::Replace([string]$a.Value, ('(?i)\$env:(' + $script:EnvLiteralNames + ')'), 'ENV_$1')
        $out = [regex]::Replace($out, ([regex]::Escape($r.Value) + '(?![A-Za-z0-9_])'), $lit.Replace('$', '$$'))
    }
    if ($out -match '\$') { return $null }
    return $out
}

# Rozbali obaly (bash -c, cmd /c, eval, xargs, sudo, find -exec, ...) na listy.
# Obal s literalem -> rozebrat vnitrek. Obal s promennou -> 'opaque' (= ask).
function Get-CommandLeaf([string]$Sub, [int]$Depth) {
    $out = New-Object System.Collections.ArrayList
    $trimmed = $Sub.Trim()
    if ($trimmed -eq '') { return $out }
    if ($Depth -gt 5) { [void]$out.Add((New-OpaqueLeaf $trimmed 'depth')); return $out }

    # `&` je operator SPUSTENI. Rozdil je podstatny az u hole promenne: `$sql | psql`
    # posila HODNOTU, kdezto `& $cmd` obsah promenne SPUSTI. Priznak se proto nese dal.
    $invoked = $false
    $trimmedHadDot = $false
    if ($trimmed.StartsWith('&') -and -not $trimmed.StartsWith('&&')) {
        $invoked = $true
        $trimmed = $trimmed.Substring(1).Trim()
        if ($trimmed -eq '') { return $out }
    }
    # N33: dot-source je DRUHY operator spusteni - `. $x` obsah promenne spusti stejne
    # jako `& $x`, jen v aktualnim scope. Resi se tady vedle `&`, ne jako `exe`: kdyby
    # se cekalo az na Split-Arguments, byl by argv[0] jen tecka a priznak by se ztratil.
    # Bila znaka za teckou je podminka - `./script.sh` ani `cd ..` dot-source nejsou.
    elseif ($trimmed -match '^\.\s') {
        $invoked = $true
        $trimmedHadDot = $true
        $trimmed = $trimmed.Substring(1).Trim()
        if ($trimmed -eq '') { return $out }
    }

    # Raw se bere PRED odstranenim prefixu promennych - hostitel DB muze byt prave tam
    # (ConnectionStrings__Default="Host=..." dotnet ef database update).
    $raw = $trimmed

    # .NET volani nemaji argv tvar a nesou `$true` jako druhy argument - kdyby sla
    # nejdriv kontrola "nerozebratelne", skoncila by ask misto deny.
    #
    # 0.1.10: druhe jmeno teze operace je `Microsoft.VisualBasic.FileIO.FileSystem`
    # (`DeleteDirectory` / `DeleteFile`). Do 0.1.9 propadalo do tridy "nerozebratelne",
    # a jakmile ta trida prestala byt dotazem, byla by z toho DIRA: mereni 7. 9. ukazalo,
    # ze prave tyhle dva tvary jsou JEDINE dva prave zasahy par. 6 ze 46 dotazu.
    # `SendToRecycleBin` se nerozlisuje - brana zni "mazani", ne "nevratne mazani".
    if ([regex]::IsMatch($trimmed, $script:NetDeleteCallPattern, 'IgnoreCase')) {
        [void]$out.Add(@{ Kind = 'leaf'; Exe = 'net-delete'; Args = @(); Raw = $raw; Text = $trimmed; GitConfig = @() })
        return $out
    }

    # Z117-Q26 = A (A117-N8): `$ExecutionContext.InvokeCommand.InvokeScript(<text>)` a `[scriptblock]::Create(<text>)`
    # spousti TEXT stejne jako `iex` - do 0.3.0 hlava `$ExecutionContext...` nebo `[scriptblock]::Create('` nesedla na zadne
    # pravidlo a `InvokeScript("$x reset --hard")` mlcel. Literal (bez promenne) se rozebere jako prikaz, jinak `invoked`.
    $runner = [regex]::Match($trimmed, '(?i)(?:\.InvokeScript|\[scriptblock\]::create)\s*\(\s*(?:''([^'']*)''|"([^"]*)")?')
    if ($runner.Success) {
        $lit = if ($runner.Groups[1].Success) { $runner.Groups[1].Value } elseif ($runner.Groups[2].Success) { $runner.Groups[2].Value } else { $null }
        if ($null -ne $lit -and -not (Test-Unexpandable $lit) -and ($runner.Groups[1].Success -or $lit -notmatch '[`$]')) {
            foreach ($l in (Get-InvokedLeaves $lit '' $Depth)) { [void]$out.Add($l) }
        } else {
            [void]$out.Add((New-OpaqueLeaf $trimmed 'invoked'))
        }
        return $out
    }

    # CR-U2 + CR-V1 (TASK-179, kola 5 a 6): pred prikazem muze stat prirazeni i presmerovani v libovolnem poradi a bez
    # mezery mezi presmerovanimi (`>out X=1 rm -rf src`, `2>/dev/null>out rm -rf src`, `<>f`, `>|f`, `<<<x`, `>nul rd ...`
    # v cmd) - jinak by exe vyslo `>out` a zadne pravidlo nesedlo. Zbyde-li na zacatku `<` nebo `>`, tvar je nerozebratelny.
    $stripped = [regex]::Replace($trimmed,
        '^\s*(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|''[^'']*''|\S*)\s+|[0-9]*(?:<<<|<>|>\||>>|>&|<&|&>>|&>|>|<)\s*(?:"[^"]*"|''[^'']*''|[^\s<>]+)\s*)+', '')
    if ($stripped.Trim() -eq '' -and $trimmed -match '^\s*[0-9]*[<>&]') { return $out }
    if ($stripped -match '^\s*[<>]') { [void]$out.Add((New-OpaqueLeaf $trimmed 'depth')); return $out }

    # PowerShellove PRIRAZENI `$x = <prikaz>` neni volani promenne v pozici prikazu.
    # Bez teto vetve bral Test-Unexpandable `$out` jako promennou v pozici prikazu
    # (Z3) a KAZDE prirazeni koncilo ask - v bypassu deny. `$out = dotnet test` je
    # ale bezna prace a falesne bloky na bezne praci branu do tydne vypnou (Amber B1).
    #
    # Prirazeni ale nic NEPERE: `$x = git branch -D y` se rozebira dal jako
    # `git branch -D y` a skonci deny.
    $assign = [regex]::Match($stripped,
        '^\s*\$(?:env:|script:|global:|local:|using:)?[A-Za-z_][A-Za-z0-9_]*\s*[+\-*/]?=(?!=)\s*(.*)$')
    if ($assign.Success) {
        $rhs = $assign.Groups[1].Value.Trim()
        # Nalez Amber C7: prava strana BEZ VOLANI (jen promenne, retezce, cisla) neni
        # prikaz - `$a = $b` ani `$env:PATH = "$env:PATH;C:\x"` nic nespousti a bez teto
        # vetve koncily ask, tedy falesny blok na bezne praci.
        if ($rhs -eq '' -or $rhs -match '^(?:\$[\w:]+|"[^"]*"|''[^'']*''|[0-9]+|\$(?:true|false|null)|[\s;+,.\-])*$') {
            return $out
        }
        foreach ($l in (Get-CommandLeaf $rhs ($Depth + 1))) { [void]$out.Add($l) }
        return $out
    }

    # Nalez Amber L1: cteni vlastnosti ani `$i++` neni prikaz. Detail a duvod, proc
    # to nesmi platit v Bashi, jsou u Test-ExpressionStatement; escape skeneru je
    # jediny spolehlivy ukazatel jazyka (prepina ho i sestup do vnorenneho shellu).
    if ((Get-ScannerEscape) -eq '`' -and (-not $invoked) -and (Test-ExpressionStatement $stripped)) { return $out }

    # Nalez Amber C7b (zmereno): zavorkovy obal `(git reset --hard)` dal argv[0] = `(git`,
    # z toho exe `(git`, a zadne pravidlo se nechytilo -> allow. Obal se strhne a vnitrek
    # se rozebere stejne jako u `&`. Kontrolni skupina `(Get-Date)` zustava allow, protoze
    # se rozebere na `Get-Date` a ten neni destruktivni.
    # Nalez Metis 3 (kolo 2): stejny obal delaji SLOZENE zavorky - `& { git reset --hard }`
    # je blok skriptu, ktery se spusti. Bez nej vychazelo exe `{` a zadne pravidlo nesedlo.
    # Nalez Amber I1: blok `{ ... }` nemusi stat na zacatku statementu. Regex ukotveny
    # na zacatek nechal `if ($x) { git reset --hard }` i viceradkovou variantu projit
    # jako exe `if` -> allow. Telo se proto hleda kvotove korektne kdekoli.
    # Nalez Amber K2 (TASK-106 bod 6, 0.2.0): rozebiraji se VSECHNY bloky statementu,
    # ne jen ten, kterym statement konci - `if ($x) { rm -rf src } else { git status }`
    # mel destruktivni prikaz v PRVNIM bloku a prosel nerozebrany.
    $blocks = Get-ScriptBlockBodies $stripped
    foreach ($block in $blocks.Blocks) {
        if ($block.Body.Trim() -eq '') { continue }
        # Nalez Amber G4: vnitrek se rozebira jako PRIKAZOVA RADKA, ne jako jediny
        # prikaz - `& { git reset --hard; rm -rf src }` jsou dva prikazy a driv se
        # z nich cetl jen prvni. Skener uz `{ }` zna, takze se sem dostane cely blok.
        # Nalez Ada N19: telo bloku prochazi tymz retezem jako hlavni beh.
        foreach ($l in (Get-CommandLineLeaves $block.Body ($Depth + 1))) { [void]$out.Add($l) }
    }
    # Nalez Amber K1: hlava pred zavorkou se ZAHAZOVALA. `rm -rf {src,lib}` neni
    # blok, ale jeden prikaz s literalnim argumentem - telo `src,lib` neznamena nic
    # a `return` po nem schoval mazani. Kdyz hlava (nebo ocas) neco nese, statement se
    # rozebira DAL jako bezny prikaz; rekurze tu neni, bloky uz v `$out` jsou.
    if ($blocks.Whole) { return $out }

    $paren = [regex]::Match($stripped, '^\s*(?:&\s*)?[$@]?\(\s*(.*?)\s*\)\s*$')
    if ($paren.Success -and $paren.Groups[1].Value.Trim() -ne '') {
        # TASK-106 bod 15: uvnitr obalu, ktery text spousti, je substituce v hlave
        # (`bash -c "$(cat cmd.txt)"`) obsah, ktery se SPUSTI - tedy `invoked`. Bez teto
        # zavory by se `$(...)` rozebralo jen jako vnitrni prikaz (`cat cmd.txt`) a vysledek
        # substituce, ktery bash spusti, by nikdo nevidel.
        if ($script:InvokedContext -and $stripped -match '^\s*(?:&\s*)?\$\(') {
            [void]$out.Add((New-OpaqueLeaf $raw 'invoked')); return $out
        }
        foreach ($l in (Get-CommandLeaf $paren.Groups[1].Value ($Depth + 1))) { [void]$out.Add($l) }
        return $out
    }

    $argv = Split-Arguments $stripped
    if ($argv.Count -eq 0) { return $out }

    if (Test-Unexpandable $argv[0]) {
        # `& $cmd` obsah promenne SPUSTI, `$out` nebo `"EXIT=$code"` ne. Priznak `$invoked`
        # se proto musi DONEST az sem - jinak by obe veci mely tutez politiku.
        # TASK-106 bod 15: uvnitr obalu, ktery text spousti (Get-InvokedLeaves), je promenna
        # v hlave statementu tez spusteni obsahu - `bash -c "$cmd arg"`, `pwsh -c "$x"`. Jen
        # kdyz je promenna nebo substituce SAMA hlavou (token zacina `$` nebo `%`): retezec
        # `"chyb: $($e.Count)"` ani volani `[IO.File]::ReadAllBytes('$f')` nic nespousti a
        # zustavaji `variable` (zmereno nad vzorkem: 19 ze 44 dotazu bylo presne tohle).
        $head = [string]$argv[0]
        $headIsVariable = $head -match '^[$%]'
        # H-a varianta 1 (Z117-Q17): hlava po literalnim prirazeni v temze prikazu se rozbali.
        if ($invoked -and -not $script:InvokedContext -and (Get-ScannerEscape) -eq '`' -and $script:LiteralAssign.Count -gt 0) {
            $expanded = Expand-LiteralHead $head $raw
            if ($null -ne $expanded) {
                $restArgs = @()
                if ($argv.Count -gt 1) { $restArgs = @($argv[1..($argv.Count - 1)]) }
                $op = if ($trimmedHadDot) { '. ' } else { '& ' }
                foreach ($l in (Get-CommandLeaf ($op + (Join-Argument (@($expanded) + $restArgs))) ($Depth + 1))) { [void]$out.Add($l) }
                return $out
            }
        }
        if ($headIsVariable -and $null -ne $script:InvokedAssigned -and $head -match '^\$\{?([A-Za-z_][A-Za-z0-9_]*)') {
            if ($script:InvokedAssigned.Contains($Matches[1])) { $headIsVariable = $false }
        }
        $why = if ($invoked -or ($script:InvokedContext -and $headIsVariable)) { 'invoked' } else { 'variable' }
        [void]$out.Add((New-OpaqueLeaf $raw $why)); return $out
    }

    $exe = Get-ExecutableName $argv[0]
    $rest = Get-RestTokens $argv
    # TASK-179: vnitrni prikaz kontejneroveho obalu - pripoji se ZA list obalu (ten zustava beze zmeny, viz Get-ContainerLeaves).
    $containerLeaves = New-Object System.Collections.ArrayList

    switch -Regex ($exe) {
        ($script:ContainerCli) {   # K2-6: tentyz seznam CLI jako Get-ContainerCommand, ne druha kopie
            foreach ($l in (Get-ContainerLeaves $argv $Depth)) { [void]$containerLeaves.Add($l) }
        }
        '^(sudo|nice|nohup|time|doas|timeout|command|builtin|exec|env|stdbuf)$' {
            # TASK-179: kontejnerovy obal za prefixem (`sudo docker --context x exec ...`). Pruchod nize (Get-WrapperTail) zustava
            # dnesni - u tvaru, ktery jeho starsi kontejnerova vetev rozbali, dal posuzuje vnitrni prikaz VSEMI pravidly (0.3.0).
            # CR-5 (kolo 1 /code-review): dvoji list = dvoji audit. Kdyz starsi pruchod konci na CLI kontejneru
            # (`sudo docker-compose ...`), rozebere ho rekurze nize sama; tail, ktery uz nasel, se nepridava podruhe.
            $ci = Get-ContainerIndex $argv
            $oldTail = Get-WrapperTail $argv
            $oldHead = if ($oldTail.Count -gt 0) { Get-ExecutableName ([string]$oldTail[0]) } else { '' }
            $inContainer = ($ci -gt 0 -and $oldHead -notmatch $script:ContainerCli)
            $prefixEnv = ''
            $prefixGroup = ''
            if ($inContainer) {
                $skip = if ($oldTail.Count -gt 0) { Join-Argument $oldTail } else { '' }
                $ccP = Get-ContainerCommand @($argv[$ci..($argv.Count - 1)])
                if ($null -ne $ccP) {
                    # K7-3: list starsiho pruchodu (cteni 0) a kandidati rozboru obalu jsou jedna skupina pro audit.
                    $prefixGroup = New-ReadingGroup
                    foreach ($l in (Get-ContainerLeaves $null $Depth $skip $ccP $prefixGroup)) { [void]$out.Add($l) }
                    # K3-6 (kolo 3): starsi pruchod `-e` obalu zahodi - jeho listy (vsechna pravidla, 0.3.0) dostanou promenne obalu
                    # a zakaz `allow` (tvar v kontejneru, AOPT-O26) samy, misto druheho listu s tymz prikazem (dvoji audit).
                    $prefixEnv = Resolve-ContainerEnv $ccP.Env
                }
            }
            # Nalez Amber G2: tady stala DRUHA, chudsi kopie tabulky obalu. Vetev jen
            # spojila `$rest` a rekurzivne se zavolala, takze u obalu s prepinacem
            # BEROUCIM HODNOTU (`sudo -u root rm -rf /srv`, `nice -n 10 rm -rf src`,
            # `timeout -s KILL 30 rm -rf src`) vysel argv[0] jako `-u` / `-n` / `-s`,
            # zadne pravidlo nesedlo a destruktivni prikaz propadl na ALLOW.
            # Oprava E4 z kola 3 sla jen do Get-UnwrappedExe; tahle vetev byla od
            # zalozeni pluginu beze zmeny. Pruchod obaly ma proto JEDINY zdroj pravdy.
            #
            # Nalez Metis 5: `command rm -rf src` obchazi jmeno spustitelneho souboru -
            # `command|builtin|exec` jsou v tabulce jako obaly bez prepinacu s hodnotou.
            $tail = $oldTail   # K2-8: tentyz pruchod jako vyse, podruhe se nepocita
            if ($tail.Count -eq 0) {
                # `env` bez prikazu je legitimni vypis prostredi, ne obal.
                if ($exe -eq 'env') {
                    [void]$out.Add(@{ Kind = 'leaf'; Exe = $exe; Args = @(); Raw = $raw; Text = 'env'; GitConfig = @() })
                }
                return $out
            }
            foreach ($l in (Get-CommandLeaf (Join-Argument $tail) ($Depth + 1))) {
                if ($inContainer) {
                    $l['NoAllow'] = $true
                    if ($prefixEnv -ne '') { Add-LeafContainerEnv $l $prefixEnv }
                    if ($prefixGroup -ne '') { Set-LeafReading $l $prefixGroup 0 }
                }
                [void]$out.Add($l)
            }
            return $out
        }
        '^(python|python3|node|nodejs|ruby|perl|php|deno)$' {
            # Nalez Metis 16/24: vnitrek `-c "..."` je kod, ne prikazova radka - rozebrat
            # ho neumime. Od 0.1.10 je to pricina `interpreter`: telo se nese dal, aby
            # nad nim mohl probehnout test destruktivniho tokenu (1C).
            for ($i = 0; $i -lt $rest.Count; $i++) {
                if ($rest[$i] -cmatch '^-{1,2}(c|e|eval)$') {
                    $body = (Join-CommandString ($rest | Select-Object -Skip ($i + 1)))
                    [void]$out.Add((New-OpaqueLeaf $raw 'interpreter' $body)); return $out
                }
            }
            return $out
        }
        '^(start-process|saps|start)$' {
            # Nalez Metis 25: Start-Process je dispatcher; skutecny prikaz je v
            # -FilePath a -ArgumentList.
            $file = ''
            $argList = ''
            for ($i = 0; $i -lt $rest.Count; $i++) {
                $t = $rest[$i].ToLowerInvariant()
                # Z117-Q27 = B (A117-N18): PowerShell bere kazdou jednoznacnou zkratku (`-f`, `-a`, `-Arg` ...); hodnota
                # parametru, ktery FilePath neni (`-Verb RunAs`, `-WorkingDirectory x`), se do 0.3.0 brala jako program.
                if (((Test-ParameterPrefix $t 'filepath') -or $t -eq '-path') -and ($i + 1) -lt $rest.Count) { $file = $rest[$i + 1]; $i++; continue }
                $isValueParam = $false
                if ($t.Length -ge 3) {
                    foreach ($vp in @('credential', 'workingdirectory', 'redirectstandarderror', 'redirectstandardinput',
                                      'redirectstandardoutput', 'verb', 'windowstyle', 'environment')) {
                        if (Test-ParameterPrefix $t $vp) { $isValueParam = $true; break }
                    }
                }
                if ($isValueParam) { $i++; continue }
                if (((Test-ParameterPrefix $t 'argumentlist') -or $t -eq '-args') -and ($i + 1) -lt $rest.Count) {
                    # Nalez Metis 7 (kolo 2): `-ArgumentList @('-enc','...')` je POLE.
                    # Bralo se to jako jeden token vcetne `@(`, `)` a apostrofu, takze
                    # se `-enc` uvnitr nikdy nenaslo. Pole se rozlozi na tokeny.
                    $val = [string]$rest[$i + 1]
                    # Pole se pri tokenizaci rozpadne (`@('-enc',` + `'x')`), takze se
                    # sbira dal, dokud se zavorka neuzavre.
                    if ($val -match '^@?\(' -and $val -notmatch '\)\s*$') {
                        $k = $i + 2
                        while ($k -lt $rest.Count) {
                            $val = $val + ' ' + [string]$rest[$k]
                            if ($rest[$k] -match '\)\s*$') { break }
                            $k++
                        }
                        $i = $k - 1
                    }
                    # A117-N18: pole bez zavorek (`-ArgumentList 'reset','--hard'`, i s mezerou za carkou) - do 0.3.0
                    # zbylo `reset,--hard` jako jeden argument a `git reset --hard` se nesestavilo.
                    if ($val -notmatch '^@?\(') {
                        $k = $i + 2
                        while ($val.EndsWith(',') -and $k -lt $rest.Count) { $val = $val + [string]$rest[$k]; $k++ }
                        $i = $k - 2
                        if ($val.Contains(',')) { $val = '(' + $val + ')' }
                    }
                    $arr = [regex]::Match($val, '^@?\(\s*(.*?)\s*\)$')
                    if ($arr.Success) {
                        $items = New-Object System.Collections.ArrayList
                        foreach ($piece in (Split-Unquoted $arr.Groups[1].Value @(','))) {
                            [void]$items.Add(($piece.Trim().Trim("'").Trim('"')))
                        }
                        $val = (Join-Argument $items)
                    }
                    $argList = $val; $i++; continue
                }
                if (-not $rest[$i].StartsWith('-') -and $file -eq '') { $file = $rest[$i]; continue }
                # A117-N18: druhy pozicni argument Start-Process je -ArgumentList (`Start-Process git 'reset','--hard'`).
                if (-not $rest[$i].StartsWith('-') -and $argList -eq '') {
                    $val = [string]$rest[$i]
                    $k = $i + 1
                    while ($val.EndsWith(',') -and $k -lt $rest.Count) { $val = $val + [string]$rest[$k]; $k++ }
                    $i = $k - 1
                    $pa = [regex]::Match($(if ($val.Contains(',') -and $val -notmatch '^@?\(') { '(' + $val + ')' } else { $val }), '^@?\(\s*(.*?)\s*\)$')
                    if ($pa.Success) {
                        $items = New-Object System.Collections.ArrayList
                        foreach ($piece in (Split-Unquoted $pa.Groups[1].Value @(','))) { [void]$items.Add(($piece.Trim().Trim("'").Trim('"'))) }
                        $val = (Join-Argument $items)
                    }
                    $argList = $val
                }
            }
            if ($file -eq '') { return $out }
            $inner = ($file + ' ' + $argList).Trim()
            # N34 (i) + N49: `Start-Process $x` spousti obsah promenne jako FilePath ->
            # `invoked`. Promenna jako CESTA (`pwsh -File $p`, `bash $script`) sem nevede -
            # tam se soubor jen predava a plati README omezeni 1 (skript souborem je
            # nepruhledny). Kontrolni tvar `Start-Process -FilePath 'pwsh' ...
            # -RedirectStandardOutput $log` ma FilePath literalni, takze do teto vetve
            # vubec nepada.
            # TASK-106 bod 15 (0.2.0): rozbor v kontextu spusteni - promenna v HLAVE je
            # `invoked`, promenna v argumentu uz ne. Nalez Ada N19: cely retez pruchodu.
            foreach ($l in (Get-InvokedLeaves $inner '' $Depth)) { [void]$out.Add($l) }
            return $out
        }
        '^(bash|sh|zsh|dash|ksh)$' {
            # Nalez Metis 4: `bash -lc '...'` - shell prijima slouceny kratky prepinac,
            # takze se hleda kterykoli tvar koncici `c`, ne presny token `-c`.
            # Telo obalu od 0.3.0 rozpoznava Get-ShellWrapperBody (_common.ps1) - tataz funkce jako v hooku secrets.
            $wb = Get-ShellWrapperBody $exe $rest
            if ($null -eq $wb) {
                # bash script.sh - skript souborem je pro hook nepruhledny, propousti se
                return $out
            }
            $inner = [string]$wb.Text
            # N34 (i): obal SPOUSTI obsah promenne, stejne jako `& $cmd` -> `invoked`.
            # TASK-106 bod 15 (0.2.0): do 0.1.11 tu stal `Test-Unexpandable $inner` nad CELYM
            # vnitrkem; ted se vnitrek rozebira a `invoked` je jen statement s promennou
            # v HLAVE (`bash -c "$x"`, `bash -c "$cmd arg"`), ne `bash -c "echo $HOME"`.
            # Nalez Amber I2: escape znak patri tomu shellu, ktery text SPUSTI, ne tomu,
            # ktery ho predal dal. Bez prepnuti se `bash -c 'echo \" ; git reset --hard'`
            # psane z PowerShell nastroje rozebiralo PS pravidly a propadlo na allow.
            foreach ($l in (Get-InvokedLeaves $inner 'Bash' $Depth)) { [void]$out.Add($l) }
            return $out
        }
        '^(pwsh|powershell)$' {
            # Nalez Metis 4 (kolo 2): PowerShell bere KAZDOU jednoznacnou zkratku parametru (`-enc`, `-enco` ...);
            # nalez Amber G5: `-c`/`-command` se porovnavaly PRESNE. Obe pravidla drzi od 0.3.0 Get-ShellWrapperBody.
            $wb = Get-ShellWrapperBody $exe $rest
            # skript souborem je pro hook nepruhledny -> propousti se (dokumentovano)
            if ($null -eq $wb) { return $out }
            if ($wb.Kind -eq 'encoded') { [void]$out.Add((New-OpaqueLeaf $raw 'encoded')); return $out }
            $inner = [string]$wb.Text
            # N34 (i): obal SPOUSTI obsah promenne, stejne jako `& $cmd` -> `invoked`.
            # TASK-106 bod 15 (0.2.0): 41 ze 44 dotazu `invoked` ve vzorku faze 1 mel PRAVE
            # tenhle tvar s literalni hlavou (`pwsh -Command ". 'x.ps1'; ...; $env:X = 1"`).
            # Vnitrek se rozebira; `invoked` je jen statement s promennou v hlave.
            # Nalez Amber I2, opacny smer: `pwsh -c '...'` psane z Bash nastroje.
            foreach ($l in (Get-InvokedLeaves $inner 'PowerShell' $Depth)) { [void]$out.Add($l) }
            return $out
        }
        '^(cmd)$' {
            $wb = Get-ShellWrapperBody $exe $rest
            if ($null -eq $wb) { return $out }
            $inner = [string]$wb.Text
            # N34 (i): obal SPOUSTI obsah promenne, stejne jako `& $cmd` -> `invoked`.
            # TASK-106 bod 15 (0.2.0): rozbor v kontextu spusteni (`cmd /c %X%` zustava ask,
            # `cmd /c "echo %PATH% && dir"` uz ne). Nalez Ada N19: cely retez pruchodu.
            # CR-T (kolo 4): cmd komentar `#` nezna - `cmd /c "echo # & rd /s /q src"` rd spusti. Komentar ve skeneru nic
            # nezahazuje a oddelovace v nem dal deli (_common.ps1, Get-CommentStart), takze `rd` je videt i tady.
            foreach ($l in (Get-InvokedLeaves $inner '' $Depth)) { [void]$out.Add($l) }
            return $out
        }
        '^(iex|invoke-expression)$' {
            # N33 (zuzeny, Ada 8. 9.): `iex` je treti tvar spusteni textu. Literal se
            # ROZEBERE jako u `bash -c '...'` (`iex 'git reset --hard'` -> deny,
            # `iex 'git status'` -> nic), promenna spadne do `invoked` (0.3.1: politika gate.opaque.invoked).
            # Pozicni i `-Command` tvar. `iex` bez argumentu (text z roury, `"x" | iex`) drzi pas
            # `auditPatterns.invoke-expression` (do 0.3.0 askPatterns).
            # A179-O4 (Amber 2026-10-20): do 0.3.1 se sem prazdny vnitrek vracel BEZ listu, takze pas nikdy nestrilel a tvar
            # prosel bez rozhodnuti i bez radku auditu (i v 0.3.0). Holy list ho pasu preda - ticho + audit, zadny deny.
            $skip = 0
            if ($rest.Count -gt 0 -and (Test-ParameterPrefix ($rest[0].ToLowerInvariant()) 'command')) { $skip = 1 }
            $inner = (Join-CommandString ($rest | Select-Object -Skip $skip))
            if ($inner -eq '') {
                [void]$out.Add(@{ Kind = 'leaf'; Exe = $exe; Args = @(); Raw = $raw; Text = $exe; GitConfig = @() })
                # CR-Q9 + CR-R6/R10 (/code-review 0.3.1): text z roury muze byt literal v prikazu (`'git reset --hard' | iex`).
                # Kazdy retezcovy literal prikazu se proto rozebere jako `iex '<literal>'` (Q5) - plny rozbor, ne hledani
                # tokenu (`'rm -r -fo C:\x' | iex`), a jen literaly, ne zbytek prikazu (`git log --grep "reset --hard"`).
                # Producent bez literalu (`irm url | iex`, `Get-Content x | iex`) zustava A179-O4: ticho + audit.
                # CR-S1/S4/S8 (kolo 3): literaly se berou z textu, ktery se prave rozebira (vnoreny `pwsh -c "..."`, ne cely
                # prikaz), tokenizerem PowerShellu (komentar `# don't` ani escape nepoplete par uvozovek) a JEDNOU - holy `iex`
                # uvnitr rozebiraneho literalu (`'a | iex' | iex`) uz se znovu neprohledava (rozbor by rostl exponencialne
                # a narazil na timeout hooku), je `depth` (A179-O1: deny). Text, ktery tokenizer neprecte, taky `depth`.
                if ($script:IexLiteralScan) { [void]$out.Add((New-OpaqueLeaf $raw 'depth')); return $out }
                $ctx = if ([string]$script:LineText -ne '') { [string]$script:LineText } else { [string]$script:FullCommand }
                $perr = $null
                $toks = [System.Management.Automation.PSParser]::Tokenize($ctx, [ref]$perr)
                if (@($perr).Count -gt 0) { [void]$out.Add((New-OpaqueLeaf $raw 'depth')); return $out }
                $script:IexLiteralScan = $true
                try {
                    foreach ($tk in @($toks)) {
                        if ([string]$tk.Type -ne 'String') { continue }
                        $lit = [string]$tk.Content
                        if ($lit.Trim() -eq '') { continue }
                        foreach ($l in (Get-InvokedLeaves $lit '' $Depth)) { [void]$out.Add($l) }
                    }
                } finally { $script:IexLiteralScan = $false }
                return $out
            }
            # TASK-106 bod 15 (0.2.0): rozbor v kontextu spusteni - `iex $cmd` zustava ask.
            foreach ($l in (Get-InvokedLeaves $inner '' $Depth)) { [void]$out.Add($l) }
            return $out
        }
        '^(eval)$' {
            $inner = (Join-CommandString $rest)
            # N34 (i): obal SPOUSTI obsah promenne, stejne jako `& $cmd` -> `invoked`.
            # TASK-106 bod 15 (0.2.0): rozbor v kontextu spusteni (`eval $cmd` zustava ask,
            # `eval "echo $x"` uz ne). Nalez Ada N19: cely retez pruchodu.
            foreach ($l in (Get-InvokedLeaves $inner '' $Depth)) { [void]$out.Add($l) }
            return $out
        }
        '^(xargs)$' {
            $i = 0
            while ($i -lt $rest.Count) {
                $t = $rest[$i]
                if ($t -eq '--') { $i++; break }
                # Nalez Metis 3: DLOUHE tvary tychz prepinacu (`--arg-file`,
                # `--process-slot-var`, `--replace`) v seznamu nestaly, takze se
                # preskocil jen prepinac a jeho HODNOTA se vzala za prikaz -> allow.
                if ($t -match '^-(n|I|i|P|L|s|d|E|a)$') { $i += 2; continue }
                if ($t -cmatch '^--(max-args|replace|max-procs|max-lines|max-chars|delimiter|eof|arg-file|process-slot-var)$') { $i += 2; continue }
                if ($t.StartsWith('-')) { $i++; continue }
                break
            }
            # Nalez Amber G3: tady se skladalo Join-CommandString, ale xargs bere ARGV,
            # ne prikazovou radku. `echo . | xargs sh -c 'git reset --hard'` se tim
            # slozilo na `sh -c git reset --hard`, vnitrni `-c` vzalo jen `git` a
            # zbytek se ztratil -> allow. Tataz trida jako nalez Metis 1 u `find -exec`.
            #
            # Pravidlo, ktere ty dve funkce deli:
            #   tail je ARGV (xargs, find -exec, sudo, ...)          -> Join-Argument
            #   tail je PRIKAZOVA RADKA (bash -c, cmd /c, eval, ...) -> Join-CommandString
            $inner = (Join-Argument ($rest | Select-Object -Skip $i))
            if ($inner -eq '') { return $out }
            foreach ($l in (Get-CommandLeaf $inner ($Depth + 1))) { [void]$out.Add($l) }
            return $out
        }
        '^(find)$' {
            # Nalez Metis 7: `find src -depth -delete` maze bez -exec. Cile jsou
            # pozicni argumenty pred prvnim prepinacem.
            if ($rest -contains '-delete') {
                $paths = New-Object System.Collections.ArrayList
                foreach ($t in $rest) {
                    if ($t.StartsWith('-')) { break }
                    [void]$paths.Add($t)
                }
                if ($paths.Count -eq 0) { [void]$paths.Add('.') }
                [void]$out.Add(@{ Kind = 'leaf'; Exe = 'rm'; Args = @('-rf') + @($paths)
                                  Raw = $raw; Text = ('rm -rf ' + ($paths -join ' ')); GitConfig = @() })
                return $out
            }
            $idx = -1
            for ($i = 0; $i -lt $rest.Count; $i++) {
                # `-okdir` je ctvrty tvar tehoz (nalez Metis 3) - GNU find ho zna.
                if ($rest[$i] -cmatch '^-(exec|execdir|ok|okdir)$') { $idx = $i; break }
            }
            if ($idx -lt 0) { return $out }
            $tail = @($rest | Select-Object -Skip ($idx + 1) | Where-Object { $_ -ne ';' -and $_ -ne '+' -and $_ -ne '\;' })
            $inner = (Join-Argument $tail)
            if ($inner -eq '') { return $out }
            foreach ($l in (Get-CommandLeaf $inner ($Depth + 1))) { [void]$out.Add($l) }
            return $out
        }
    }

    $args2 = Expand-ColonParameter $rest
    $gitConfig = @()
    if ($exe -eq 'git') {
        # Hodnoty `-c klic=hodnota` se pri normalizaci zahazuji, ale nektere z nich
        # MENI VYZNAM podprikazu (nalezy Metis 26 a 27) - proto se schovaji na list.
        for ($i = 0; $i -lt $args2.Count; $i++) {
            if ($args2[$i] -eq '-c' -and ($i + 1) -lt $args2.Count) { $gitConfig += $args2[$i + 1] }
            elseif ($args2[$i] -match '^--config-env=(.*)$') { $gitConfig += $Matches[1] }
        }
        $args2 = Remove-GitGlobalOption $args2
    }
    $text = ($exe + ' ' + ($args2 -join ' ')).Trim()
    [void]$out.Add(@{ Kind = 'leaf'; Exe = $exe; Args = @($args2); Raw = $raw; Text = $text
                      GitConfig = @($gitConfig) })
    foreach ($l in $containerLeaves) { [void]$out.Add($l) }
    return $out
}

# ---------------------------------------------------- strukturalni pravidla ---

# Vsechny hostitele DB, ktere prikaz jmenuje (TASK-117, Z117-Q16 = A). Do 0.2.0 vracela funkce
# PRVNI shodu (Get-DbHost) - navnada `Server=localhost;Addr=db.firma.cz` cetla jen `localhost`.
# Synonyma serveru SqlClient: Server, Data Source, Address, Addr, Network Address
# (https://learn.microsoft.com/en-us/dotnet/api/microsoft.data.sqlclient.sqlconnection.connectionstring);
# Npgsql: Host, Server. Hodnota prepinace smi byt v uvozovkach i slepena (`-S"x"`, `-Sx`).
function Get-DbHosts([string]$Raw, [string]$Exe = '') {
    $q = '(?:"([^"]*)"|''([^'']*)''|([^\s"'';]+))'
    $patterns = @(
        'host\s*=\s*([^;"''\s]+)',
        # Nalez Amber B5: Npgsql bere `Server=` i `Data Source=` jako synonymum `Host=`.
        '(?:^|[;\s"''])server\s*=\s*([^;"''\s]+)',
        '(?:^|[;\s"''])data\s+source\s*=\s*([^;"''\s]+)',
        '(?:^|[;\s"''])(?:network\s+)?addr(?:ess)?\s*=\s*([^;"''\s]+)',
        ('(?:^|\s)-h(?:\s+|(?=["'']))' + $q),
        '(?:^|\s)-h([^\s"'';\-][^\s"'';]*)',
        ('--host(?:=|\s+)' + $q),
        'postgres(?:ql)?://(?:[^@/\s"'']*@)?([^:/\s?"'']+)'
    )
    # Nalez Amber F1: `-S` je hostitel JEN u sqlcmd. U psql je `-S` single-line bez
    # hodnoty, takze `psql -S -c "TRUNCATE x"` cetlo jako hostitele `-c` a skoncilo
    # deny misto ask. Vzor se proto pridava jen podle jmena nastroje.
    if ($Exe -eq 'sqlcmd') {
        $patterns = @(('(?:^|\s)-S(?:\s+|(?=["'']))' + $q), '(?:^|\s)-S([^\s"'';\-][^\s"'';]*)') + $patterns
    }
    $out = New-Object System.Collections.ArrayList
    foreach ($p in $patterns) {
        foreach ($m in [regex]::Matches($Raw, $p, 'IgnoreCase')) {
            for ($g = 1; $g -lt $m.Groups.Count; $g++) {
                if ($m.Groups[$g].Success) {
                    $v = $m.Groups[$g].Value.Trim()
                    # CR-P4 (/code-review): sber VSECH shod udelal z `sqlcmd -h -1` (hlavicky) a `psql -H -c` hostitele
                    # `-1` / `-c`. Hodnota, ktera sama zacina pomlckou, je dalsi prepinac, ne hostitel.
                    if ($v.StartsWith('-')) { break }
                    if ($out -notcontains $v) { [void]$out.Add($v) }
                    break
                }
            }
        }
    }
    return ,@($out)
}

# Z117-Q18 = A (Tom 2026-10-08): LocalDB (`(localdb)\<instance>`) je MISTNI - pevna mnozina
# v kodu (Test-FixedLocalDbHost v _common.ps1), ne polozka prepisovatelneho `localDbHosts`.
# Do 0.2.0 byla LocalDB v `--connection` "vzdalena" (deny), v `sqlcmd -S "(localdb)\..."`
# se hodnota v uvozovkach neprecetla vubec (ask) - obe cesty jsou od 0.3.0 `ask`.
function Test-LocalHost([string]$HostName, $LocalHosts) {
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $true }   # bez hostu = default local
    foreach ($h in $LocalHosts) {
        if ($HostName.ToLowerInvariant() -eq ([string]$h).ToLowerInvariant()) { return $true }
    }
    if ($HostName -match $script:LocalDbInstancePattern) { return $true }
    return $false
}

# CR-Q7 (/code-review 0.3.1): Test-LocalHost bere chybejiciho hostitele jako mistniho. To plati, jen kdyz hostitele
# nenese promenna prostredi: prirazeni v drivejsim statementu (`$env:PGHOST=...; psql ...`, `export PGHOST=...`) list
# nevidi a hodnotu z prostredi procesu (zdedi ji i spousteny prikaz) taky ne. Jmeno promenne v textu prikazu = hostitel
# neznamy; v prostredi hooku rozhoduje hodnota (`PGSERVICE` vzdy - hostitele nese soubor sluzby).
# (CR-R5, kolo 2: conninfo `service=` / `hostaddr=` konci deny uz dnes - retezec conninfo s mezerou je necitelne jmeno DB;
# zmereno nad 002b863, hlidaji radky CR-R5.)
# CR-U (kolo 5, konec "zaplatovani"): kola CR-R az CR-T hledala, ktere OSTATNI statementy prikazu a ktere hodnoty prostredi
# hooku hostitele nemeni (vycty tvaru, mnozina neutralnich prikazu, explicitni hostitel prebijejici PGHOST, seznam PGHOST
# se socketem ...) - a kazde kolo nasel dalsi obchvat. `allow` z gate.dbDestroyLocal proto plati jen pro JEDNODUCHY prikaz
# (Test-DbAllowContext): jediny statement, jehoz vsechny listy jsou tentyz SQL klient (nebo telo heredocu pro nej), bez
# jmena promenne hostitele v textu (i po odstraneni escapu a uvozovek) a s prazdnymi
# PGHOST, PGHOSTADDR, PGSERVICE, PGSERVICEFILE, SQLCMDSERVER a PSQLRC v prostredi hooku. Cokoli jineho = deny (jako kazdy
# jiny necitelny tvar). Mez: profil shellu a existujici ~/.psqlrc hook nevidi (README).
# CR-V5 (kolo 6): i PGSYSCONFDIR (systemovy psqlrc a pg_service.conf z jineho adresare).
$script:DbHostEnvNames = @('PGHOST', 'PGHOSTADDR', 'PGSERVICE', 'PGSERVICEFILE', 'PGSYSCONFDIR', 'SQLCMDSERVER', 'PSQLRC')
function Test-DbAllowContext($Leaf, [string]$HostExe) {
    foreach ($n in $script:DbHostEnvNames) {
        if (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($n))) { return $false }
    }
    $cmd = [string]$script:FullCommand
    $rx = '(?i)(?<![A-Za-z0-9_])(' + ($script:DbHostEnvNames -join '|') + ')(?![A-Za-z0-9_])'
    if ($cmd -match $rx -or ($cmd -replace '[\\`''"]', '') -match $rx) { return $false }
    # Jediny statement (telo heredocu se nepocita): drivejsi statement muze zmenit prostredi i bez listu (`$env:X = ...`,
    # `[Environment]::SetEnvironmentVariable(...)`).
    # CR-V4 (kolo 6): `&>soubor` je v Bashi presmerovani, ne oddelovac statementu (v cmd oddelovac je - list za nim pak
    # neprojde kontrolou listu nize).
    $rest = [regex]::Replace([string](Split-Heredoc $cmd).Rest, '&>>?\s*(?:"[^"]*"|''[^'']*''|[^\s;&|]+)', ' ')
    $stmts = @(Split-Statement $rest)
    if ($stmts.Count -ne 1) { return $false }
    # CR-V2 (kolo 6): statement JE ten prikaz - ne vyraz, ve kterem prikaz stoji (`[Environment]::X(...) + (psql ...)`).
    $leafText = if ([string](Get-LeafField $Leaf 'Kind' '') -eq 'heredoc') { [string](Get-LeafField $Leaf 'Outer' '') } else { [string]$Leaf.Raw }
    $norm = { param($s) ([regex]::Replace([string]$s, '&>>?\s*(?:"[^"]*"|''[^'']*''|[^\s;&|]+)|<<-?\s*([''"]?)[A-Za-z_][A-Za-z0-9_]*\1', ' ') -replace '\s+', ' ').Trim() }
    if ((& $norm $stmts[0]) -cne (& $norm $leafText)) { return $false }
    # Kazdy list prikazu je tentyz SQL klient nebo telo heredocu pro nej - roura (`| cat`), substituce, zpetne apostrofy
    # i komentar (vlastni segment) pridavaji jiny list.
    $found = $false
    foreach ($l in @($script:AllLeaves)) {
        if ([object]::ReferenceEquals($l, $Leaf)) { $found = $true; continue }
        $kind = [string](Get-LeafField $l 'Kind' '')
        $e = if ($kind -eq 'heredoc') { [string](Get-LeafField $l 'OuterExe' '') } else { [string](Get-LeafField $l 'Exe' '') }
        if ($e.ToLowerInvariant() -cne $HostExe) { return $false }
    }
    return $found
}

# CR-S6 (kolo 3): psql a dropdb ctou dlouhe volby pres getopt_long, ktery bere i jednoznacnou ZKRATKU (`--fil=x` = `--file`,
# `--ho=prod` = `--host`). Zkratka volby, ktera nese hostitele, jmeno DB, soubor nebo SQL, = argumenty necitelne -> bez `allow`.
function Test-AbbreviatedDbOption($Leaf, [string]$HostExe) {
    if (@('psql', 'dropdb') -cnotcontains $HostExe) { return $false }
    foreach ($m in [regex]::Matches(([string]$Leaf.Raw + ' ' + [string](Get-LeafField $Leaf 'Outer' '')), '(?:^|\s)--([A-Za-z][A-Za-z-]*)')) {
        $name = $m.Groups[1].Value.ToLowerInvariant()
        foreach ($full in @('host', 'port', 'dbname', 'file', 'command', 'maintenance-db')) {
            if ($name.Length -lt $full.Length -and $full.StartsWith($name)) { return $true }
        }
    }
    return $false
}

# ZOPT-Q102 + A179-O3 (Q10), 0.3.1: jmena databazi, kterych se destruktivni operace nad MISTNIM hostitelem tyka. Do 0.3.0
# konila `ask` (H-f povoloval jen uzkou sadu tvaru). Od 0.3.1: VSECHNA jmena precitelna a ve vzorech
# `gate.dbDestroyLocal.databases` (testovaci a vyvojove DB GSD i HRMS) -> hook mlci + audit; jinak deny. Cte se doslova
# z textu prikazu - konfigurace projektu ani prostredi procesu ne (soubor muze nest tajemstvi a mezi kontrolou a behem se
# muze zmenit; H-f). Vraci $null = jmeno nejde precist.
#   pripojena DB: `-d x` / `-dx` (psql, pgcli, sqlcmd; velikost pismen rozhoduje), `--dbname[=| ]x`, `dbname=x`,
#                 URI `postgres://.../x`, `Database=x` / `Initial Catalog=x`, `PGDATABASE=x`, prvni pozicni argument psql/pgcli
#   rusena DB:    `DROP DATABASE [IF EXISTS] x`, pozicni argument `dropdb`, `Database=` u `dotnet ef database drop`
# U `DROP DATABASE` / `dropdb` / `ef database drop` rozhoduje RUSENA DB (pripojena byva udrzbova, `postgres`); jine
# destruktivni SQL meni PRIPOJENOU DB - ta musi byt precitelna a ve vzoru taky. Kazde nalezene jmeno musi sedet (navnada
# `-d gsd_test_x` vedle jineho jmena nepomuze). Necitelne: zadne jmeno; jmeno s promennou, substituci nebo zastupnym
# znakem; SQL s `USE`, meta-prikazem psql (`\c`, `\!`), dynamickym SQL (`EXEC`, `EXECUTE`, `sp_executesql`, `dblink`;
# nalez councilu Codex K5) nebo trojdilnym jmenem objektu (`db.schema.t`); pgcli s DSN.
$script:PsqlValueFlags = '^(-c|-d|-f|-h|-p|-U|-v|-o|-L|-T|-F|-R|-P|-D|--command|--dbname|--file|--host|--port|--username|--set|--variable|--output|--log-file|--table-attr|--field-separator|--record-separator|--pset|--dsn)$'
$script:DropdbValueFlags = '^(-h|-p|-U|--host|--port|--username|--maintenance-db)$'
function Get-DbTargetNames($Leaf, [string]$SqlVisible, [string]$NameText, [string]$HostExe) {
    if ($SqlVisible -match '(?i)\bUSE\b|\bEXEC(UTE)?\b|\bsp_executesql\b|\bdblink') { return $null }
    # Meta-prikaz (`\c`, `\!`) zna jen psql/pgcli - u sqlcmd by `\` v hodnote `-S "(localdb)\X"` (Get-SqlText bere i ji) cetl jako meta.
    if (@('psql', 'pgcli') -ccontains $HostExe -and $SqlVisible -match '\\[A-Za-z!]') { return $null }
    # CR-Q4 (/code-review 0.3.1): prikazy sqlcmd (`:connect` prepne server, `:r` vlozi soubor, `!!` spusti shell).
    if ($SqlVisible -match '(?i)(?:^|[\s"''])(?::(?:connect|r|setvar|on|out|error|reset|ed|list|listvar|perftrace|serverlist|xml|exit|quit)\b|!!)') { return $null }
    # CR-R1/R2 (/code-review 0.3.1, kolo 2): komentar SQL (`/**/`, `--`) muze stat mezi jmenem a carkou seznamu
    # i mezi castmi jmena - SQL s komentarem = necitelne.
    # CR-S9 (kolo 3): escape `]]` / `""` uvnitr jmena (`[prod]]x].[dbo].[t]`, `DROP DATABASE [x_test]]y]`) vzory jmen nectou.
    if ($SqlVisible -match '/\*|--|\]\]|""') { return $null }
    # CR-Q2 + CR-R2 (/code-review 0.3.1): i jmena v hranatych zavorkach nebo uvozovkach (i s mezerou, `[prod].[my schema].[t]`)
    # a mezery kolem tecek. Vedlejsi ucinek: tecky v textu (`'A. B. C'`, `-S "127.0.0.1"`) = necitelne - smer deny.
    $part = '(?:\[[^\]]*\]|"[^"]*"|\w+)'
    if ($SqlVisible -match ($part + '\s*\.\s*(?:' + $part + ')?\s*\.\s*' + $part)) { return $null }
    $q = '(?:"([^"]*)"|''([^'']*)''|([^\s"'';|&]+))'
    $conn = New-Object System.Collections.ArrayList
    $targets = New-Object System.Collections.ArrayList
    $rx = @(
        @(('(?:^|\s)-d(?:\s+|(?=["'']))' + $q), 'None'),
        @('(?:^|\s)-d([^\s"'';|&\-][^\s"'';|&]*)', 'None'),
        @(('--dbname(?:=|\s+)' + $q), 'IgnoreCase'),
        @('(?:^|[\s;"''])dbname\s*=\s*([^\s"'';|&]+)', 'IgnoreCase'),
        @('postgres(?:ql)?://[^/\s"''?]*/([^?\s"''/;|&]+)', 'IgnoreCase'),
        @('(?:^|[;\s"''])(?:database|initial\s+catalog)\s*=\s*([^;"''\s|&]+)', 'IgnoreCase'),
        @(('(?:^|[\s;&|(:])PGDATABASE\s*=\s*' + $q), 'IgnoreCase')
    )
    foreach ($p in $rx) {
        foreach ($m in [regex]::Matches($NameText, [string]$p[0], [string]$p[1])) {
            for ($g = 1; $g -lt $m.Groups.Count; $g++) {
                if ($m.Groups[$g].Success) { [void]$conn.Add($m.Groups[$g].Value.Trim()); break }
            }
        }
    }

    # ARGV klienta: list nese Exe + Args; telo heredocu a roury nese uvozujici prikaz v `Outer`.
    $argv = @()
    if ([string](Get-LeafField $Leaf 'Kind' '') -eq 'leaf') {
        $argv = @([string]$Leaf.Exe) + @(Get-LeafField $Leaf 'Args' @())
    } else {
        $argv = @(Split-Arguments ([string](Get-LeafField $Leaf 'Outer' '')))
    }
    $ci = -1
    for ($i = 0; $i -lt $argv.Count; $i++) {
        if ((Get-ExecutableName ([string]$argv[$i])) -eq $HostExe) { $ci = $i; break }
    }
    if ($ci -ge 0 -and @('psql', 'pgcli', 'dropdb') -ccontains $HostExe) {
        $flags = if ($HostExe -eq 'dropdb') { $script:DropdbValueFlags } else { $script:PsqlValueFlags }
        $pos = New-Object System.Collections.ArrayList
        for ($i = $ci + 1; $i -lt $argv.Count; $i++) {
            $t = [string]$argv[$i]
            if ($HostExe -eq 'pgcli' -and $t -cmatch '^(-D|--dsn)(=|$)') { return $null }
            # CR-T7 (kolo 4): presmerovani (`2>&1`, `> out.txt`, `< in`) neni pozicni argument klienta.
            if ($t -match '^[0-9*&]?[<>]') { if ($t -match '^[0-9*&]?[<>]+&?$') { $i++ }; continue }
            if ($t -cmatch $flags) { $i++; continue }
            if ($t.StartsWith('-')) { continue }
            [void]$pos.Add($t)
        }
        if ($HostExe -eq 'dropdb') {
            if ($pos.Count -ne 1) { return $null }
            [void]$targets.Add([string]$pos[0])
        } elseif ($pos.Count -gt 0) {
            # psql [OPTION]... [DBNAME [USERNAME]] - prvni pozicni argument je databaze.
            [void]$conn.Add([string]$pos[0])
        }
    }

    $dropDbRx = 'DROP' + $script:SqlGap + 'DATABASE(?:' + $script:SqlGap + 'IF' + $script:SqlGap + 'EXISTS)?' + $script:SqlGap + '(\[[^\]]+\]|"[^"]+"|[^\s;,()]+)'
    foreach ($m in [regex]::Matches($SqlVisible, $dropDbRx, 'IgnoreCase')) {
        # CR-Q1b (/code-review 0.3.1): `DROP DATABASE a, b` rusi i dalsi jmena - seznam = necitelne.
        if ($SqlVisible.Substring($m.Index + $m.Length) -match '^\s*,') { return $null }
        [void]$targets.Add($m.Groups[1].Value.Trim('[', ']', '"'))
    }
    $efDrop = [regex]::IsMatch([string]$Leaf.Raw + ' ' + [string](Get-LeafField $Leaf 'Outer' ''),
                               ('\bdotnet[- ]ef' + $script:SqlGap + 'database' + $script:SqlGap + 'drop\b'), 'IgnoreCase')
    if ($efDrop) {
        if ($conn.Count -eq 0) { return $null }
        foreach ($c in $conn) { [void]$targets.Add($c) }
    }

    $names = New-Object System.Collections.ArrayList
    $rest = [regex]::Replace($SqlVisible, $dropDbRx, ' ', 'IgnoreCase')
    if ($rest.Trim() -ne '' -and (Test-DestructiveSql $rest)) {
        if ($conn.Count -eq 0) { return $null }
        foreach ($c in $conn) { [void]$names.Add($c) }
    }
    foreach ($t in $targets) { [void]$names.Add($t) }
    if ($names.Count -eq 0) { return $null }
    foreach ($n in $names) {
        if ([string]::IsNullOrWhiteSpace([string]$n) -or [string]$n -match '[\$%`{}()*?\s]') { return $null }
    }
    return ,@($names)
}

# Vzor `databases` je glob (`*`, `?`) ukotveny na cele jmeno, bez ohledu na velikost pismen (M14).
function Test-DbNamesAllowed($Names, $Patterns) {
    foreach ($n in @($Names)) {
        $ok = $false
        foreach ($pat in @($Patterns)) {
            $rx = '^' + ([regex]::Escape([string]$pat)).Replace('\*', '.*').Replace('\?', '.') + '$'
            if ([regex]::IsMatch([string]$n, $rx, 'IgnoreCase')) { $ok = $true; break }
        }
        if (-not $ok) { return $false }
    }
    return $true
}

function Get-ShortFlagLetter($Tokens) {
    # Vraci pismena kratkych prepinacu case-SENSITIVNE (-fdX -> f, d, X).
    # Case-insensitive porovnani by neodlisilo `git clean -X` od `-x`.
    # POZOR: parametr se NESMI jmenovat $Args - to je automaticka promenna a splatting
    # by sem tise poslal prazdny seznam (pouceni "jmeno, ktere si prostredi drzi").
    $letters = New-Object System.Collections.ArrayList
    foreach ($a in $Tokens) {
        # Strop 4 pismen odlisuje POSIX skupinu kratkych prepinacu (-rf, -fdX) od
        # dlouheho PowerShelloveho parametru s JEDNIM pomlckou (-LiteralPath, -Force).
        # Bez nej by `-LiteralPath` propujcilo pismeno `r` a Remove-Item bez -Recurse
        # by se cetl jako rekurzivni.
        if ($a -cmatch '^-[A-Za-z]{1,4}$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) { [void]$letters.Add([string]$ch) }
        }
    }
    return ,@($letters)
}

function Test-GitPushRule($Leaf, $Config) {
    if ($Leaf.Exe -ne 'git') { return $null }
    if ($Leaf.Args.Count -eq 0 -or $Leaf.Args[0] -ne 'push') { return $null }

    $protected = @(Get-Field (Get-Field $Config 'gate') 'protectedBranches' @('main'))
    $shapes = Get-Field (Get-Field $Config 'gate') 'shapes'

    $force = $false
    $mirror = $false
    $positional = New-Object System.Collections.ArrayList
    foreach ($a in (Get-RestTokens $Leaf.Args)) {
        if ($a -match '^--force(-with-lease|-if-includes)?(=.*)?$') { $force = $true; continue }
        # Nalez Metis 14: --mirror force-updatuje zmenene reference a MAZE chybejici,
        # tedy dela oboji, co deny zakazuje - jen se to jinak jmenuje.
        if ($a -eq '--mirror') { $mirror = $true; continue }
        if ($a -cmatch '^-[A-Za-z]*f[A-Za-z]*$') { $force = $true; continue }
        if ($a.StartsWith('-')) { continue }
        [void]$positional.Add($a)
    }
    if ($mirror) {
        return @{ Id = 'forcePushProtected'; Decision = 'deny'; Shape = (Get-Field $shapes 'forcePushProtected' 'force push') }
    }

    # prvni pozicni token je remote, zbytek jsou refspecy
    $refspecs = @()
    if ($positional.Count -gt 1) { $refspecs = @($positional[1..($positional.Count - 1)]) }

    $hitsProtected = $false
    $plusForce = $false
    $deletesRef = $false
    $wildcardTarget = $false
    foreach ($r in $refspecs) {
        $spec = $r
        if ($spec.StartsWith('+')) { $plusForce = $true; $spec = $spec.Substring(1) }
        # Nalez Metis 3: `git push origin :main` je smazani vzdalene vetve - prazdny
        # zdroj refspecu. Zadny prepinac u toho neni, takze pravidlo o force ho minulo.
        if ($spec.StartsWith(':')) { $deletesRef = $true }
        $target = $spec
        $colon = $spec.LastIndexOf(':')
        if ($colon -ge 0) { $target = $spec.Substring($colon + 1) }
        $target = $target -replace '^refs/heads/', ''
        # Nalez Metis 15: `+refs/heads/*:refs/heads/*` cil `*` chranenou vetev OBSAHUJE.
        if ($target -match '[\*\?]') { $wildcardTarget = $true }
        foreach ($p in $protected) {
            if ($target.ToLowerInvariant() -eq ([string]$p).ToLowerInvariant()) { $hitsProtected = $true }
        }
    }

    if ($deletesRef) {
        return @{ Id = 'pushDeleteRefspec'; Decision = 'deny'; Shape = (Get-Field $shapes 'pushDeleteRefspec' 'git push :vetev') }
    }
    if ($wildcardTarget -and ($plusForce -or $force)) {
        return @{ Id = 'forcePushProtected'; Decision = 'deny'; Shape = (Get-Field $shapes 'forcePushProtected' 'force push') }
    }

    if ($plusForce -and $hitsProtected) {
        return @{ Id = 'forcePushProtected'; Decision = 'deny'; Shape = (Get-Field $shapes 'forcePushProtected' 'force push') }
    }
    if (-not $force) { return $null }
    if ($hitsProtected) {
        return @{ Id = 'forcePushProtected'; Decision = 'deny'; Shape = (Get-Field $shapes 'forcePushProtected' 'force push') }
    }
    # ZOPT-Q102 / A179-O3 (Q1, Q2): bez cile muze force push mirit na main -> deny; na nechranenou vetev -> audit.
    $gate = Get-Field $Config 'gate'
    if ($refspecs.Count -eq 0) {
        return (New-PolicyVerdict $gate 'forcePushUnknown' ([string](Get-Field $shapes 'forcePushUnknown' 'force push')))
    }
    return (New-PolicyVerdict $gate 'forcePushOther' ([string](Get-Field $shapes 'forcePushOther' 'force push')))
}

function Test-GitCleanRule($Leaf, $Config) {
    if ($Leaf.Exe -ne 'git') { return $null }
    if ($Leaf.Args.Count -eq 0 -or $Leaf.Args[0] -ne 'clean') { return $null }

    $shapes = Get-Field (Get-Field $Config 'gate') 'shapes'
    $rest = Get-RestTokens $Leaf.Args
    $letters = Get-ShortFlagLetter $rest
    $long = @($rest | Where-Object { $_.StartsWith('--') })

    if (($letters -contains 'n') -or ($long -contains '--dry-run')) { return $null }
    $force = ($letters -contains 'f') -or ($long -contains '--force')
    # Nalez Metis 26: `git -c clean.requireForce=false clean -dx` vypne pozadavek na -f
    # v samotnem gitu. Bez teto vetve by pravidlo videlo "neni -f" a pustilo mazani.
    foreach ($cfg in $Leaf.GitConfig) {
        if ($cfg -match '(?i)^clean\.requireforce\s*=\s*(false|0|no)$') { $force = $true }
    }
    if (-not $force) { return $null }

    # -ccontains, ne -contains: `-contains` je case-INSENSITIVE a neodlisil by
    # `git clean -X` (jen ignorovane, legitimni uklid) od `-x` (i neverzovane).
    # Rozhodnuti Toma 2026-09-07/T36-F1 T-10 A: `git clean -fdX` (jen IGNOROVANE soubory,
    # tedy uklid buildu) je bezna prace a konci ALLOW. `-x` (i neverzovane) zustava deny -
    # rozdil je case-SENSITIVNI a drzi ho `-ccontains`.
    if (($letters -ccontains 'X') -and -not ($letters -ccontains 'x')) {
        return $null
    }
    return @{ Id = 'gitClean'; Decision = 'deny'; Shape = (Get-Field $shapes 'gitClean' 'git clean -f') }
}

$script:RecursiveShortExe = @('rm')
$script:PsRemoveExe       = @('remove-item', 'ri', 'rm', 'rmdir', 'rd', 'del', 'erase', 'rimraf')

function Test-RecursiveDeleteRule($Leaf, $Config) {
    $gate = Get-Field $Config 'gate'
    $shapes = Get-Field $gate 'shapes'
    $allowedRoots = @(Get-Field $gate 'allowedRemoveRoots' @())

    $targets = New-Object System.Collections.ArrayList
    $recursive = $false

    # .NET volani nejsou argv-tvaru, hledaji se regexem nad surovym textem
    $netMatches = [regex]::Matches($Leaf.Raw, $script:NetDeleteTargetPattern, 'IgnoreCase')
    foreach ($m in $netMatches) { $recursive = $true; [void]$targets.Add($m.Groups[1].Value) }

    # Nalez Amber A1: `[IO.Directory]::Delete($p, $true)` - cil je PROMENNA, regex nad
    # literalem v uvozovkach ji nenajde a bez teto vetve by cely tvar skoncil jako
    # allow. Zadani par. 2.3: obal s promennou -> ask. Cil nezname, tak se pta.
    # ZOPT-Q102 / A179-O3 (Q4): cil nejde dolozit -> politika `netDeleteVariable` (vychozi deny).
    if ($Leaf.Exe -eq 'net-delete' -and $targets.Count -eq 0) {
        return (New-PolicyVerdict $gate 'netDeleteVariable' (([string](Get-Field $shapes 'netDeleteVariable' 'mazani .NET volanim s promennou v ceste ({text})')).Replace('{text}', [string]($Leaf.Text))))
    }

    if (-not $recursive) {
        if ($script:PsRemoveExe -notcontains $Leaf.Exe) { return $null }

        $rest = $Leaf.Args
        # Nalez Metis 1: rimraf JE rekurzivni sam o sobe, zadny prepinac k tomu nepotrebuje.
        if ($Leaf.Exe -eq 'rimraf') { $recursive = $true }
        $letters = Get-ShortFlagLetter $rest
        if (($letters -contains 'r') -or ($letters -contains 'R')) { $recursive = $true }
        foreach ($a in $rest) {
            if ($a -match '^--recursive$') { $recursive = $true }
            if ($a -match '^-r(e|ec|ecu|ecur|ecurs|ecurse)?$') { $recursive = $true }
            if ($a -match '^/s$') { $recursive = $true }
        }
        $shortAbsolute = New-Object System.Collections.ArrayList
        foreach ($a in $rest) {
            if ($a.StartsWith('-')) { continue }
            # cmd prepinac je /s /q /f - ale /etc/x je ABSOLUTNI CESTA, ne prepinac.
            # `/srv` (do tri pismen) je od prepinace k nerozeznani - cil se NEBERE, ale
            # pamatuje se, ze tu byl (TASK-106 bod 4).
            if ($a -match '^/[a-zA-Z]{1,3}$') { [void]$shortAbsolute.Add($a); continue }
            [void]$targets.Add($a)
        }

        # Nalez Amber I6 (TASK-106 bod 4, 0.2.0): `rm -rf /srv` konci ask, ale do 0.1.11
        # nesl duvod "mazani se vstupem z roury" - hlaska lhala o pricine. Skutecna pricina
        # je kratka absolutni cesta, kterou od prepinace `cmd` nejde odlisit, a tak cil neni
        # videt. Rozhodnuti `ask` se nemeni, meni se veta; tvar `deleteFromPipeline` zustava
        # tomu, co roura opravdu je (kontrolni skupina: Metis 8).
        if ($targets.Count -eq 0 -and $shortAbsolute.Count -gt 0) {
            return (New-PolicyVerdict $gate 'shortAbsolutePath' (([string](Get-Field $shapes 'shortAbsolutePath' 'mazani s kratkou absolutni cestou ({target})')).Replace('{target}', [string]([string]$shortAbsolute[0]))))
        }

        # Nalez Metis 8: `Get-ChildItem src -Recurse -File | Remove-Item -Force` -
        # rekurzi dela PRVNI clanek roury, mazani druhy, a kazdy sam o sobe projde.
        # Mazaci prikaz BEZ pozicniho cile bere vstup z roury, takze rozsah nezname:
        # plati Z3 (nerozebratelne -> ask). Mazani konkretniho souboru bez -Recurse
        # zustava bezna prace (`Remove-Item -LiteralPath x -Force` ve skriptech GSD).
        if ($targets.Count -eq 0) {
            return (New-PolicyVerdict $gate 'deleteFromPipeline' ([string](Get-Field $shapes 'deleteFromPipeline' 'mazani z roury')))
        }
        if (-not $recursive) { return $null }
    }

    if ($targets.Count -eq 0) { return $null }

    $cwdNorm = ConvertTo-NormalPath $script:Cwd
    $homeNorm = ConvertTo-NormalPath ([Environment]::GetFolderPath('UserProfile'))
    $worst = $null

    foreach ($t in $targets) {
        $hasVar = ($t -match '[\$%]')
        $hasStar = ($t -match '[\*\?]')
        $hasDotDot = ($t -match '\.\.')

        $norm = ConvertTo-NormalPath $t
        $isAbsolute = ($norm -match '^[a-z]:/' ) -or $norm.StartsWith('/')

        $rel = $norm
        if ($isAbsolute) {
            $bare = ($norm -replace '[\*\?]', '').TrimEnd('/')
            if ($bare -eq '' -or $bare -match '^[a-z]:$' -or $bare -eq $homeNorm) {
                return @{ Id = 'recursiveDelete'; Decision = 'deny'
                          Shape = (([string](Get-Field $shapes 'recursiveDelete' 'rm -rf {target}')).Replace('{target}', [string]($t))) }
            }
            if ($norm.StartsWith($cwdNorm + '/')) {
                $rel = $norm.Substring($cwdNorm.Length + 1)
            } else {
                return @{ Id = 'recursiveDelete'; Decision = 'deny'
                          Shape = (([string](Get-Field $shapes 'recursiveDelete' 'rm -rf {target}')).Replace('{target}', [string]($t))) }
            }
        }

        $rel = $rel -replace '^\./', ''
        $first = $rel
        $slash = $rel.IndexOf('/')
        if ($slash -ge 0) { $first = $rel.Substring(0, $slash) }

        $allowed = $false
        foreach ($root in $allowedRoots) {
            if ($first -eq ([string]$root).ToLowerInvariant()) { $allowed = $true }
        }

        # ZOPT-Q102 / A179-O3 (Q4): promenna v cili (mimo povoleny koren i v nem) a `..` = cil nejde dolozit -> politika
        # `recursiveDeleteVariable` / `recursiveDeleteDotDot` (vychozi deny); hvezdicka UVNITR povoleneho korene -> `recursiveDeleteWildcard`
        # (vychozi audit). Deny kterehokoli cile rozhoduje hned, audit se drzi jako nejhorsi dosavadni.
        $v = $null
        if (-not $allowed) {
            if (-not $hasVar) {
                return @{ Id = 'recursiveDelete'; Decision = 'deny'
                          Shape = (([string](Get-Field $shapes 'recursiveDelete' 'rm -rf {target}')).Replace('{target}', [string]($t))) }
            }
            $v = New-PolicyVerdict $gate 'recursiveDeleteVariable' (([string](Get-Field $shapes 'recursiveDeleteVariable' 'rm -rf {target}')).Replace('{target}', [string]($t)))
        } elseif ($hasVar) {
            $v = New-PolicyVerdict $gate 'recursiveDeleteVariable' (([string](Get-Field $shapes 'recursiveDeleteVariable' 'rm -rf {target}')).Replace('{target}', [string]($t)))
        } elseif ($hasDotDot) {
            $v = New-PolicyVerdict $gate 'recursiveDeleteDotDot' (([string](Get-Field $shapes 'recursiveDeleteDotDot' 'rm -rf {target}')).Replace('{target}', [string]($t)))
        } elseif ($hasStar) {
            $v = New-PolicyVerdict $gate 'recursiveDeleteWildcard' (([string](Get-Field $shapes 'recursiveDeleteWildcard' 'rm -rf {target}')).Replace('{target}', [string]($t)))
        }
        if ($null -eq $v) { continue }
        if ($v.Decision -eq 'deny') { return $v }
        if ($null -eq $worst) { $worst = $v }
    }
    return $worst
}

# Rozhodnuti Toma 2026-09-05/T36-F1 T-1: `DELETE FROM` bez `WHERE` ma stejny dopad
# jako TRUNCATE (nalez Metis 9), takze patri mezi hlidane tvary. S `WHERE` je to
# bezna prace a musi projit - proto se dotaz deli po strednicich a `WHERE` se hleda
# v TOM statementu, ne kdekoli v textu.
function Test-DeleteWithoutWhere([string]$Sql) {
    if ([string]::IsNullOrWhiteSpace($Sql)) { return $false }
    foreach ($stmt in [regex]::Split($Sql, ';')) {
        if (-not [regex]::IsMatch($stmt, '\bdelete(?:\s|/\*.*?\*/)+from\b', 'IgnoreCase')) { continue }
        if (-not [regex]::IsMatch($stmt, '\bwhere\b', 'IgnoreCase')) { return $true }
    }
    return $false
}

# Nalez Ada N22 (rozsireni rozsahu rozhodl Tom 2026-09-06/T36-F1 T-9 A): `UPDATE ... SET`
# bez `WHERE` prepise KAZDY radek tabulky - tedy tyz dopad jako `DELETE FROM` bez `WHERE`
# a jako TRUNCATE. `WHERE` se hleda v TOMTEZ statementu, ne kdekoli v textu; jinak by
# jeden neskodny `WHERE` v davce omluvil vsechny ostatni prikazy.
function Test-UpdateWithoutWhere([string]$Sql) {
    if ([string]::IsNullOrWhiteSpace($Sql)) { return $false }
    foreach ($stmt in [regex]::Split($Sql, ';')) {
        # Nalez Ada N25: `\S+` je JEDEN token, takze vzor minul `UPDATE ONLY t SET ...`
        # i `UPDATE t AS x SET ...` - oboji je platny SQL a oboji prepise cely obsah.
        if (-not [regex]::IsMatch($stmt, '\bupdate\s+(?:only\s+)?\S+(?:\s+as\s+\S+)?\s+set\b', 'IgnoreCase')) { continue }
        if (-not [regex]::IsMatch($stmt, '\bwhere\b', 'IgnoreCase')) { return $true }
    }
    return $false
}

# Destruktivni mnozina SQL pravidla (AOPT-O24 = mnozina Test-DatabaseRule na 245a0fe): DROP TABLE|DATABASE|SCHEMA, TRUNCATE,
# DELETE a UPDATE bez WHERE. Od 0.3.1 jedna funkce - vola ji Test-DatabaseRule i Test-ContainerLeaf (TASK-179).
# `(?:\s|/\*.*?\*/)+` misto `\s+`: nalez Metis 17 - SQL bere blokovy komentar jako bily znak. Od 0.3.1 jedna promenna
# pro Test-DestructiveSql, Test-DbDestructiveText i Test-DatabaseRule (CR-8 kola 1 /code-review).
$script:SqlGap = '(?:\s|/\*.*?\*/)+'
function Test-DestructiveSql([string]$Sql) {
    if ([string]::IsNullOrWhiteSpace($Sql)) { return $false }
    return ([regex]::IsMatch($Sql, ('\bdrop' + $script:SqlGap + '(table|database|schema)\b'), 'IgnoreCase')) -or
           ([regex]::IsMatch($Sql, '\btruncate\b', 'IgnoreCase')) -or
           (Test-DeleteWithoutWhere $Sql) -or
           (Test-UpdateWithoutWhere $Sql)
}

# TASK-179 (clen tridy M-d): text uvnitr kontejneru, ktery nejde rozebrat (promenna v hlave `sh -c "$PSQL -c '...'"`),
# ale destruktivni DB literal v nem VIDET JE. Na hostiteli by takovy tvar skoncil `invoked` = ask; uvnitr kontejneru
# plati jen DB pravidlo (AOPT-O25), takze se pta jen tehdy, kdyz text nese celou destruktivni DB mnozinu - SQL i jmena
# programu (`dropdb`, `dotnet ef database drop`, `sqllocaldb delete`).
function Test-DbDestructiveText([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    # CR-7 (kolo 1 /code-review): prikaz coreutils `truncate -s 0 log` neni SQL - tady jde o text SHELLU, ne o SQL z klienta,
    # takze se jeho volani s prepinacem (kratkym nebo dlouhym z man truncate) vyjme. SQL `TRUNCATE -- komentar` zustava.
    $Text = [regex]::Replace($Text, '(?i)\btruncate(?=\s+(?:-[a-z]|--(?:size|reference|no-create|io-blocks)\b))', ' ')
    # K4-7 (kolo 4): souborove API (`os.truncate(...)`, `f.truncate()`) neni SQL - SQL TRUNCATE nikdy nestoji pred zavorkou.
    $Text = [regex]::Replace($Text, '(?i)\btruncate(?=\s*\()', ' ')
    if (Test-DestructiveSql $Text) { return $true }
    if ([regex]::IsMatch($Text, '(?:^|[\s;|&(''"/\\])dropdb(?:\.exe)?(?:\s|$|[''";|&)])', 'IgnoreCase')) { return $true }
    if ([regex]::IsMatch($Text, ('\bdotnet[- ]ef' + $script:SqlGap + 'database' + $script:SqlGap + 'drop\b'), 'IgnoreCase')) { return $true }
    if ([regex]::IsMatch($Text, '\bsqllocaldb(?:\.exe)?\s+(?:delete|d)\b', 'IgnoreCase')) { return $true }
    return $false
}

# Nalez Ada N20: je v prikazu presmerovani stdin s NELITERALNIM operandem?
#
# !! Regexem to nejde: `psql -c "SELECT * FROM t WHERE a < 5"` ma `<` UVNITR retezce
# a vzor nad surovym textem by z bezneho dotazu udelal falesny ask. Rozhoduje se proto
# nad znaky mimo uvozovky, tymz zpusobem jako skener - vcetne escapu podle shellu.
#
# Operand v uvozovkach ($true se nevraci) je LITERAL: ten uz vyzobne kontrola uvozovek
# v Get-SqlText a cte se jako SQL. Nelliteralni operand (soubor, promenna) videt neni,
# takze plati Z3 -> ask.
function Test-StdinRedirect([string]$Text) {
    $t = [string]$Text
    if ($t -eq '') { return $false }
    $esc = Get-ScannerEscape
    $inSingle = $false
    $inDouble = $false
    $i = 0
    $n = $t.Length
    while ($i -lt $n) {
        $c = $t[$i]
        if ($inSingle) { if ($c -eq "'") { $inSingle = $false }; $i++; continue }
        if ($c -eq $esc -and ($i + 1) -lt $n) { $i += 2; continue }
        if ($c -eq '"') { $inDouble = -not $inDouble; $i++; continue }
        if ($inDouble) { $i++; continue }
        if ($c -eq "'") { $inSingle = $true; $i++; continue }
        if ($c -eq '<') {
            # Heredoc (`<<SLOVO`) sem nepatri - ten resi Split-Heredoc. Rozliseni je
            # v tom, ze `<<<` je here-string, kdezto `<<` uvozuje telo.
            $j = $i
            while ($j -lt $n -and $t[$j] -eq '<') { $j++ }
            $count = $j - $i
            if ($count -eq 2) { $i = $j; continue }
            while ($j -lt $n -and $t[$j] -eq ' ') { $j++ }
            if ($j -ge $n) { return $false }
            if ($t[$j] -eq '"' -or $t[$j] -eq "'") { $i = $j; continue }
            return $true
        }
        $i++
    }
    return $false
}

# Text, ktery je SKUTECNE SQL - ne cely prikaz.
#
# Nalez Amber B4: vzory bezely nad surovym textem vcetne retezcu, takze
# `git commit -m "Add DROP TABLE migration"`, `grep -r "DROP TABLE" src`,
# `[Math]::Truncate($x)` i `truncate -s 0 x.log` koncily ask. To je falesny blok
# na bezne praci a takova brana se do tydne vypne.
#
# SQL se proto cte jen odtud:
#   - telo heredocu, jehoz UVOZUJICI prikaz je SQL klient (a4),
#   - hodnoty -c / --command u SQL klienta,
#   - retezce v uvozovkach u SQL klienta.
# `dropdb` a `dotnet ef` zustavaji vazane na JMENO nastroje, ne na text.
function Get-SqlText($Leaf, $SqlClients) {
    $kind = [string](Get-LeafField $Leaf 'Kind' '')
    if ($kind -eq 'heredoc') {
        $outerExe = [string](Get-LeafField $Leaf 'OuterExe' '')
        if ($SqlClients -ccontains $outerExe.ToLowerInvariant()) { return [string]$Leaf.Raw }
        return ''
    }

    $exe = [string](Get-LeafField $Leaf 'Exe' '')
    if (-not ($SqlClients -ccontains $exe.ToLowerInvariant())) { return '' }

    $parts = New-Object System.Collections.ArrayList
    $args2 = @(Get-LeafField $Leaf 'Args' @())
    for ($i = 0; $i -lt $args2.Count; $i++) {
        # `-Q`/`-q` je sqlcmd, `-c`/`--command` psql (nalez Amber C4).
        if ($args2[$i] -cmatch '^(-c|--command|-Q|-q)$' -and ($i + 1) -lt $args2.Count) {
            [void]$parts.Add([string]$args2[$i + 1]); $i++
            continue
        }
        if ($args2[$i] -match '^--command=(.*)$') { [void]$parts.Add($Matches[1]) }
        # `-f x.sql` (psql) a `-i x.sql` (sqlcmd) davaji SQL ze SOUBORU - obsah v prikazu
        # videt neni, takze plati Z3. Signalizuje se zvlastnim tokenem, ktery Test-DatabaseRule
        # cte jako "neznamy rozsah".
        # CR-R3 (/code-review 0.3.1, kolo 2): i `--file=x`, `--file x`, slepene `-fx.sql` / `-ix.sql`, skupina `-Xf x`
        # a `--input-file`. CR-R4: jen u klienta, kde prepinac SQL soubor znamena - u `dropdb` je `-f` --force
        # a `-i` --interactive (`dropdb -f gsd_test_1` je bezne ruseni testovaci DB).
        $exeL = $exe.ToLowerInvariant()
        $fileFlag = $null
        # CR-S7 (kolo 3): ve skupine jen volby psql BEZ hodnoty pred `f` - `-Ufred`, `-dfoo_test`, `-hfoo` soubor nejsou.
        if (@('psql', 'pgcli') -ccontains $exeL) { $fileFlag = '^(-[aAbeEHlnqsStxXz01wW]*f|--file(=|$))' }
        elseif ($exeL -eq 'sqlcmd') { $fileFlag = '^(-i|--input-file(=|$))' }
        elseif ($exeL -ne 'dropdb') { $fileFlag = '^(-f|-i)$' }
        if ($null -ne $fileFlag -and $args2[$i] -cmatch $fileFlag) {
            [void]$parts.Add('__SQL_ZE_SOUBORU__')
            if ($args2[$i] -cmatch '^(-[aAbeEHlnqsStxXz01wW]*f|-i|--file|--input-file)$' -and ($i + 1) -lt $args2.Count) { $i++ }
        }
    }

    # Nalez Ada N20: SQL se do klienta dostane i PRESMEROVANIM stdin, ne jen prepinacem.
    #   psql -h prod < drop.sql     obsah souboru v prikazu videt neni -> Z3, ask
    #   psql -h prod <<< $SQL       obsah promenne taky ne          -> Z3, ask
    #   psql -h prod <<< "DROP ..." literal JE videt                -> cte se jako SQL
    # Literal za `<<<` chytnou uz uvozovky nize; tady se resi jen ten NElliteralni tvar,
    # jinak by `<` u kazdeho dotazu vyrobilo falesny ask.
    if (Test-StdinRedirect ([string]$Leaf.Raw)) { [void]$parts.Add('__SQL_ZE_SOUBORU__') }
    foreach ($m in [regex]::Matches([string]$Leaf.Raw, '"([^"]*)"|''([^'']*)''')) {
        foreach ($g in 1, 2) { if ($m.Groups[$g].Success) { [void]$parts.Add($m.Groups[$g].Value) } }
    }
    return ($parts -join ' ; ')
}

# `git checkout .` / `git restore .` = navrat pracovniho stromu, tedy ztrata prace.
#
# Nalez Amber E3: driv to byly dva regexy nad textem a byly UZSI nez puvodni vzor -
# `git restore -s HEAD .`, `-W .`, `-q .` ani `git checkout -q HEAD -- .` nechytily.
# Regex to ani chytit nemuze: `-s` bere HODNOTU, takze `HEAD` neni prepinac a vzor
# `(-\S*\s+)*` se o nej zastavi. Rozhoduje se proto nad TOKENY, ne nad textem.
# Miri pathspec na CELY strom? Nalez Amber G7: vyjmenovane cile `. ./ .\ *` minuly
# tvary, ktere git chape stejne - `:/` je koren repozitare, `:(top)` je magicky
# pathspec s tymz vyznamem a `./*` je obycejny glob. Vsechny propadaly na allow.
function Test-WholeTreeTarget([string]$Token) {
    $t = ([string]$Token).Trim().Trim('"').Trim("'")
    if ($t -eq '') { return $false }
    if (@('.', './', '.\', '*', './*', '.\*', '**', '**/*', ':/', ':/*') -contains $t) { return $true }
    # `:/neco` je cesta od korene repozitare; `:(top)`, `:(exclude)x` jsou magicke
    # pathspecy, ktere zabiraji cely strom (pripadne cely strom krome neceho).
    if ($t.StartsWith(':/') -or $t.StartsWith(':(')) { return $true }
    return $false
}

function Test-GitRestoreRule($Leaf, $Config) {
    if ($Leaf.Exe -ne 'git') { return $null }
    $gate = Get-Field $Config 'gate'
    $shapes = Get-Field $gate 'shapes'

    $rest = @(Get-LeafField $Leaf 'Args' @())
    if ($rest.Count -eq 0) { return $null }
    $sub = [string]$rest[0]
    if ($sub -ne 'checkout' -and $sub -ne 'restore') { return $null }

    $valueFlags = '^(-s|--source|--pathspec-from-file|-b|-B|--orphan)$'

    $positional = New-Object System.Collections.ArrayList
    $hasStaged = $false
    $hasWorktree = $false
    $createsBranch = $false

    for ($i = 1; $i -lt $rest.Count; $i++) {
        $t = [string]$rest[$i]
        if ($t -eq '--') { continue }
        if ($t -cmatch '^(--staged|-S)$') { $hasStaged = $true; continue }
        if ($t -cmatch '^(--worktree|-W)$') { $hasWorktree = $true; continue }
        if ($t -cmatch '^(-b|-B|--orphan)$') { $createsBranch = $true; $i++; continue }
        if ($t -match '^--[A-Za-z-]+=') { continue }        # `--source=HEAD` je jeden token
        if ($t -cmatch $valueFlags) { $i++; continue }       # prepinac s hodnotou
        if ($t -match '^-') { continue }                     # prepinac bez hodnoty
        [void]$positional.Add($t)
    }

    # Zakladani vetve neni navrat stromu.
    if ($createsBranch) { return $null }
    # Odstagovani NENI ztrata prace - ztrata je az se stromem (nalez Amber C2).
    if ($sub -eq 'restore' -and $hasStaged -and -not $hasWorktree) { return $null }

    foreach ($p in $positional) {
        if (Test-WholeTreeTarget $p) {
            $shapeKey = if ($sub -eq 'checkout') { 'gitCheckoutDot' } else { 'gitRestoreDot' }
            return @{ Id = $shapeKey; Decision = 'deny'
                      Shape = (Get-Field $shapes $shapeKey ('git ' + $sub + ' .')) }
        }
    }
    return $null
}

function Test-DatabaseRule($Leaf, $Config) {
    $gate = Get-Field $Config 'gate'
    $shapes = Get-Field $gate 'shapes'
    $localHosts = @(Get-Field $gate 'localDbHosts' @('localhost', '127.0.0.1', '::1'))
    $sqlClients = @(Get-Field $gate 'sqlClients' @('psql', 'pgcli', 'dropdb'))
    $raw = $Leaf.Raw

    # Hostitel se cte i z UVOZUJICIHO prikazu - u tela heredocu stoji jen tam (A4).
    # TASK-179: u vnitrniho prikazu kontejneru i z promennych prostredi, ktere mu obal predava (`-e PGHOST=...`, AOPT-O26).
    $hostText = [string]$raw + ' ' + [string](Get-LeafField $Leaf 'Outer' '') + ' ' + [string](Get-LeafField $Leaf 'ContainerEnv' '')

    $sql = Get-SqlText $Leaf $sqlClients

    # `(?:\s|/\*.*?\*/)+` misto `\s+`: nalez Metis 17 - SQL bere blokovy komentar jako
    # bily znak, takze `DROP/**/TABLE` je platny prikaz, ktery `\s+` nikdy nepotka.
    # `dotnet[- ]ef`: nalez Metis 10 - primo nainstalovany nastroj se jmenuje `dotnet-ef`.
    $gap = $script:SqlGap

    # !! Nalez Ada N28 (0.1.11): marker "SQL ze souboru" je PRIZNAK, ne text SQL.
    # Get-SqlText ho pridava VEDLE viditelneho SQL z `-c`/uvozovek, takze do 0.1.10
    # stacilo k libovolnemu destruktivnimu `-c` prilepit `< /dev/null` nebo `-f x.sql`
    # a vetev markeru rozhodla driv, nez se na viditelny text kdokoli podival:
    #   psql -h prod -c "DROP TABLE x" < /dev/null  ma byt deny, bylo allow + audit
    #   psql -h prod -f m.sql -c "DROP TABLE x"     ma byt deny, bylo allow + audit
    # Do 0.1.8 prednost markeru degradovala deny jen na ask, takze si toho nikdo nevsiml;
    # T-10 z ni udelala allow. Trida: VYJIMKA VYHODNOCENA PRED PRAVIDLEM JE BYPASS -
    # tataz, kterou plugin sam zapsal u `cmd /c` a u bloku s ocasem.
    #
    # Oprava je PORADI, ne nove pravidlo: marker se z textu odstrani, destruktivnost se
    # pocita nad tim, co je VIDET, a audit se uplatni az kdyz nic viditelneho nestrili.
    # Hlaska ani tvar u deny se nemeni (host prod x localhost zustava beze zmeny).
    $sqlFromFile = ($sql -match '__SQL_ZE_SOUBORU__')
    $sqlVisible = ($sql -replace '__SQL_ZE_SOUBORU__', ' ').Trim()

    $sqlDestructive = $false
    if ($sqlVisible -ne '') { $sqlDestructive = Test-DestructiveSql $sqlVisible }

    # !! Nalez Amber A-1 (kolo 1 nad 01afb82): prvni oprava N28 zavrela bypass jen pro
    # SQL v TEXTU. Destruktivnost ale nese jeste DVA zdroje, ktere s textem nemaji nic
    # spolecneho - jmeno spustitelneho souboru (`dropdb`) a `dotnet ef database drop`.
    # `dropdb` je pritom v `sqlClients`, takze mu `Get-SqlText` marker taky prida:
    #   dropdb -h prod mydb < /dev/null   melo byt deny, bylo allow + audit
    #   dropdb -h prod mydb -f x.sql      melo byt deny, bylo allow + audit
    # Tataz trida jako N28, o jeden radek niz. Duvod je stejny: podminka auditu se
    # ptala na UZSI vec (`$sqlDestructive`), nez na kterou se pta pravidlo (`$destructive`).
    # Proto se `$destructive` i `$update` pocitaji PRED auditem a audit se uplatni az
    # tehdy, kdyz nestrili ANI JEDEN z nich.
    # (`dotnet ef` v `sqlClients` neni, takze marker nikdy nedostane - overeno mericim
    # behem; je tu pro uplnost podminky, ne kvuli znamemu tvaru.)
    # Z117-Q20 = A (Tom 2026-10-08, nalez Amber A117-N4): `sqllocaldb delete <instance>` smaze
    # instanci LocalDB a s ni VSECHNY jeji databaze (MS Learn: "Deleting an instance removes all
    # databases associated with that instance") - do 0.2.0 ticho. Od 0.3.0 `ask` jako `dropdb`;
    # H-f to nikdy nepovoli. `sqllocaldb stop` je beze zmeny (nic nemaze).
    $localDbDelete = $false
    if ([string]$Leaf.Exe -eq 'sqllocaldb') {
        $la = @(Get-LeafField $Leaf 'Args' @())
        if ($la.Count -ge 1 -and ([string]$la[0]) -match '^(delete|d)$') { $localDbDelete = $true }
    }
    $destructive = $sqlDestructive -or $localDbDelete -or
                   ($Leaf.Exe -eq 'dropdb') -or
                   ([regex]::IsMatch($raw, ('\bdotnet[- ]ef' + $gap + 'database' + $gap + 'drop\b'), 'IgnoreCase'))

    $update = [regex]::IsMatch($raw, ('\bdotnet[- ]ef' + $gap + 'database' + $gap + 'update\b'), 'IgnoreCase')

    # SQL prislo ze souboru nebo z roury - obsah nevidime, rozsah nezname (Z3).
    # T-10 A: `psql -f migrace.sql`, `psql < drop.sql`, `psql <<< $SQL` je bezna prace,
    # takze audit misto brany. Az TADY, po rozhodnuti o vsem, co videt JE (N28 + A-1).
    if ($sqlFromFile -and -not $destructive -and -not $update) {
        Write-GateAudit $script:ToolName 'sqlFromFile' 'allow' $Config
        return $null
    }

    if (-not $destructive -and -not $update) { return $null }

    # U tela heredocu i roury je nastrojem uvozujici prikaz, ne 'heredoc'.
    $hostExe = [string](Get-LeafField $Leaf 'OuterExe' '')
    if ($hostExe -eq '') { $hostExe = [string](Get-LeafField $Leaf 'Exe' '') }
    # Z117-Q16 = A (Tom 2026-10-08, T117-N13): do 0.2.0 rozhodovala PRVNI shoda vzoru kdekoli
    # v textu - `Addr=` / `Address=` / `Network Address=` (synonyma SqlClient) nenasla nic,
    # hostitel vysel prazdny = "lokalni" a `dotnet ef database update` proti vzdalenemu serveru
    # proslo BEZ dotazu; hodnota v uvozovkach (`-S "db.firma.cz"`), slepena (`-Sdb.firma.cz`)
    # a URI bez uzivatele koncily `ask` misto `deny`. Od 0.3.0 se sbiraji VSECHNY hodnoty
    # vsech synonym a rozhoduje nejprisnejsi: kterykoli vzdaleny hostitel = vzdaleny prikaz.
    # CR-P1 (/code-review): Get-DbHosts vraci `,@(...)` - dalsi `@()` by pole zabalil podruhe (N-H10) a vsechny
    # hostitele slil do JEDNOHO retezce, takze dva mistni hostitele vysli jako jeden vzdaleny.
    $dbHosts = Get-DbHosts $hostText $hostExe.ToLowerInvariant()
    $dbHost = ''
    $isLocal = $true
    foreach ($h in $dbHosts) {
        if (-not (Test-LocalHost $h $localHosts)) { $dbHost = $h; $isLocal = $false; break }
    }

    if ($destructive) {
        if (-not $isLocal) {
            return @{ Id = 'dbDestroyRemote'; Decision = 'deny'
                      Shape = (([string](Get-Field $shapes 'dbDestroyRemote' 'DB {host}')).Replace('{host}', [string]($dbHost))) }
        }
        # H-f (Z117-Q13 = A) + ZOPT-Q102 / A179-O3 (Q10), 0.3.1: rozhodnuti o LOKALNI destruktivni operaci nese
        # `gate.dbDestroyLocal` - `deny` zakaze vse, vychozi `allow` pusti jen databaze ve vzorech `databases`
        # (Get-DbTargetNames); cokoli jineho je deny. Obsah prepisu uz zkontrolovalo H-c (neplatny klic = vychozi hodnota).
        $dl = Get-Field $gate 'dbDestroyLocal'
        if ((Get-DbDestroyLocalDecision $dl) -eq 'deny') { return (New-DbDestroyLocalDenied $shapes) }
        # TASK-179 (AOPT-O26): tvar uvnitr kontejneru nikdy `allow` - ani kdyz jeho vnitrni text je doslova povoleny statement.
        # K3-2 (kolo 3): totez pro tvar v kontejneru, ktery rozbalil starsi pruchod (`docker exec -i c sh <<EOF`) - NoAllow.
        if ([bool](Get-LeafField $Leaf 'Container' $false) -or [bool](Get-LeafField $Leaf 'NoAllow' $false)) {
            return @{ Id = 'dbDestroyContainer'; Decision = 'deny'; Shape = (Get-Field $shapes 'dbDestroyContainer' 'DB') }
        }
        # Z117-Q20 + A179-O3 (Q10): `sqllocaldb delete` smaze instanci se VSEMI databazemi - nikdy allow.
        # CR-Q3 (/code-review 0.3.1): SQL ze souboru nebo stdin (`-f`, `-i`, `<`) vedle viditelneho nevidime - jmeno DB,
        # ke ktere se pripoji (`\c`, `:connect`), nejde precist. CR-Q7 + CR-U: jen jednoduchy prikaz s cistym prostredim
        # (Test-DbAllowContext) - jinak "bez hostitele = mistni" neplati.
        $hostExeL = $hostExe.ToLowerInvariant()
        if (-not $localDbDelete -and -not $sqlFromFile -and -not (Test-AbbreviatedDbOption $Leaf $hostExeL)) {
            $names = Get-DbTargetNames $Leaf $sqlVisible $hostText $hostExeL
            if ($null -ne $names -and (Test-DbNamesAllowed $names @(Get-Field $dl 'databases' @()))) {
                if (Test-DbAllowContext $Leaf $hostExeL) {
                    # "allow" = hook MLCI + radek auditu (bez jmena DB, serveru i textu prikazu) - NE
                    # `permissionDecision: allow`; vrstva opravneni Claude Code rozhoduje dal.
                    Write-GateAudit $script:ToolName 'gate:dbDestroyLocal' 'allow' $Config
                    return $null
                }
                # A179-O7 (Amber 2026-10-21): jmena sedi, ale prikaz neni jednoduchy - hlaska jmenuje povoleny tvar.
                return @{ Id = 'dbDestroyLocalCompound'; Decision = 'deny'
                          Shape = (Get-Field $shapes 'dbDestroyLocalCompound' 'DB') }
            }
        }
        return @{ Id = 'dbDestroyLocal'; Decision = 'deny'; Shape = (Get-Field $shapes 'dbDestroyLocal' 'DB') }
    }

    if ($update -and -not $isLocal) {
        return @{ Id = 'efUpdateRemote'; Decision = 'deny'
                  Shape = (([string](Get-Field $shapes 'efUpdateRemote' 'ef update {host}')).Replace('{host}', [string]($dbHost))) }
    }
    return $null
}

function Test-ConfiguredPattern($Leaf, $Patterns) {
    foreach ($p in $Patterns) {
        $pattern = Get-Field $p 'pattern' ''
        if ($pattern -eq '') { continue }
        if ([regex]::IsMatch($Leaf.Text, $pattern, 'IgnoreCase')) {
            # H-b (TASK-117): ID pravidla jde do auditu, text tvaru do duvodu.
            return @{ Shape = (Get-Field $p 'shape' (Get-Field $p 'id' 'pravidlo')); Id = [string](Get-Field $p 'id' 'pravidlo') }
        }
    }
    return $null
}

# Nalez Ada N24: prepinac s HODNOTOU se pocital jako pozicionalni argument, takze
# `ssh -i key.pem host` vypadalo jako "host + prikaz" -> ask, a v bypassu deny.
# Falesny blok na uplne bezne praci; tabulka je proto stejna jako u obalu
# (Get-WrapperTail) - jediny zpusob, jak se to nerozejde.
$script:SshValueFlags = '^(-p|-i|-o|-l|-F|-J|-L|-R|-D|-b|-c|-e|-m|-w|-E|-I|-Q|-S|-W)$'

function Get-RemoteShellPositional($Argv) {
    $out = New-Object System.Collections.ArrayList
    $i = 0
    while ($i -lt $Argv.Count) {
        $t = [string]$Argv[$i]
        if ($t -cmatch $script:SshValueFlags) { $i += 2; continue }
        if ($t.StartsWith('-')) { $i++; continue }
        [void]$out.Add($t)
        $i++
    }
    return $out
}

# Write-GateAudit zije od 0.2.0 v _common.ps1 - secrets.ps1 audituje taky (TASK-106 bod 11,
# vyrok 7: trida chranena jmenem u globu). Volani tady zustavaji beze zmeny.

# Politika pro nerozebratelny list (rozhodnuti Toma 2026-09-07/T36-O5 = A).
#
# !! `audit` vraci $null, NE `permissionDecision: allow`. Rozdil je cely smysl zmeny:
# `allow` z hooku PRESKOCI vrstvu opravneni Claude Code (klasifikator auto rezimu,
# pravidla `permissions.*`), kdezto ticho ji necha rozhodnout. Plugin timhle prestava
# byt POSLEDNI instanci parseru a stava se prvni - viz README "Tri rozhodnuti, ne dve".
#
# Neznama hodnota politiky konci `deny` (do 0.3.0 `ask`), ne vyjimkou: preklep v projektovem
# override nesmi branu tise otevrit.
# 1C: kod interpretu se nerozebira, ale JMENO destruktivniho volani v nem videt je.
# Je to test na TOKEN, ne parser jazyka - `python -c "print(1)"` musi projit,
# `python -c "shutil.rmtree('x')"` ne. Porovnani je case-SENSITIVNI (`Remove-Item`
# ano, `remove-item` ne bylo by falesne siroke pres bezna anglicka slova).
# K7-5 (TASK-179, kolo 7): samostatna funkce - zavora K6-5 (interpret v kontejneru s DB literalem) se pta nejdriv na ni,
# aby tvar 0.3.0 nesl dal svuj Id `interpreterDestructive`.
# ZOPT-Q102 / A179-O3 (Q6), 0.3.1: DB token (`gate.interpreterDbTokens`) = zniceni databaze, jejiz jmeno nepreteme ->
# politika `interpreterDestructiveDb` (vychozi deny); ostatni tokeny -> `interpreterDestructive` (vychozi audit).
# DB tokeny se zkousi prvni, aby je obecny token tehoz tela (`subprocess`) neprebil auditem.
function Get-InterpreterDestructiveVerdict([string]$Body, $Config) {
    if ($Body -eq '') { return $null }
    $gate = Get-Field $Config 'gate'
    $shapes = Get-Field $gate 'shapes'
    foreach ($t in @(Get-Field $gate 'interpreterDbTokens' @())) {
        $token = [string]$t
        if ($token -eq '') { continue }
        if ($Body.IndexOf($token, [System.StringComparison]::Ordinal) -ge 0) {
            return (New-PolicyVerdict $gate 'interpreterDestructiveDb' (([string](Get-Field $shapes 'interpreterDestructiveDb' 'kod interpretu rusi databazi ({token})')).Replace('{token}', [string]($token))))
        }
    }
    foreach ($t in @(Get-Field $gate 'interpreterDestructiveTokens' @())) {
        $token = [string]$t
        if ($token -eq '') { continue }
        if ($Body.IndexOf($token, [System.StringComparison]::Ordinal) -ge 0) {
            return (New-PolicyVerdict $gate 'interpreterDestructive' (([string](Get-Field $shapes 'interpreterDestructive' 'kod interpretu s destruktivnim volanim ({token})')).Replace('{token}', [string]($token))))
        }
    }
    return $null
}

function Get-RawDestructiveVerdict([string]$Raw, $Config) {
    $gate = Get-Field $Config 'gate'
    $shapes = Get-Field $gate 'shapes'
    foreach ($t in @(Get-Field $gate 'rawDestructiveTokens' @())) {
        $token = [string]$t
        if ($token -eq '') { continue }
        if ($Raw.IndexOf($token, [System.StringComparison]::Ordinal) -ge 0) {
            return (New-PolicyVerdict $gate 'opaqueDestructive' (([string](Get-Field $shapes 'opaqueDestructive' 'nerozebratelny tvar s destruktivnim literalem ({token})')).Replace('{token}', [string]($token))))
        }
    }
    return $null
}

function Resolve-OpaqueDecision([string]$Why, [string]$Raw, [string]$Body, $Config) {
    $gate = Get-Field $Config 'gate'
    $shapes = Get-Field $gate 'shapes'

    if ($Why -eq 'interpreter') {
        $id = Get-InterpreterDestructiveVerdict $Body $Config
        if ($null -ne $id) { return $id }
    }

    # !! Nalez Ada N35 (0.1.11), sourozenec N28: klasifikace PRED pohledem na text.
    # `Where-Object { ... -or (git reset --hard) }`, `$SUDO git reset --hard` (hlava
    # promenna, ocas viditelny) i neukonceny heredoc s destruktivnim telem koncily od
    # 0.1.10 auditem, prestoze destruktivni LITERAL je v nich VIDET. Neni to nutna cena:
    # 1C uz presne tenhle token-test dela nad telem interpretu - tady se dela nad `Raw`.
    #
    # Do 0.3.0 `ask` (kontext nezname); od 0.3.1 politika `gate.decisions.opaqueDestructive` (ZOPT-Q102 / A179-O3 Q5:
    # vychozi deny - literaly jsou jen z deny trid). Porovnani je stejne jako u `interpreterDestructiveTokens` - IndexOf, Ordinal,
    # zadny parser. N50: `DELETE FROM` v tomhle seznamu JE (o tvaru nevime nic jineho,
    # ask je levny), v `interpreterDestructiveTokens` NENI (telo interpretu bezne nese
    # SQL retezce s WHERE, ktere overit nejde).
    # ZOPT-Q102 (0.3.1): `invoked` sem patri taky - do 0.3.0 koncil `ask` sam, od 0.3.1 je jeho politika `audit`, takze by
    # `$x = 'a'; ${x} = 'git'; & $x reset --hard` (hlava nerozbalena, literal videt) prosel tichem (A179-O3 Q5: deny).
    if (@('variable', 'heredocUnterminated', 'depth', 'invoked') -ccontains $Why -and $Raw -ne '') {
        $dv = Get-RawDestructiveVerdict $Raw $Config
        if ($null -ne $dv) { return $dv }
    }

    # ZOPT-Q102 / A179-O3 (0.3.1): politika `gate.opaque.<pricina>` je `audit` nebo `deny`; neznama hodnota nebo pricina
    # (`unknown`, Q8) = deny. `audit` zapise radek `opaque:<pricina>` jako dosud.
    if (([string](Get-Field (Get-Field $gate 'opaque') $Why 'deny')) -ceq 'audit') {
        Write-GateAudit $script:ToolName ('opaque:' + $Why) 'allow' $Config
        return $null
    }

    $text = [string]$Raw
    if ($text.Length -gt 60) { $text = $text.Substring(0, 60) }
    return @{ Id = ('opaque:' + $Why); Decision = 'deny'
              Shape = (([string](Get-Field $shapes 'opaque' 'neznamy prikaz ({text})')).Replace('{text}', [string]($text))) }
}

# TASK-179 (0.3.1, AOPT-O25): list VNITRNIHO prikazu kontejneroveho obalu posuzuje JEN DB pravidlo. Cesty a git v obrazu
# zustavaji README omezenim 11 (TASK-106 bod 3) - list obalu samotny jde dal beznou cestou s dnesnim verdiktem.
# K5-8 (kolo 5): jedno misto pro pripojeni promennych obalu k listu (K4-2: pripojit, neprepsat - vnoreny obal uvnitr tela)
# a jedno pro nejhorsi verdikt vnitrnich listu tela.
function Add-LeafContainerEnv($Leaf, [string]$EnvText) {
    $Leaf['ContainerEnv'] = ([string](Get-LeafField $Leaf 'ContainerEnv' '') + ' ' + $EnvText).Trim()
}

# K6-6/K7-3/K7-4 (kola 6 a 7): skupina a cteni listu (New-ReadingGroup) plati pro jeho audit (Write-GateAudit,
# $script:AuditReading) - i pro listy, ktere z nej vzniknou rozborem tela az tady (ty skupinu nemaji a dedi ji).
# Audit se pise hluboko v pravidlech sdilenych se secrets.ps1, proto kontext behu a ne parametr.
$script:AuditReading = $null
function Invoke-LeafVerdict($Leaf, $Config, [bool]$InContainer) {
    $prevReading = $script:AuditReading
    $grp = [string](Get-LeafField $Leaf 'ReadingGroup' '')
    if ($grp -ne '') {
        # K8-1 (kolo 8): cteni listu z tela, ktere se rozebralo pri verdiktu vnejsiho cteni, se pocita pod cestou toho cteni
        # (`0/1`) - stejna udalost v jinem vnejsim cteni je jine cteni tehoz klice skupiny, ne dalsi vyskyt.
        $rd = [string][int](Get-LeafField $Leaf 'Reading' 0)
        if ($null -ne $prevReading) { $rd = [string]$prevReading.R + '/' + $rd }
        $script:AuditReading = @{ G = $grp; R = $rd }
    }
    try {
        if ($InContainer) { return (Test-ContainerLeaf $Leaf $Config) }
        return (Test-Leaf $Leaf $Config)
    } finally {
        $script:AuditReading = $prevReading
    }
}

# K6-10 (kolo 6): jeden tvar "nerozebratelne v kontejneru s DB textem". ZOPT-Q102 / A179-O3 (Q10), 0.3.1: jmeno DB
# nejde precist a v kontejneru se nepovoluje nikdy (AOPT-O26) -> deny (do 0.3.0 ask).
function New-ContainerOpaqueDenied($Shapes) {
    return @{ Id = 'dbDestroyContainerOpaque'; Decision = 'deny'
              Shape = (Get-Field $Shapes 'dbDestroyContainerOpaque' 'DB v kontejneru') }
}

# K8-2 (kolo 8): jeden tvar `deny` z prepisu gate.dbDestroyLocal (Test-DatabaseRule a zaloha po stropu prace substituci).
function New-DbDestroyLocalDenied($Shapes) {
    return @{ Id = 'dbDestroyLocalDenied'; Decision = 'deny'
              Shape = (Get-Field $Shapes 'dbDestroyLocalDenied' 'DB (gate.dbDestroyLocal = deny)') }
}

# K9-5 (kolo 9): rozhodnuti prepisu gate.dbDestroyLocal cte jedno misto (Test-DatabaseRule i zaloha po stropu prace).
# K10-7 (kolo 10): bere uz nacteny objekt prepisu - Test-DatabaseRule z nej cte i seznamy pro `allow`.
function Get-DbDestroyLocalDecision($DbDestroyLocal) {
    # ZOPT-Q102 (0.3.1): chybejici rozhodnuti = deny (fail-closed); `ask` uz neni hodnota.
    if ([string](Get-Field $DbDestroyLocal 'decision' 'deny') -ceq 'allow') { return 'allow' }
    return 'deny'
}

# $InContainer = $true: vnitrni listy jsou v kontejneru (jen DB pravidlo, Test-ContainerLeaf). $false: telo tvaru 0.3.0
# (Test-Leaf, vsechna pravidla) - v kontejneru (NoAllow) dedi zakaz `allow` a promenne obalu.
function Get-WorstInnerVerdict($Inner, $Leaf, [bool]$InContainer, $Config) {
    $envText = [string](Get-LeafField $Leaf 'ContainerEnv' '')
    $noAllow = [bool](Get-LeafField $Leaf 'NoAllow' $false)
    $worst = $null
    foreach ($inner in $Inner) {
        if ($InContainer) { $inner['Container'] = $true; Add-LeafContainerEnv $inner $envText }
        elseif ($noAllow) { $inner['NoAllow'] = $true; Add-LeafContainerEnv $inner $envText }
        $r = Invoke-LeafVerdict $inner $Config $InContainer
        if ($null -eq $r) { continue }
        if ($r.Decision -eq 'deny') { return $r }
        if ($null -eq $worst) { $worst = $r }
    }
    return $worst
}

function Test-ContainerLeaf($Leaf, $Config) {
    $gate = Get-Field $Config 'gate'
    $shapes = Get-Field $gate 'shapes'
    $kind = [string](Get-LeafField $Leaf 'Kind' '')
    if ($kind -eq 'leaf') { return (Test-DatabaseRule $Leaf $Config) }
    if ($kind -eq 'heredoc') {
        $oe = ([string](Get-LeafField $Leaf 'OuterExe' '')).ToLowerInvariant()
        # K6-9 (kolo 6): tentyz seznam klientu jako Get-UnwrappedCommand ($script:SqlClients s vychozi hodnotou).
        if (@($script:SqlClients) -ccontains $oe) { return (Test-DatabaseRule $Leaf $Config) }
        if (@($script:ShellInterpreters) -ccontains $oe) {
            $shellTool = if ($oe -match '^(pwsh|powershell)$') { 'PowerShell' } else { 'Bash' }
            # Hostitelsky text tela = JEN promenne obalu (Get-UnwrappedCommand), ne argumenty shellu (K3-5: `bash -s -- --host=x`).
            return (Get-WorstInnerVerdict (Get-NestedShellLeaf ([string]$Leaf.Raw) $shellTool 0) $Leaf $true $Config)
        }
        # K4-3 (kolo 4): telo heredocu do interpretu v kontejneru (`docker compose exec -T db python3 <<EOF`) = kod, ktery
        # rozebrat neumime - tataz zavora jako u `python -c` v kontejneru (clen M-d): viditelny destruktivni DB literal -> deny
        # (0.3.1, ZOPT-Q102; do 0.3.0 ask).
        if (@($script:CodeInterpreters) -ccontains $oe) {
            if (Test-DbDestructiveText ([string]$Leaf.Raw)) { return (New-ContainerOpaqueDenied $shapes) }
        }
        return $null
    }
    if ($kind -eq 'sqlPipeOpaque') {
        # Tataz udalost jako na hostiteli (T-10 A): SQL z roury nevidime -> audit a ticho.
        Write-GateAudit $script:ToolName 'sqlFromPipe' 'allow' $Config
        return $null
    }
    if ($kind -eq 'opaque') {
        # K4-4 (kolo 4): `pwsh -EncodedCommand` uvnitr kontejneru - literal neni videt, ale text jde dekodovat (UTF-16LE base64,
        # jako hook secrets, A117-N16). Dekodovany text se rozebere jako prikaz v kontejneru; nejde-li dekodovat, plati politika
        # `gate.opaque.encoded` jako na hostiteli (0.3.1, ZOPT-Q102 / A179-O3: vychozi audit; do 0.3.0 ask).
        if ([string](Get-LeafField $Leaf 'Why' '') -eq 'encoded') {
            $argvE = Split-Arguments ([string]$Leaf.Raw)
            $wb = $null
            if ($argvE.Count -gt 0) {
                $restE = @(if ($argvE.Count -gt 1) { $argvE[1..($argvE.Count - 1)] })
                $wb = Get-ShellWrapperBody (Get-ExecutableName ([string]$argvE[0])) $restE
            }
            # K5-6 (kolo 5): totez dekodovani jako hook secrets (ConvertFrom-EncodedCommandText).
            $decoded = if ($null -ne $wb) { ConvertFrom-EncodedCommandText ([string]$wb.Text) } else { '' }
            if ($decoded -eq '') { return (Resolve-OpaqueDecision 'encoded' '' '' $Config) }
            return (Get-WorstInnerVerdict (Get-NestedShellLeaf $decoded 'PowerShell' 0) $Leaf $true $Config)
        }
        if ((Test-DbDestructiveText ([string]$Leaf.Raw)) -or (Test-DbDestructiveText ([string](Get-LeafField $Leaf 'Body' '')))) {
            return (New-ContainerOpaqueDenied $shapes)
        }
    }
    return $null
}

function Test-Leaf($Leaf, $Config) {
    $gate = Get-Field $Config 'gate'
    $shapes = Get-Field $gate 'shapes'

    if ([bool](Get-LeafField $Leaf 'Container' $false)) { return (Test-ContainerLeaf $Leaf $Config) }

    if ($Leaf.Kind -eq 'opaque') {
        # N39: chybejici `Why` NESMI tise dedit politiku `variable` (dnes `audit`) -
        # to by z vady konstrukce udelalo ticho. `unknown` neni klic v `gate.opaque`,
        # takze Resolve-OpaqueDecision vezme svuj vlastni default `ask`. Je to
        # fail-closed KONSTRUKCI, ne testem: list bez `Why` zvenci vyrobit nejde -
        # New-OpaqueLeaf ma `Why` povinny parametr a vsech osm volani ho predava.
        return (Resolve-OpaqueDecision ([string](Get-LeafField $Leaf 'Why' 'unknown')) `
                                       ([string]$Leaf.Raw) `
                                       ([string](Get-LeafField $Leaf 'Body' '')) $Config)
    }

    # Nalez Ada N21: prikaz jako ARGUMENT vzdaleneho shellu. `ssh host "rm -rf /"` se
    # spusti na CIZIM stroji, kde pravidla nad cestami ani seznam lokalnich hostu
    # neplati - rozebrat to nedokazeme a tvrdit "je to v poradku" uz vubec. Plati Z3.
    # !! Uzka podminka schvalne: `ssh host` (interaktivni) a `ssh -T git@github.com`
    # (jen prepinac a host) zustavaji allow, protoze prikaz nenesou. Falesny blok na
    # `git push` pres ssh by branu vypnul rychleji, nez by cokoli ochranil.
    if ($Leaf.Kind -eq 'leaf') {
        $remote = @(Get-Field $gate 'remoteShells' @('ssh', 'plink'))
        if ($remote -ccontains ([string]$Leaf.Exe).ToLowerInvariant()) {
            $positional = @(Get-RemoteShellPositional (@(Get-LeafField $Leaf 'Args' @())))
            if ($positional.Count -ge 2) {
                $text = [string]$Leaf.Raw
                if ($text.Length -gt 60) { $text = $text.Substring(0, 60) }
                # ZOPT-Q102 / A179-O3, 0.3.1: politika `gate.decisions.remoteShell` (vychozi audit; do 0.3.0 ask).
                return (New-PolicyVerdict $gate 'remoteShell' (([string](Get-Field $shapes 'remoteShell' 'prikaz na cizim stroji ({text})')).Replace('{text}', [string]($text))))
            }
        }
    }

    # Nalez Amber C1: do SQL klienta tece neco, co v prikazu neni videt
    # (`cat drop.sql | psql`, `$sql | psql`). Rozsah nezname -> Z3.
    if ($Leaf.Kind -eq 'sqlPipeOpaque') {
        # T-10 A: rozsah nezname, ale `cat migrace.sql | psql` je bezna prace. Misto
        # dotazu se udalost ZAPISE (audit) a pusti se dal.
        Write-GateAudit $script:ToolName 'sqlFromPipe' 'allow' $Config
        return $null
    }

    # Nalez Amber D3: telo heredocu je DATA, ne prikazova radka. Bez teto zavory
    # prochazelo denyPatterns, takze `cat > NOTES.md <<EOF / git reset --hard je
    # nebezpecny / EOF` skoncilo deny - zapis poznamky o prikazu blokovan jako prikaz.
    # SQL pravidlo se dal uplatnuje, ale jen kdyz uvozujici prikaz JE SQL klient.
    if ($Leaf.Kind -eq 'heredoc') {
        # K6-9 (kolo 6): tentyz seznam klientu jako Get-UnwrappedCommand. `sqlClients` je v defaults.json `superset`, takze
        # konfigurace bez nej nevznikne - verdikt se nemeni, jen zmizel druhy zdroj seznamu.
        $clients = @($script:SqlClients)
        $shells = @($script:ShellInterpreters)
        $oe = ([string](Get-LeafField $Leaf 'OuterExe' '')).ToLowerInvariant()

        if ($clients -ccontains $oe) { return (Test-DatabaseRule $Leaf $Config) }

        # Nalez Amber E2: D3 udelala z tela heredocu SLEPE MISTO. `bash <<'EOF' /
        # git reset --hard / EOF` je telo, ktere se SPUSTI - a zahazovalo se.
        # Kdyz je uvozujici prikaz shell, telo je prikazova radka a rozebere se.
        if ($shells -ccontains $oe) {
            # Nalez Amber K3: tataz trida jako I2 - telo heredocu spousti UVOZUJICI
            # shell, ne ten, ktery prikaz predal. Bez prepnuti propadl `bash <<'EOF'`
            # s bashovym escapem psany z PowerShellu (a naopak) na allow.
            # `cmd` zustava na escapu hostitele - to je zname omezeni (README).
            $shellTool = if ($oe -match '^(pwsh|powershell)$') { 'PowerShell' } else { 'Bash' }
            # K3-2/K3-3: telo shellu v kontejneru (tvar 0.3.0) - vsechna pravidla, ale bez `allow` a s promennymi obalu.
            return (Get-WorstInnerVerdict (Get-NestedShellLeaf ([string]$Leaf.Raw) $shellTool 0) $Leaf $false $Config)
        }

        # Nalez Amber G8: telo se SPUSTI, ale rozebrat ho neumime - je to kod interpretu
        # (`python <<EOF`) nebo prikazy na cizim stroji (`ssh prod <<EOF`). Brat ho jako
        # data znamenalo allow, pritom `python -c` uz konci ask.
        #
        # 0.1.10 ty dva pripady ROZDELUJE, prestoze do 0.1.9 sdilely jednu podminku:
        #   kod interpretu = tataz vec jako `python -c`, tedy pricina `interpreter`,
        #   cizi stroj      = tataz vec jako `ssh host "cmd"` (nalez Ada N21), tedy ask
        #                     BEZE ZMENY - pravidla nad cestami tam neplati a audit
        #                     na nasem stroji o cizim stroji netvrdi nic.
        if (@($script:CodeInterpreters) -ccontains $oe) {
            # K5-1 (TASK-179, kolo 5): interpret v kontejneru rozbaleny starsim pruchodem (`docker exec -i app python3 <<EOF`)
            # ma verdikt 0.3.0 a navic zavoru K4-3 - viditelny destruktivni DB literal v tele -> deny (0.3.1; do 0.3.0 ask).
            # K6-5 (kolo 6): zavora PRED Resolve-OpaqueDecision - ta by pri `audit` zapsala allow radek k listu, ktery konci deny.
            # K7-5 (kolo 7): destruktivni token interpretu ma prednost, je-li jeho politika deny (Id `interpreterDestructiveDb`);
            # token s politikou audit (ZOPT-Q102) DB literal v kontejneru neprebije.
            if ([bool](Get-LeafField $Leaf 'NoAllow' $false) -and (Test-DbDestructiveText ([string]$Leaf.Raw))) {
                $id = Get-InterpreterDestructiveVerdict ([string]$Leaf.Raw) $Config
                if ($null -ne $id -and $id.Decision -eq 'deny') { return $id }
                return (New-ContainerOpaqueDenied $shapes)
            }
            return (Resolve-OpaqueDecision 'interpreter' ([string]$Leaf.Raw) ([string]$Leaf.Raw) $Config)
        }
        if (@(Get-Field $gate 'remoteShells' @()) -ccontains $oe) {
            $text = [string]$Leaf.Raw
            if ($text.Length -gt 60) { $text = $text.Substring(0, 60) }
            return (New-PolicyVerdict $gate 'remoteShell' (([string](Get-Field $shapes 'remoteShell' 'prikaz na cizim stroji ({text})')).Replace('{text}', [string]($text))))
        }

        # Jinak je telo DATA (`cat > NOTES.md <<EOF`) a pravidla se na nej neuplatnuji.
        return $null
    }

    # Nalez Metis 27: `git -c alias.bd='branch -D' bd x` schova destruktivni podprikaz
    # do definice aliasu. Rozbalit to neumime, takze plati Z3: nerozebratelne -> politika `gate.decisions.gitAlias`
    # (0.3.1, ZOPT-Q102 / A179-O3 Q3: vychozi deny - alias spusti cokoli; do 0.3.0 ask).
    if ($Leaf.Exe -eq 'git') {
        foreach ($cfg in $Leaf.GitConfig) {
            if ($cfg -match '(?i)^alias\.') {
                return (New-PolicyVerdict $gate 'gitAlias' (([string](Get-Field $shapes 'gitAlias' '{text}')).Replace('{text}', [string]($cfg))))
            }
        }
    }

    $shape = Test-ConfiguredPattern $Leaf @(Get-Field $gate 'denyPatterns' @())
    if ($shape) { return @{ Id = $shape.Id; Decision = 'deny'; Shape = $shape.Shape } }

    # Seda zona (`audit`) jednoho pravidla se drzi stranou - `deny` pozdejsiho pravidla tehoz listu ma prednost.
    foreach ($rule in @('Test-GitPushRule', 'Test-GitCleanRule', 'Test-GitRestoreRule', 'Test-RecursiveDeleteRule', 'Test-DatabaseRule')) {
        $r = & $rule $Leaf $Config
        if ($r -and $r.Decision -eq 'deny') { return $r }
        if ($r -and $r.Decision -eq 'audit' -and -not $script:PendingAudit) { $script:PendingAudit = $r }
    }

    # ZOPT-Q102 / A179-O3 (Q7), 0.3.1: do 0.3.0 `askPatterns`; shoda = seda zona (audit).
    $shape = Test-ConfiguredPattern $Leaf @(Get-Field $gate 'auditPatterns' @())
    if ($shape) { $script:PendingAudit = $null; return @{ Id = $shape.Id; Decision = 'audit'; Shape = $shape.Shape } }

    if ($script:PendingAudit) { $r = $script:PendingAudit; $script:PendingAudit = $null; return $r }
    return $null
}

# ------------------------------------------------------------------ beh ---

$raw = Read-HookStdin
if ([string]::IsNullOrWhiteSpace($raw)) {
    Write-HookStderr $script:InternalMessage
    exit 2
}

$payload = $null
try { $payload = $raw | ConvertFrom-Json } catch { $payload = $null }
if ($null -eq $payload) {
    Write-HookStderr $script:InternalMessage
    exit 2
}

$toolName = [string](Get-Field $payload 'tool_name' '')
$command  = [string](Get-Field (Get-Field $payload 'tool_input') 'command' '')
$script:Cwd = [string](Get-Field $payload 'cwd' (Get-Location).Path)
$mode = [string](Get-Field $payload 'permission_mode' 'default')

$projectDir = $env:CLAUDE_PROJECT_DIR
if ([string]::IsNullOrWhiteSpace($projectDir)) { $projectDir = $script:Cwd }

$config = Get-HookConfig $PluginRoot $projectDir
$script:InternalMessage = Get-Text $config 'gateInternalError' $script:InternalMessage

if ($toolName -ne 'Bash' -and $toolName -ne 'PowerShell') {
    Write-HookStderr $script:InternalMessage
    exit 2
}
if ([string]::IsNullOrWhiteSpace($command)) {
    Write-HookStderr $script:InternalMessage
    exit 2
}

# Escape znak skeneru je jiny v Bashi (`\`) a v PowerShellu (zpetny apostrof) a zamena
# dela diru obema smery - viz komentar u Set-ScannerEscape (nalez Amber G1).
Set-ScannerEscape $toolName
# Jmeno nastroje potrebuje evidence T-10 A hluboko v rozhodovani, kam se parametrem
# neprotahne bez refaktoru vsech podpisu.
$script:ToolName = $toolName
# T36-Q7 = A: rezim opravneni potrebuje evidence (Write-GateAudit) ze stejneho duvodu
# jako jmeno nastroje - parametrem se tam bez refaktoru vsech podpisu neprotahne.
$script:PermissionMode = $mode

if (-not (Test-HookEnabled $config 'gate')) { exit 0 }
# H-c: odmitnuty klic prepisu je videt v auditu jednou za session (CR-P10) a v kanarku (jen jmeno klice).
Write-OverrideRejectedAudit $toolName $config ([string](Get-Field $payload 'session_id' ''))

$script:PendingAudit = $null
$decision = $null

# Nalez Ada N19: retez pruchodu (heredoc -> roura do SQL klienta -> prikazova radka)
# zije v Get-CommandLineLeaves a volaji ho i vsechny rekurze. Drive stal rozepsany
# tady a zanoreni znalo jen posledni clanek.
$script:SqlClients = @(Get-Field (Get-Field $config 'gate') 'sqlClients' @('psql', 'pgcli', 'dropdb', 'sqlcmd'))
# K3-8 (TASK-179, kolo 3 /code-review): jeden seznam shellu pro Test-Leaf, Test-ContainerLeaf i Get-UnwrappedCommand.
$script:ShellInterpreters = @(Get-Field (Get-Field $config 'gate') 'shellInterpreters' @('bash', 'sh', 'zsh', 'dash', 'ksh', 'pwsh', 'powershell', 'cmd'))
# K5-7 (kolo 5): totez pro interprety kodu (Test-Leaf, Test-ContainerLeaf, Get-UnwrappedCommand).
$script:CodeInterpreters = @(Get-Field (Get-Field $config 'gate') 'codeInterpreters' @())
# H-a (TASK-117): literalni prirazeni prikazu - jen PowerShell nastroj (viz Get-LiteralAssignment).
$script:FullCommand = $command
if ($toolName -eq 'PowerShell') { $script:LiteralAssign = Get-LiteralAssignment $command }
$leaves = Get-CommandLineLeaves $command 0
# CR-U (TASK-179, kolo 5): `allow` z gate.dbDestroyLocal posuzuje cely seznam listu (Test-DbAllowContext).
$script:AllLeaves = @($leaves)
# CR-U1: blokovy komentar s oddelovacem uvnitr nejde sestavit zpet - nerozebratelny tvar (`depth`, A179-O1: deny).
if ($script:BlockCommentSplit) { $leaves = @($leaves) + @(New-OpaqueLeaf $command 'depth') }

foreach ($leaf in $leaves) {
    $r = Invoke-LeafVerdict $leaf $config $false
    if ($null -eq $r) { continue }
    if ($r.Decision -eq 'deny') { $decision = $r; break }
    if ($null -eq $decision) { $decision = $r }
}

# CR-S8/CR-T/CR-U (kola 3 az 5): prikaz s `#` se rozebere jeste jednou BEZ komentare (cteni 0.3.0) - kde `#` komentarem
# neni (cmd, `${...}`, zpetne apostrofy), muze cteni s komentarem videt mene. Z druheho cteni plati jen `deny` (bez auditu);
# komentar tak rozbor jen rozsiri.
if (($null -eq $decision -or $decision.Decision -ne 'deny') -and $command.IndexOf('#') -ge 0) {
    $script:CommentAware = $false
    $script:AuditMuted = $true
    # CR-V6 (kolo 6): druhe cteni dostane vlastni rozpocet prace na substituce (prvni ho mohlo vycerpat); preteceni plati
    # z obou cteni.
    $overflow1 = $script:SubstOverflow
    $script:SubstWork = 0
    $script:SubstOverflow = $false
    try {
        Set-ScannerEscape $toolName
        $plainLeaves = @(Get-CommandLineLeaves $command 0)
        $script:AllLeaves = $plainLeaves
        foreach ($leaf in $plainLeaves) {
            $r = Invoke-LeafVerdict $leaf $config $false
            if ($null -ne $r -and $r.Decision -eq 'deny') { $decision = $r; break }
        }
    } finally {
        $script:CommentAware = $true
        $script:AuditMuted = $false
        $script:SubstOverflow = $overflow1 -or $script:SubstOverflow
    }
}

# K7-1 (TASK-179, kolo 7): rozbor substituci v obalu kontejneru narazil na strop prace (_common.ps1, SubstWorkBudget) - cil
# a vnitrni prikaz obalu nemusely byt prectene cele. Je-li v nekterem rozebiranem textu destruktivni DB literal, ptame se.
# K8-2 (kolo 8): hostitel takoveho prikazu neni prectany = mistni (jako pruchozi `-e PGHOST` bez hodnoty, CR-3) - plati
# `gate.dbDestroyLocal`: `deny` z prepisu zustava `deny`, jinak `ask` (`allow` v kontejneru nikdy, AOPT-O26).
# K9-1 (kolo 9): zaloha bezi i po sede zone jineho listu - `deny` zalohy ji prebije.
# ZOPT-Q102 / A179-O3 (Q10), 0.3.1: jmeno DB po prekroceni stropu nejde precist -> deny vzdy (do 0.3.0 ask; s prepisem
# `gate.dbDestroyLocal = deny` tvar `dbDestroyLocalDenied`).
if ($script:SubstOverflow -and ($null -eq $decision -or $decision.Decision -ne 'deny')) {
    $ovGate = Get-Field $config 'gate'
    foreach ($pt in @($script:ParsedTexts)) {
        if (Test-DbDestructiveText ([string]$pt.Text)) {
            $ovShapes = Get-Field $ovGate 'shapes'
            if ((Get-DbDestroyLocalDecision (Get-Field $ovGate 'dbDestroyLocal')) -eq 'deny') {
                $decision = New-DbDestroyLocalDenied $ovShapes
            } else {
                $decision = New-ContainerOpaqueDenied $ovShapes
            }
            break
        }
    }
}

if ($null -eq $decision) { exit 0 }

# ZOPT-Q102 (0.3.1): seda zona (`audit`) = hook mlci a zapise radek auditu s ID tvaru; `ask` uz neexistuje.
if ($decision.Decision -eq 'audit') {
    Write-GateAudit $toolName ('gate:' + [string](Get-LeafField $decision 'Id' 'unknown')) 'allow' $config
    exit 0
}

# H-b (TASK-117, Z117-Q8 = B): kazde `deny` jde do auditu s ID tvaru, nikdy s textem prikazu.
Write-GateAudit $toolName ('gate:' + [string](Get-LeafField $decision 'Id' 'unknown')) 'deny' $config
$reason = ([string](Get-Text $config 'gateReason' 'Brana par. 6: {shape}')).Replace('{shape}', [string]$decision.Shape)
Write-DenyDecision $reason
