#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Sdilene jadro hooku sinogard-hooks: stdin/stdout/stderr v UTF-8, cteni konfigurace,
  normalizace cest, rozklad prikazove radky a vystupni JSON.

.DESCRIPTION
  ASCII-ONLY. Windows PowerShell 5.1 cte .ps1 bez BOM jako ANSI, takze jakykoli
  non-ASCII znak ve zdroji by se rozsypal. Vsechny lidske texty (ceske) proto zijou
  v hooks/config/defaults.json a ctou se explicitne jako UTF-8.

  Tenhle soubor si NENASTAVUJE rezim (StrictMode, ErrorActionPreference) - dot-source
  vklada kod do scope volajiciho a rezim patri vstupnimu bodu. Vse nize je proto
  napsane tak, aby obstalo pod `Set-StrictMode -Version Latest`.
#>

# ------------------------------------------------------------------ I/O ---

function Read-HookStdin {
    $stream = [Console]::OpenStandardInput()
    $reader = New-Object System.IO.StreamReader($stream, (New-Object System.Text.UTF8Encoding($false)))
    return $reader.ReadToEnd()
}

function Write-HookStdout([string]$Text) {
    $stream = [Console]::OpenStandardOutput()
    $writer = New-Object System.IO.StreamWriter($stream, (New-Object System.Text.UTF8Encoding($false)))
    $writer.Write($Text)
    $writer.Flush()
}

function Write-HookStderr([string]$Text) {
    $stream = [Console]::OpenStandardError()
    $writer = New-Object System.IO.StreamWriter($stream, (New-Object System.Text.UTF8Encoding($false)))
    $writer.Write($Text)
    $writer.Flush()
}

function Read-Utf8File([string]$Path) {
    return [System.IO.File]::ReadAllText($Path, (New-Object System.Text.UTF8Encoding($false)))
}

# ------------------------------------------------------- bezpecny pristup ---

# Pod StrictMode je cteni neexistujici vlastnosti vyjimka. Vstup hooku je cizi JSON,
# takze kazdy pristup k nemu jde pres tohle.
function Get-Field($Object, [string]$Name, $Default = $null) {
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    if ($null -eq $prop.Value) { return $Default }
    return $prop.Value
}

# ------------------------------------------------------------------ cesty ---

# Join-Path a Test-Path resolvuji PSDrive, takze na ceste s neexistujici jednotkou
# (W:\... na cizim stroji, odpojeny sitovy disk) VYHODI vyjimku misto toho, aby
# rekly "neni". U hooku je vstupem cizi cesta (cwd sezeni, CLAUDE_PROJECT_DIR),
# takze by pad znamenal, ze fail-closed zablokuje uplne vsechno.
# [IO.Path]::Combine je ciste retezcova matematika - zadny disk se nehleda.

function Join-SafePath([string]$Base, [string]$Leaf) {
    if ([string]::IsNullOrWhiteSpace($Base)) { return $null }
    try { return [System.IO.Path]::Combine($Base, $Leaf) } catch { return $null }
}

function Test-SafePath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try { return [System.IO.File]::Exists($Path) -or [System.IO.Directory]::Exists($Path) }
    catch { return $false }
}

# ------------------------------------------------------------ konfigurace ---

function Get-HookConfig([string]$PluginRoot, [string]$ProjectDir) {
    $defaultsPath = Join-Path $PluginRoot 'hooks/config/defaults.json'
    $config = ConvertFrom-Json (Read-Utf8File $defaultsPath)

    if ([string]::IsNullOrWhiteSpace($ProjectDir)) { return $config }
    $overridePath = Join-SafePath $ProjectDir '.claude/sinogard-hooks.json'
    if (-not (Test-SafePath $overridePath)) { return $config }

    # Melke slouceni: klic v override NAHRAZUJE cely klic defaults. Zadny hluboky
    # merge - jinak by z override neslo polozku seznamu odebrat, jen pridat.
    $override = ConvertFrom-Json (Read-Utf8File $overridePath)
    foreach ($prop in $override.PSObject.Properties) {
        if ($config.PSObject.Properties[$prop.Name]) {
            $config.PSObject.Properties.Remove($prop.Name)
        }
        $config | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value
    }
    return $config
}

function Test-HookEnabled($Config, [string]$HookName) {
    $hooks = Get-Field $Config 'hooks'
    $value = Get-Field $hooks $HookName $true
    return [bool]$value
}

function Get-Text($Config, [string]$Key, [string]$Fallback) {
    $texts = Get-Field $Config 'texts'
    $value = Get-Field $texts $Key $null
    if ($null -eq $value) { return $Fallback }
    return [string]$value
}

# --------------------------------------------------------------- vystupy ---

function New-PreToolUseJson([string]$Decision, [string]$Reason) {
    $payload = [ordered]@{
        hookSpecificOutput = [ordered]@{
            hookEventName            = 'PreToolUse'
            permissionDecision       = $Decision
            permissionDecisionReason = $Reason
        }
    }
    return ($payload | ConvertTo-Json -Depth 6 -Compress)
}

# deny = JSON + exit 2 + tyz duvod na stderr (T36-N10: pri exit 2 cte Claude stderr
# a exit 2 blokuje i tehdy, kdyby JSON neproslo validaci schematu).
function Write-DenyDecision([string]$Reason) {
    Write-HookStdout (New-PreToolUseJson 'deny' $Reason)
    Write-HookStderr $Reason
    exit 2
}

function Write-AskDecision([string]$Reason) {
    Write-HookStdout (New-PreToolUseJson 'ask' $Reason)
    exit 0
}

# ------------------------------------------------------ normalizace cesty ---

function ConvertTo-NormalPath([string]$Path) {
    if ([string]::IsNullOrEmpty($Path)) { return '' }
    $p = $Path.Trim()
    $p = $p.Trim('"').Trim("'")
    $p = $p -replace '\\', '/'
    $p = [regex]::Replace($p, '%([A-Za-z_][A-Za-z0-9_]*)%', {
        param($m)
        $v = [Environment]::GetEnvironmentVariable($m.Groups[1].Value)
        if ($v) { ($v -replace '\\', '/') } else { $m.Value }
    })
    $p = [regex]::Replace($p, '\$env:([A-Za-z_][A-Za-z0-9_]*)', {
        param($m)
        $v = [Environment]::GetEnvironmentVariable($m.Groups[1].Value)
        if ($v) { ($v -replace '\\', '/') } else { $m.Value }
    })
    if ($p.StartsWith('~')) {
        $profileDir = [Environment]::GetFolderPath('UserProfile')
        if ($profileDir) { $p = ($profileDir -replace '\\', '/') + $p.Substring(1) }
    }
    $p = $p -replace '/{2,}', '/'
    return $p.ToLowerInvariant()
}

# ------------------------------------------------- rozklad prikazove radky ---

# --------------------------------------------------------------- skener ---
#
# JEDINY skener pro vsechna deleni prikazove radky. Vzniknul po tretim kole oprav,
# kde po sobe sla oprava -> nova dira na TEMZE miste (B4 -> C1, D3 -> E2, C2 -> E3).
# Spolecna pricina nebyla ani jedna z tech oprav: bylo to deleni textu s uvozovkami
# REGEXEM. `[regex]::Split` neumi uvozovky, takze `echo "DROP TABLE users;" | psql`
# se rozpadlo uprostred retezce a destruktivni prikaz propadl (nalez Amber E1).
#
# Pravidlo: nad prikazovou radkou se NEDELI regexem. Vsechno deli tahle funkce.

# ------------------------------------------------------------ escape znak ---
#
# Nalez Amber G1: escape znak PRED uvozovkou je literal, ne prepnuti stavu retezce.
# `echo \" ; git reset --hard` neotevira retezec, takze `;` deli - jenze skener o
# escapu nevedel, cely zbytek radku spolkl "do retezce" a zbyl jediny list `echo`.
#
# Escape znak ale NENI stejny v obou shellech a zamenit je nelze - obe zamena dela
# NOVOU diru presne opacnym smerem (obe jsou v kontrolni skupine):
#   PowerShell  `echo "C:\src\" ; git reset --hard`  - `\` v PS neescapuje; kdyby ano,
#               retezec by se nikdy nezavrel a `;` by nedelilo -> allow.
#   Bash        echo `"foo"` ; git reset --hard      - zpetny apostrof v Bashi neescapuje
#               (je to substituce); kdyby ano, druha `"` by retezec OTEVRELA -> allow.
# Znak se proto bere podle `tool_name` vstupu hooku (Bash / PowerShell), ne globalne.
#
# Escapovana dvojice se do vystupu vklada CELA a doslova. Kdyby se escape zahazoval,
# `C:\src` ve Split-Arguments by se zmenilo na `C:src` a shoda na chranene cesty by
# prestala platit - tenhle escape resi VYHRADNE stav uvozovek, nic jineho.
$script:ScannerEscape = '\'

function Set-ScannerEscape([string]$ToolName) {
    if ($ToolName -eq 'PowerShell') { $script:ScannerEscape = '`' } else { $script:ScannerEscape = '\' }
}

function Get-ScannerEscape { return $script:ScannerEscape }

function Split-Unquoted([string]$Text, [string[]]$Separators) {
    if ([string]::IsNullOrEmpty($Text)) { return ,@() }

    $r = Split-UnquotedCore $Text $Separators $true $true
    # Nevyvazena slozena zavorka => zanoreni se nikdy nevratilo na nulu a nedelilo by
    # se uz vubec nic. Druhy pruchod ji ignoruje.
    if ($r.BraceOpen) { $r = Split-UnquotedCore $Text $Separators $true $false }
    # Sken skoncil s OTEVRENOU dvojitou uvozovkou => vstup je bud rozbity, nebo jsme
    # si escapem zavreli oci (`echo "C:\src\"` je v Bashi opravdu neuzavreny retezec).
    # Druhy pruchod BEZ escapu deli VIC, tedy smerem k deny; propustit kvuli tomu nic
    # nejde, nanejvys se rozdeli neco, co se delit nemelo.
    if ($r.Open) { $r = Split-UnquotedCore $Text $Separators $false $false }
    return ,@($r.Parts)
}

function Split-UnquotedCore([string]$Text, [string[]]$Separators, [bool]$HonorEscape, [bool]$HonorBrace) {
    $esc = $script:ScannerEscape

    $out = New-Object System.Collections.ArrayList
    $buf = New-Object System.Text.StringBuilder
    $i = 0
    $n = $Text.Length
    $inSingle = $false
    $inDouble = $false
    $depth = 0        # zanoreni do $( ... )
    $brace = 0        # zanoreni do { ... }

    # Delsi separatory se zkousi driv, jinak by `&&` rozpadlo na dve `&`.
    $seps = @($Separators | Sort-Object -Property Length -Descending)

    while ($i -lt $n) {
        $c = $Text[$i]

        if ($inSingle) {
            [void]$buf.Append($c)
            if ($c -eq "'") { $inSingle = $false }
            $i++; continue
        }
        # Escape plati MIMO jednoduche uvozovky (uvnitr nich escape neexistuje ani
        # v jednom shellu). Oba znaky se opisuji doslova, stav uvozovek se nemeni.
        if ($HonorEscape -and $c -eq $esc -and ($i + 1) -lt $n) {
            [void]$buf.Append($c); [void]$buf.Append($Text[$i + 1]); $i += 2; continue
        }
        if ($c -eq "'" -and -not $inDouble) {
            $inSingle = $true; [void]$buf.Append($c); $i++; continue
        }
        if ($c -eq '"') { $inDouble = -not $inDouble; [void]$buf.Append($c); $i++; continue }
        if ($inDouble) { [void]$buf.Append($c); $i++; continue }

        # $( ... ) se nedeli - je to jeden vyraz, ktery se rozebira zvlast.
        if ($c -eq '$' -and ($i + 1) -lt $n -and $Text[$i + 1] -eq '(') {
            $depth++; [void]$buf.Append('$('); $i += 2; continue
        }
        if ($depth -gt 0) {
            if ($c -eq '(') { $depth++ }
            elseif ($c -eq ')') { $depth-- }
            [void]$buf.Append($c); $i++; continue
        }

        # Nalez Amber G4: `{ ... }` je zanoreni stejne jako `$( ... )`. Bez toho se
        # `& { rm -rf src; }` rozpadlo na stredniku, prvni segment byl `& { rm -rf src`,
        # exe vyslo jako `{` a zadne pravidlo nesedlo -> allow. (Bez stredniku uvnitr
        # to deny bylo, takze diru otevrel prave ten stredni k.)
        if ($HonorBrace) {
            if ($c -eq '{') { $brace++; [void]$buf.Append($c); $i++; continue }
            if ($c -eq '}' -and $brace -gt 0) { $brace--; [void]$buf.Append($c); $i++; continue }
            if ($brace -gt 0) { [void]$buf.Append($c); $i++; continue }
        }

        $hit = $null
        foreach ($s in $seps) {
            if ($s.Length -gt 0 -and ($n - $i) -ge $s.Length -and
                [string]::CompareOrdinal($Text, $i, $s, 0, $s.Length) -eq 0) {
                $hit = $s; break
            }
        }
        if ($null -ne $hit) {
            [void]$out.Add($buf.ToString()); [void]$buf.Clear(); $i += $hit.Length; continue
        }

        [void]$buf.Append($c); $i++
    }
    [void]$out.Add($buf.ToString())

    # `,` je nutna: PowerShell rozbaluje vracene pole a jednoprvkovy vysledek by
    # se vratil jako skalar, na kterem `.Count` pod StrictMode pada.
    # POZOR: na volajicim miste uz se kolem toho `@()` NEDAVA - zabalilo by to znovu.
    # POZOR: tady `@()` BEZ carky. Carka je potreba jen u NAVRATU z funkce (PowerShell
    # by jednoprvkove pole rozbalil na skalar); hodnota v hashtable se nerozbaluje,
    # takze `,@(...)` by pole zabalilo JESTE JEDNOU a Count by byl 1 misto poctu casti.
    # Prave na tomhle spadly testy M6 a M7 hned po zavedeni escapu.
    return @{
        Parts     = @($out | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        Open      = $inDouble
        BraceOpen = ($brace -ne 0)
    }
}

# Najde pozici ZA uzavirajici zavorkou k otevrene zavorce zacinajici na $Start.
#
# Nalez Amber H4 (zmereno: misto je tady, ne ve Split-Unquoted - ten uvozovky uz umi):
# tenhle pruchod je pocital naslepo, takze `$(echo ')')` skoncil na zavorce UVNITR
# retezce a obsah substituce se ustrihl na `echo '`. Kdyz se do te ustrizene casti
# nevejde cesta, `echo $(rm -rf ")" src)` uz zadne pravidlo nechytne -> allow.
function Find-CloseParen([string]$Text, [int]$Start) {
    $esc = $script:ScannerEscape
    $n = $Text.Length
    $depth = 1
    $j = $Start
    $inSingle = $false
    $inDouble = $false
    while ($j -lt $n -and $depth -gt 0) {
        $c = $Text[$j]
        if ($inSingle) { if ($c -eq "'") { $inSingle = $false }; $j++; continue }
        if ($c -eq $esc -and ($j + 1) -lt $n) { $j += 2; continue }
        if ($c -eq '"') { $inDouble = -not $inDouble; $j++; continue }
        if ($inDouble) { $j++; continue }
        if ($c -eq "'") { $inSingle = $true; $j++; continue }
        if ($c -eq '(') { $depth++ }
        elseif ($c -eq ')') { $depth-- }
        $j++
    }
    return $j
}

# Obsah vsech `$( ... )` v textu (kvotove korektne, vcetne zanoreni).
function Get-Substitution([string]$Text) {
    $out = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrEmpty($Text)) { return ,@() }

    $esc = $script:ScannerEscape
    $i = 0
    $n = $Text.Length
    $inSingle = $false
    while ($i -lt $n) {
        $c = $Text[$i]
        if ($inSingle) { if ($c -eq "'") { $inSingle = $false }; $i++; continue }
        # `\$(...)` v Bashi substituci NEPROVEDE (nalez Amber G1, tataz trida).
        if ($c -eq $esc -and ($i + 1) -lt $n) { $i += 2; continue }
        if ($c -eq "'") { $inSingle = $true; $i++; continue }
        # V dvojitych uvozovkach se substituce PROVADI, takze se prochazi dal.
        # Procesova substituce `<( ... )` a `>( ... )` je taky spusteny prikaz
        # (nalez Metis 5, kolo 2) - bere se stejne jako `$( ... )`.
        if (($c -eq '<' -or $c -eq '>' -or $c -eq '$') -and ($i + 1) -lt $n -and $Text[$i + 1] -eq '(') {
            $start = $i + 2
            $j = Find-CloseParen $Text $start
            $len = [Math]::Max(0, ($j - 1) - $start)
            if ($len -gt 0) { [void]$out.Add($Text.Substring($start, $len)) }
            $i = $j; continue
        }
        $i++
    }
    return ,@($out)
}

# Slozi tokeny zpatky do prikazove radky a ZACHOVA hranice, ktere nesly uvozovky.
#
# Nalez Metis 1 (kolo 2): `find . -exec sh -c 'rm -rf "$0"' {} \;` se rozbaloval tak,
# ze se tokeny spojily mezerou - `sh -c rm -rf "$0" {}` - a vnitrni `-c` uz vzalo jen
# `rm`. Zbytek prikazu se ztratil. Token s bilym znakem se proto uvozuje zpet.
function Join-Argument($Tokens) {
    $parts = New-Object System.Collections.ArrayList
    foreach ($t in $Tokens) {
        $s = [string]$t
        if ($s -match '\s') {
            if ($s -notmatch "'") { [void]$parts.Add("'" + $s + "'") }
            else { [void]$parts.Add('"' + ($s -replace '"', '""') + '"') }
        } else {
            [void]$parts.Add($s)
        }
    }
    return ($parts -join ' ')
}

# Protejsek Join-Argument pro obaly, ktere berou PRIKAZOVOU RADKU jako jeden retezec
# (`bash -c "..."`, `cmd /c "..."`, `eval`). Tam se hranice tokenu NESMI obnovovat -
# ten retezec se ma znovu rozebrat jako prikaz, ne predat jako jeden argument.
#
# Rozdil mezi temihle dvema funkcemi neni kosmeticky: kdyz jsem Join-Argument pouzila
# i tady, `cmd /c "rd /s /q src"` se zabalilo zpatky do uvozovek, uz se nerozebralo
# a propadlo na allow. Chytil to regresni invariant, ne novy test.
function Join-CommandString($Tokens) {
    return (($Tokens | ForEach-Object { [string]$_ }) -join ' ')
}

# Statementy = to, co je oddeleno `;`, `&&`, `||`, `&` nebo koncem radku. ROURA NE.
function Split-Statement([string]$Text) {
    return (Split-Unquoted $Text @('&&', '||', ';', '&', "`n", "`r"))
}

# Clanky roury. Vstup uz MUSI byt jeden statement - jinak by se `||` rozpadlo na `|`.
function Split-Pipe([string]$Statement) {
    return (Split-Unquoted $Statement @('|'))
}

function Split-CommandLine([string]$Command) {
    if ([string]::IsNullOrWhiteSpace($Command)) { return ,@() }

    $result = New-Object System.Collections.ArrayList
    foreach ($seg in (Split-Unquoted $Command @('&&', '||', ';', '|', '&', "`n", "`r"))) {
        [void]$result.Add($seg)
    }

    # Substituce se rozebiraji navic - `echo $(git branch -D x)` je i to vnitrni.
    foreach ($e in (Get-Substitution $Command)) {
        foreach ($sub in (Split-CommandLine $e)) { [void]$result.Add($sub) }
    }

    # Pary zpetnych apostrofu = substituce v Bashi. V PowerShellu je zpetny apostrof
    # escape, takze prevzeti obsahu je nanejvys falesne pozitivni, nikdy negativni.
    foreach ($m in [regex]::Matches($Command, '`([^`]+)`')) {
        foreach ($sub in (Split-CommandLine $m.Groups[1].Value)) { [void]$result.Add($sub) }
    }

    return ,@($result | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
}

function Split-Arguments([string]$Command) {
    $esc = $script:ScannerEscape
    $items = New-Object System.Collections.ArrayList
    $buffer = New-Object System.Text.StringBuilder
    $i = 0
    $n = $Command.Length
    $inSingle = $false
    $inDouble = $false
    $any = $false

    while ($i -lt $n) {
        $c = $Command[$i]
        if ($inSingle) {
            if ($c -eq "'") { $inSingle = $false } else { [void]$buffer.Append($c); $any = $true }
            $i++; continue
        }
        # Escapovana dvojice se opisuje CELA (nalez Amber G1). Zahodit escape nelze:
        # `C:\src` by se zmenilo na `C:src` a shoda na chranenou cestu by prestala platit.
        # Escape pred koncem radku je pokracovani radku - to je jediny pripad, kdy se
        # dvojice zahazuje, jinak by v argv zbyl token `\` a posunul pozicni argumenty.
        if ($c -eq $esc -and ($i + 1) -lt $n) {
            if ($Command[$i + 1] -eq "`n" -or $Command[$i + 1] -eq "`r") {
                if ($any) { [void]$items.Add($buffer.ToString()); [void]$buffer.Clear(); $any = $false }
                $i += 2; continue
            }
            [void]$buffer.Append($c); [void]$buffer.Append($Command[$i + 1]); $any = $true; $i += 2; continue
        }
        if ($inDouble) {
            if ($c -eq '"') { $inDouble = $false } else { [void]$buffer.Append($c); $any = $true }
            $i++; continue
        }
        if ($c -eq "'") { $inSingle = $true; $any = $true; $i++; continue }
        if ($c -eq '"') { $inDouble = $true; $any = $true; $i++; continue }
        # Konec radku je oddelovac argumentu stejne jako mezera - bez toho se
        # `git reset` a `--hard` ze dvou radku slepily do jednoho tokenu.
        if ($c -eq ' ' -or $c -eq "`t" -or $c -eq "`n" -or $c -eq "`r") {
            if ($any) { [void]$items.Add($buffer.ToString()); [void]$buffer.Clear(); $any = $false }
            $i++; continue
        }
        [void]$buffer.Append($c); $any = $true; $i++
    }
    if ($any) { [void]$items.Add($buffer.ToString()) }
    return ,@($items)
}

# PowerShell prijima hodnotu parametru i pres dvojtecku: `-Path:.env`,
# `-LiteralPath:src`, `-Recurse:$true`. Takovy token zacina pomlckou, takze by ho
# kazde pravidlo preskocilo jako prepinac a HODNOTA by zmizela i s cestou.
# Rozpad na jmeno a hodnotu tuhle diru zavira. (Nalez councilu Metis, 2026-09-05.)
# Hodnota `$true`/`$false` se zahazuje - je to argument prepinace, ne cesta.
function Expand-ColonParameter($Tokens) {
    $out = New-Object System.Collections.ArrayList
    foreach ($t in $Tokens) {
        if ($t -match '^(-[A-Za-z][A-Za-z0-9]*):(.*)$') {
            [void]$out.Add($Matches[1])
            $value = $Matches[2]
            if ($value -ne '' -and $value -notmatch '^\$(true|false)$') { [void]$out.Add($value) }
        } else {
            [void]$out.Add($t)
        }
    }
    return ,@($out)
}

# Jmeno spustitelneho souboru bez cesty, pripony a uvozovek:
# /usr/bin/git -> git, git.exe -> git, "git" -> git.
function Get-ExecutableName([string]$Token) {
    if ([string]::IsNullOrWhiteSpace($Token)) { return '' }
    $t = $Token.Trim().Trim('"').Trim("'")
    $t = $t -replace '\\', '/'
    $idx = $t.LastIndexOf('/')
    if ($idx -ge 0) { $t = $t.Substring($idx + 1) }
    $t = $t -replace '\.(exe|cmd|bat|com)$', ''
    return $t.ToLowerInvariant()
}

# Nese token neznamou expanzi (promennou, substituci)?
function Test-Unexpandable([string]$Text) {
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if ($Text -match '\$\(') { return $true }
    if ($Text -match '\$\{?[A-Za-z_][A-Za-z0-9_:]*') { return $true }
    if ($Text -match '%[A-Za-z_][A-Za-z0-9_]*%') { return $true }
    return $false
}
