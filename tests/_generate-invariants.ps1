#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Generator regresniho invariantu (tests/fixtures/invariants.json).

.DESCRIPTION
  Nalez Amber H2: soubor vznikl "generovano z pripadovych poli", ale generator
  v repu nebyl. Pri pristim rustu sady by ho nikdo nezopakoval, invariant by
  zkamenel na 142 radcich a prestal by delat to, kvuli cemu vznikl.

  Postup: sady se spusti v rezimu SBERU (parametr -Collect) - pripady se jen
  ohlasi, hook se nespousti, takze to trva sekundy. Vysledek se PRIDA
  k existujicim radkum.

  Nalez Amber L2: tenhle odstavec jmenoval promennou prostredi SINOGARD_HOOKS_COLLECT.
  Ta rezim od opravy J2 nezapina, naopak sadu SHODI - popis by navadel na presny
  opak toho, co plati.

  Soubor je APPEND-ONLY. Generator existujici radky NIKDY nemeni ani neodebira -
  jen doplni ty, ktere v nem jeste nejsou. To je zamer: radek odsud odchazi jen
  s citovanym rozhodnutim, ne proto, ze se zmenilo pripadove pole.

  Radky prvniho vydani nemaji klice `hook` a `kind` - tehdy byl invariant jen pro
  branu nad prikazy. Chybejici klic proto znamena `gate` / `cmd` a dopisovat ho
  zpetne by znamenalo prepsat 142 radku, ktere prepsat nemam.

.EXAMPLE
  pwsh -NoProfile -File tests/_generate-invariants.ps1
  pwsh -NoProfile -File tests/_generate-invariants.ps1 -WhatIf
#>
param(
    [switch]$WhatIf,
    [string]$Interpreter = 'pwsh',
    # !! Nalez Ady N38 (0.1.11): zmena OCEKAVANI byla dosud rucni editace souboru, tedy
    # jediny ukon nad invariantem, ktery nemel nastroj ani stopu. `-Prijmout <citace>`
    # je ta cesta: prepise jen radky, na kterych generator hlasi SPOR, a do hlavicky
    # `_zmeneno` doplni datum, citaci, smer a vycet tvaru. Bez citace se nezapise nic -
    # radek invariantu meni ocekavani vzdy s tim, kdo o tom rozhodl.
    [string]$Prijmout = '',
    # TASK-106 bod 14 (0.2.0): cesta k souboru invariantu je parametr, aby sel generator
    # otestovat nad KOPII - test bajtove neutrality `-Prijmout` nesmi sahat na ostry soubor.
    [string]$InvariantsPath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path $PSScriptRoot -Parent
$invPath = if ($InvariantsPath -ne '') { $InvariantsPath } else { Join-Path $PSScriptRoot 'fixtures/invariants.json' }
$utf8 = New-Object System.Text.UTF8Encoding($false)

# TASK-106 bod 14: telo JSON retezce z textu - escapuje se JEN `\`, `"` a ridici znaky, nic
# jineho. ConvertTo-Json to nesmi delat: PowerShell 5.1 escapuje navic `<`, `>`, `&`, `'`
# (do escape sekvenci u0026 a u0027), pwsh 7 jen `<` a `>` - tyz text da v kazdem interpretu jine bajty a
# hlavicka, kterou nikdo nezmenil, by se v diffu "zmenila". Hlavicka `_zmeneno` se proto
# neprepisuje deserializaci a serializaci, ale nova veta se PRIPISUJE do stavajiciho
# literalu textove - stare bajty zustavaji, jak byly.
function ConvertTo-JsonStringBody([string]$Text) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        switch ($ch) {
            '\' { [void]$sb.Append('\\') }
            '"' { [void]$sb.Append('\"') }
            "`n" { [void]$sb.Append('\n') }
            "`r" { [void]$sb.Append('\r') }
            "`t" { [void]$sb.Append('\t') }
            default {
                if ([int]$ch -lt 32) { [void]$sb.Append(('\u{0:x4}' -f [int]$ch)) } else { [void]$sb.Append($ch) }
            }
        }
    }
    return $sb.ToString()
}

function Get-SuiteCases([string]$Suite) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Interpreter
    # Rezim sberu je PARAMETR, ne promenna prostredi (nalez Amber J2): promennou
    # z okoli by sada spolkla tise a vydala zelenou nad necim, co vubec nemerila.
    $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $PSScriptRoot ($Suite + '.tests.ps1')) + '" -Collect'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = $utf8
    $psi.WorkingDirectory = $repoRoot
    $psi.EnvironmentVariables['SINOGARD_HOOKS_COLLECT'] = ''
    $p = [System.Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEnd()
    [void]$p.StandardError.ReadToEnd()
    $p.WaitForExit()

    $m = [regex]::Match($out, '<<<SINOGARD-CASES\s*(.*?)\s*SINOGARD-CASES>>>', 'Singleline')
    if (-not $m.Success) { throw ("Sada {0} nevydala sber pripadu." -f $Suite) }
    return @($m.Groups[1].Value | ConvertFrom-Json)
}

# Klic radku: hook + nastroj + doslovny prikaz/cesta. Ocekavani do klice NEPATRI -
# kdyby se zmenilo, ma to byt VIDET jako spor, ne se pridat jako druhy radek.
function Get-RowKey($Hook, $Tool, $Value) {
    # Oddelovac je znak, ktery se v prikazu nevyskytne. `u{...}` tu byt nemuze -
    # Windows PowerShell 5.1 ho nezna a skript ma bezet v obou interpretech.
    $sep = [string][char]1
    return ([string]$Hook + $sep + [string]$Tool + $sep + [string]$Value)
}

$doc = [System.IO.File]::ReadAllText($invPath, $utf8) | ConvertFrom-Json
$existing = @($doc.rows)

# !! Nalez Hestia N27: `@{}` je v PowerShellu case-INSENSITIVE, takze `git clean -fdX`
# a `git clean -fdx` splynuly v JEDEN klic - a prave na tom rozdilu tahle brana stoji
# (`-X` je uklid buildu, `-x` maze i neverzovane soubory). Generator z toho hlasil
# falesny SPOR. Porovnava se proto ordinalne.
$seen = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::Ordinal)
foreach ($row in $existing) {
    $hook = if ($row.PSObject.Properties['hook']) { [string]$row.hook } else { 'gate' }
    $seen[(Get-RowKey $hook $row.tool $row.cmd)] = [string]$row.expect
}

$added = New-Object System.Collections.ArrayList
$conflicts = New-Object System.Collections.ArrayList

foreach ($suite in @('gate', 'secrets')) {
    foreach ($c in (Get-SuiteCases $suite)) {
        $key = Get-RowKey $c.hook $c.tool $c.cmd
        if ($seen.ContainsKey($key)) {
            # Tyz tvar s JINYM ocekavanim = spor, ne novy radek. Rozhodnout ho musi
            # clovek: bud se zmenilo pravidlo (a patri to do hlaseni), nebo je chyba
            # v novem pripadu.
            if ($seen[$key] -ne [string]$c.expect) {
                [void]$conflicts.Add(("{0} / {1}: invariant rika {2}, sada {3}" -f $c.hook, $c.cmd, $seen[$key], $c.expect))
            }
            continue
        }
        $seen[$key] = [string]$c.expect
        $row = [ordered]@{ tool = [string]$c.tool; cmd = [string]$c.cmd
                           expect = [string]$c.expect; since = [string]$c.since }
        if ([string]$c.hook -ne 'gate') { $row['hook'] = [string]$c.hook }
        if ([string]$c.kind -ne 'cmd')  { $row['kind'] = [string]$c.kind }
        [void]$added.Add($row)
    }
}

if ($conflicts.Count -gt 0 -and $Prijmout -eq '') {
    Write-Host 'SPOR - tvar uz v invariantu je, ale s jinym ocekavanim:' -ForegroundColor Red
    foreach ($c in $conflicts) { Write-Host ("  " + $c) -ForegroundColor Red }
    Write-Host 'Nic se nezapisuje. Rozhodnuti patri cloveku.' -ForegroundColor Red
    Write-Host 'Je-li rozhodnute, prijmi ho citaci: -Prijmout "T36-N34 (i)"' -ForegroundColor Yellow
    exit 1
}

# ------------------------------------------------ -Prijmout: zmena ocekavani ---
#
# !! Zapisuje se JEN to, co generator sam oznacil za spor. Nejde tudy pridat radek,
# odebrat radek ani zmenit tvar prikazu - jen ocekavani u tvaru, ktery uz v souboru
# je a ktery sada ted tvrdi jinak. Append-only pravidlo tim drzi.
if ($Prijmout -ne '') {
    if ($conflicts.Count -eq 0) {
        Write-Host '-Prijmout: zadny spor, neni co menit.' -ForegroundColor Yellow
    } else {
        $utf8b = New-Object System.Text.UTF8Encoding($false)
        $text = [System.IO.File]::ReadAllText($invPath, $utf8b)
        $doc2 = $text | ConvertFrom-Json
        $vsechny = @($doc2.rows)

        # Mapa klic -> nove ocekavani, sestavena znovu ze SADY (ne z hlaseni o sporu:
        # to je text pro cloveka a parsovat ho zpatky by byl druhy zdroj pravdy).
        $nove = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::Ordinal)
        foreach ($suite in @('gate', 'secrets')) {
            foreach ($c in (Get-SuiteCases $suite)) {
                $nove[(Get-RowKey $c.hook $c.tool $c.cmd)] = [string]$c.expect
            }
        }

        # !! Nahrazuje se PO RADCICH uvnitr jednoho objektu, ne serializaci celeho
        # souboru: ta by preformatovala 548 radku, ktere prepsat nemam.
        #
        # !! Zmereno, ne odhadnuto: hledat radek podle `ConvertTo-Json $cmd` NEFUNGUJE -
        # PowerShell escapuje `<` a `>` jako `<` / `>`, takze tvar
        # `bash <<EOF\ngit status` se ve vygenerovanem vzoru nikdy nepotka s tim, co
        # v souboru doopravdy stoji. Klic proto vznika ROZBOREM bloku, ne jeho
        # skladanim: kazdy objekt se prelozi zpet z JSONu a porovna se hodnotami.
        $radky = $text -split "`n"
        $zmeneno = New-Object System.Collections.ArrayList
        $zacatek = -1
        for ($i = 0; $i -lt $radky.Count; $i++) {
            $l = $radky[$i]
            if ($l -match '^\s{4}\{\s*$') { $zacatek = $i; continue }
            if ($zacatek -lt 0) { continue }
            if ($l -notmatch '^\s{4}\}') { continue }

            $blokText = ($radky[$zacatek..$i] -join "`n").TrimEnd(",`r`n ".ToCharArray())
            $zacatek = -1
            $obj = $null
            try { $obj = $blokText | ConvertFrom-Json } catch { continue }
            if ($null -eq $obj -or -not $obj.PSObject.Properties['expect']) { continue }

            $hook = if ($obj.PSObject.Properties['hook']) { [string]$obj.hook } else { 'gate' }
            $key = Get-RowKey $hook $obj.tool $obj.cmd
            if (-not $nove.ContainsKey($key)) { continue }
            $stary = [string]$obj.expect
            $novy = [string]$nove[$key]
            if ($stary -eq $novy) { continue }

            # Prepise se prave ten radek `"expect"` uvnitr TOHOTO objektu.
            $trefa = $false
            for ($k = $i; $k -ge 0; $k--) {
                if ($radky[$k] -match '^(\s*"expect": )"' + [regex]::Escape($stary) + '"(,?)\s*\r?$') {
                    $radky[$k] = $Matches[1] + '"' + $novy + '"' + $Matches[2]
                    $trefa = $true
                    break
                }
            }
            if (-not $trefa) { throw ("Radek `"expect`" se nenasel u tvaru: {0}" -f $obj.cmd) }
            [void]$zmeneno.Add([pscustomobject]@{ Cmd = [string]$obj.cmd; Z = $stary; Na = $novy })
        }
        $text = $radky -join "`n"

        if ($zmeneno.Count -eq 0) {
            Write-Host '-Prijmout: spor hlasi sada, ale v souboru nic k prepsani neni.' -ForegroundColor Red
            exit 1
        }

        # Hlavicka `_zmeneno` se PRIPISUJE, nenahrazuje - je to historie rozhodnuti.
        #
        # !! Tyz mechanismus jako u radku, jen o vrstvu vys, a poprve to projelo tise:
        # slozit hledany text pres `ConvertTo-Json $stara` NEFUNGUJE, protoze PowerShell
        # escapuje `<` a `>` (`u003c`/`u003e`) - a stara hlavicka nese `bash <<EOF`.
        # `String.Replace`, ktery nic nenajde, vrati puvodni retezec BEZ CHYBY, takze
        # zapis probehl a hlavicka se nezmenila. Hleda se proto RADEK podle klice
        # a nova hodnota se serializuje az jako nahrada.
        #
        # !! TASK-106 bod 14 (0.2.0): ani ta nahrada se NESERIALIZUJE. Do 0.1.11 se cela
        # hlavicka (stara + nova veta) prohnala pres ConvertTo-Json, ktery v PS 5.1 escapuje
        # `&` a `'` a pwsh 7 ne - takze prijeti zmenilo BAJTY stare casti hlavicky podle toho,
        # kdo ho spustil, a diff ukazoval zmenu, kterou nikdo nerozhodl. Nova veta se proto
        # PRIPISUJE do stavajiciho literalu textove (jen `\`, `"` a ridici znaky escapovane);
        # stare bajty zustavaji. Kontrolni skupina: prijeti se ZMENENYM ocekavanim diff mit
        # musi - presne jeden radek `expect` a tuhle hlavicku.
        $smery = @($zmeneno | ForEach-Object { $_.Z + ' -> ' + $_.Na } | Sort-Object -Unique) -join ', '
        $novaVeta = ("{0}, {1}: {2} radkum se zmenilo ocekavani ({3}). Seznam: {4}." -f `
                     (Get-Date -Format 'yyyy-MM-dd'), $Prijmout, $zmeneno.Count, $smery,
                     (($zmeneno | ForEach-Object { $_.Cmd -replace '\r?\n', ' / ' }) -join ' - '))
        $radky2 = $text -split "`n"
        $hlavickaTrefa = $false
        for ($h = 0; $h -lt $radky2.Count; $h++) {
            if ($radky2[$h] -match '^(\s*"_zmeneno": ")(.*)("(,?)\s*\r?)$') {
                $prefix = $Matches[1]
                $staraTelo = $Matches[2]
                $suffix = $Matches[3]
                $pripis = if ($staraTelo -eq '') { ConvertTo-JsonStringBody $novaVeta } else { ConvertTo-JsonStringBody (' || ' + $novaVeta) }
                $radky2[$h] = $prefix + $staraTelo + $pripis + $suffix
                $hlavickaTrefa = $true
                break
            }
        }
        if (-not $hlavickaTrefa) { throw 'Hlavicka "_zmeneno" se v souboru nenasla.' }
        $text = $radky2 -join "`n"

        if ($WhatIf) {
            Write-Host ("-Prijmout ({0}) - zmenilo by se {1} radku:" -f $Prijmout, $zmeneno.Count) -ForegroundColor Yellow
            foreach ($z in $zmeneno) { Write-Host ("  ~ [{0} -> {1}] {2}" -f $z.Z, $z.Na, $z.Cmd) }
            exit 0
        }

        [System.IO.File]::WriteAllText($invPath, $text, $utf8b)
        $kontrola = [System.IO.File]::ReadAllText($invPath, $utf8b) | ConvertFrom-Json
        if (@($kontrola.rows).Count -ne $vsechny.Count) {
            throw ("Pocet radku se zmenil: bylo {0}, je {1}." -f $vsechny.Count, @($kontrola.rows).Count)
        }
        Write-Host ("-Prijmout ({0}): zmeneno {1} radku, pocet radku beze zmeny ({2})." -f `
                    $Prijmout, $zmeneno.Count, $vsechny.Count) -ForegroundColor Green
        foreach ($z in $zmeneno) { Write-Host ("  ~ [{0} -> {1}] {2}" -f $z.Z, $z.Na, $z.Cmd) }
    }
}

Write-Host ("Existujicich radku: {0}" -f $existing.Count)
Write-Host ("Novych radku:       {0}" -f $added.Count)

if ($added.Count -eq 0) { Write-Host 'Neni co pridat.'; exit 0 }
if ($WhatIf) {
    foreach ($r in $added) { Write-Host ("  + [{0}] {1} -> {2}" -f $r.tool, $r.cmd, $r.expect) }
    exit 0
}

# Zapis: hlavicka a existujici radky se berou z puvodniho souboru DOSLOVA (append-only),
# nove se pripoji za ne. Cely soubor se neserializuje znovu - tim by se 142 radku
# prepsalo formatovanim, a to je presne to, co se tu delat nema.
$text = [System.IO.File]::ReadAllText($invPath, $utf8)
$lastBracket = $text.LastIndexOf(']')
if ($lastBracket -lt 0) { throw 'invariants.json nema uzavirajici zavorku pole.' }
$head = $text.Substring(0, $lastBracket).TrimEnd()
$tail = $text.Substring($lastBracket)

$sb = New-Object System.Text.StringBuilder
[void]$sb.Append($head)
foreach ($r in $added) {
    [void]$sb.Append(",`n    {`n")
    $keys = @($r.Keys)
    for ($i = 0; $i -lt $keys.Count; $i++) {
        $k = $keys[$i]
        $v = ConvertTo-Json ([string]$r[$k]) -Compress
        $comma = if ($i -lt $keys.Count - 1) { ',' } else { '' }
        [void]$sb.Append(("      `"{0}`": {1}{2}`n" -f $k, $v, $comma))
    }
    [void]$sb.Append('    }')
}
[void]$sb.Append("`n  " + $tail.TrimStart())

[System.IO.File]::WriteAllText($invPath, $sb.ToString(), $utf8)

# Kontrola, ze vysledek je porad platny JSON a ze radku PRIBYLO, ne ubylo.
$check = [System.IO.File]::ReadAllText($invPath, $utf8) | ConvertFrom-Json
$after = @($check.rows).Count
Write-Host ("Po zapisu radku:    {0}" -f $after)
if ($after -ne ($existing.Count + $added.Count)) {
    throw ("Pocet radku nesedi: cekano {0}, je {1}." -f ($existing.Count + $added.Count), $after)
}
