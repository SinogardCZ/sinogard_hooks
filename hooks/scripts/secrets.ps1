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
    $msg = $script:InternalMessage
    # Nalez Amber D1: README slibovalo diagnostiku i pro secrets.ps1, kod ji nemel.
    # Sjednoceno smerem ke kodu - stejne jako v gate.ps1 je opt-in a NEOSLABUJE
    # fail-closed: blokuje se dal, jen se navic rekne proc.
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
$script:PluginRootPath = $PluginRoot

$script:ReadTools  = @('Read')
$script:WriteTools = @('Edit', 'Write', 'MultiEdit', 'NotebookEdit')
$script:CmdTools   = @('Bash', 'PowerShell')

# Write-GateAudit (od 0.2.0 v _common.ps1) cte rezim a nastroj ze scope skriptu - vychozi
# hodnoty MUSI stat driv, nez je nekdo precte (StrictMode; v tele auditu by vyjimku spolkl catch).
$script:PermissionMode = 'default'
$script:ToolName = ''

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

# ------------------------------------------------------- glob nad cestou (bod 11) ---

# Glob -> regex nad normalizovanou cestou (`/`, lowercase). `*` a `?` neprekracuji `/`,
# `**` ano. Bez kotev - ty doplnuje volajici.
function ConvertTo-GlobRegex([string]$Glob) {
    # Zastupny znak pro `**` je [char]1 - `u{...}` Windows PowerShell 5.1 nezna.
    $mark = [string][char]1
    $r = [regex]::Escape($Glob)
    $r = $r.Replace('\*\*', $mark)
    $r = $r.Replace('\*', '[^/]*').Replace('\?', '[^/]')
    return $r.Replace($mark, '.*')
}

# Miri glob na chranenou CESTU? Dve cesty k `ask`:
#   (a) `denyPathPatterns` sedne DOSLOVA na text globu - `~/.ssh/*` nese `/.ssh/`;
#   (b) glob dokaze padnout na kanonickou chranenou cestu z `protectedPaths`: posledni
#       segmenty globu se zarovnaji na segmenty kanonicke cesty (`~/.aws/*` -> `.aws/credentials`),
#       u `**` se kanonicka cesta zkousi za libovolnym prefixem.
# Glob, ktery adresar chranene cesty NEJMENUJE (`cat *`, `*.json`), na cestu nemiri - to je
# trida chranena jmenem a resi ji volajici auditem (vyrok 7).
#
# !! C1 (delta review Amber 2026-09-13, vada vyroku 7): glob, ktery na secret MIRI VZOREM
# (`*.env`, `.env*`, `*secrets.json`), je jina trida nez glob, ktery na chranene jmeno NARAZI
# NAHODOU (`*.yml` ~ `secrets.yml`). Prvni tvar 0.2.0 slil obe do auditu a `cat *.env` zacal
# mlcet - regrese proti 0.1.11 (`ask`), pricemz `permissions.deny` v GSD kryje jen tool Read.
# Rozliseni je DOSLOVNE nad textem globu, zadne cteni disku:
#   (c) `envFile.denyNames` sedne na JMENO globu (`*.env` -> `\.env$`), stejne jako `.pem`
#       sedi na `denyPathPatterns`;
#   (d) glob bez zastupnych znaku se ROVNA chranenemu jmenu (`*.env` -> `.env`, `.env*` -> `.env`,
#       `*secrets.json` -> `secrets.json`) - glob to jmeno vypisuje, ne trefuje.
# Co tim zustava mez (README 9): `cat *` a `.en?` - glob bez pripony nebo se zastupnym znakem
# uvnitr jmena deterministicky nerozlisit; audit + pojmenovana mez se spoustecem.
function Test-GlobAimsAtProtectedPath([string]$GlobNorm, $Sec) {
    if (Test-AnyPattern $GlobNorm @(Get-Field $Sec 'denyPathPatterns' @())) { return $true }
    if (Test-AnyPattern $GlobNorm @(Get-Field $Sec 'askPathPatterns' @())) { return $true }
    $globBase = Get-BaseName $GlobNorm
    if (Test-AnyPattern $globBase @(Get-Field (Get-Field $Sec 'envFile') 'denyNames' @())) { return $true }
    $literal = ($globBase -replace '[\*\?]', '')
    if ($literal -ne '') {
        foreach ($known in @(Get-Field $Sec 'protectedBaseNames' @())) {
            if ($literal -eq ([string]$known).ToLowerInvariant()) { return $true }
        }
    }
    $globRegex = '^' + (ConvertTo-GlobRegex $GlobNorm) + '$'
    $gsegs = @($GlobNorm.Split('/'))
    foreach ($p in @(Get-Field $Sec 'protectedPaths' @())) {
        $canonical = ([string]$p).ToLowerInvariant().Replace('\', '/')
        if ($canonical -eq '') { continue }
        $csegs = @($canonical.Split('/'))
        $sample = ''
        if ($GlobNorm.Contains('**')) {
            $starAt = -1
            for ($i = 0; $i -lt $gsegs.Count; $i++) { if ($gsegs[$i].Contains('**')) { $starAt = $i; break } }
            $prefix = if ($starAt -gt 0) { (@($gsegs[0..($starAt - 1)]) -join '/') + '/' } else { '' }
            $sample = $prefix + 'q/' + $canonical
        } else {
            if ($gsegs.Count -lt $csegs.Count) { continue }
            $head = @()
            if ($gsegs.Count -gt $csegs.Count) { $head = @($gsegs[0..($gsegs.Count - $csegs.Count - 1)]) }
            $sample = (@($head) + @($csegs)) -join '/'
        }
        if ([regex]::IsMatch($sample, $globRegex, 'IgnoreCase')) { return $true }
    }
    return $false
}

# --------------------------------------------------------- pravidlo cesty ---

# Absolutni normalizovana cesta: relativni se pripoji k cwd hooku, `.` a `..` se sbali ciste retezcove
# ([IO.Path]::GetFullPath nesaha na disk). Junction/symlink se NEresi (README omezeni 25).
function Get-AbsoluteNormalPath([string]$Path) {
    $n = ConvertTo-NormalPath $Path
    if ($n -eq '') { return '' }
    if ($n -notmatch '^([a-z]:/|/)') {
        $cwd = ConvertTo-NormalPath ([string]$script:Cwd)
        if ($cwd -ne '') { $n = $cwd.TrimEnd('/') + '/' + $n }
    }
    # R2 (/code-review kolo 2): `\` je oddelovac jen na Windows - jinde je to znak jmena a `..` by se nesbalilo.
    $sep = [System.IO.Path]::DirectorySeparatorChar
    try { $n = ([System.IO.Path]::GetFullPath($n.Replace([char]47, $sep))).Replace($sep, [char]47).ToLowerInvariant() } catch { }
    return $n
}

# Meni prikaz pracovni adresar pred zapisem? Pak relativni cil nejde dosadit k cwd hooku (R2, /code-review kolo 2:
# `Set-Location <kopie pluginu>; Set-Content hooks/hooks.json '{}'`).
function Test-CwdChange([string]$Command) {
    return [regex]::IsMatch([string]$Command, '(?i)(^|[\s;&|({])(cd|chdir|pushd|popd|set-location|sl|push-location|pop-location)(\s|;|$)')
}
$script:CwdUncertain = $false

function Test-SecretPath([string]$Path, [bool]$IsWrite, $Config, [bool]$AllowGlob = $true) {
    $sec = Get-Field $Config 'secrets'
    $shapes = Get-Field $sec 'shapes'
    $norm = ConvertTo-NormalPath $Path
    if ($norm -eq '') { return $null }
    $base = Get-BaseName $norm

    # Nalez Metis 21: `Get-Content .en?` shell rozvine na `.env`, ale kontrola vidi
    # `.en?`. Zastupny znak je neznamy cil -> Z3: ask. POZOR: ale NE u kazdeho globu:
    # `ls *.md` nebo `grep x *.ts` by se ptalo pokazde a takova brana se do tydne
    # vypne. Ptame se jen tehdy, kdyz ten glob DOKAZE padnout na chranene jmeno.
    # Nalez N26 (Tom, ziva ukazka): glob se vyhodnocoval i nad textem, ktery zadna
    # cesta neni. `git commit -m "**2**"` (hvezdicky z markdownu) dalo glob `**2**`,
    # ten sedne na `server.p12` a hook se ZEPTAL na commit message. Vyhodnocuje se
    # proto jen tam, kde glob DOOPRAVDY rozvine shell: nad NEUVOZENYM tokenem
    # v pozici cesty u prikazu, ktery soubory cte nebo kopiruje. Detail u
    # Get-PathCandidate; sem prichazi uz jen vysledek.
    #
    # TASK-106 bod 11 (0.2.0; N16 = navrh Hestie prijaty vyrokem 8 Amber 2026-09-12 v mandatu
    # Toma, N26 = vyrok 7): glob se posuzuje podle CELE normalizovane cesty, ne jen podle
    # jmena. Do 0.1.11 se `*.yml` srovnavalo se `secrets.yml` bez ohledu na adresar, takze
    # `head .github/workflows/*.yml` a `ls docs/technical/*.json` koncily dotazem (2 ze 3
    # dotazu `wildcardPath` ve vzorku faze 1; treti byl `echo **2` z doby pred N26).
    #   - trida chranena CESTOU (`denyPathPatterns` doslova nad textem globu, nebo glob, ktery
    #     MIRI na kanonickou chranenou cestu z `protectedPaths`) -> `ask` jako dosud;
    #   - trida chranena JMENEM (`protectedBaseNames` sedne na posledni segment) -> AUDIT:
    #     hook mlci a zapise radek `secrets:wildcardName` (ne ticho bez stopy - bez zaznamu
    #     by se nikdy nezjistilo, jak casto k tomu doslo; ctenar auditu je od 0.2.0 kanarek
    #     a tests/_audit-report.ps1).
    # Semantika (N16): `*` a `?` neprekracuji `/`, `**` ano, kotvi se na hranici adresare -
    # tvar gitignore/pathspec, tedy tyz, jaky uz maji `denyPathPatterns`. Mez a spoustec
    # prehodnoceni (fixture adresar u invariantu) nese README.
    if ($AllowGlob -and $norm -match '[\*\?]') {
        if (Test-GlobAimsAtProtectedPath $norm $sec) {
            return @{ Id = 'wildcardPath'; Decision = 'ask'
                      Shape = (([string](Get-Field $shapes 'wildcardPath' '{path}')).Replace('{path}', [string]$Path)) }
        }
        $globRegex = '^' + (ConvertTo-GlobRegex $base) + '$'
        foreach ($known in @(Get-Field $sec 'protectedBaseNames' @())) {
            if ([regex]::IsMatch([string]$known, $globRegex, 'IgnoreCase')) {
                Write-GateAudit $script:ToolName 'secrets:wildcardName' 'allow' $Config
                return $null
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
            return @{ Id = 'secretFile'; Decision = 'deny'
                      Shape = (([string](Get-Field $shapes 'secretFile' '{path}')).Replace('{path}', [string]($Path))) }
        }
        $rel = Get-RelativeToCwd $norm (ConvertTo-NormalPath $script:Cwd)
        if (Test-GitTracked $script:Cwd $rel) { return $null }
        return @{ Id = 'envFileUntracked'; Decision = 'ask'
                  Shape = (([string](Get-Field $shapes 'envFileUntracked' '{path}')).Replace('{path}', [string]($Path))) }
    }

    # (2) tvrde zakazane tvary
    if (Test-AnyPattern $norm @(Get-Field $sec 'denyPathPatterns' @())) {
        return @{ Id = 'secretFile'; Decision = 'deny'
                  Shape = (([string](Get-Field $shapes 'secretFile' '{path}')).Replace('{path}', [string]($Path))) }
    }

    # (3) sebeochrana - soubory, kterymi se brana vypina (jen zapis)
    # Z117-Q23 = A (Tom 2026-10-08): konfigurace pluginu je chranena jen v NAINSTALOVANE kopii (`.claude/plugins/`),
    # ne ve vyvojovem klonu. Aby to neslo obejit relativni cestou z adresare kopie nebo `..`, posuzuje se navic
    # ABSOLUTNI cesta (relativni vuci cwd, `..` sbalene) - vzory se zkousi nad obema tvary.
    # R2 (/code-review kolo 2): navic (a) cokoli pod korenem PRAVE BEZICIHO pluginu (`$PluginRoot` - pokryje i
    # `--plugin-dir` a jiny CLAUDE_CONFIG_DIR) a (b) relativni cil v prikazu, ktery meni adresar - tam se cwd hooku
    # nevi, takze plati vzor 0.2.0 (`hooks/hooks.json`, `hooks/config/*` kdekoli).
    $abs = Get-AbsoluteNormalPath $Path
    $rootNorm = (ConvertTo-NormalPath $script:PluginRootPath).TrimEnd('/')
    $underRoot = ($rootNorm -ne '' -and $abs.StartsWith($rootNorm + '/hooks/'))
    $relUncertain = ($script:CwdUncertain -and $norm -notmatch '^([a-z]:/|/)' -and
                     $norm -match '(^|/)hooks/(hooks\.json|config/[^/]+)$')
    if ($IsWrite -and ($underRoot -or $relUncertain -or (Test-AnyPattern $norm @(Get-Field $sec 'selfProtectPathPatterns' @())) -or
                       (Test-AnyPattern $abs @(Get-Field $sec 'selfProtectPathPatterns' @())))) {
        return @{ Id = 'selfProtect'; Decision = 'ask'
                  Shape = (([string](Get-Field $shapes 'selfProtect' '{path}')).Replace('{path}', [string]($Path))) }
    }

    # (4) seda zona
    if (Test-AnyPattern $norm @(Get-Field $sec 'askPathPatterns' @())) {
        return @{ Id = 'settingsLocal'; Decision = 'ask'
                  Shape = (([string](Get-Field $shapes 'settingsLocal' '{path}')).Replace('{path}', [string]($Path))) }
    }

    return $null
}

# ------------------------------------------------------- pravidlo prikazu ---

# Vytahne z prikazu tokeny v POZICI CESTY (TASK-106 bod 12, 0.2.0). Do 0.1.11 byl kandidatem
# kazdy token s teckou nebo lomitkem a kazdy retezec v uvozovkach - takze `$_.Key`,
# `SelectOption.Key` (identifikatory, N-H1: 3 ze 7 deny ve vzorku faze 1 vcetne mericiho
# prikazu) i proza v tele heredocu (`cat >> notes.md <<EOF` se jmeny `id_rsa`, `secrets.json`)
# koncily `deny secretFile`. Pozice cesty je:
#   (P1) cil presmerovani `<`, `>`, `>>` (cil `>`-tvaru je ZAPIS - i `2> soubor`; `2>&1` je
#        duplikace deskriptoru, ne soubor),
#   (P2) hodnota prepinace `--opt=hodnota`,
#   (P3) pozicni argument prikazu z `secrets.pathCommands` (cte/kopiruje soubory) - siroky
#        test (lomitko, tecka, `~`, `%`, `id_`, glob) a JEN TADY se vyhodnocuje glob (N26),
#   (P4) pozicni argument prikazu ze `secrets.writeCommands` (`tee`, `Set-Content`, ...) = ZAPIS,
#   (P5) pozicni argument JINEHO prikazu jen tehdy, kdyz token VYPADA jako cesta: lomitko, `~`,
#        `%`, tecka NA ZACATKU, prefix `id_` nebo presne chranene jmeno (`server.key`); bez mezer,
#   (a)  retezec v uvozovkach (literal ve vyrazu, Metis 23/24) tymz testem jako P5.
# N14 je podminka, ne bonus: `< ~/.ssh/id_rsa` (P1), `--file=~/.ssh/id_rsa` (P2), cesta v roure
# nebo pres xargs (P5 - lomitko) i heredoc pro shell/interpret zustavaji deny.
# Zapis (bod 9 + N-H3) je od 0.2.0 vlastnost KANDIDATA, ne prikazu: do 0.1.11 jeden priznak
# `$isWrite` nad celym textem udelal z `cat ~/.claude/settings.json 2>/dev/null` "zapis do
# souboru, kterym se brana vypina" (2x ve vzorku faze 1).
$script:PathReadCommandsFallback = @(
    'cat', 'type', 'get-content', 'gc', 'more', 'less', 'head', 'tail',
    'cp', 'copy', 'copy-item', 'mv', 'move', 'move-item',
    'ls', 'dir', 'get-childitem', 'gci', 'get-item', 'gi',
    'compress-archive', 'tar', 'zip', 'scp', 'rsync', 'findstr', 'select-string',
    'openssl', 'ssh-keygen', 'keytool', 'certutil', 'gpg'
)
$script:WriteCommandsFallback = @('tee', 'set-content', 'sc', 'out-file', 'add-content', 'ac')

# Siroky test cesty - pro prikazy, ktere soubory ctou (P3), cile presmerovani (P1) a hodnoty
# prepinacu (P2): tam je kazdy token s teckou nebo lomitkem pravdepodobne soubor.
function Test-PathLikeBroad([string]$Token) {
    return ($Token.Contains('/') -or $Token.Contains('\') -or
            $Token.StartsWith('.') -or $Token.StartsWith('~') -or $Token.StartsWith('%') -or
            $Token.Contains('.') -or $Token -match '^id_' -or
            $Token.Contains('*') -or $Token.Contains('?'))
}

# Uzky test cesty - pro pozicni argumenty OSTATNICH prikazu a pro literaly v uvozovkach (P5, a).
# `entityType.Key` ani `console.log(obj.key)` cestou nejsou; `.env`, `~/.aws/x`, `id_rsa`
# a presne chranene jmeno (`server.key` u `openssl -in`) ano. Token s mezerou je proza.
function Test-PathLikeStrict([string]$Token, $ProtectedNamesLower) {
    if ($Token -eq '' -or $Token -match '\s') { return $false }
    if ($Token.Contains('/') -or $Token.Contains('\')) { return $true }
    if ($Token.StartsWith('.') -or $Token.StartsWith('~') -or $Token.StartsWith('%')) { return $true }
    if ($Token -match '^id_') { return $true }
    if ($ProtectedNamesLower -contains $Token.ToLowerInvariant()) { return $true }
    return $false
}

# Telo heredocu, jehoz host je DATOVY prikaz (`cat >> x <<EOF`, `git commit -F - <<EOF`, `tee`),
# jsou data, ne cesty - proza v hlaseni nebo commit message se do rozboru nebere (bod 12, N-H6
# druhy nositel). Telo pro shell, interpret nebo NEZNAMY host je kod a rozebira se dal
# (`bash <<EOF / cat .env`, `python - <<PY / open('.env')`). Uvozujici radek se rozebira vzdy.
# Host je prvni token statementu, ve kterem `<<` stoji, po preskoceni obalu (`sudo`, `env`, ...);
# neznamy host = kod, tedy smerem k prisnosti.
function Remove-DataHeredocBody([string]$Command, $Config) {
    if ([string]::IsNullOrWhiteSpace($Command) -or $Command -notmatch '<<') { return $Command }
    $sec = Get-Field $Config 'secrets'
    $dataHosts = @(Get-Field $sec 'dataHeredocHosts' @('cat', 'tee', 'git'))
    $wrappers = @('sudo', 'doas', 'env', 'nice', 'nohup', 'time', 'timeout', 'command', 'builtin', 'exec', 'stdbuf')

    $joined = [regex]::Replace($Command, [regex]::Escape((Get-ScannerEscape)) + '\r?\n', ' ')
    $lines = [regex]::Split($joined, '\r?\n')
    $keep = New-Object System.Collections.ArrayList
    $i = 0
    while ($i -lt $lines.Count) {
        $line = $lines[$i]
        if (-not (Test-HeredocOutsideQuotes $line)) { [void]$keep.Add($line); $i++; continue }
        $ms = [regex]::Matches($line, $script:HeredocPattern)
        if ($ms.Count -eq 0) { [void]$keep.Add($line); $i++; continue }
        [void]$keep.Add($line)

        $delims = New-Object System.Collections.ArrayList
        foreach ($mm in $ms) {
            foreach ($g in 1, 2, 3) { if ($mm.Groups[$g].Success) { [void]$delims.Add($mm.Groups[$g].Value) } }
        }
        $outer = [regex]::Replace($line, $script:HeredocPattern, ' ')
        $stages = @(Split-Statement $outer)
        $j = $i + 1
        for ($d = 0; $d -lt $delims.Count; $d++) {
            $delim = [string]$delims[$d]
            $body = New-Object System.Collections.ArrayList
            while ($j -lt $lines.Count -and $lines[$j].Trim() -ne $delim) { [void]$body.Add($lines[$j]); $j++ }
            $stage = if ($d -lt $stages.Count) { [string]$stages[$d] } else { $outer }
            $hostExe = ''
            foreach ($tok in (Split-Arguments $stage)) {
                if ($tok.StartsWith('-')) { continue }
                $name = Get-ExecutableName $tok
                if ($wrappers -contains $name) { continue }
                $hostExe = $name; break
            }
            if ($dataHosts -notcontains $hostExe) { foreach ($b in $body) { [void]$keep.Add($b) } }
            $j++   # radek s ukoncovacim delimiterem
        }
        $i = $j
    }
    return ($keep -join "`n")
}

# N-C (TASK-117): zavorka seskupeni na okraji tokenu (`(Get-ChildItem`, `<soubor>)`) do cesty
# nepatri. Vedouci `(` se strhne vzdy, koncova `)` jen tehdy, kdyz je v tokenu NAVIC - `foo(1)`
# zustava cele.
function Remove-GroupingParen([string]$Token) {
    $x = [string]$Token
    if ($x.StartsWith('(')) { $x = $x.TrimStart('(') }
    while ($x.EndsWith(')')) {
        $open = @($x.ToCharArray() | Where-Object { $_ -eq '(' }).Count
        $close = @($x.ToCharArray() | Where-Object { $_ -eq ')' }).Count
        if ($close -le $open) { break }
        $x = $x.Substring(0, $x.Length - 1)
    }
    return $x
}

# N-C (TASK-117): obsah zavorkoveho seskupeni `( ... )` a `@( ... )` je SPUSTENY prikaz (PowerShell
# vyhodnoti seskupeni pred volanim, Bash `( ... )` je subshell). `$( ... )`, `<( ... )` a `>( ... )`
# uz rozebira Split-CommandLine. Volani metody nebo funkce (`.Replace(...)`, `foo(...)`,
# `[IO.File]::ReadAllText(...)`) seskupenim neni - zavorka hned za slovem, `]` nebo `)` se
# preskoci (jeho literal v uvozovkach chyta Get-PathCandidate bod (a)). Kvotove korektne.
function Get-GroupingSubcommand([string]$Text, [int]$Depth) {
    $out = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrEmpty($Text) -or $Depth -gt 5) { return ,@($out) }
    $esc = Get-ScannerEscape
    $inSingle = $false
    $inDouble = $false
    $i = 0
    $n = $Text.Length
    while ($i -lt $n) {
        $c = $Text[$i]
        if ($inSingle) { if ($c -eq "'") { $inSingle = $false }; $i++; continue }
        if ($c -eq $esc -and ($i + 1) -lt $n) { $i += 2; continue }
        if ($c -eq '"') { $inDouble = -not $inDouble; $i++; continue }
        if ($c -eq "'" -and -not $inDouble) { $inSingle = $true; $i++; continue }
        if ($c -eq '(') {
            $prev = if ($i -gt 0) { $Text[$i - 1] } else { ' ' }
            $isGroup = -not ([char]::IsLetterOrDigit($prev) -or $prev -eq '_' -or $prev -eq ']' -or
                             $prev -eq ')' -or $prev -eq '.' -or $prev -eq '$' -or $prev -eq '<' -or $prev -eq '>')
            $j = Find-CloseParen $Text ($i + 1)
            if ($isGroup) {
                $len = [Math]::Max(0, ($j - 1) - ($i + 1))
                if ($len -gt 0) {
                    $body = $Text.Substring($i + 1, $len)
                    foreach ($s in (Split-CommandLine $body)) { [void]$out.Add($s) }
                    foreach ($s in (Get-GroupingSubcommand $body ($Depth + 1))) { [void]$out.Add($s) }
                }
                $i = $j; continue
            }
        }
        $i++
    }
    return ,@($out)
}

# Z117-Q25 = A (Tom 2026-10-08 21:24): kam kopie / presun ZAPISE. Cil = hodnota `-Destination` (i `-Destination:x`
# a zkratky `-Des...`, ktere PowerShell prijme), cil `-t` / `--target-directory` (GNU), jinak POSLEDNI pozicni argument.
# Adresarovy cil se slozi s jmenem kazdeho zdroje (`cp settings.json .claude/` zapise `.claude/settings.json`) - bez
# cteni disku se proto skladani dela VZDY, i kdyz cil soubor je (`b` i `b/a` jsou kandidati zapisu; neskodne).
# `xcopy` = tytez pravidla (prepinace `/x`); `robocopy <zdroj> <cil> [soubory]` = cil + cil/<soubor> pro kazdy soubor.
# Mimo: glob v cili (`robocopy x .claude *.json`) - kandidat nese `*` a vzory chranenych cest na nem nesednou.
# Z117-Q26 = A (A117-N5): podprikazy z tel slozenych zavorek (kvotove korektne - Get-ScriptBlockBodies; `@{ }`,
# `${x}`, `stash@{0}` blok neotviraji), rekurzivne vcetne seskupeni uvnitr tela.
function Get-BraceSubcommand([string]$Text, [int]$Depth) {
    $out = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Text) -or $Depth -gt 5 -or -not $Text.Contains('{')) { return ,@($out) }
    foreach ($blk in (Get-ScriptBlockBodies $Text).Blocks) {
        $body = [string]$blk.Body
        foreach ($s in (Split-CommandLine $body)) {
            [void]$out.Add($s)
            foreach ($s2 in (Get-BraceSubcommand ([string]$s) ($Depth + 1))) { [void]$out.Add($s2) }
        }
        foreach ($s in (Get-GroupingSubcommand $body ($Depth + 1))) { [void]$out.Add($s) }
    }
    return ,@($out)
}

$script:CopyMoveExe = @('cp', 'copy', 'copy-item', 'cpi', 'mv', 'move', 'move-item', 'mi', 'xcopy')
function Get-CopyWriteTarget($Tokens, [string]$Exe) {
    $out = New-Object System.Collections.ArrayList
    $isRobo = ($Exe -eq 'robocopy')
    if (-not $isRobo -and $script:CopyMoveExe -notcontains $Exe) { return ,@($out) }
    $winSwitch = ($isRobo -or $Exe -eq 'xcopy' -or $Exe -eq 'copy' -or $Exe -eq 'move')
    $positional = New-Object System.Collections.ArrayList
    $sources = New-Object System.Collections.ArrayList
    $targetDirs = New-Object System.Collections.ArrayList
    $dest = $null
    $n = $Tokens.Count
    for ($i = 1; $i -lt $n; $i++) {
        $t = Remove-GroupingParen ([string]$Tokens[$i])
        if ($t -eq '') { continue }
        if ($t -match '^(?i)-des[a-z]*$') { if (($i + 1) -lt $n) { $dest = Remove-GroupingParen ([string]$Tokens[$i + 1]); $i++ }; continue }
        if ($t -ceq '-t' -or $t -match '^(?i)--target-directory$') { if (($i + 1) -lt $n) { [void]$targetDirs.Add([string]$Tokens[$i + 1]); $i++ }; continue }
        if ($t -match '^(?i)--target-directory=(.+)$') { [void]$targetDirs.Add($Matches[1]); continue }
        if ($t -match '^(?i)-(path|literalpath|lp|pspath)$') { if (($i + 1) -lt $n) { [void]$sources.Add([string]$Tokens[$i + 1]); $i++ }; continue }
        if ($t -match '^(?i)-(filter|include|exclude|credential|tosession|fromsession|suffix|backup)$') { $i++; continue }
        if ($t.StartsWith('-')) { continue }
        if ($winSwitch -and $t -match '^/[A-Za-z][A-Za-z0-9]{0,5}(:.*)?$') { continue }
        [void]$positional.Add($t)
    }
    $targets = New-Object System.Collections.ArrayList
    if ($isRobo) {
        if ($positional.Count -lt 2) { return ,@($out) }
        $dst = [string]$positional[1]
        [void]$out.Add($dst)
        for ($k = 2; $k -lt $positional.Count; $k++) { [void]$out.Add($dst.TrimEnd('/', '\') + '/' + [string]$positional[$k]) }
        return ,@($out)
    }
    if ($null -ne $dest) {
        [void]$targets.Add($dest)
        foreach ($p in $positional) { [void]$sources.Add($p) }
    } elseif ($targetDirs.Count -gt 0) {
        foreach ($p in $positional) { [void]$sources.Add($p) }
    } elseif ($positional.Count -ge 2 -or ($positional.Count -ge 1 -and $sources.Count -gt 0)) {
        [void]$targets.Add($positional[$positional.Count - 1])
        for ($k = 0; $k -lt $positional.Count - 1; $k++) { [void]$sources.Add($positional[$k]) }
    }
    foreach ($tg in $targets) { [void]$out.Add([string]$tg) }
    $dirs = @($targets) + @($targetDirs)
    foreach ($d in $dirs) {
        foreach ($s in $sources) {
            $leaf = (([string]$s) -replace '\\', '/').TrimEnd('/')
            $leaf = $leaf.Substring($leaf.LastIndexOf('/') + 1)
            if ($leaf -ne '') { [void]$out.Add(([string]$d).TrimEnd('/', '\') + '/' + $leaf) }
        }
    }
    return ,@($out)
}

function Get-PathCandidate([string]$Command, $Config = $null) {
    $out = New-Object System.Collections.ArrayList
    $sec = $null
    if ($null -ne $Config) { $sec = Get-Field $Config 'secrets' }
    $pathCommands  = @(Get-Field $sec 'pathCommands' $script:PathReadCommandsFallback)
    $writeCommands = @(Get-Field $sec 'writeCommands' $script:WriteCommandsFallback)
    $protectedLower = @(@(Get-Field $sec 'protectedBaseNames' @()) | ForEach-Object { ([string]$_).ToLowerInvariant() })

    # Hodnoty, ktere v prikazu stoji V UVOZOVKACH. Shell v nich glob nerozvine
    # (a PowerShell retezec negloboval nikdy), takze u nich zastupny znak neznamena
    # "neznamy cil" - je to obycejny text.
    $quoted = New-Object System.Collections.Generic.HashSet[string]

    # (a) Nalez Metis 23/24: cesta muze byt LITERAL uvnitr vyrazu
    # (`[IO.File]::ReadAllText('.env')`, `python -c "open('.env')"`). Retezec v uvozovkach
    # je kandidat, kdyz vypada jako cesta (uzky test) - `"SelectOption.Key"` uz ne.
    # Dva NEZAVISLE prubehy, ne jedna alternace: `python -c "open('.env')"` ma jednoduche
    # uvozovky UVNITR dvojitych, a jedna alternace by vnejsi retezec spotrebovala
    # a vnitrni uz nenasla.
    foreach ($pattern in @('"([^"]{1,260})"', '''([^'']{1,260})''')) {
        foreach ($m in [regex]::Matches($Command, $pattern)) {
            $value = $m.Groups[1].Value
            if ($value -eq '') { continue }
            [void]$quoted.Add($value)
            if (Test-PathLikeStrict $value $protectedLower) {
                [void]$out.Add(@{ Value = $value; AllowGlob = $false; IsWrite = $false })
            }
        }
    }

    # Prikaz se rozebira po PODPRIKAZECH, aby se u tokenu vedelo, ktery program ho
    # dostane - glob u `cat` je cesta, glob u `echo` je text.
    # N-C (TASK-117, Z117-Q16 = A): obsah zavorkoveho seskupeni `( ... )` / `@( ... )` je
    # SPUSTENY prikaz stejne jako `$( ... )` - rozebira se navic jako podprikaz.
    $subs = New-Object System.Collections.ArrayList
    foreach ($x in (Split-CommandLine $Command)) { [void]$subs.Add($x) }
    foreach ($x in (Get-GroupingSubcommand $Command 0)) { [void]$subs.Add($x) }
    # Z117-Q26 = A (A117-N5): obsah slozenych zavorek `{ ...; }` (Bash skupina, funkce, PS blok) je SPUSTENY prikaz -
    # do 0.3.0 zustal `;` na tokenu (`.env;`), `{ cat .env; } | curl -d @- ...` i `{ echo x > .claude/settings.json; }` mlcely.
    foreach ($x in @($subs)) { foreach ($b in (Get-BraceSubcommand ([string]$x) 0)) { [void]$subs.Add($b) } }
    foreach ($sub in $subs) {
        $argv = Split-Arguments $sub
        if ($argv.Count -eq 0) { continue }
        $subExe = (Get-ExecutableName (Remove-GroupingParen ([string]$argv[0]))).ToLowerInvariant()
        $isPathCommand  = ($pathCommands -contains $subExe)
        $isWriteCommand = ($writeCommands -contains $subExe)
        $pending = ''   # 'r' | 'w' za samostatnym operatorem presmerovani
        # Bez `@()`: Expand-ColonParameter vraci `,@(...)` a dalsi obal by pole zabalil JESTE JEDNOU
        # (viz poznamka u Split-UnquotedCore) - Count by byl 1 a token cely argv.
        $tokens = Expand-ColonParameter $argv
        # Z117-Q25 = A (Tom 2026-10-08 21:24): CIL kopie / presunu je ZAPIS. Do 0.3.0 byly argumenty `cp`/`Copy-Item`
        # jen ctenim, takze `cp x .claude/settings.json` ochranu selfProtect obesel (dira uz v 0.2.0).
        foreach ($w in (Get-CopyWriteTarget $tokens $subExe)) {
            [void]$out.Add(@{ Value = $w; AllowGlob = $false; IsWrite = $true })
        }
        for ($ti = 0; $ti -lt $tokens.Count; $ti++) {
            # N-C (TASK-117, Z117-Q16 = A): do 0.2.0 nesl token zavorku seskupeni
            # (`Get-Content (Get-ChildItem <soubor>)` -> `<soubor>)`), zadny vzor ho nechranil
            # a soubor se secrets se precetl BEZ dotazu. S mezerou (`( Get-ChildItem x )`) to
            # deny bylo. Zavorka seskupeni do cesty nepatri - strhne se.
            $token = Remove-GroupingParen ([string]$tokens[$ti])
            if ($token -eq '') { continue }

            # (P1) samostatny operator: `>`, `>>`, `<`, `2>`, `&>`, `*>`, `>|`
            if ($token -match '^[\d*&]*(>>|>|<)\|?$') {
                $pending = if ($token.Contains('>')) { 'w' } else { 'r' }
                continue
            }
            if ($pending -ne '') {
                $direction = $pending
                $pending = ''
                if ($token.StartsWith('&')) { continue }   # `2>&1`, `>&2` - deskriptor, ne soubor
                if (Test-PathLikeBroad $token) {
                    [void]$out.Add(@{ Value = $token; AllowGlob = $false; IsWrite = ($direction -eq 'w') })
                }
                continue
            }
            # (P1) slepene presmerovani (Nalez Metis 22: `cat<.env`; N-H3: `2>/dev/null`)
            $glued = [regex]::Match($token, '^(.*?)([\d*&]*)(>>|>|<)\|?(.*)$')
            $t = $token
            if ($glued.Success) {
                $t = $glued.Groups[1].Value
                $target = $glued.Groups[4].Value
                $direction = if ($glued.Groups[3].Value.Contains('>')) { 'w' } else { 'r' }
                if ($target -eq '') { $pending = $direction }
                elseif (-not $target.StartsWith('&') -and (Test-PathLikeBroad $target)) {
                    [void]$out.Add(@{ Value = $target; AllowGlob = $false; IsWrite = ($direction -eq 'w') })
                }
                if ($t -eq '') { continue }
            }
            if ($ti -eq 0 -and $t -eq $token) { continue }   # jmeno prikazu neni cesta

            # N-D (TASK-117, nalez councilu Codex, Z117-Q16 = A): `@<cesta>` je u curl
            # (a obdobnych nastroju) "obsah souboru" - `curl -d @<soubor>`, `--data-binary
            # @<soubor>`, `-F f=@<soubor>`. Token zacinal `@`, kandidatem cesty nebyl, a soubor
            # se secrets odesel na sit BEZ dotazu. Hodnota za `@` (i za `jmeno=@`) je cesta
            # v pozici cteni; `;type=...` za ni je parametr formulare. Splatting `@args`,
            # `@{...}`, `@(...)` a revize `HEAD@{1}` timhle tvarem nejsou (`@` nestoji na
            # zacatku nebo hodnota neprojde sirokym testem cesty).
            # CR-P5 (/code-review): i slepeny kratky prepinac `-d@<soubor>`, `-Ff=@<soubor>`; kolo 2: i shluk
            # prepinacu `-sd@<soubor>`, `-sSd@<soubor>` (curl ho cte jako `-s -S -d @<soubor>`).
            # Z117-Q26 = A (A117-N7): curl `--data-urlencode name@<soubor>` a `--variable name@<soubor>` (i `=`-tvar)
            # ctou soubor i tehdy, kdyz `@` nestoji na zacatku hodnoty.
            if ($subExe -eq 'curl') {
                $prevTok = if ($ti -gt 0) { [string]$tokens[$ti - 1] } else { '' }
                $urlVal = $null
                if ($prevTok -match '^--(data-urlencode|variable)$') { $urlVal = $t }
                elseif ($t -match '^--(data-urlencode|variable)=(.+)$') { $urlVal = $Matches[2] }
                if ($null -ne $urlVal) {
                    $um = [regex]::Match($urlVal, '^[^@=]*=?@([^@;]+)')
                    if (-not $um.Success) { $um = [regex]::Match($urlVal, '^[^@]*@([^@;]+)') }
                    if ($um.Success -and (Test-PathLikeBroad $um.Groups[1].Value)) {
                        [void]$out.Add(@{ Value = $um.Groups[1].Value; AllowGlob = $false; IsWrite = $false })
                        continue
                    }
                }
            }
            $at = [regex]::Match($t, '^(?:-{1,2}[A-Za-z][A-Za-z0-9-]*=|-[A-Za-z]+)?(?:[A-Za-z0-9_.\-]*=)?@([^@{(;][^;]*)')
            if ($at.Success) {
                $atPath = $at.Groups[1].Value
                if (Test-PathLikeBroad $atPath) {
                    [void]$out.Add(@{ Value = $atPath; AllowGlob = $false; IsWrite = $false })
                }
                continue
            }

            # (P2) hodnota prepinace `--opt=hodnota`
            if ($t.StartsWith('-')) {
                $eq = $t.IndexOf('=')
                if ($eq -lt 0) { continue }
                $t = $t.Substring($eq + 1)
                if ($t -ne '' -and (Test-PathLikeBroad $t)) {
                    [void]$out.Add(@{ Value = $t; AllowGlob = $false; IsWrite = $false })
                }
                continue
            }
            # git show <ref>:<cesta>  (ale ne disk C:\...)
            if ($t -notmatch '^[A-Za-z]:[\\/]' -and $t -match '^[^/\\]+:[^\\/:]') {
                $t = $t.Substring($t.LastIndexOf(':') + 1)
            }
            if ($t -eq '') { continue }

            if ($isPathCommand) {
                # (P3) Nalez Metis 2: `Get-Content id_rsa` - hole jmeno bez lomitka a bez tecky
                # na zacatku se drive kandidatem nestalo. Glob se vyhodnoti jen u NEUVOZENEHO
                # tokenu (nalez N26).
                if (Test-PathLikeBroad $t) {
                    [void]$out.Add(@{ Value = $t; AllowGlob = (-not $quoted.Contains($t)); IsWrite = $false })
                }
                continue
            }
            if ($isWriteCommand) {
                # (P4) `tee x`, `Set-Content x`, `Out-File x` - cil je zapis
                if (Test-PathLikeBroad $t) {
                    [void]$out.Add(@{ Value = $t; AllowGlob = $false; IsWrite = $true })
                }
                continue
            }
            # (P5) jiny prikaz: jen token, ktery vypada jako cesta
            if (Test-PathLikeStrict $t $protectedLower) {
                [void]$out.Add(@{ Value = $t; AllowGlob = $false; IsWrite = $false })
            }
        }
    }
    return ,@($out)
}

# Z117-Q23 = A (c) (Tom 2026-10-08): `Get-ChildItem Env: | Where-Object Name -like 'GSD_TEST*' | Select-Object
# -ExpandProperty Name` vypise jen JMENA promennych - do 0.2.0 dotaz `envDump`, jako by vypisoval hodnoty.
# Statement mlci, kdyz vypis prostredi tece JEN do filtru podle jmena a konci projekci na jmeno (nebo poctem);
# filtr podle hodnoty, skript-blok, cokoli dalsiho nebo vypis bez projekce = envDump jako dosud.
function Test-EnvNamesOnly([string]$Statement) {
    $stages = @(Split-Pipe $Statement)
    if ($stages.Count -lt 2) { return $false }
    if (([string]$Statement).Contains('{') -or ([string]$Statement).Contains('$')) { return $false }
    $a0 = Split-Arguments ([string]$stages[0])
    if ($a0.Count -ne 2) { return $false }
    if (@('get-childitem', 'gci', 'dir', 'ls') -notcontains (Get-ExecutableName $a0[0])) { return $false }
    if ([string]$a0[1] -notmatch '^env:[\\/*]*$') { return $false }
    for ($i = 1; $i -lt $stages.Count; $i++) {
        $a = Split-Arguments ([string]$stages[$i])
        if ($a.Count -eq 0) { return $false }
        $exe = ([string]$a[0]).ToLowerInvariant()
        $last = ($i -eq $stages.Count - 1)
        if (-not $last) {
            if (@('where-object', 'where', '?') -contains $exe -and $a.Count -eq 4 -and [string]$a[1] -ieq 'Name' -and
                [string]$a[2] -match '^(?i)-(c|i)?(like|notlike|match|notmatch|eq|ne)$') { continue }
            if (@('sort-object', 'sort') -contains $exe -and ($a.Count -eq 1 -or ($a.Count -eq 2 -and [string]$a[1] -ieq 'Name'))) { continue }
            return $false
        }
        if (@('select-object', 'select') -contains $exe) {
            $rest = @($a | Select-Object -Skip 1 | ForEach-Object { ([string]$_).ToLowerInvariant() })
            return (($rest -join ' ') -match '^(-expandproperty |-property )?name$')
        }
        if (@('foreach-object', '%', 'foreach') -contains $exe) { return ($a.Count -eq 2 -and [string]$a[1] -ieq 'Name') }
        if (@('measure-object', 'measure') -contains $exe) { return ($a.Count -eq 1) }
        return $false
    }
    return $false
}

function Test-EnvironmentDump([string]$Command) {
    $kept = New-Object System.Collections.ArrayList
    # R2 (/code-review kolo 2): zastineni `measure` / `select` / `%` aliasem nebo funkci v temze prikazu
    # (`Set-Alias measure Format-List; gci env: | measure`) vyjimku rusi - tataz pojistka jako u jmenujicich tvaru.
    $namesOnlyAllowed = -not (Test-NamingDisqualified $Command)
    foreach ($st in @(Split-Statement $Command)) { if (-not ($namesOnlyAllowed -and (Test-EnvNamesOnly $st))) { [void]$kept.Add($st) } }
    $Command = ($kept -join "`n")
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

# ------------------------------------------- polozka 7: prikaz, ktery soubor jen JMENUJE ---
#
# TASK-117 (0.3.0) - Z117-Q1 = A (Tom 2026-09-28), Z117-Q2 = A, Z117-Q3 = A, Z117-Q5 = A (Tom
# 2026-10-01): do 0.2.0 rozhodovala CESTA, ne co s ni prikaz dela, takze `git check-ignore -v
# <soubor prostredi>` nebo `git ls-files .claude/settings.local.json` koncily deny/ask, prestoze
# obsah souboru nikdo necetl. Od 0.3.0 statement, ktery je CELY jednim z uzavreneho vyctu
# jmenujicich tvaru a jehoz vystup NIKAM NETECE, hook do rozboru cest nebere a zapise audit
# `secrets:nameOnly` (bez cesty).
#
# Vycet (Z117-Q5): `git ls-files`, `git check-ignore`, `git ls-tree --name-only`, `Test-Path`,
# `ls` / `dir` / `Get-ChildItem` - kazdy jen s prepinaci z POVOLENE mnoziny daneho programu
# (T117-N2); cokoli mimo ni = jako 0.2.0.
# "Vystup nikam netece" (Z117-Q3): statement nesmi nest rouru, substituci, promennou, blok,
# seskupeni ani presmerovani - dovolene je jen presmerovani stderr do nicoty. Pro jistotu se
# odmita KAZDY z techto znaku kdekoli ve statementu, i v uvozovkach.
# Nalez councilu Codex (K1): jmenujici tvar jde ZASTINIT - Bash `ls() { cat "$@"; }; ls <soubor>`,
# PowerShell `function x { Get-Content @args }; Set-Alias ls x; ls <soubor>`, nebo zmenou PATH.
# Vyjimka proto neplati pro CELY prikaz, ktery definuje funkci nebo alias, meni PATH, nacita
# cizi kod (`source`, dot-source, `Import-Module`), text spousti (`eval`, `iex`) nebo nese
# heredoc. Statement, ktery vyjimku nedostal, se rozebira presne jako v 0.2.0.
$script:NamingDisqualifiers = @(
    '(^|[\s;&|({])(function|filter)\s+[\w:.\-]+',
    '[\w.\-]+\s*\(\s*\)\s*\{',
    '(^|[\s;&|({])(set-alias|new-alias|sal|nal|alias|unalias|hash|enable|source|import-module|ipmo|eval|iex|invoke-expression)(\s|$)',
    '(^|[\s;&|({])\.\s+\S',
    '\bpath\s*\+?=',
    'export\s+path\b',
    '\b(function|alias):',
    '<<'
)

function Test-NamingDisqualified([string]$Command) {
    foreach ($p in $script:NamingDisqualifiers) {
        if ([regex]::IsMatch($Command, $p, 'IgnoreCase')) { return $true }
    }
    return $false
}

function Test-NamingGit($Rest) {
    $i = 0
    $n = $Rest.Count
    while ($i -lt $n) {
        $t = [string]$Rest[$i]
        if ($t -ceq '-C') { if (($i + 1) -ge $n) { return $false }; $i += 2; continue }
        if ($t -ceq '--no-optional-locks' -or $t -ceq '--no-pager') { $i++; continue }
        if ($t -ceq '-c') {
            if (($i + 1) -ge $n) { return $false }
            # Jen `core.quotepath` - `-c alias.*` je jina trida (gate) a jine klice nikdo nezmeril.
            if ([string]$Rest[$i + 1] -notmatch '^core\.quotepath=(true|false|on|off|yes|no|0|1)$') { return $false }
            $i += 2; continue
        }
        break
    }
    if ($i -ge $n) { return $false }
    $sub = [string]$Rest[$i]
    $i++
    $allowed = switch -CaseSensitive ($sub) {
        'ls-files'     { @('--error-unmatch', '-c', '--cached', '-o', '--others', '-i', '--ignored', '--exclude-standard', '--full-name', '-z') }
        'check-ignore' { @('-v', '--verbose', '-n', '--non-matching', '-q', '--quiet', '--no-index', '-z') }
        'ls-tree'      { @('--name-only', '--name-status', '-r', '-d', '-t', '--full-name', '--full-tree', '-z') }
        default        { $null }
    }
    if ($null -eq $allowed) { return $false }
    $nameFlag = $false
    $positional = 0
    $endOpts = $false
    for (; $i -lt $n; $i++) {
        $t = [string]$Rest[$i]
        if (-not $endOpts -and $t -ceq '--') { $endOpts = $true; continue }
        if (-not $endOpts -and $t.StartsWith('-')) {
            if ($allowed -cnotcontains $t) { return $false }
            if ($t -ceq '--name-only' -or $t -ceq '--name-status') { $nameFlag = $true }
            continue
        }
        $positional++
    }
    # `git ls-tree` bez `--name-only` vypise id blobu (M11) a potrebuje prave jeden <tree-ish>.
    if ($sub -ceq 'ls-tree' -and (-not $nameFlag -or $positional -lt 1)) { return $false }
    return $true
}

function Test-NamingPsParams($Rest, $ValueParams, $SwitchParams) {
    $n = $Rest.Count
    for ($i = 0; $i -lt $n; $i++) {
        $t = ([string]$Rest[$i]).ToLowerInvariant()
        if (-not $t.StartsWith('-')) { continue }
        if ($SwitchParams -contains $t) { continue }
        if ($ValueParams.ContainsKey($t)) {
            if (($i + 1) -ge $n) { return $false }
            $v = [string]$Rest[$i + 1]
            if ($ValueParams[$t] -ne '' -and $v -notmatch $ValueParams[$t]) { return $false }
            $i++
            continue
        }
        return $false
    }
    return $true
}

function Test-NamingStatement([string]$Statement, [string]$ToolName) {
    $s = ([string]$Statement).Trim()
    if ($s -eq '') { return $false }
    # stderr do nicoty vystup NEposila dal - jedine dovolene presmerovani
    $s = [regex]::Replace($s, '(?<=^|\s)2>\s*(/dev/null|\$null|nul|&1)(?=\s|$)', ' ', 'IgnoreCase')
    if ($s -match '[|<>$`(){}@;&]') { return $false }
    # typograficke uvozovky jsou v PowerShellu uvozovky; skener je nezna -> radsi nic
    if ($s -match '[^\x20-\x7E\t]') { return $false }
    $argv = Split-Arguments $s
    if ($argv.Count -lt 2) { return $false }
    # Jen hole jmeno programu - `./ls`, `C:\x\git.exe` nebo `X=1 git ...` vycet nejsou.
    if ([string]$argv[0] -notmatch '^[A-Za-z][A-Za-z\-]*(\.exe)?$') { return $false }
    $exe = Get-ExecutableName ([string]$argv[0])
    $rest = @($argv[1..($argv.Count - 1)])
    $isPs = ($ToolName -eq 'PowerShell')
    if ($exe -eq 'git') { return (Test-NamingGit $rest) }
    if ($isPs -and $exe -eq 'test-path') {
        return (Test-NamingPsParams $rest @{ '-path' = ''; '-literalpath' = ''; '-pathtype' = '^(?i)(leaf|container|any)$' } @('-isvalid'))
    }
    if ($isPs -and @('ls', 'dir', 'gci', 'get-childitem') -contains $exe) {
        return (Test-NamingPsParams $rest @{ '-path' = ''; '-literalpath' = ''; '-depth' = '^[0-9]+$' } `
                                    @('-force', '-file', '-directory', '-hidden', '-name', '-recurse'))
    }
    if (-not $isPs -and @('ls', 'dir') -contains $exe) {
        $endOpts = $false
        foreach ($t in $rest) {
            $t = [string]$t
            if ($endOpts -or -not $t.StartsWith('-')) { continue }
            if ($t -ceq '--') { $endOpts = $true; continue }
            if ($t.StartsWith('--')) {
                if (@('--all', '--almost-all', '--directory', '--human-readable', '--color') -ccontains $t) { continue }
                if ($t -cmatch '^--color=(always|auto|never)$') { continue }
                return $false
            }
            if ($t -cnotmatch '^-[1aAdFhlRrStisG]+$') { return $false }
        }
        return $true
    }
    return $false
}

# Rozdeli text (po odstraneni datovych tel heredocu) na statementy, ktere soubor jen jmenuji,
# a zbytek. Zbytek se rozebira beze zmeny proti 0.2.0.
function Split-NamingStatement([string]$Scan, [string]$Command, [string]$ToolName) {
    $named = New-Object System.Collections.ArrayList
    if (Test-NamingDisqualified $Command) { return @{ Rest = $Scan; Named = '' } }
    $keep = New-Object System.Collections.ArrayList
    foreach ($st in @(Split-Statement $Scan)) {
        if (Test-NamingStatement $st $ToolName) { [void]$named.Add($st) } else { [void]$keep.Add($st) }
    }
    if ($named.Count -eq 0) { return @{ Rest = $Scan; Named = '' } }
    return @{ Rest = ($keep -join "`n"); Named = ($named -join "`n") }
}

# ------------------------------------- H-g: jmeno citlive promenne JEN JAKO TEXT ---
#
# TASK-117 H-g (Z117-Q14 = A, Tom 2026-10-07; vycet Z117-Q22 = A, Tom 2026-10-08 = varianta A
# navrhu `01-navrh-allow-list.md` par. 5): do 0.2.0 se `Get-SensitiveEnvName` ptal u KAZDEHO
# vyskytu jmena kdekoli v textu, bez ohledu na uvozovky. Dotaz, ktery zastavil nocni session
# na 7 h, byl `grep -n "^\$env:GSD_E2E_PASSWORD" ...` v Bash nastroji - `\$` v dvojitych
# uvozovkach je doslovny dolar, grep hledal TEXT. Od 0.3.0 hook mlci (audit
# `secrets:nameOnly:envVarText`), kdyz je KAZDY vyskyt citliveho jmena (M22) textem podle
# uzavreneho vyctu:
#   1 Bash  uvnitr '...'                                } vzor grep/egrep/fgrep/rg/git grep:
#   2 Bash  v "..." a kazdy `$` v tom retezci za `\`     } prvni pozicni argument nebo hodnota -e
#   3 PS    uvnitr '...' (i typograficke apostrofy)     } vzor Select-String (-Pattern / prvni
#   4 PS    v "..." a kazdy `$` v tom retezci za `      } pozicni) a nativni grep/rg/git grep
# Zdroj pravidel uvozovani: Bash manual par. Quoting, SC2016, about_Quoting_Rules (PowerShell).
# Podminky (vse ostatni = jako 0.2.0): prikaz je JEDEN statement bez seskupeni, bloku,
# substituce a vstupniho presmerovani; kazdy prepinac programu je z povolene mnoziny (nalez
# councilu Codex K7: `rg --pre=printenv`, `git grep --textconv` text SPUSTI); roura za
# programem jen do programu, ktery nic nespousti (`grep '$X' f.sh | bash` by text z souboru
# rozvinul - zprisneni proti navrhu, faze 2). Pasti uvozovek (T117-N17): jednoduche uvnitr
# dvojitych nejsou uvozovky, v Bash '...' `\` neescapuje, parita escapu, sousedstvi `'x'$X`,
# typograficke uvozovky v PowerShellu - resi je skener nize, ne regex.

$script:EnvPatterns = @(
    '\$env:([A-Za-z_][A-Za-z0-9_]*)',
    # Z117-Q15 + A117-O5: cesta `Env:\X` / `Env:/X` (PowerShell provider) cte hodnotu stejne
    # jako `env:X` - do 0.2.0 chtel vzor za `env:` hned pismeno a obe cesty mlcely.
    '(?:^|[^A-Za-z0-9_])env:[\\/]?([A-Za-z_][A-Za-z0-9_]*)',
    '\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?',
    'getenvironmentvariable\s*\(\s*["'']([^"'']+)["'']',
    '%([A-Za-z_][A-Za-z0-9_]*)%'
)

function Test-SensitiveEnvName([string]$Name, [string]$NamePattern, [string]$CamelPattern) {
    # DVA vzory se DVEMA rezimy - jeden vzor to neumi (nalezy Amber C6 a E5):
    #  - podtrzitkovy zapis IGNORE-CASE, aby chytil i `db_password`;
    #    mnozne cislo jen ZA podtrzitkem, takze `API_KEYS` ano, hole `tokens` ne,
    #  - camelCase CASE-SENSITIVNE, jinak by `monkey` a `keyFile` byly citlive.
    if ([regex]::IsMatch($Name, $NamePattern, 'IgnoreCase')) { return $true }
    if ($CamelPattern -ne '' -and [regex]::IsMatch($Name, $CamelPattern)) { return $true }
    return $false
}

# Vsechny vyskyty citliveho jmena: pozice, delka, jmeno. Poradi = poradi vzoru, pak pozice -
# prvni prvek je tedy tyz, ktery do 0.2.0 vracel Get-SensitiveEnvName (text duvodu se nemeni).
function Get-SensitiveEnvOccurrence([string]$Command, [string]$NamePattern, [string]$CamelPattern) {
    $out = New-Object System.Collections.ArrayList
    foreach ($p in $script:EnvPatterns) {
        foreach ($m in [regex]::Matches($Command, $p, 'IgnoreCase')) {
            $name = $m.Groups[1].Value
            if (-not (Test-SensitiveEnvName $name $NamePattern $CamelPattern)) { continue }
            $start = $m.Index
            $end = $m.Groups[1].Index + $m.Groups[1].Length
            # vzor 2 nese hranicni znak pred `env:` - do vyskytu nepatri
            if ($m.Value.Length -gt 0 -and $Command[$start] -ne '$' -and $Command[$start] -ne '%' -and
                $Command.Substring($start, [Math]::Min(6, $Command.Length - $start)) -inotmatch '^(env:|getenv)') { $start++ }
            [void]$out.Add(@{ Start = $start; End = $end; Name = $name })
        }
    }
    return ,@($out)
}

# Z117-Q15 (Tom 2026-10-07): `printenv NAME` vypise hodnotu jedne promenne - do 0.2.0 se
# Test-EnvironmentDump ptal jen u `printenv` BEZ argumentu.
function Get-PrintenvSensitiveName([string]$Command, [string]$NamePattern, [string]$CamelPattern) {
    foreach ($sub in (Split-CommandLine $Command)) {
        $argv = Split-Arguments $sub
        if ($argv.Count -lt 2) { continue }
        if ((Get-ExecutableName $argv[0]) -ne 'printenv') { continue }
        foreach ($a in @($argv[1..($argv.Count - 1)])) {
            $a = [string]$a
            if ($a.StartsWith('-')) { continue }
            if (Test-SensitiveEnvName $a $NamePattern $CamelPattern) { return $a }
        }
    }
    return ''
}

# Skener uvozovek s POZICI: pro kazdy znak stav (0 mimo, 1 jednoduche, 2 dvojite), priznak
# "escapovany", cislo dvojiteho retezce; tokeny (bily znak mimo uvozovky) se zacatkem, koncem
# a hodnotou bez uvozovek; hranice roury. $null = tvar, ktery vycet nepokryva.
function Get-QuoteMap([string]$Text, [bool]$IsPs) {
    $n = $Text.Length
    $state = New-Object int[] $n
    $escaped = New-Object bool[] $n
    $seg = New-Object int[] $n
    $tokens = New-Object System.Collections.ArrayList
    $stages = New-Object System.Collections.ArrayList
    $cur = New-Object System.Collections.ArrayList
    $sq = if ($IsPs) { "'" + [char]0x2018 + [char]0x2019 + [char]0x201A + [char]0x201B } else { "'" }
    $dq = if ($IsPs) { '"' + [char]0x201C + [char]0x201D + [char]0x201E } else { '"' }
    $esc = if ($IsPs) { '`' } else { '\' }
    $st = 0
    $segId = 0
    $tokStart = -1
    $buf = New-Object System.Text.StringBuilder
    $i = 0
    while ($i -lt $n) {
        $c = [string]$Text[$i]
        if ($st -eq 0) {
            if ($c -eq ' ' -or $c -eq "`t") {
                if ($tokStart -ge 0) { [void]$cur.Add(@{ Start = $tokStart; End = $i; Value = $buf.ToString() }); [void]$buf.Clear(); $tokStart = -1 }
                $i++; continue
            }
            if ($c -eq '|') {
                if ($tokStart -ge 0) { [void]$cur.Add(@{ Start = $tokStart; End = $i; Value = $buf.ToString() }); [void]$buf.Clear(); $tokStart = -1 }
                if (($i + 1) -lt $n -and $Text[$i + 1] -eq '|') { return $null }
                [void]$stages.Add($cur); $cur = New-Object System.Collections.ArrayList
                $i++; continue
            }
            if ('(){}<'.Contains($c) -or $c -eq "`n" -or $c -eq "`r") { return $null }
            if (-not $IsPs -and $c -eq '`') { return $null }
            if ($tokStart -lt 0) { $tokStart = $i }
            if ($c -eq $esc) {
                if (($i + 1) -ge $n) { return $null }
                $escaped[$i + 1] = $true
                [void]$buf.Append($Text[$i + 1]); $i += 2; continue
            }
            if ($sq.Contains($c)) { $st = 1; $state[$i] = 1; $i++; continue }
            if ($dq.Contains($c)) { $st = 2; $segId++; $state[$i] = 2; $seg[$i] = $segId; $i++; continue }
            [void]$buf.Append($c); $i++; continue
        }
        if ($st -eq 1) {
            $state[$i] = 1
            if ($sq.Contains($c)) {
                if ($IsPs -and ($i + 1) -lt $n -and $sq.Contains([string]$Text[$i + 1])) {
                    $state[$i + 1] = 1; [void]$buf.Append("'"); $i += 2; continue
                }
                $st = 0; $i++; continue
            }
            [void]$buf.Append($c); $i++; continue
        }
        # st 2 - dvojite uvozovky
        $state[$i] = 2
        $seg[$i] = $segId
        if (-not $IsPs -and $c -eq '`') { return $null }
        if ($c -eq $esc -and ($i + 1) -lt $n) {
            $next = [string]$Text[$i + 1]
            if ($IsPs -or ('$`"\'.Contains($next))) {
                $state[$i + 1] = 2; $seg[$i + 1] = $segId; $escaped[$i + 1] = $true
                [void]$buf.Append($next); $i += 2; continue
            }
        }
        if ($dq.Contains($c)) {
            if ($IsPs -and ($i + 1) -lt $n -and $dq.Contains([string]$Text[$i + 1])) {
                $state[$i + 1] = 2; $seg[$i + 1] = $segId; [void]$buf.Append('"'); $i += 2; continue
            }
            $st = 0; $i++; continue
        }
        [void]$buf.Append($c); $i++
    }
    if ($st -ne 0) { return $null }
    if ($tokStart -ge 0) { [void]$cur.Add(@{ Start = $tokStart; End = $n; Value = $buf.ToString() }) }
    [void]$stages.Add($cur)
    return @{ State = $state; Escaped = $escaped; Seg = $seg; Stages = $stages }
}

# Index tokenu, ktere jsou VZOREM grep/rg/git grep (od $From). $null = nepovoleny prepinac.
function Get-GrepPatternToken($Tokens, [int]$From, [string]$Flavor) {
    $letters = switch ($Flavor) { 'rg' { 'nilcwFvoHS' } default { 'nirlcwFEvohH' } }
    $patterns = New-Object System.Collections.ArrayList
    $positional = New-Object System.Collections.ArrayList
    $endOpts = $false
    $n = $Tokens.Count
    for ($i = $From; $i -lt $n; $i++) {
        $t = [string]$Tokens[$i].Value
        if (-not $endOpts -and $t -ceq '--') { $endOpts = $true; continue }
        if (-not $endOpts -and $t.StartsWith('--')) {
            $ok = switch ($Flavor) {
                'grep'   { ($t -ceq '--color') -or ($t -cmatch '^--(color|include|exclude)=.+$') }
                'rg'     { ($t -ceq '--no-config') -or ($t -cmatch '^--color=.+$') }
                default  { ($t -ceq '--color') -or ($t -cmatch '^--color=.+$') }
            }
            if (-not $ok) { return $null }
            continue
        }
        if (-not $endOpts -and $t.StartsWith('-') -and $t.Length -gt 1) {
            if ($t -cmatch '^-[ABC][0-9]+$') { continue }
            if ($t -cmatch '^-[ABC]$') {
                if (($i + 1) -ge $n -or ([string]$Tokens[$i + 1].Value) -notmatch '^[0-9]+$') { return $null }
                $i++; continue
            }
            $body = $t.Substring(1)
            $takesPattern = $false
            if ($body.EndsWith('e')) { $takesPattern = $true; $body = $body.Substring(0, $body.Length - 1) }
            foreach ($ch in $body.ToCharArray()) { if (-not $letters.Contains([string]$ch)) { return $null } }
            if ($takesPattern) {
                if (($i + 1) -ge $n) { return $null }
                [void]$patterns.Add($i + 1); $i++
            }
            continue
        }
        [void]$positional.Add($i)
    }
    if ($patterns.Count -eq 0) {
        if ($positional.Count -eq 0) { return $null }
        [void]$patterns.Add($positional[0])
    }
    return ,@($patterns)
}

function Get-SelectStringPatternToken($Tokens, [int]$From) {
    $valueParams = @('-pattern', '-path', '-literalpath', '-context')
    $switchParams = @('-simplematch', '-casesensitive', '-list', '-notmatch')
    $patterns = New-Object System.Collections.ArrayList
    $positional = New-Object System.Collections.ArrayList
    $n = $Tokens.Count
    for ($i = $From; $i -lt $n; $i++) {
        $t = ([string]$Tokens[$i].Value).ToLowerInvariant()
        if ($t.StartsWith('-') -and $t.Length -gt 1) {
            if ($switchParams -contains $t) { continue }
            if ($valueParams -contains $t) {
                if (($i + 1) -ge $n) { return $null }
                if ($t -eq '-pattern') { [void]$patterns.Add($i + 1) }
                $i++; continue
            }
            return $null
        }
        [void]$positional.Add($i)
    }
    if ($patterns.Count -eq 0) {
        if ($positional.Count -eq 0) { return $null }
        [void]$patterns.Add($positional[0])
    }
    return ,@($patterns)
}

# Programy, do kterych smi tect vystup vyhledavani: radky souboru jen preusporadaji nebo
# zkrati, nic z nich nespusti.
$script:EnvTextDownstream = @('head', 'tail', 'sort', 'uniq', 'wc', 'cut', 'select-object', 'sort-object', 'measure-object', 'out-null')

function Test-EnvOccurrenceText([string]$Command, $Occurrences, [string]$ToolName) {
    if (@(Split-Statement $Command).Count -ne 1) { return $false }
    $isPs = ($ToolName -eq 'PowerShell')
    $map = Get-QuoteMap $Command $isPs
    if ($null -eq $map) { return $false }
    $stages = $map.Stages
    if ($stages.Count -lt 1 -or $stages[0].Count -lt 2) { return $false }
    for ($s = 1; $s -lt $stages.Count; $s++) {
        if ($stages[$s].Count -lt 1) { return $false }
        $down = [string]$stages[$s][0].Value
        if ($down -notmatch '^[A-Za-z][A-Za-z\-]*$' -or $script:EnvTextDownstream -notcontains $down.ToLowerInvariant()) { return $false }
    }
    $tok = $stages[0]
    $head = [string]$tok[0].Value
    if ($head -notmatch '^[A-Za-z][A-Za-z\-]*$') { return $false }
    $exe = $head.ToLowerInvariant()
    $patternIdx = $null
    if (@('grep', 'egrep', 'fgrep') -contains $exe) { $patternIdx = Get-GrepPatternToken $tok 1 'grep' }
    elseif ($exe -eq 'rg') { $patternIdx = Get-GrepPatternToken $tok 1 'rg' }
    elseif ($exe -eq 'git') {
        $i = 1
        while ($i -lt $tok.Count) {
            $v = [string]$tok[$i].Value
            if ($v -ceq '-C') { $i += 2; continue }
            if ($v -ceq '--no-pager' -or $v -ceq '--no-optional-locks') { $i++; continue }
            break
        }
        if ($i -lt $tok.Count -and ([string]$tok[$i].Value) -ceq 'grep') { $patternIdx = Get-GrepPatternToken $tok ($i + 1) 'gitgrep' }
    }
    elseif ($isPs -and @('select-string', 'sls') -contains $exe) { $patternIdx = Get-SelectStringPatternToken $tok 1 }
    if ($null -eq $patternIdx) { return $false }

    foreach ($o in $Occurrences) {
        $hit = -1
        for ($k = 0; $k -lt $tok.Count; $k++) {
            if ($o.Start -ge $tok[$k].Start -and $o.End -le $tok[$k].End) { $hit = $k; break }
        }
        if ($hit -lt 0 -or $patternIdx -notcontains $hit) { return $false }
        $segs = New-Object System.Collections.Generic.HashSet[int]
        for ($c = $o.Start; $c -lt $o.End; $c++) {
            if ($map.State[$c] -eq 0) { return $false }
            if ($map.State[$c] -eq 2) { [void]$segs.Add($map.Seg[$c]) }
        }
        # Dvojite uvozovky: KAZDY `$` v celem retezci musi byt escapovany - `"${env:X}"`
        # nese `$` PRED vyskytem a `"\$X $Y"` jinou promennou vedle nej.
        foreach ($sid in $segs) {
            for ($c = 0; $c -lt $Command.Length; $c++) {
                if ($map.State[$c] -eq 2 -and $map.Seg[$c] -eq $sid -and $Command[$c] -eq '$' -and -not $map.Escaped[$c]) { return $false }
            }
        }
    }
    return $true
}

function Test-SecretCommand([string]$Command, $Config) {
    $sec = Get-Field $Config 'secrets'
    $shapes = Get-Field $sec 'shapes'
    $worst = $null
    $script:CwdUncertain = Test-CwdChange $Command

    # Zapis je vlastnost KANDIDATA (bod 9 + N-H3, 0.2.0) - viz Get-PathCandidate. Telo
    # heredocu s datovym hostem se do rozboru cest nebere (bod 12); promenne prostredi se
    # hledaji nad CELYM textem - `echo $DB_PASSWORD` v tele `cat <<EOF` shell rozvine.
    $scan = Remove-DataHeredocBody $Command $Config
    # Polozka 7 (TASK-117): statementy, ktere soubor jen jmenuji, do rozboru cest nejdou.
    $split = Split-NamingStatement $scan $Command $script:ToolName
    foreach ($candidate in (Get-PathCandidate $split.Rest $Config)) {
        $r = Test-SecretPath $candidate.Value ([bool]$candidate.IsWrite) $Config ([bool]$candidate.AllowGlob)
        if ($null -eq $r) { continue }
        if ($r.Decision -eq 'deny') { return $r }
        if ($null -eq $worst) { $worst = $r }
    }
    # H-b: jmenovani, ktere by v 0.2.0 rozhodlo, se zapise do auditu - bez cesty.
    if ($split.Named -ne '') {
        foreach ($candidate in (Get-PathCandidate $split.Named $Config)) {
            $r = Test-SecretPath $candidate.Value ([bool]$candidate.IsWrite) $Config ([bool]$candidate.AllowGlob)
            if ($null -ne $r) { Write-GateAudit $script:ToolName 'secrets:nameOnly' 'allow' $Config; break }
        }
    }

    if (Test-EnvironmentDump $Command) {
        if ($null -eq $worst) {
            $worst = @{ Id = 'envDump'; Decision = 'ask'; Shape = (Get-Field $shapes 'envDump' 'env') }
        }
    }

    $namePattern = [string](Get-Field $sec 'envVarNamePattern' '(^|_)(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)S?(_|$)')
    $camelPattern = [string](Get-Field $sec 'envVarNameCamelPattern' '')
    $name = Get-PrintenvSensitiveName $Command $namePattern $camelPattern
    if ($name -eq '') {
        $occ = Get-SensitiveEnvOccurrence $Command $namePattern $camelPattern
        if ($occ.Count -gt 0) {
            # H-g: rozhodnuti PER VYSKYT (M22) - mlci se, jen kdyz je textem kazdy z nich.
            if (Test-EnvOccurrenceText $Command $occ $script:ToolName) {
                Write-GateAudit $script:ToolName 'secrets:nameOnly:envVarText' 'allow' $Config
            } else {
                $name = [string]$occ[0].Name
            }
        }
    }
    if ($name -ne '') {
        if ($null -eq $worst) {
            $worst = @{ Id = 'envVarRead'; Decision = 'ask'
                        Shape = (([string](Get-Field $shapes 'envVarRead' '{name}')).Replace('{name}', [string]($name))) }
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
$script:PermissionMode = $mode
$script:ToolName = $toolName

$projectDir = $env:CLAUDE_PROJECT_DIR
if ([string]::IsNullOrWhiteSpace($projectDir)) { $projectDir = $script:Cwd }

$config = Get-HookConfig $PluginRoot $projectDir
$script:InternalMessage = Get-Text $config 'secretsInternalError' $script:InternalMessage

$known = @($script:ReadTools + $script:WriteTools + $script:CmdTools)
if ($known -notcontains $toolName) { Write-HookStderr $script:InternalMessage; exit 2 }

if (-not (Test-HookEnabled $config 'secrets')) { exit 0 }
# H-c: odmitnuty klic prepisu je videt v auditu jednou za session (CR-P10) a v kanarku (jen jmeno klice).
Write-OverrideRejectedAudit $toolName $config ([string](Get-Field $payload 'session_id' ''))

# Tyz skener jako brana, takze i tyz escape znak podle shellu (nalez Amber G1).
# Pro nastroje nad souborem (Read/Edit/Write) je hodnota bez vyznamu - skener se
# nepouzije - ale nastavit ji je levnejsi nez vetvit.
Set-ScannerEscape $toolName

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

# H-b (TASK-117): kazde `ask` a `deny` jde do auditu s ID tvaru - nikdy s cestou ani jmenem.
Write-GateAudit $toolName ('secrets:' + [string]$decision.Id) ([string]$decision.Decision) $config

$reason = ([string](Get-Text $config 'gateReason' 'Brana par. 6: {shape}')).Replace('{shape}', [string]$decision.Shape)

if ($decision.Decision -eq 'ask' -and $mode -eq 'bypassPermissions') {
    $reason = $reason + (Get-Text $config 'bypassSuffix' ' bypass')
    Write-DenyDecision $reason
}
if ($decision.Decision -eq 'deny') { Write-DenyDecision $reason }
Write-AskDecision $reason
