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
function Test-GlobAimsAtProtectedPath([string]$GlobNorm, $Sec) {
    if (Test-AnyPattern $GlobNorm @(Get-Field $Sec 'denyPathPatterns' @())) { return $true }
    if (Test-AnyPattern $GlobNorm @(Get-Field $Sec 'askPathPatterns' @())) { return $true }
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
            return @{ Decision = 'ask'
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
            return @{ Decision = 'deny'
                      Shape = (([string](Get-Field $shapes 'secretFile' '{path}')).Replace('{path}', [string]($Path))) }
        }
        $rel = Get-RelativeToCwd $norm (ConvertTo-NormalPath $script:Cwd)
        if (Test-GitTracked $script:Cwd $rel) { return $null }
        return @{ Decision = 'ask'
                  Shape = (([string](Get-Field $shapes 'envFileUntracked' '{path}')).Replace('{path}', [string]($Path))) }
    }

    # (2) tvrde zakazane tvary
    if (Test-AnyPattern $norm @(Get-Field $sec 'denyPathPatterns' @())) {
        return @{ Decision = 'deny'
                  Shape = (([string](Get-Field $shapes 'secretFile' '{path}')).Replace('{path}', [string]($Path))) }
    }

    # (3) sebeochrana - soubory, kterymi se brana vypina (jen zapis)
    if ($IsWrite -and (Test-AnyPattern $norm @(Get-Field $sec 'selfProtectPathPatterns' @()))) {
        return @{ Decision = 'ask'
                  Shape = (([string](Get-Field $shapes 'selfProtect' '{path}')).Replace('{path}', [string]($Path))) }
    }

    # (4) seda zona
    if (Test-AnyPattern $norm @(Get-Field $sec 'askPathPatterns' @())) {
        return @{ Decision = 'ask'
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
    'compress-archive', 'tar', 'zip', 'scp', 'rsync', 'findstr', 'select-string'
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
    foreach ($sub in (Split-CommandLine $Command)) {
        $argv = Split-Arguments $sub
        if ($argv.Count -eq 0) { continue }
        $subExe = (Get-ExecutableName $argv[0]).ToLowerInvariant()
        $isPathCommand  = ($pathCommands -contains $subExe)
        $isWriteCommand = ($writeCommands -contains $subExe)
        $pending = ''   # 'r' | 'w' za samostatnym operatorem presmerovani
        # Bez `@()`: Expand-ColonParameter vraci `,@(...)` a dalsi obal by pole zabalil JESTE JEDNOU
        # (viz poznamka u Split-UnquotedCore) - Count by byl 1 a token cely argv.
        $tokens = Expand-ColonParameter $argv
        for ($ti = 0; $ti -lt $tokens.Count; $ti++) {
            $token = [string]$tokens[$ti]

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

function Get-SensitiveEnvName([string]$Command, [string]$NamePattern, [string]$CamelPattern) {
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
            # DVA vzory se DVEMA rezimy - jeden vzor to neumi (nalezy Amber C6 a E5):
            #  - podtrzitkovy zapis IGNORE-CASE, aby chytil i `db_password`;
            #    mnozne cislo jen ZA podtrzitkem, takze `API_KEYS` ano, hole `tokens` ne,
            #  - camelCase CASE-SENSITIVNE, jinak by `monkey` a `keyFile` byly citlive.
            if ([regex]::IsMatch($name, $NamePattern, 'IgnoreCase')) { return $name }
            if ($CamelPattern -ne '' -and [regex]::IsMatch($name, $CamelPattern)) { return $name }
        }
    }
    return ''
}

function Test-SecretCommand([string]$Command, $Config) {
    $sec = Get-Field $Config 'secrets'
    $shapes = Get-Field $sec 'shapes'
    $worst = $null

    # Zapis je vlastnost KANDIDATA (bod 9 + N-H3, 0.2.0) - viz Get-PathCandidate. Telo
    # heredocu s datovym hostem se do rozboru cest nebere (bod 12); promenne prostredi se
    # hledaji nad CELYM textem - `echo $DB_PASSWORD` v tele `cat <<EOF` shell rozvine.
    $scan = Remove-DataHeredocBody $Command $Config
    foreach ($candidate in (Get-PathCandidate $scan $Config)) {
        $r = Test-SecretPath $candidate.Value ([bool]$candidate.IsWrite) $Config ([bool]$candidate.AllowGlob)
        if ($null -eq $r) { continue }
        if ($r.Decision -eq 'deny') { return $r }
        if ($null -eq $worst) { $worst = $r }
    }

    if (Test-EnvironmentDump $Command) {
        if ($null -eq $worst) {
            $worst = @{ Decision = 'ask'; Shape = (Get-Field $shapes 'envDump' 'env') }
        }
    }

    $namePattern = [string](Get-Field $sec 'envVarNamePattern' '(^|_)(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)S?(_|$)')
    $camelPattern = [string](Get-Field $sec 'envVarNameCamelPattern' '')
    $name = Get-SensitiveEnvName $Command $namePattern $camelPattern
    if ($name -ne '') {
        if ($null -eq $worst) {
            $worst = @{ Decision = 'ask'
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

$reason = ([string](Get-Text $config 'gateReason' 'Brana par. 6: {shape}')).Replace('{shape}', [string]$decision.Shape)

if ($decision.Decision -eq 'ask' -and $mode -eq 'bypassPermissions') {
    $reason = $reason + (Get-Text $config 'bypassSuffix' ' bypass')
    Write-DenyDecision $reason
}
if ($decision.Decision -eq 'deny') { Write-DenyDecision $reason }
Write-AskDecision $reason
