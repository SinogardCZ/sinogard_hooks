#!/usr/bin/env pwsh
<#
.SYNOPSIS
  PreToolUse brana par. 6: destruktivni git a DB operace konci deny nebo ask.

.DESCRIPTION
  ASCII-ONLY zdroj (viz _common.ps1). Vsechny lidske texty jsou v
  hooks/config/defaults.json.

  Fail-closed: jakakoli vyjimka, nevalidni nebo prazdny vstup, chybejici prikaz
  i neznamy nastroj konci exit 2. Ukazkovy validator Anthropicu tohle nedela
  (exit 1 = fail-open); lisime se vedome.

  deny = JSON permissionDecision "deny" + exit 2 + tyz duvod na stderr.
  ask  = JSON permissionDecision "ask" + exit 0.
  jinak = exit 0 bez vystupu (zadne rozhodnuti, plati normalni tok opravneni).
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

# ------------------------------------------------------------- pomocne ---

# List je hashtable a ne kazdy nese kazdy klic. Pod StrictMode je pristup k chybejicimu
# klici hazardni, takze se cte pres ContainsKey.
function Get-LeafField($Leaf, [string]$Name, $Default = '') {
    if ($null -eq $Leaf) { return $Default }
    if (-not $Leaf.ContainsKey($Name)) { return $Default }
    if ($null -eq $Leaf[$Name]) { return $Default }
    return $Leaf[$Name]
}

# Heredoc: telo je SQL, ale hostitel DB stoji v uvozujicim prikazu PRED `<<`.
# Split-CommandLine deli i na konci radku, takze by se telo stalo samostatnym
# podprikazem BEZ hosta - a `psql -h db.firma.cz <<SQL / DROP TABLE x / SQL`
# by skoncilo jako lokalni operace (ask) misto vzdalene (deny). Nalez Amber A4.
#
# Vraci @{ Rest = prikaz bez tel heredocu; Bodies = @(@{ Outer; OuterExe; Body }) }.
function Split-Heredoc([string]$Command) {
    $bodies = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Command)) {
        return @{ Rest = $Command; Bodies = @() }
    }
    if ($Command -notmatch '<<') { return @{ Rest = $Command; Bodies = @() } }

    $lines = [regex]::Split($Command, '\r?\n')
    $keep = New-Object System.Collections.ArrayList
    $i = 0
    while ($i -lt $lines.Count) {
        $line = $lines[$i]
        # `<<EOF`, `<<-EOF`, `<<'EOF'`, `<<"EOF"` - ne `<<<` (here-string) a ne `<`.
        $m = [regex]::Match($line, '<<-?\s*(?:''([A-Za-z_][A-Za-z0-9_]*)''|"([A-Za-z_][A-Za-z0-9_]*)"|([A-Za-z_][A-Za-z0-9_]*))\s*$')
        if (-not $m.Success) {
            [void]$keep.Add($line); $i++; continue
        }
        $delim = ''
        foreach ($g in 1, 2, 3) { if ($m.Groups[$g].Success) { $delim = $m.Groups[$g].Value } }

        $outer = $line.Substring(0, $m.Index).Trim()
        [void]$keep.Add($outer)

        $bodyLines = New-Object System.Collections.ArrayList
        $j = $i + 1
        while ($j -lt $lines.Count -and $lines[$j].Trim() -ne $delim) {
            [void]$bodyLines.Add($lines[$j]); $j++
        }
        $outerArgv = Split-Arguments $outer
        $outerExe = ''
        if ($outerArgv.Count -gt 0) { $outerExe = Get-ExecutableName $outerArgv[0] }
        [void]$bodies.Add(@{ Outer = $outer; OuterExe = $outerExe; Body = ($bodyLines -join "`n") })

        $i = $j + 1   # radek s ukoncovacim delimiterem se zahazuje
    }
    return @{ Rest = ($keep -join "`n"); Bodies = @($bodies) }
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

# Rozbali obaly (bash -c, cmd /c, eval, xargs, sudo, find -exec, ...) na listy.
# Obal s literalem -> rozebrat vnitrek. Obal s promennou -> 'opaque' (= ask).
function Get-CommandLeaf([string]$Sub, [int]$Depth) {
    $out = New-Object System.Collections.ArrayList
    $trimmed = $Sub.Trim()
    if ($trimmed -eq '') { return $out }
    if ($Depth -gt 5) { [void]$out.Add(@{ Kind = 'opaque'; Raw = $trimmed }); return $out }

    if ($trimmed.StartsWith('&') -and -not $trimmed.StartsWith('&&')) {
        $trimmed = $trimmed.Substring(1).Trim()
        if ($trimmed -eq '') { return $out }
    }

    # Raw se bere PRED odstranenim prefixu promennych - hostitel DB muze byt prave tam
    # (ConnectionStrings__Default="Host=..." dotnet ef database update).
    $raw = $trimmed

    # .NET volani nemaji argv tvar a nesou `$true` jako druhy argument - kdyby sla
    # nejdriv kontrola "nerozebratelne", skoncila by ask misto deny.
    if ([regex]::IsMatch($trimmed, '\[(?:System\.)?IO\.(?:Directory|File)\]::Delete\(', 'IgnoreCase')) {
        [void]$out.Add(@{ Kind = 'leaf'; Exe = 'net-delete'; Args = @(); Raw = $raw; Text = $trimmed; GitConfig = @() })
        return $out
    }

    $stripped = [regex]::Replace($trimmed,
        '^\s*([A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|''[^'']*''|\S*)\s+)+', '')

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
        # Prirazeni literalu (`$env:FOO = 'x'`, `$i = 0`) neni prikaz - zadny list.
        if ($rhs -eq '' -or $rhs -match '^(?:''[^'']*''|"[^"$`]*"|[0-9]+|\$(?:true|false|null))$') {
            return $out
        }
        foreach ($l in (Get-CommandLeaf $rhs ($Depth + 1))) { [void]$out.Add($l) }
        return $out
    }

    $argv = Split-Arguments $stripped
    if ($argv.Count -eq 0) { return $out }

    if (Test-Unexpandable $argv[0]) {
        [void]$out.Add(@{ Kind = 'opaque'; Raw = $raw }); return $out
    }

    $exe = Get-ExecutableName $argv[0]
    $rest = Get-RestTokens $argv

    switch -Regex ($exe) {
        '^(sudo|nice|nohup|time|doas)$' {
            $inner = ($rest -join ' ')
            foreach ($l in (Get-CommandLeaf $inner ($Depth + 1))) { [void]$out.Add($l) }
            return $out
        }
        '^(timeout)$' {
            $skip = 0
            if ($rest.Count -gt 0 -and $rest[0] -match '^[0-9]') { $skip = 1 }
            $inner = (($rest | Select-Object -Skip $skip) -join ' ')
            foreach ($l in (Get-CommandLeaf $inner ($Depth + 1))) { [void]$out.Add($l) }
            return $out
        }
        '^(command|builtin|exec)$' {
            # Nalez Metis 5: `command rm -rf src` obchazi jmeno spustitelneho souboru.
            $tail = @($rest | Where-Object { $_ -ne '-p' -and $_ -ne '-v' -and $_ -ne '-V' })
            foreach ($l in (Get-CommandLeaf ($tail -join ' ') ($Depth + 1))) { [void]$out.Add($l) }
            return $out
        }
        '^(python|python3|node|nodejs|ruby|perl|php|deno)$' {
            # Nalez Metis 16/24: vnitrek `-c "..."` je kod, ne prikazova radka - rozebrat
            # ho neumime, takze plati Z3: nerozebratelne -> ask.
            foreach ($t in $rest) {
                if ($t -cmatch '^-{1,2}(c|e|eval)$') {
                    [void]$out.Add(@{ Kind = 'opaque'; Raw = $raw }); return $out
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
                if (($t -eq '-filepath' -or $t -eq '-path') -and ($i + 1) -lt $rest.Count) { $file = $rest[$i + 1]; $i++; continue }
                if (($t -eq '-argumentlist' -or $t -eq '-args') -and ($i + 1) -lt $rest.Count) { $argList = $rest[$i + 1]; $i++; continue }
                if (-not $rest[$i].StartsWith('-') -and $file -eq '') { $file = $rest[$i] }
            }
            if ($file -eq '') { return $out }
            $inner = ($file + ' ' + $argList).Trim()
            if (Test-Unexpandable $inner) { [void]$out.Add(@{ Kind = 'opaque'; Raw = $raw }); return $out }
            foreach ($s in (Split-CommandLine $inner)) {
                foreach ($l in (Get-CommandLeaf $s ($Depth + 1))) { [void]$out.Add($l) }
            }
            return $out
        }
        '^(env)$' {
            # Nalez Metis 28: `env -i rm -rf src` - prepinace env se musi preskocit,
            # jinak zacne rozbor u `-i` a skutecny prikaz zmizi.
            $i = 0
            while ($i -lt $rest.Count) {
                $t = $rest[$i]
                if ($t -eq '-' -or $t -eq '-i' -or $t -eq '--ignore-environment' -or $t -eq '-0' -or $t -eq '--null') { $i++; continue }
                if ($t -eq '-u' -or $t -eq '--unset' -or $t -eq '-C' -or $t -eq '--chdir' -or $t -eq '-S') { $i += 2; continue }
                if ($t -match '^--(unset|chdir)=') { $i++; continue }
                if ($t -match '^[A-Za-z_][A-Za-z0-9_]*=') { $i++; continue }
                break
            }
            $tail = @($rest | Select-Object -Skip $i)
            if ($tail.Count -eq 0) {
                [void]$out.Add(@{ Kind = 'leaf'; Exe = $exe; Args = @(); Raw = $raw; Text = 'env'; GitConfig = @() })
                return $out
            }
            foreach ($l in (Get-CommandLeaf ($tail -join ' ') ($Depth + 1))) { [void]$out.Add($l) }
            return $out
        }
        '^(bash|sh|zsh|dash|ksh)$' {
            # Nalez Metis 4: `bash -lc '...'` - shell prijima slouceny kratky prepinac,
            # takze se hleda kterykoli tvar koncici `c`, ne presny token `-c`.
            $idx = -1
            for ($i = 0; $i -lt $rest.Count; $i++) { if ($rest[$i] -cmatch '^-[a-z]*c$') { $idx = $i; break } }
            if ($idx -lt 0 -or ($idx + 1) -ge $rest.Count) {
                # bash script.sh - skript souborem je pro hook nepruhledny, propousti se
                return $out
            }
            $inner = $rest[$idx + 1]
            if (Test-Unexpandable $inner) { [void]$out.Add(@{ Kind = 'opaque'; Raw = $inner }); return $out }
            foreach ($s in (Split-CommandLine $inner)) {
                foreach ($l in (Get-CommandLeaf $s ($Depth + 1))) { [void]$out.Add($l) }
            }
            return $out
        }
        '^(pwsh|powershell)$' {
            $idx = -1
            $isFile = $false
            for ($i = 0; $i -lt $rest.Count; $i++) {
                $t = $rest[$i].ToLowerInvariant()
                if ($t -eq '-encodedcommand' -or $t -eq '-e' -or $t -eq '-ec') {
                    [void]$out.Add(@{ Kind = 'opaque'; Raw = $raw }); return $out
                }
                if ($t -eq '-file' -or $t -eq '-f') { $isFile = $true; break }
                if ($t -eq '-c' -or $t -eq '-command') { $idx = $i; break }
            }
            # skript souborem je pro hook nepruhledny -> propousti se (dokumentovano)
            if ($isFile) { return $out }
            if ($idx -lt 0 -or ($idx + 1) -ge $rest.Count) { return $out }
            $inner = (($rest | Select-Object -Skip ($idx + 1)) -join ' ')
            if (Test-Unexpandable $inner) { [void]$out.Add(@{ Kind = 'opaque'; Raw = $inner }); return $out }
            foreach ($s in (Split-CommandLine $inner)) {
                foreach ($l in (Get-CommandLeaf $s ($Depth + 1))) { [void]$out.Add($l) }
            }
            return $out
        }
        '^(cmd)$' {
            $idx = -1
            for ($i = 0; $i -lt $rest.Count; $i++) {
                if ($rest[$i].ToLowerInvariant() -eq '/c' -or $rest[$i].ToLowerInvariant() -eq '/k') { $idx = $i; break }
            }
            if ($idx -lt 0 -or ($idx + 1) -ge $rest.Count) { return $out }
            $inner = (($rest | Select-Object -Skip ($idx + 1)) -join ' ')
            if (Test-Unexpandable $inner) { [void]$out.Add(@{ Kind = 'opaque'; Raw = $inner }); return $out }
            foreach ($s in (Split-CommandLine $inner)) {
                foreach ($l in (Get-CommandLeaf $s ($Depth + 1))) { [void]$out.Add($l) }
            }
            return $out
        }
        '^(eval)$' {
            $inner = ($rest -join ' ')
            if (Test-Unexpandable $inner) { [void]$out.Add(@{ Kind = 'opaque'; Raw = $inner }); return $out }
            foreach ($s in (Split-CommandLine $inner)) {
                foreach ($l in (Get-CommandLeaf $s ($Depth + 1))) { [void]$out.Add($l) }
            }
            return $out
        }
        '^(xargs)$' {
            $i = 0
            while ($i -lt $rest.Count) {
                $t = $rest[$i]
                if ($t -eq '--') { $i++; break }
                if ($t -match '^-(n|I|i|P|L|s|d|E)$') { $i += 2; continue }
                if ($t.StartsWith('-')) { $i++; continue }
                break
            }
            $inner = (($rest | Select-Object -Skip $i) -join ' ')
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
                if ($rest[$i] -eq '-exec' -or $rest[$i] -eq '-execdir' -or $rest[$i] -eq '-ok') { $idx = $i; break }
            }
            if ($idx -lt 0) { return $out }
            $tail = @($rest | Select-Object -Skip ($idx + 1) | Where-Object { $_ -ne ';' -and $_ -ne '+' -and $_ -ne '\;' })
            $inner = ($tail -join ' ')
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
    return $out
}

# ---------------------------------------------------- strukturalni pravidla ---

function Get-DbHost([string]$Raw, $LocalHosts) {
    $patterns = @(
        'host\s*=\s*([^;"''\s]+)',
        # Nalez Amber B5: Npgsql bere `Server=` i `Data Source=` jako synonymum `Host=`.
        # Bez nich se `--connection "Server=db.firma.cz;..."` cetlo jako lokalni.
        '(?:^|[;\s"''])server\s*=\s*([^;"''\s]+)',
        '(?:^|[;\s"''])data\s+source\s*=\s*([^;"''\s]+)',
        '(?:^|\s)-h\s+([^\s"'']+)',
        '--host[= ]([^\s"'']+)',
        'postgres(?:ql)?://[^@/\s]*@([^:/\s]+)'
    )
    foreach ($p in $patterns) {
        $m = [regex]::Match($Raw, $p, 'IgnoreCase')
        if ($m.Success) { return $m.Groups[$m.Groups.Count - 1].Value }
    }
    return ''
}

function Test-LocalHost([string]$HostName, $LocalHosts) {
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $true }   # bez hostu = default local
    foreach ($h in $LocalHosts) {
        if ($HostName.ToLowerInvariant() -eq ([string]$h).ToLowerInvariant()) { return $true }
    }
    return $false
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
        return @{ Decision = 'deny'; Shape = (Get-Field $shapes 'forcePushProtected' 'force push') }
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
        return @{ Decision = 'deny'; Shape = (Get-Field $shapes 'pushDeleteRefspec' 'git push :vetev') }
    }
    if ($wildcardTarget -and ($plusForce -or $force)) {
        return @{ Decision = 'deny'; Shape = (Get-Field $shapes 'forcePushProtected' 'force push') }
    }

    if ($plusForce -and $hitsProtected) {
        return @{ Decision = 'deny'; Shape = (Get-Field $shapes 'forcePushProtected' 'force push') }
    }
    if (-not $force) { return $null }
    if ($hitsProtected) {
        return @{ Decision = 'deny'; Shape = (Get-Field $shapes 'forcePushProtected' 'force push') }
    }
    if ($refspecs.Count -eq 0) {
        return @{ Decision = 'ask'; Shape = (Get-Field $shapes 'forcePushUnknown' 'force push') }
    }
    return @{ Decision = 'ask'; Shape = (Get-Field $shapes 'forcePushOther' 'force push') }
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
    if (($letters -ccontains 'X') -and -not ($letters -ccontains 'x')) {
        return @{ Decision = 'ask'; Shape = (Get-Field $shapes 'gitCleanIgnored' 'git clean -X') }
    }
    return @{ Decision = 'deny'; Shape = (Get-Field $shapes 'gitClean' 'git clean -f') }
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
    $netMatches = [regex]::Matches($Leaf.Raw,
        '\[(?:System\.)?IO\.(?:Directory|File)\]::Delete\(\s*[''"]([^''"]+)[''"]', 'IgnoreCase')
    foreach ($m in $netMatches) { $recursive = $true; [void]$targets.Add($m.Groups[1].Value) }

    # Nalez Amber A1: `[IO.Directory]::Delete($p, $true)` - cil je PROMENNA, regex nad
    # literalem v uvozovkach ji nenajde a bez teto vetve by cely tvar skoncil jako
    # allow. Zadani par. 2.3: obal s promennou -> ask. Cil nezname, tak se pta.
    if ($Leaf.Exe -eq 'net-delete' -and $targets.Count -eq 0) {
        return @{ Decision = 'ask'
                  Shape = ((Get-Field $shapes 'netDeleteVariable' 'mazani .NET volanim s promennou v ceste ({text})') `
                           -replace '\{text\}', $Leaf.Text) }
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
        foreach ($a in $rest) {
            if ($a.StartsWith('-')) { continue }
            # cmd prepinac je /s /q /f - ale /etc/x je ABSOLUTNI CESTA, ne prepinac
            if ($a -match '^/[a-zA-Z]{1,3}$') { continue }
            [void]$targets.Add($a)
        }

        # Nalez Metis 8: `Get-ChildItem src -Recurse -File | Remove-Item -Force` -
        # rekurzi dela PRVNI clanek roury, mazani druhy, a kazdy sam o sobe projde.
        # Mazaci prikaz BEZ pozicniho cile bere vstup z roury, takze rozsah nezname:
        # plati Z3 (nerozebratelne -> ask). Mazani konkretniho souboru bez -Recurse
        # zustava bezna prace (`Remove-Item -LiteralPath x -Force` ve skriptech GSD).
        if ($targets.Count -eq 0) {
            return @{ Decision = 'ask'; Shape = (Get-Field $shapes 'deleteFromPipeline' 'mazani z roury') }
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
                return @{ Decision = 'deny'
                          Shape = ((Get-Field $shapes 'recursiveDelete' 'rm -rf {target}') -replace '\{target\}', $t) }
            }
            if ($norm.StartsWith($cwdNorm + '/')) {
                $rel = $norm.Substring($cwdNorm.Length + 1)
            } else {
                return @{ Decision = 'deny'
                          Shape = ((Get-Field $shapes 'recursiveDelete' 'rm -rf {target}') -replace '\{target\}', $t) }
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

        if (-not $allowed) {
            if ($hasVar) {
                if ($null -eq $worst) {
                    $worst = @{ Decision = 'ask'
                                Shape = ((Get-Field $shapes 'recursiveDeleteWildcard' 'rm -rf {target}') -replace '\{target\}', $t) }
                }
                continue
            }
            return @{ Decision = 'deny'
                      Shape = ((Get-Field $shapes 'recursiveDelete' 'rm -rf {target}') -replace '\{target\}', $t) }
        }

        if ($hasStar -or $hasDotDot -or $hasVar) {
            if ($null -eq $worst) {
                $worst = @{ Decision = 'ask'
                            Shape = ((Get-Field $shapes 'recursiveDeleteWildcard' 'rm -rf {target}') -replace '\{target\}', $t) }
            }
        }
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
        if ($args2[$i] -match '^(-c|--command)$' -and ($i + 1) -lt $args2.Count) {
            [void]$parts.Add([string]$args2[$i + 1]); $i++
            continue
        }
        if ($args2[$i] -match '^--command=(.*)$') { [void]$parts.Add($Matches[1]) }
    }
    foreach ($m in [regex]::Matches([string]$Leaf.Raw, '"([^"]*)"|''([^'']*)''')) {
        foreach ($g in 1, 2) { if ($m.Groups[$g].Success) { [void]$parts.Add($m.Groups[$g].Value) } }
    }
    return ($parts -join ' ; ')
}

function Test-DatabaseRule($Leaf, $Config) {
    $gate = Get-Field $Config 'gate'
    $shapes = Get-Field $gate 'shapes'
    $localHosts = @(Get-Field $gate 'localDbHosts' @('localhost', '127.0.0.1', '::1'))
    $sqlClients = @(Get-Field $gate 'sqlClients' @('psql', 'pgcli', 'dropdb'))
    $raw = $Leaf.Raw

    # Hostitel se cte i z UVOZUJICIHO prikazu - u tela heredocu stoji jen tam (A4).
    $hostText = [string]$raw + ' ' + [string](Get-LeafField $Leaf 'Outer' '')

    $sql = Get-SqlText $Leaf $sqlClients

    # `(?:\s|/\*.*?\*/)+` misto `\s+`: nalez Metis 17 - SQL bere blokovy komentar jako
    # bily znak, takze `DROP/**/TABLE` je platny prikaz, ktery `\s+` nikdy nepotka.
    # `dotnet[- ]ef`: nalez Metis 10 - primo nainstalovany nastroj se jmenuje `dotnet-ef`.
    $gap = '(?:\s|/\*.*?\*/)+'

    $sqlDestructive = $false
    if ($sql -ne '') {
        $sqlDestructive = ([regex]::IsMatch($sql, ('\bdrop' + $gap + '(table|database|schema)\b'), 'IgnoreCase')) -or
                          ([regex]::IsMatch($sql, '\btruncate\b', 'IgnoreCase')) -or
                          (Test-DeleteWithoutWhere $sql)
    }

    $destructive = $sqlDestructive -or
                   ($Leaf.Exe -eq 'dropdb') -or
                   ([regex]::IsMatch($raw, ('\bdotnet[- ]ef' + $gap + 'database' + $gap + 'drop\b'), 'IgnoreCase'))

    $update = [regex]::IsMatch($raw, ('\bdotnet[- ]ef' + $gap + 'database' + $gap + 'update\b'), 'IgnoreCase')
    if (-not $destructive -and -not $update) { return $null }

    $dbHost = Get-DbHost $hostText $localHosts
    $isLocal = Test-LocalHost $dbHost $localHosts

    if ($destructive) {
        if (-not $isLocal) {
            return @{ Decision = 'deny'
                      Shape = ((Get-Field $shapes 'dbDestroyRemote' 'DB {host}') -replace '\{host\}', $dbHost) }
        }
        return @{ Decision = 'ask'; Shape = (Get-Field $shapes 'dbDestroyLocal' 'DB') }
    }

    if ($update -and -not $isLocal) {
        return @{ Decision = 'deny'
                  Shape = ((Get-Field $shapes 'efUpdateRemote' 'ef update {host}') -replace '\{host\}', $dbHost) }
    }
    return $null
}

function Test-ConfiguredPattern($Leaf, $Patterns) {
    foreach ($p in $Patterns) {
        $pattern = Get-Field $p 'pattern' ''
        if ($pattern -eq '') { continue }
        if ([regex]::IsMatch($Leaf.Text, $pattern, 'IgnoreCase')) {
            return (Get-Field $p 'shape' (Get-Field $p 'id' 'pravidlo'))
        }
    }
    return $null
}

function Test-Leaf($Leaf, $Config) {
    $gate = Get-Field $Config 'gate'
    $shapes = Get-Field $gate 'shapes'

    if ($Leaf.Kind -eq 'opaque') {
        $text = $Leaf.Raw
        if ($text.Length -gt 60) { $text = $text.Substring(0, 60) }
        return @{ Decision = 'ask'
                  Shape = ((Get-Field $shapes 'opaque' 'neznamy prikaz ({text})') -replace '\{text\}', $text) }
    }

    # Nalez Metis 27: `git -c alias.bd='branch -D' bd x` schova destruktivni podprikaz
    # do definice aliasu. Rozbalit to neumime, takze plati Z3: nerozebratelne -> ask.
    if ($Leaf.Exe -eq 'git') {
        foreach ($cfg in $Leaf.GitConfig) {
            if ($cfg -match '(?i)^alias\.') {
                return @{ Decision = 'ask'
                          Shape = ((Get-Field $shapes 'opaque' '{text}') -replace '\{text\}', $cfg) }
            }
        }
    }

    $shape = Test-ConfiguredPattern $Leaf @(Get-Field $gate 'denyPatterns' @())
    if ($shape) { return @{ Decision = 'deny'; Shape = $shape } }

    foreach ($rule in @('Test-GitPushRule', 'Test-GitCleanRule', 'Test-RecursiveDeleteRule', 'Test-DatabaseRule')) {
        $r = & $rule $Leaf $Config
        if ($r -and $r.Decision -eq 'deny') { return $r }
        if ($r -and $r.Decision -eq 'ask' -and -not $script:PendingAsk) { $script:PendingAsk = $r }
    }

    $shape = Test-ConfiguredPattern $Leaf @(Get-Field $gate 'askPatterns' @())
    if ($shape) { return @{ Decision = 'ask'; Shape = $shape } }

    if ($script:PendingAsk) { $r = $script:PendingAsk; $script:PendingAsk = $null; return $r }
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

if (-not (Test-HookEnabled $config 'gate')) { exit 0 }

$script:PendingAsk = $null
$decision = $null

# Tela heredocu se vytahnou PRED delenim - jinak by se telo stalo samostatnym
# podprikazem bez hosta a vzdalena operace by se cetla jako lokalni (Amber A4).
$heredoc = Split-Heredoc $command

$leaves = New-Object System.Collections.ArrayList
foreach ($sub in (Split-CommandLine $heredoc.Rest)) {
    foreach ($leaf in (Get-CommandLeaf $sub 0)) { [void]$leaves.Add($leaf) }
}
foreach ($b in $heredoc.Bodies) {
    [void]$leaves.Add(@{ Kind = 'heredoc'; Exe = 'heredoc'; Args = @(); Raw = $b.Body
                         Text = $b.Body; Outer = $b.Outer; OuterExe = $b.OuterExe; GitConfig = @() })
}

foreach ($leaf in $leaves) {
    $r = Test-Leaf $leaf $config
    if ($null -eq $r) { continue }
    if ($r.Decision -eq 'deny') { $decision = $r; break }
    if ($null -eq $decision) { $decision = $r }
}

if ($null -eq $decision) { exit 0 }

$reason = (Get-Text $config 'gateReason' 'Brana par. 6: {shape}') -replace '\{shape\}', $decision.Shape

if ($decision.Decision -eq 'ask' -and $mode -eq 'bypassPermissions') {
    $reason = $reason + (Get-Text $config 'bypassSuffix' ' bypass')
    Write-DenyDecision $reason
}

if ($decision.Decision -eq 'deny') { Write-DenyDecision $reason }
Write-AskDecision $reason
