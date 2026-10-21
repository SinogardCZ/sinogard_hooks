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

    # !! Nalez K2-1 (review Amber) + Ada N37/N43, opraveno v 0.1.11: slouceni je
    # JEDNOUROVNOVE nad KAZDYM top-level objektem, ne uplne melke.
    #
    # Do 0.1.10 nahrazoval klic z override cely klic defaults, takze
    # `{"gate":{"opaque":{"variable":"ask"}}}` zahodilo `denyPatterns`,
    # `allowedRemoveRoots` i `shapes`. Slo to OBEMA smery a prave proto se to
    # nepoznalo: `git reset --hard` prestal byt deny a zaroven `rm -rf bin` ZACAL byt
    # deny, takze "brana porad neco blokuje" bylo pravdive pozorovani a falesny zaver.
    # Tataz stavba je u `secrets` (N43): `{"secrets":{"envFile":{...}}}` by zahodilo
    # `denyPathPatterns`, tedy `id_rsa`, `.envrc` i `secrets.json`.
    #
    # Pravidlo je proto GENERICKE, ne vyjmenovane pro `gate`: je-li hodnota na obou
    # stranach OBJEKT, slouci se o JEDNU uroven (klic po klici); pole a skalary se
    # nahrazuji CELE. Duvod melkeho slucovani tim drzi - polozku seznamu porad nejde
    # z override jen odebrat - jen uz kvuli jednomu klici nemizi zbytek objektu.
    # Hloub nez o jednu uroven se vedome nejde (TASK-106 bod 10; N42: rozhodnuto
    # v 0.1.11, ne odlozeno do v0.2).
    $override = ConvertFrom-Json (Read-Utf8File $overridePath)

    # TASK-117 H-c (0.3.0, Z117-Q21 = A, Tom 2026-10-08): do 0.2.0 se OBSAH prepisu
    # nekontroloval vubec - `{"gate":{"denyPatterns":[]}}` vypnulo `git reset --hard`
    # a `localDbHosts` s `db.firma.cz` udelalo ze vzdaleneho hostitele "lokalni" (deny ->
    # ask, sonda F21). Pravidlo: prepis smi branu jen ZPRISNIT, s pojmenovanymi vyjimkami.
    # Mnozina pravidel se cte z VYCHOZI konfigurace PRED sloucenim - prepis ji sam zmenit
    # nemuze (vstup bezpecnostni brany nikdy hodnota, kterou si jeji adresat prepise).
    # Rezim selhani: odmitne se JEN vadny klic (spadne na vychozi hodnotu), zbytek prepisu
    # plati - zahodit cely prepis by tise zrusilo i jeho zprisneni, zakazat vse by zamklo
    # i session, ktera ma prepis opravit. Odmitnute klice nese $script:OverrideRejected
    # (jen jmena, nikdy hodnoty) - cte je kanarek a audit `config:overrideRejected`.
    $policy = Get-Field $config '_overridePolicy'
    $script:OverrideRejected = New-Object System.Collections.ArrayList
    foreach ($prop in @($override.PSObject.Properties)) {
        if ($prop.Name.StartsWith('_')) { continue }
        $rules = Get-Field $policy $prop.Name
        if ($null -eq $rules) {
            if (@(Get-Field $policy 'acceptTopLevel' @()) -notcontains $prop.Name) {
                [void]$script:OverrideRejected.Add($prop.Name)
                $override.PSObject.Properties.Remove($prop.Name)
            }
            continue
        }
        $value = $prop.Value
        if (-not (Test-MergeableObject $value)) {
            [void]$script:OverrideRejected.Add($prop.Name)
            $override.PSObject.Properties.Remove($prop.Name)
            continue
        }
        $defaultsSection = Get-Field $config $prop.Name
        foreach ($inner in @($value.PSObject.Properties)) {
            if ($inner.Name.StartsWith('_')) { continue }
            $rule = [string](Get-Field $rules $inner.Name '')
            $ok = Test-OverrideValue $rule $inner.Value (Get-Field $defaultsSection $inner.Name)
            if (-not $ok) {
                [void]$script:OverrideRejected.Add($prop.Name + '.' + $inner.Name)
                $value.PSObject.Properties.Remove($inner.Name)
            }
        }
    }

    foreach ($prop in $override.PSObject.Properties) {
        $current = $null
        if ($config.PSObject.Properties[$prop.Name]) {
            $current = $config.PSObject.Properties[$prop.Name].Value
        }
        $value = $prop.Value
        if ((Test-MergeableObject $current) -and (Test-MergeableObject $value)) {
            foreach ($inner in $value.PSObject.Properties) {
                if ($current.PSObject.Properties[$inner.Name]) {
                    $current.PSObject.Properties.Remove($inner.Name)
                }
                $current | Add-Member -NotePropertyName $inner.Name -NotePropertyValue $inner.Value
            }
            continue
        }
        if ($config.PSObject.Properties[$prop.Name]) {
            $config.PSObject.Properties.Remove($prop.Name)
        }
        $config | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $value
    }
    return $config
}

$script:OverrideRejected = New-Object System.Collections.ArrayList

# CR-P9 (/code-review): jedna definice pro H-c, H-f i rozhodnuti o vzdalenosti.
$script:LocalDbInstancePattern = '^\(localdb\)\\[A-Za-z0-9_][A-Za-z0-9_ .\-]*$'
$script:DbServerKeys = @('host', 'server', 'data source', 'address', 'addr', 'network address')

# Polozka seznamu jako ordinalni klic porovnani. Objekt (radek `denyPatterns`) se porovnava
# kompaktnim JSON; objekt, ktery nese jen komentarove klice (`_...`), neni pravidlo a do
# porovnani nevstupuje.
function Get-ListItemKey($Item) {
    if ($Item -is [System.Management.Automation.PSCustomObject]) {
        $real = @($Item.PSObject.Properties | Where-Object { -not $_.Name.StartsWith('_') })
        if ($real.Count -eq 0) { return $null }
        # CR-P6 (/code-review): pravidlo (`denyPatterns`, `auditPatterns`) urcuje jeho id a VZOR - poradi klicu ani
        # lidsky text `shape` ho nemeni; porovnani celeho JSON by kvuli nim odmitlo zprisnujici prepis.
        if ($Item.PSObject.Properties['pattern']) { return ([string](Get-Field $Item 'id' '') + [char]1 + [string]$Item.pattern) }
        return ($Item | ConvertTo-Json -Depth 6 -Compress)
    }
    return [string]$Item
}

function Test-ListRelation($Value, $Default, [string]$Relation) {
    if ($null -eq $Value -or -not ($Value -is [System.Array])) { return $false }
    $have = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($v in $Value) { $k = Get-ListItemKey $v; if ($null -ne $k) { [void]$have.Add($k) } }
    $base = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($d in @($Default)) { $k = Get-ListItemKey $d; if ($null -ne $k) { [void]$base.Add($k) } }
    if ($Relation -eq 'superset') { foreach ($k in $base) { if (-not $have.Contains($k)) { return $false } }; return $true }
    foreach ($k in $have) { if (-not $base.Contains($k)) { return $false } }
    return $true
}

# TASK-117 H-f (Z117-Q18 = A, Tom 2026-10-08): MISTNI server je PEVNA mnozina v kodu, ne
# hodnota, kterou si projekt prepise - `gate.localDbHosts` i `gate.dbDestroyLocal.hosts`
# z ni smi jen VYBIRAT (H-c), a cesta `allow` rozhoduje "mistni" jen podle ni (M17, T117-N12).
# LocalDB je funkce SQL Server Express pro vyvojare, bezi pod uzivatelem (MS Learn, overeno
# Amber 2026-10-08) - je mistni. Prefixy protokolu (`tcp:`, `np:`, `lpc:`) a pojmenovana roura
# nejsou v mnozine: jmeno roury se meni s kazdym startem instance a `tcp:` muze mirit kamkoli.
function Test-FixedLocalDbHost([string]$HostName) {
    $h = ([string]$HostName).Trim()
    if ($h -eq '') { return $false }
    if ($h -match $script:LocalDbInstancePattern) { return $true }
    if ($h -match '^(localhost|127\.0\.0\.1)(,[0-9]{1,5})?$') { return $true }
    if ($h -match '^(localhost|127\.0\.0\.1|::1|\(local\)|\.)(\\[A-Za-z0-9_$\-]+)?$') { return $true }
    return $false
}

# Pravidlo H-c pro jeden klic prepisu. Neznamy klic (prazdne pravidlo) = odmitnout: preklep
# nebo budouci povrch se nesmi tise uplatnit.
function Test-OverrideValue([string]$Rule, $Value, $Default) {
    switch ($Rule) {
        'accept'   { return $true }
        'superset' { return (Test-ListRelation $Value $Default 'superset') }
        'subset'   { return (Test-ListRelation $Value $Default 'subset') }
        'localHosts' {
            if ($null -eq $Value -or -not ($Value -is [System.Array])) { return $false }
            foreach ($h in $Value) { if (-not (Test-FixedLocalDbHost ([string]$h))) { return $false } }
            return $true
        }
        # ZOPT-Q102 / A179-O3 (0.3.1): politiky byvaleho `ask` (`gate.opaque`, `gate.decisions`, `secrets.decisions`) maji
        # hodnoty `audit` | `deny` a prepis smi jen zprisnit - klic s vychozim `deny` zustava `deny`. Neznamy klic = odmitnout.
        'policy' {
            if (-not (Test-MergeableObject $Value)) { return $false }
            foreach ($p in $Value.PSObject.Properties) {
                if ($p.Name.StartsWith('_')) { continue }
                $d = Get-Field $Default $p.Name $null
                if ($null -eq $d) { return $false }
                $v = [string]$p.Value
                if ($v -cne 'audit' -and $v -cne 'deny') { return $false }
                if ([string]$d -ceq 'deny' -and $v -cne 'deny') { return $false }
            }
            return $true
        }
        'envFile' {
            if (-not (Test-MergeableObject $Value)) { return $false }
            foreach ($p in $Value.PSObject.Properties) {
                if ($p.Name.StartsWith('_')) { continue }
                if (@('denyNames', 'allowNames', 'otherPolicy') -cnotcontains $p.Name) { return $false }
            }
            # Objekt se slucovanim nahrazuje CELY - chybejici `denyNames` = prazdny seznam = uvolneni.
            if (-not (Test-ListRelation (Get-Field $Value 'denyNames' @()) (Get-Field $Default 'denyNames' @()) 'superset')) { return $false }
            $allow = Get-Field $Value 'allowNames' $null
            if ($null -ne $allow -and -not (Test-ListRelation $allow (Get-Field $Default 'allowNames' @()) 'subset')) { return $false }
            $other = Get-Field $Value 'otherPolicy' $null
            if ($null -ne $other -and [string]$other -cne [string](Get-Field $Default 'otherPolicy' '')) { return $false }
            return $true
        }
        'dbDestroyLocal' {
            if (-not (Test-MergeableObject $Value)) { return $false }
            foreach ($p in $Value.PSObject.Properties) {
                if ($p.Name.StartsWith('_')) { continue }
                if (@('decision', 'databases', 'hosts') -cnotcontains $p.Name) { return $false }
            }
            # T117-N14: chybejici `decision` NIKDY allow - objekt se nahrazuje cely, takze by
            # jinak rozhodl vychozi kod; odmitnuti vrati vychozi hodnotu explicitne.
            # ZOPT-Q102 (0.3.1): `ask` uz neni hodnota; `allow` = jen databaze ve vzorech `databases`, jinak deny.
            $decision = Get-Field $Value 'decision' $null
            if ($null -eq $decision -or @('allow', 'deny') -cnotcontains [string]$decision) { return $false }
            # CR-Q1 (/code-review 0.3.1): `deny` vzory necte - odmitnuti kvuli vzorum mimo strop by vratilo vychozi `allow`,
            # tedy UVOLNENI prepisu, ktery bral vse.
            if ([string]$decision -ceq 'deny') { return $true }
            # A179-O3 (Q10): vychozi vzory testovacich a vyvojovych DB jsou strop - prepis z nich smi jen vybirat
            # (chybejici `databases` = prazdny seznam = zadna DB se nepovoli, tedy zprisneni).
            $dbs = Get-Field $Value 'databases' @()
            if (-not ($dbs -is [System.Array]) -and $null -ne $dbs) { $dbs = @($dbs) }
            if (-not (Test-ListRelation @($dbs) (Get-Field $Default 'databases' @()) 'subset')) { return $false }
            $hosts = Get-Field $Value 'hosts' @()
            foreach ($h in @($hosts)) { if (-not (Test-FixedLocalDbHost ([string]$h))) { return $false } }
            return $true
        }
    }
    return $false
}

# Objekt z ConvertFrom-Json je PSCustomObject. Pole ani skalar se neslucuji - pole by
# se slucovanim nedalo zkratit a skalar zadne klice nema. `$null` taky ne: klic, ktery
# v defaults vubec neni, se pridava cely.
function Test-MergeableObject($Value) {
    if ($null -eq $Value) { return $false }
    if ($Value -is [System.Array]) { return $false }
    return ($Value -is [System.Management.Automation.PSCustomObject])
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

# ZOPT-Q102 (Tom 2026-10-20) + A179-O3 (Amber), 0.3.1: zapisovac `ask` zmizel - hook ve sede zone necheka na cloveka.
# Kazde byvale `ask` ma politiku `audit` (hook mlci + radek auditu) nebo `deny`; chybejici nebo neznama hodnota = `deny`
# (fail-closed: preklep v prepisu branu tise neotevre).
function Get-PolicyDecision($Section, [string]$Id) {
    $v = [string](Get-Field (Get-Field $Section 'decisions') $Id 'deny')
    if ($v -ceq 'audit') { return 'audit' }
    return 'deny'
}

function New-PolicyVerdict($Section, [string]$Id, [string]$Shape) {
    return @{ Id = $Id; Decision = (Get-PolicyDecision $Section $Id); Shape = $Shape }
}

# ------------------------------------------------------ normalizace cesty ---

function ConvertTo-NormalPath([string]$Path) {
    if ([string]::IsNullOrEmpty($Path)) { return '' }
    $p = $Path.Trim()
    $p = $p.Trim('"').Trim("'")
    $p = $p -replace '\\', '/'
    # Z117-Q26 = A (A117-N6): prefix Win32 cest `\\?\` / `\\.\` (a `\\?\UNC\server\share`) je jen zpusob zapisu - do 0.3.0
    # zustal `?` v ceste, brala se jako glob a `\\?\...\.claude\settings.json` zapis mlcel, `\\?\...\.env` cteni bylo jen ask.
    $p = [regex]::Replace($p, '^//[?.]/unc/', '//', 'IgnoreCase')
    $p = [regex]::Replace($p, '^//[?.]/', '')
    # A117-N19: NT prefix objektu `\??\C:\...` tataz trida.
    $p = [regex]::Replace($p, '^/\?\?/', '')
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
# CR-S8 + CR-T1..T6 (TASK-179, kola 3 a 4 /code-review): Bash i PowerShell maji komentar `#` (PowerShell i `<# ... #>`).
# Skener o nem nevedel, takze apostrof v komentari (`# don't` + novy radek + `git reset --hard`) otevrel "retezec" az do
# konce prikazu a dalsi statementy se nerozdelily -> allow (i v 0.3.0). Prvni oprava (kolo 3) komentar ZAHAZOVALA - a kde
# `#` komentarem neni (cmd, `${a #}`, zpetne apostrofy), zahodila i spousteny prikaz. Od kola 4 komentar NIC NEZAHAZUJE:
# v nem jen uvozovky (a zavorky) prestanou byt specialni, oddelovace dal deli a text zustava. Kde `#` komentarem neni,
# skener tak vidi VIC prikazu, ne mene (smer deny).
# Zacatek komentare: `#` na zacatku textu nebo za bilym znakem ci `; | & ( {`; v PowerShellu i `<#`. Vraci delku
# uvozujiciho tokenu (0 = neni komentar).
# Kde `#` komentarem NENI (cmd, `${x:- #}`, zpetne apostrofy) a za nim je otevrena uvozovka pres konec radku, mohlo by
# cteni s komentarem videt i MENE nez cteni bez nej. Oba hooky (gate.ps1, secrets.ps1) proto prikaz s `#` rozeberou jeste
# jednou BEZ komentare ($script:CommentAware = $false, cteni 0.3.0) a z druheho cteni berou jen `deny`.
$script:CommentAware = $true
$script:BlockCommentSplit = $false

# CR-W2/W3/W8 + CR-X + CR-Y (TASK-179, kola 7 az 9): druhe cteni prikazu BEZ komentare - jeden protokol pro gate.ps1
# i secrets.ps1. Spousti se, kdyz prikaz obsahuje `#`, nebo kdyz prvni cteni dekodovalo `-EncodedCommand` s `#` v tele
# (ConvertFrom-EncodedCommandText, $script:DecodedHasHash). Rozpocet prace na substituce se NEnuluje (strop jednoho behu
# hooku drzi timeout 10 s); narazi-li na nej az druhe cteni, gate.ps1 rozhodne `deny` (nerozebratelne).
# Z druheho cteni plati jen `deny`, audit je ztlumeny.
$script:DecodedHasHash = $false
function Test-NeedsPlainReading([string]$Command) {
    return ($Command.IndexOf('#') -ge 0 -or $script:DecodedHasHash)
}
function Invoke-PlainCommentReading([scriptblock]$Body) {
    $prevAware = $script:CommentAware
    $prevMuted = $script:AuditMuted
    $script:CommentAware = $false
    $script:AuditMuted = $true
    try { return (& $Body) } finally { $script:CommentAware = $prevAware; $script:AuditMuted = $prevMuted }
}

function Get-CommentStart([string]$Text, [int]$I) {
    if (-not $script:CommentAware) { return 0 }
    $c = $Text[$I]
    if ($c -eq '<' -and $script:ScannerEscape -eq '`' -and ($I + 1) -lt $Text.Length -and $Text[$I + 1] -eq '#') { return 2 }
    if ($c -ne '#') { return 0 }
    if ($I -eq 0) { return 1 }
    $p = $Text[$I - 1]
    if ([char]::IsWhiteSpace($p) -or ';|&('.IndexOf($p) -ge 0) { return 1 }
    # CR-U4 (kolo 5): `{#` je komentar jen v PowerShellu a ne v `${#x}` (delka retezce v Bashi, jmeno promenne v PowerShellu).
    if ($p -eq '{' -and $script:ScannerEscape -eq '`' -and -not ($I -ge 2 -and $Text[$I - 2] -eq '$')) { return 1 }
    return 0
}

# Konec komentare od pozice $I: radkovy konci PRED koncem radku, blokovy (`<#`) ZA `#>`. Vraci index prvniho znaku za
# komentarem (u radkoveho = konec radku, ten dal deli).
function Get-CommentEnd([string]$Text, [int]$I, [int]$StartLen) {
    if ($StartLen -eq 2) {
        $e = $Text.IndexOf('#>', $I + 2)
        if ($e -lt 0) { return $Text.Length }
        return $e + 2
    }
    $j = $I
    while ($j -lt $Text.Length -and $Text[$j] -ne "`n" -and $Text[$j] -ne "`r") { $j++ }
    return $j
}

function Set-ScannerEscape([string]$ToolName) {
    if ($ToolName -eq 'PowerShell') { $script:ScannerEscape = '`' } else { $script:ScannerEscape = '\' }
}

function Get-ScannerEscape { return $script:ScannerEscape }

# Nalez Amber I2: pri sestupu do VNORENEHO shellu se escape znak neprepnul, takze
# `pwsh -c 'echo <zpetny apostrof>" ; git reset --hard'` psane z Bash nastroje se
# rozebiralo bashovymi pravidly a propadlo. Znak patri k tomu shellu, ktery ten
# text SPUSTI, ne k tomu, ktery ho predal dal.
function Set-ScannerEscapeChar([string]$Char) { $script:ScannerEscape = $Char }

# Nalez Amber K1: `{` neotevira blok vsude. Za `@` je to hashtable nebo revize
# (`@{ Path = 'src' }`, `stash@{0}`, `HEAD@{1}`), za `$` promenna (`${DIR}`),
# za pismenem nebo cislici cast slova. Takova zavorka se do zanoreni POCITA -
# jinak by `${env:X}` uzavrelo blok, ktery nikdy neotevrelo - ale blok neotevira.
function Test-BlockOpenPosition([string]$Text, [int]$Index) {
    if ($Index -le 0) { return $true }
    $prev = $Text[$Index - 1]
    if ($prev -eq '@' -or $prev -eq '$') { return $false }
    if ([char]::IsLetterOrDigit($prev) -or $prev -eq '_') { return $false }
    return $true
}

# Bloky skriptu `{ ... }` ve statementu - kvotove a escape korektne. Vraci hashtable
# `Blocks` (seznam @{ Head; Body } pro KAZDY blok na nejvyssi urovni) a `Whole`
# (statement je PRESNE jeden blok bez hlavy a bez ocasu, napr. `{ rm -rf src }`).
#
# Nalez Amber I1: rozbaleni bloku delal regex ukotveny na ZACATEK statementu, takze
# `& { rm -rf src }` se rozebralo, ale `if ($x) { git reset --hard }` uz ne - a po
# zavedeni zanoreni slozenych zavorek (G4) se to navic drzelo pohromade i pres konce
# radku, takze viceradkovy blok schoval prikaz uplne.
#
# Nalez Amber K1: oprava I1 pak brala PRVNI `{` kdekoli a hlavu zahazovala, takze
# `git stash drop stash@{0}` vyslo jako telo `0` -> allow. Hlava se proto vraci
# volajicimu a ten ji rozebira taky.
#
# Nalez Amber K2 (TASK-106 bod 6, 0.2.0): do 0.1.11 se telo hledalo jen tehdy, kdyz
# statement zavorkou KONCIL - `if ($x) { rm -rf src } else { git status }`,
# `try { ... } catch { ... }` i `{ ... } # poznamka` prosly NEROZEBRANE, protoze prvni
# blok nebyl posledni znak textu. Stara dira, ne regrese (zmereno na klonu 0.1.4).
# Rozebiraji se proto VSECHNY bloky statementu, ne prvni; hlava kazdeho z nich je
# text mezi koncem predchoziho bloku a jeho zavorkou. Kontrolni skupina (vyrok 2
# Amber 2026-09-12): `if ($x) { git status } else { git log }` NESMI skoncit dotazem.
function Get-ScriptBlockBodies([string]$Text) {
    $blocks = New-Object System.Collections.ArrayList
    $t = ([string]$Text).Trim()
    if ($t.Length -lt 2) { return @{ Blocks = $blocks; Whole = $false } }

    $esc = $script:ScannerEscape
    $inSingle = $false
    $inDouble = $false
    $open = -1
    $depth = 0
    $prevEnd = 0     # index ZA koncem predchoziho bloku = zacatek hlavy dalsiho
    $lastClose = -1  # index `}` posledniho zaznamenaneho bloku
    $i = 0
    $n = $t.Length
    while ($i -lt $n) {
        $c = $t[$i]
        if ($inSingle) { if ($c -eq "'") { $inSingle = $false }; $i++; continue }
        if ($c -eq $esc -and ($i + 1) -lt $n) { $i += 2; continue }
        if ($c -eq '"') { $inDouble = -not $inDouble; $i++; continue }
        if ($inDouble) { $i++; continue }
        # CR-T (kolo 4): zavorka ani uvozovka v komentari blok neotevira ani nezavira (`{ # it's` + novy radek + `rm -rf x }`).
        $cl = Get-CommentStart $t $i
        if ($cl -gt 0) { $i = Get-CommentEnd $t $i $cl; continue }
        if ($c -eq "'") { $inSingle = $true; $i++; continue }
        if ($c -eq '{') {
            if ($open -lt 0 -and (Test-BlockOpenPosition $t $i)) { $open = $i }
            $depth++
        } elseif ($c -eq '}') {
            if ($depth -gt 0) { $depth-- }
            # Uzavreni otevrene zavorky na nejvyssi urovni = jeden blok. Text ZA nim
            # muze nest dalsi blok (`else { ... }`, `catch { ... }`), tak se cte dal.
            if ($depth -eq 0 -and $open -ge 0) {
                $len = $i - $open - 1
                if ($len -gt 0) {
                    [void]$blocks.Add(@{ Head = $t.Substring($prevEnd, $open - $prevEnd).Trim()
                                         Body = $t.Substring($open + 1, $len) })
                    $lastClose = $i
                    $prevEnd = $i + 1
                }
                $open = -1
            }
        }
        $i++
    }
    $whole = ($blocks.Count -eq 1 -and $blocks[0].Head -eq '' -and $lastClose -eq ($n - 1))
    return @{ Blocks = $blocks; Whole = $whole }
}

# `KeepSeparators`: separatory, ktere maji z deleni PREZIT a pripojit se
# k NASLEDUJICIMU segmentu. Vznik: `&` je v PowerShellu operator SPUSTENI, ne
# oddelovac - jenze delenim se z `& $cmd` stal `$cmd` a informace, ze se obsah
# promenne spousti, se ztratila (0.1.9 to zaznamenala v CHANGELOGu jako fakt,
# ktery brani otevrit `$sql | psql`). Do 0.1.9 to nevadilo, protoze KAZDA
# nerozebratelna vec byla `ask`; od 0.1.10 na tom rozdilu zalezi.
#
# !! Vychozi hodnota je PRAZDNA schvalne. `secrets.ps1` deli tymz skenerem a segment
# zacinajici na `&` by mu posunul argv[0] - `& cat secrets.json` by prestal byt videt.
# Marker si proto vyzada jen ten volajici, ktery ho umi zpracovat (`Get-CommandLeaf`
# vedouci `&` strhava hned na zacatku).
function Split-Unquoted([string]$Text, [string[]]$Separators, [string[]]$KeepSeparators = @()) {
    if ([string]::IsNullOrEmpty($Text)) { return ,@() }

    $r = Split-UnquotedCore $Text $Separators $true $true $KeepSeparators
    # Nevyvazena slozena zavorka => zanoreni se nikdy nevratilo na nulu a nedelilo by
    # se uz vubec nic. Druhy pruchod ji ignoruje.
    if ($r.BraceOpen) { $r = Split-UnquotedCore $Text $Separators $true $false $KeepSeparators }
    # Sken skoncil s OTEVRENOU dvojitou uvozovkou => vstup je bud rozbity, nebo jsme
    # si escapem zavreli oci (`echo "C:\src\"` je v Bashi opravdu neuzavreny retezec).
    # Druhy pruchod BEZ escapu deli VIC, tedy smerem k deny; propustit kvuli tomu nic
    # nejde, nanejvys se rozdeli neco, co se delit nemelo.
    if ($r.Open) { $r = Split-UnquotedCore $Text $Separators $false $false $KeepSeparators }
    return ,@($r.Parts)
}

function Split-UnquotedCore([string]$Text, [string[]]$Separators, [bool]$HonorEscape, [bool]$HonorBrace,
                            [string[]]$KeepSeparators = @()) {
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
            [void]$buf.Append($c); [void]$buf.Append($Text[$i + 1])
            $i += 2
            # Nalez Amber I4: konec radku je na Windows CRLF. Escape spolkl jen CR
            # a LF zustalo jako separator, takze `git reset \<CRLF>--hard` se rozpadlo
            # na dva prikazy a `--hard` samo nic nespoustelo -> allow.
            if ($Text[$i - 1] -eq "`r" -and $i -lt $n -and $Text[$i] -eq "`n") {
                [void]$buf.Append($Text[$i]); $i++
            }
            continue
        }
        if ($c -eq "'" -and -not $inDouble) {
            $inSingle = $true; [void]$buf.Append($c); $i++; continue
        }
        if ($c -eq '"') { $inDouble = -not $inDouble; [void]$buf.Append($c); $i++; continue }
        if ($inDouble) { [void]$buf.Append($c); $i++; continue }

        # CR-S8/CR-T (kola 3 a 4): komentar - text zustava, uvozovky a zavorky v nem nejsou specialni, oddelovace na nejvyssi
        # urovni dal deli (viz Get-CommentStart). Komentar je VLASTNI segment (`<# it's #> git reset --hard` -> `<# it's #>`
        # a `git reset --hard`); druhe cteni bez komentare (Invoke-PlainCommentReading v gate.ps1 a secrets.ps1) vidi i cely
        # `Remove-Item <# x; #> -Recurse src`. Uvnitr `$( ... )` / `{ ... }` se komentar opise cely (deli ho az rozbor tela).
        $cl = Get-CommentStart $Text $i
        if ($cl -gt 0) {
            $ce = Get-CommentEnd $Text $i $cl
            if ($depth -gt 0 -or $brace -gt 0) {
                [void]$buf.Append($Text.Substring($i, $ce - $i)); $i = $ce; continue
            }
            # Blokovy komentar BEZ oddelovace uvnitr je v PowerShellu bily znak (`cat <# x #> .env` = `cat .env`).
            if ($cl -eq 2) {
                $body = $Text.Substring($i, $ce - $i)
                $sepIn = $false
                foreach ($s in $seps) { if ($s.Length -gt 0 -and $body.IndexOf($s, [System.StringComparison]::Ordinal) -ge 0) { $sepIn = $true; break } }
                # CR-V3 (kolo 6): komentar mezi statementy (hlavicka `<# .SYNOPSIS ... #>`, `git status <# a; b #>`) nic
                # nedeli - pred nim na radku nic neni, nebo za nim do konce radku nic neni.
                $after = $Text.Substring($ce)
                $nl = $after.IndexOfAny([char[]]@("`n", "`r"))
                $tail = if ($nl -ge 0) { $after.Substring(0, $nl) } else { $after }
                if ($sepIn -and ($buf.ToString().Trim() -eq '' -or $tail.Trim() -eq '' -or $tail.Trim().StartsWith(';'))) { $sepIn = $false }
                if (-not $sepIn) { [void]$buf.Append(' '); $i = $ce; continue }
                # CR-U1 (kolo 5): s oddelovacem uvnitr (`git reset <# ; #> --hard`) ho zadne cteni nesestavi zpet jako
                # PowerShell (komentar = bily znak), a v cmd `<#` komentarem neni. Hook gate takovy prikaz zakaze (depth).
                $script:BlockCommentSplit = $true
            }
            [void]$out.Add($buf.ToString()); [void]$buf.Clear()
            while ($i -lt $ce) {
                $hit = $null
                foreach ($s in $seps) {
                    if ($s.Length -gt 0 -and ($ce - $i) -ge $s.Length -and
                        [string]::CompareOrdinal($Text, $i, $s, 0, $s.Length) -eq 0) { $hit = $s; break }
                }
                if ($null -ne $hit) {
                    [void]$out.Add($buf.ToString()); [void]$buf.Clear()
                    if ($KeepSeparators -ccontains $hit) { [void]$buf.Append($hit) }
                    $i += $hit.Length; continue
                }
                [void]$buf.Append($Text[$i]); $i++
            }
            [void]$out.Add($buf.ToString()); [void]$buf.Clear()
            continue
        }

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
        # CR-T7 (kolo 4): `&` v duplikaci deskriptoru (`2>&1`, `<&3`) neni oddelovac - `psql ... 2>&1` se rozpadlo na list
        # `1`. CR-U2 (kolo 5): `&>` ano - v cmd `echo hi &>nul rd /s /q src` spusti `rd`.
        if ($hit -ceq '&' -and $i -gt 0 -and '<>'.IndexOf($Text[$i - 1]) -ge 0) { $hit = $null }
        if ($null -ne $hit) {
            [void]$out.Add($buf.ToString()); [void]$buf.Clear()
            # -ccontains: porovnani separatoru je ordinalni jako vsude jinde ve skeneru.
            if ($KeepSeparators -ccontains $hit) { [void]$buf.Append($hit) }
            $i += $hit.Length; continue
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
        # CR-T (kolo 4): zavorka ani uvozovka v komentari se nepocita (`$( # it's)` + novy radek + `rm -rf x )`).
        $cl = Get-CommentStart $Text $j
        if ($cl -gt 0) { $j = Get-CommentEnd $Text $j $cl; continue }
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
    $inDouble = $false
    # CR-T (kolo 4): konec komentare (-1 = mimo komentar). V komentari uvozovky nejsou specialni, `$( ... )` se hleda dal
    # (kde `#` komentarem neni, vidime vic).
    $cmtEnd = -1
    while ($i -lt $n) {
        $c = $Text[$i]
        if ($cmtEnd -ge 0 -and $i -ge $cmtEnd) { $cmtEnd = -1 }
        if ($inSingle) { if ($c -eq "'") { $inSingle = $false }; $i++; continue }
        # `\$(...)` v Bashi substituci NEPROVEDE (nalez Amber G1, tataz trida).
        if ($c -eq $esc -and ($i + 1) -lt $n) { $i += 2; continue }
        if ($cmtEnd -lt 0 -and -not $inDouble) {
            $cl = Get-CommentStart $Text $i
            if ($cl -gt 0) { $cmtEnd = Get-CommentEnd $Text $i $cl }
        }
        # Nalez Amber I3: apostrof UVNITR dvojitych uvozovek neni uvozovka, ale znak.
        # `echo "it's $(git reset --hard)"` otevrel "retezec" na apostrofu a substituce
        # se uz nenasla -> allow. Stav dvojitych uvozovek se proto sleduje taky - ale
        # jen kvuli apostrofu: substituce se v nich PROVADI, takze se prochazi dal.
        if ($c -eq '"' -and $cmtEnd -lt 0) { $inDouble = -not $inDouble; $i++; continue }
        if ($c -eq "'" -and -not $inDouble -and $cmtEnd -lt 0) { $inSingle = $true; $i++; continue }
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
# !! Nalez Hestia N23 (kolo 6): `return (Split-Unquoted ...)` zahodi carku, kterou si
# Split-Unquoted hlida, takze JEDNOPRVKOVY vysledek se rozbali na RETEZEC. Volajici pak
# sahne na `.Count`, coz pod StrictMode vyhodi vyjimku a hook fail-closed BLOKUJE:
# `bash -c 'git log | head'` koncilo "interni chyba" - falesny blok na bezne praci.
#
# !! Opravou NENI pridat `,@(...)` sem: kolem uz zabaleneho pole to prida DALSI uroven
# a dvouclankova roura pak vyjde jako jeden prvek (zmereno - `count=1`). Carka patri
# tam, kde pole vznika (Split-Unquoted), a volajici si vysledek zabaluje `@(...)`.
function Split-Statement([string]$Text) {
    return (Split-Unquoted $Text @('&&', '||', ';', '&', "`n", "`r"))
}

# Clanky roury. Vstup uz MUSI byt jeden statement - jinak by se `||` rozpadlo na `|`.
function Split-Pipe([string]$Statement) {
    return (Split-Unquoted $Statement @('|'))
}

function Split-CommandLine([string]$Command, [string[]]$KeepSeparators = @()) {
    if ([string]::IsNullOrWhiteSpace($Command)) { return ,@() }

    $result = New-Object System.Collections.ArrayList
    foreach ($seg in (Split-Unquoted $Command @('&&', '||', ';', '|', '&', "`n", "`r") $KeepSeparators)) {
        [void]$result.Add($seg)
    }

    # Substituce se rozebiraji navic - `echo $(git branch -D x)` je i to vnitrni.
    foreach ($e in (Get-Substitution $Command)) {
        foreach ($sub in (Split-CommandLine $e $KeepSeparators)) { [void]$result.Add($sub) }
    }

    # Pary zpetnych apostrofu = substituce v Bashi. Do 0.1.11 se braly REGEXEM bez
    # ohledu na escape a uvozovky (N-H6, TASK-106): `git merge -m "... \`& \$cmd\` ..."`
    # z transkriptu skoncil `invoked`, ac `\`` je v Bashi literal. Skener nize cte
    # escape a jednoduche uvozovky; v PowerShellu je zpetny apostrof ESCAPE a zadna
    # substituce, takze se tam obsah neprebira vubec (drive "nanejvys falesne
    # pozitivni" - a presne to falesne pozitivni se ve vzorku naslo).
    foreach ($e in (Get-BacktickSubstitution $Command)) {
        foreach ($sub in (Split-CommandLine $e $KeepSeparators)) { [void]$result.Add($sub) }
    }

    return ,@($result | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
}

# Obsah paru zpetnych apostrofu v Bashi - jen NEescapovanych a mimo jednoduche uvozovky.
# V dvojitych uvozovkach se substituce PROVADI (`echo "\`git reset --hard\`"`), takze se
# jejich stav nesleduje. Pod PowerShellovym escapem (zpetny apostrof) vraci prazdno:
# tam zadna substituce zpetnymi apostrofy neexistuje.
function Get-BacktickSubstitution([string]$Text) {
    $out = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrEmpty($Text)) { return ,@() }
    $esc = $script:ScannerEscape
    if ($esc -eq '`') { return ,@() }

    $i = 0
    $n = $Text.Length
    $inSingle = $false
    $start = -1
    while ($i -lt $n) {
        $c = $Text[$i]
        if ($inSingle) { if ($c -eq "'") { $inSingle = $false }; $i++; continue }
        if ($c -eq $esc -and ($i + 1) -lt $n) { $i += 2; continue }
        # CR-T (kolo 4): komentar mimo zpetne apostrofy je preskoci (Bash je v komentari nebere); uvnitr nich konci komentar
        # i na zaviracim apostrofu (`` `rm -rf x # y` `` - obsah se rozebere).
        $cl = Get-CommentStart $Text $i
        if ($cl -gt 0) {
            $ce = Get-CommentEnd $Text $i $cl
            if ($start -ge 0) {
                $bt = $Text.IndexOf('`', $i)
                if ($bt -ge 0 -and $bt -lt $ce) { $ce = $bt }
            }
            $i = $ce; continue
        }
        if ($c -eq "'" -and $start -lt 0) { $inSingle = $true; $i++; continue }
        if ($c -eq '`') {
            if ($start -lt 0) { $start = $i + 1 }
            else {
                $len = $i - $start
                if ($len -gt 0) { [void]$out.Add($Text.Substring($start, $len)) }
                $start = -1
            }
        }
        $i++
    }
    return ,@($out)
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
                $i += 2
                # CRLF je dva znaky (nalez Amber I4).
                if ($Command[$i - 1] -eq "`r" -and $i -lt $n -and $Command[$i] -eq "`n") { $i++ }
                continue
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
# !! POZOR (N-H10, TASK-117): funkce vraci `,@(...)`, takze na volajicim miste se vysledek
# do `@( )` NEBALI - `@(Expand-ColonParameter $x)` zabali pole JESTE JEDNOU, Count je 1
# a prvni "token" je cele argv. Tataz past jako u Split-UnquotedCore (viz poznamka tam).
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

# Operatory PowerShellu. Za nimi uz nestoji prikaz, ale druhy operand.
$script:PsOperators = '(?:c|i)?(?:eq|ne|lt|le|gt|ge|like|notlike|match|notmatch|contains|notcontains|in|notin|is|isnot|and|or|xor|not|band|bor|bxor|bnot|shl|shr|replace|split|join|as|f)'

# Nalez Amber L1: v PowerShellu je `$_.Name -like '*.cs'` VYRAZ, ne prikaz.
# Z3 ("promenna v pozici prikazu -> ask") mysli tvar `$VAR arg`, kde se obsah
# promenne SPUSTI. Cteni vlastnosti ani `$i++` nespousti nic - jenze od opravy I1
# se telo bloku rozebira vzdycky, takze KAZDY bezny `Where-Object { ... }` koncil
# na ask a v bypassu na deny. Falesny blok na bezne praci branu do tydne vypne.
#
# Zavorka kdekoli rusi vyjimku: `$_.Delete()` maze a `$x -or (git reset --hard)`
# spousti podvyraz. Radsi falesny ask nez slepe misto.
#
# Volajici tohle smi uplatnit JEN v PowerShellu - `$cmd -rf src` je v Bashi prikaz.
function Test-ExpressionStatement([string]$Text) {
    $t = ([string]$Text).Trim()
    if ($t -eq '' -or -not $t.StartsWith('$')) { return $false }
    if ($t.Contains('(')) { return $false }

    # `$i++`, `$i--`
    if ($t -match '^\$[\w:]+\s*(?:\+\+|--)\s*$') { return $true }
    # `$_`, `$_ -eq 'x'`, `$x -like '*.cs'`
    if ($t -match '^\$_\s*$') { return $true }
    if ($t -match ('^\$(?:_|[A-Za-z_][\w:]*)\s+-' + $script:PsOperators + '\b')) { return $true }
    # `$_.Name`, `$_.Name -like '*.cs'`, `$files[0].Length` - pristup k vlastnosti
    # nebo index, za nim uz jen konec, operator nebo dalsi clen vyrazu. Bare slovo
    # za retezcem clenu ZUSTAVA prikazem (`$x.Cmd arg`).
    if ($t -match ('^\$(?:_|[A-Za-z_][\w:]*)(?:\.[A-Za-z_]\w*|\[[^\]]*\])+\s*(?:$|-' + $script:PsOperators + '\b|[|,;+*/])')) { return $true }
    return $false
}

# ------------------------------------------------------------- audit (T-10 A) ---
#
# TASK-117 H-b (0.3.0, Z117-Q8 = B): radek auditu nese i kazde `ask` a `deny` - s ID tvaru
# (`gate:git-reset-hard`, `secrets:secretFile`), nikdy s textem prikazu, cestou ani jmenem
# promenne. Odmitnute klice prepisu (H-c) se zapisuji jednou za session (CR-P10; znacka bez zamku -
# soubezne volani gate + secrets radek muze zdvojit a dve soubezne session nad tymz CLAUDE_PLUGIN_DATA si znacku
# prepisuji, takze se radek opakuje - nikdy se neztrati):
# `config:overrideRejected:<klic>`, rozhodnuti `reject`.
function Write-OverrideRejectedAudit([string]$ToolName, $Config, [string]$SessionId = '') {
    if (@($script:OverrideRejected).Count -eq 0) { return }
    # CR-P10 (/code-review): radek pri KAZDEM volani obou hooku by audit zaplavil (2 radky na tool call) a prehlusil
    # kanarek. Zapisuje se proto jednou za session a sadu klicu: znacka `override-rejected.json` vedle auditu.
    try {
        $dir = $env:CLAUDE_PLUGIN_DATA
        if (-not [string]::IsNullOrWhiteSpace($dir) -and $SessionId -ne '') {
            $mark = Join-SafePath $dir 'override-rejected.json'
            $sig = $SessionId + '|' + (@($script:OverrideRejected) -join ',')
            if ($null -ne $mark -and (Test-SafePath $mark) -and ([System.IO.File]::ReadAllText($mark)).Trim() -eq $sig) { return }
            [void][System.IO.Directory]::CreateDirectory($dir)
            if ($null -ne $mark) { [System.IO.File]::WriteAllText($mark, $sig) }
        }
    } catch { }
    foreach ($k in @($script:OverrideRejected)) {
        Write-GateAudit $ToolName ('config:overrideRejected:' + [string]$k) 'reject' $Config
    }
}

# Do 0.1.11 zila funkce v gate.ps1; od 0.2.0 je sdilena - secrets.ps1 zapisuje audit u tridy
# chranene jmenem (TASK-106 bod 11, vyrok 7 Amber 2026-09-12). Cte $script:PermissionMode a
# $script:ToolName ze scope volajiciho skriptu - oba je nastavuji PRED prvnim rozhodnutim.
# Rozhodnuti Toma T-10 A: tvary, kde SQL v prikazu NENI videt, uz nezastavuji - ale
# ZAZNAMENAVAJI se. Audit misto brany.
#
# !! Loguje se UDALOST, ne obsah: cas, nastroj, id tvaru a rozhodnuti. Text prikazu do
# souboru NEJDE (zadani par. 4 bod 8 - riziko uniku). Bez CLAUDE_PLUGIN_DATA se nezapisuje
# nic a hook mlci; evidence nesmi byt duvod, proc brana spadne.
$script:AuditReadingCount = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::Ordinal)
$script:AuditGroupMax = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::Ordinal)
$script:AuditMuted = $false
function Write-GateAudit([string]$ToolName, [string]$ShapeId, [string]$Decision, $Config) {
    # CR-U (kolo 5): druhe cteni prikazu bez komentare (gate.ps1) hleda jen `deny` - radky auditu by se zapsaly dvakrat.
    if ($script:AuditMuted) { return }
    try {
        # T36-Q7 = A (Tom, 8. 9.): v `bypassPermissions` nad pluginem uz zadna vrstva
        # neni - audit tam znamena "proslo bez druhe kontroly", ne "rozhodne to
        # opravneni Claude Code". Radek to proto rekne sam; nic se neblokuje.
        # Mapuje se TADY, ne na volajicich mistech, aby na to neslo u jednoho zapomenout.
        if ($Decision -eq 'allow' -and $script:PermissionMode -eq 'bypassPermissions') {
            $Decision = 'allow-bypass'
        }
        # TASK-179 kolo 6/7 (K6-6, K7-3, K7-4): vic cteni TEHOZ vyskytu obalu (gate.ps1, $script:AuditReading = skupina G
        # a cteni R) je jedna udalost, ne tolik, kolik je cteni - jinak by nafoukla pocty, nad kterymi stoji T-10 A a T36-O5.
        # Za skupinu se zapise tolikrat, kolikrat udalost nese NEJBOHATSI cteni (maximum, ne soucet ani prvni). Jiny vyskyt
        # (jina skupina, list bez skupiny) se nepocita s nim. secrets.ps1 skupinu nema (Test-Path).
        if ((Test-Path variable:script:AuditReading) -and $null -ne $script:AuditReading) {
            $groupKey = [string]$script:AuditReading.G + '|' + $ToolName + '|' + $ShapeId + '|' + $Decision
            $readingKey = $groupKey + '|' + [string]$script:AuditReading.R
            $count = 1
            if ($script:AuditReadingCount.ContainsKey($readingKey)) { $count += $script:AuditReadingCount[$readingKey] }
            $script:AuditReadingCount[$readingKey] = $count
            if ($script:AuditGroupMax.ContainsKey($groupKey) -and $count -le $script:AuditGroupMax[$groupKey]) { return }
            $script:AuditGroupMax[$groupKey] = $count
        }
        $dir = $env:CLAUDE_PLUGIN_DATA
        if ([string]::IsNullOrWhiteSpace($dir)) { return }
        $file = [string](Get-Field (Get-Field $Config 'gate') 'auditFile' 'gate-audit.jsonl')
        $path = Join-SafePath $dir $file
        if ($null -eq $path) { return }
        [void][System.IO.Directory]::CreateDirectory($dir)
        $line = [ordered]@{
            ts       = (Get-Date).ToString('o')
            tool     = $ToolName
            shape    = $ShapeId
            decision = $Decision
        } | ConvertTo-Json -Depth 3 -Compress
        $bytes = ([System.Text.UTF8Encoding]::new($false)).GetBytes($line + "`n")
        $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Append,
                                         [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Dispose()
    } catch {
        # Evidence je fail-OPEN: kdyz se zapsat nepodari, brana se tim nesmi zastavit.
    }
}

# ------------------------------------------------- obaly prikazu (sdilene, 0.3.0) ---
# Z117-Q27 = B (Tom 2026-10-09, A117-N16): do 0.3.0 zily v gate.ps1 a hook secrets obal `bash -c 'cat .env'`
# nerozbaloval - jednim krokem obesel kazde cteni tajemstvi. Tabulka obalu, pruchod a rozpoznani tela obalu, ktery
# spousti TEXT jinym shellem, maji proto JEDINY zdroj pravdy tady a volaji je oba hooky.

# Nalez Amber E4: JEDEN spolecny seznam prepinacu s hodnotou byl spatne. `-n` bere
# hodnotu u `nice`, ale NE u `sudo` (tam je to "neinteraktivne"), takze
# `sudo -n psql <<SQL` preskocilo rovnou psql a destruktivni operace propadla.
# Tabulka je proto podle OBALU, ne globalni.
#
# Nalez Amber G2: tabulka existovala DVAKRAT - tady a jeste jednou, hur, primo ve
# vetvich Get-CommandLeaf. Oprava E4 dosla jen do jedne kopie, takze
# `sudo -u root rm -rf /srv` dal davalo argv[0] = `-u` a propadalo na allow.
# Tabulka i pruchod jsou proto od kola 4 na JEDINEM miste (Get-WrapperTail)
# a obe volajici strany se pisou nad nim.
$script:WrapperValueFlags = @{
    'sudo'    = '^(-u|-g|-C|-p|-r|-t|-T|-U|--user|--group)$'
    'doas'    = '^(-u|-C)$'
    'nice'    = '^(-n|--adjustment)$'
    # `-S` je tu ZAMERNE ne: jeho hodnota neni parametr, ale prikazova radka.
    # Preskocit ji znamenalo propustit `env -S "rm -rf src"` (nalez Metis 3).
    'env'     = '^(-u|-C|--unset|--chdir)$'
    'timeout' = '^(-s|--signal|-k|--kill-after)$'
    # GNU /usr/bin/time bere prepinace s hodnotou; `time -o log rm -rf src` davalo
    # jako prikaz `log` (nalez Metis 3).
    'time'    = '^(-o|-f|--output|--format)$'
    'docker'  = '^(-e|-v|-w|-u|-p|--name|--env|--user|--workdir|--volume)$'
    'podman'  = '^(-e|-v|-w|-u|-p|--name|--env|--user|--workdir|--volume)$'
    'stdbuf'  = '^(-i|-o|-e|--input|--output|--error)$'
}
$script:PlainWrappers = '^(nohup|command|builtin|exec)$'
$script:ContainerWrappers = '^(docker|podman)$'

# Odloupne z ARGV vsechny obaly a vrati zbytek - tedy skutecny prikaz vcetne jmena.
# Kdyz zadny obal nesedi, vraci vstup nedotceny.
function Get-WrapperTail($Argv, [int]$Depth = 0) {
    $arr = @($Argv)
    $i = 0
    $guard = 0
    while ($i -lt $arr.Count -and $guard -lt 64) {
        $guard++
        $tok = [string]$arr[$i]

        # Prirazeni promenne pred prikazem (`FOO=1 psql ...`)
        # CR-X9 (TASK-179, kolo 8): i se jmenem s escapem nebo uvozovkami (`env PGHO\ST=x dropdb ...` - env dostane PGHOST=x).
        if (($tok -replace '[\\`''"]', '') -match '^[A-Za-z_][A-Za-z0-9_]*=') { $i++; continue }
        if ($tok -match '^-') { $i++; continue }   # osamely prepinac bez znameho obalu

        $name = Get-ExecutableName $tok
        if ($name -match $script:PlainWrappers) { $i++; continue }
        if (-not $script:WrapperValueFlags.ContainsKey($name)) { break }

        $flagPattern = [string]$script:WrapperValueFlags[$name]
        $i++
        if ($name -match $script:ContainerWrappers) {
            if ($i -lt $arr.Count -and $arr[$i] -match '^(exec|run)$') { $i++ }
        }
        while ($i -lt $arr.Count -and $arr[$i] -match '^-') {
            $t = [string]$arr[$i]
            # Nalez Metis 3: `env -S "rm -rf src"` (a `--split-string`) nese v hodnote
            # celou PRIKAZOVOU RADKU, ne parametr. Preskocit ji znamenalo, ze prikaz
            # zmizel a zbyl obal bez cile -> allow. Hodnota se proto rozlozi na tokeny
            # a pokracuje se v ni.
            if ($name -eq 'env' -and $Depth -lt 4) {
                $split = $null
                $skip = 0
                if (($t -eq '-S' -or $t -eq '--split-string') -and ($i + 1) -lt $arr.Count) {
                    $split = [string]$arr[$i + 1]; $skip = 2
                } elseif ($t -match '^(-S|--split-string)=(.*)$') {
                    $split = $Matches[2]; $skip = 1
                }
                if ($null -ne $split) {
                    $tail = @(Split-Arguments $split)
                    if (($i + $skip) -lt $arr.Count) { $tail += @($arr[($i + $skip)..($arr.Count - 1)]) }
                    return (Get-WrapperTail $tail ($Depth + 1))
                }
            }
            if ($t -cmatch $flagPattern) { $i += 2 } else { $i++ }
        }
        if ($name -match $script:ContainerWrappers -and $i -lt $arr.Count) {
            $i++   # jmeno kontejneru nebo obrazu
        }
        # `timeout 30 psql ...` - po prepinacich stoji CISLO, ktere se preskakuje.
        if ($name -eq 'timeout' -and $i -lt $arr.Count -and $arr[$i] -match '^\d+(\.\d+)?[smhd]?$') { $i++ }
    }
    if ($i -ge $arr.Count) { return ,@() }
    return ,@($arr[$i..($arr.Count - 1)])
}

# ------------------------------------------- kontejnerovy obal (TASK-179, 0.3.1) ---
# TASK-179 (0.3.1; AOPT-O24 az O27, Amber 2026-10-18): `docker|podman exec|run` byl pro gate obycejny list s Exe `docker`,
# DB pravidlo v nem nenaslo SQL klienta a destruktivni prikaz uvnitr kontejneru MLCEL - i proti vzdalenemu hostiteli
# (pripady 17-24). Rozbor obalu proto zije tady: globalni volby, `exec|run`, management `container exec|run` a compose
# (`docker compose`, `podman compose`, `docker-compose`, `podman-compose`). Tabulky voleb s hodnotou jsou z dokumentace
# docker/cli v29.9.0, docker/compose v5.6.0, podman v6.1.3 (+ nainstalovany 5.5.2) a podman-compose 1.6.0 (krok 0).
# Volba, kterou tabulka nezna (budouci verze CLI), muze a nemusi brat hodnotu - rozbor proto vrati OBA kandidaty
# vnitrniho prikazu, smerem k prisnosti (clen tridy M-c).
# !! Get-WrapperTail se tim NEMENI (AOPT-O25): jeho starsi kontejnerova vetev drzi dnesni verdikt hooku secrets i cestovych
# a git pravidel za prefixovym obalem (`sudo docker exec ...`). Tahle funkce slouzi jen DB pravidlu gate (README omezeni 11).
# `podman-remote` je tentyz klient podmana pod jinym jmenem binarky (CR-2 kola 1 /code-review).
$script:ContainerCli = '^(docker|podman|podman-remote|docker-compose|podman-compose)$'

function New-ContainerOptionTable([string]$ValueLong, [string]$ValueShort, [string]$BoolLong, [string]$BoolShort) {
    # Kratke volby jsou case-SENSITIVNI (`-H` host enginu x `-h` hostname kontejneru) - proto Ordinal, ne hashtable.
    $t = @{}
    foreach ($k in @('VL', 'VS', 'BL', 'BS')) { $t[$k] = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal) }
    foreach ($x in ($ValueLong -split '\s+')) { if ($x -ne '') { [void]$t['VL'].Add($x) } }
    foreach ($x in ($ValueShort -split '\s+')) { if ($x -ne '') { [void]$t['VS'].Add($x) } }
    foreach ($x in ($BoolLong -split '\s+')) { if ($x -ne '') { [void]$t['BL'].Add($x) } }
    foreach ($x in ($BoolShort -split '\s+')) { if ($x -ne '') { [void]$t['BS'].Add($x) } }
    return $t
}

function Join-ContainerOptionTable($A, $B) {
    $t = @{}
    foreach ($k in @('VL', 'VS', 'BL', 'BS')) {
        $t[$k] = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        foreach ($x in $A[$k]) { [void]$t[$k].Add($x) }
        foreach ($x in $B[$k]) { [void]$t[$k].Add($x) }
    }
    return $t
}

# Tabulky se stavi az pri prvnim kontejnerovem obalu - dot-source _common.ps1 plati kazdy beh obou hooku (i secrets,
# ktery je nepouziva), takze bezny prikaz bez kontejneru je stavet nema.
$script:CtDockerGlobal = $null
function Initialize-ContainerOptionTables {
$script:CtDockerGlobal = New-ContainerOptionTable 'config context host log-level tlscacert tlscert tlskey' 'c H l' 'debug tls tlsverify help version' 'D v'
# Globalni volby podmana jsou "persistent" - smeji stat i za podprikazem, proto se pridavaji i k tabulkam `exec` a `run`.
$script:CtPodmanGlobal = New-ContainerOptionTable ('cdi-spec-dir cgroup-manager config conmon connection events-backend hooks-dir identity imagestore ' +
    'log-level module network-config-dir out root runroot runtime runtime-flag ssh storage-driver storage-opt tls-ca tls-cert tls-details ' +
    'tls-key tmpdir url volumepath') 'c' 'remote syslog transient-store help version' 'r v'
$script:CtDockerExec = New-ContainerOptionTable 'detach-keys env env-file user workdir' 'e u w' 'detach interactive privileged tty' 'd i t'
$script:CtPodmanExec = Join-ContainerOptionTable (New-ContainerOptionTable 'cidfile detach-keys env env-file preserve-fd preserve-fds user workdir' 'e u w' 'detach interactive latest no-session privileged tty' 'd i l t') $script:CtPodmanGlobal
$script:CtDockerRun = New-ContainerOptionTable ('add-host annotation attach blkio-weight blkio-weight-device cap-add cap-drop cgroup-parent cgroupns cidfile ' +
    'cpu-count cpu-percent cpu-period cpu-quota cpu-rt-period cpu-rt-runtime cpu-shares cpus cpuset-cpus cpuset-mems detach-keys device ' +
    'device-cgroup-rule device-read-bps device-read-iops device-write-bps device-write-iops dns dns-option dns-search domainname entrypoint ' +
    'env env-file expose gpus group-add health-cmd health-interval health-retries health-start-interval health-start-period health-timeout ' +
    'hostname io-maxbandwidth io-maxiops ip ip6 ipc isolation label label-file link link-local-ip log-driver log-opt mac-address memory ' +
    'memory-reservation memory-swap memory-swappiness mount name network network-alias oom-score-adj pid pids-limit platform publish pull ' +
    'restart runtime security-opt shm-size stop-signal stop-timeout storage-opt sysctl tmpfs ulimit umask user userns uts volume ' +
    'volume-driver volumes-from workdir') 'a c e h l m p u v w' ('detach help init interactive no-healthcheck oom-kill-disable privileged ' +
    'publish-all quiet read-only rm sig-proxy tty use-api-socket') 'd i P q t'
$script:CtPodmanRun = Join-ContainerOptionTable (New-ContainerOptionTable ('add-host annotation arch attach authfile blkio-weight ' +
    'blkio-weight-device cap-add cap-drop cgroup-conf cgroup-parent cgroupns cgroups chrootdirs cidfile conmon-pidfile cpu-period cpu-quota ' +
    'cpu-rt-period cpu-rt-runtime cpu-shares cpus cpuset-cpus cpuset-mems decryption-key detach-keys device device-cgroup-rule ' +
    'device-read-bps device-read-iops device-write-bps device-write-iops dns dns-option dns-search entrypoint env env-file env-merge expose ' +
    'gidmap gpus group-add group-entry health-cmd health-interval health-log-destination health-max-log-count health-max-log-size ' +
    'health-on-failure health-retries health-start-period health-startup-cmd health-startup-interval health-startup-retries ' +
    'health-startup-success health-startup-timeout health-timeout hostname hosts-file hostuser image-volume init-path ip ip6 ipc label ' +
    'label-file log-driver log-opt mac-address memory memory-reservation memory-swap memory-swappiness mount name network network-alias ' +
    'oom-score-adj os passwd-entry personality pid pidfile pids-limit platform pod pod-id-file preserve-fd preserve-fds publish pull ' +
    'rdt-class requires restart retry retry-delay sdnotify seccomp-policy secret security-opt shm-size shm-size-systemd stop-signal ' +
    'stop-timeout subgidname subuidname sysctl systemd timeout tmpfs tz uidmap ulimit umask unsetenv user userns uts variant volume ' +
    'volumes-from workdir') 'a c e h l m p u v w' ('detach disable-content-trust help http-proxy init interactive no-healthcheck no-hostname ' +
    'no-hosts oom-kill-disable passwd privileged publish-all quiet read-only read-only-tmpfs replace rm rmi rootfs sig-proxy tls-verify tty ' +
    'unsetenv-all') 'd i P q t') $script:CtPodmanGlobal
# compose: docker compose v5.6.0 a podman-compose 1.6.0 v jedne tabulce (`podman compose` predava volby providerovi).
$script:CtComposeGlobal = New-ContainerOptionTable ('ansi env-file file parallel profile progress project-directory project-name in-pod ' +
    'pod-args podman-path podman-args podman-pull-args podman-push-args podman-build-args podman-inspect-args podman-run-args ' +
    'podman-start-args podman-stop-args podman-rm-args podman-volume-args') 'f p' ('all-resources compatibility dry-run no-ansi no-cleanup ' +
    'verbose help version') 'v'
$script:CtComposeExec = New-ContainerOptionTable 'env index user workdir' 'e u w' 'detach dry-run no-tty privileged help' 'd T'
$script:CtComposeRun = New-ContainerOptionTable 'cap-add cap-drop entrypoint env env-from-file label name publish pull user volume workdir' 'e l p u v w' ('build detach dry-run interactive no-deps no-tty quiet quiet-build quiet-pull remove-orphans rm ' +
    'service-ports use-aliases help') 'd i q P T'
}

# Jedna volba na pozici $I (pflag: `--x=hodnota`, `--x hodnota`, shluk `-abc`, v nemz prvni pismeno s hodnotou vezme zbytek
# tokenu nebo dalsi token). Vraci 1 nebo vic moznych cteni @{ I = dalsi pozice; Name; Value } - vic jen u volby, kterou
# tabulka nezna (bere hodnotu? nevime -> obe cteni).
# K3-4 (kolo 3 /code-review): podman-compose je Python argparse a bere kazdou JEDNOZNACNOU zkratku dlouhe volby
# (`--entry` = `--entrypoint`, `--en` = `--env`). Pro compose se proto zkratka rozvine na plne jmeno z tabulky.
function Resolve-ContainerLongOption([string]$Name, $Table) {
    if ($Table['VL'].Contains($Name) -or $Table['BL'].Contains($Name)) { return $Name }
    $hit = @(@($Table['VL']) + @($Table['BL']) | Where-Object { $_.StartsWith($Name, [System.StringComparison]::Ordinal) } | Sort-Object -Unique)
    if ($Name -ne '' -and $hit.Count -eq 1) { return [string]$hit[0] }
    return $Name
}

function Read-ContainerOption($Arr, [int]$I, $Table, [bool]$Abbrev = $false) {
    $out = New-Object System.Collections.ArrayList
    $t = [string]$Arr[$I]
    $hasNext = ($I + 1) -lt $Arr.Count
    $next = if ($hasNext) { [string]$Arr[$I + 1] } else { '' }
    if ($t.StartsWith('--')) {
        $body = $t.Substring(2)
        $eq = $body.IndexOf('=')
        if ($eq -ge 0) {
            $nm0 = $body.Substring(0, $eq)
            if ($Abbrev) { $nm0 = Resolve-ContainerLongOption $nm0 $Table }
            [void]$out.Add(@{ I = $I + 1; Name = $nm0; Value = $body.Substring($eq + 1) })
            return ,@($out)
        }
        if ($Abbrev) { $body = Resolve-ContainerLongOption $body $Table }
        if ($Table['VL'].Contains($body)) {
            [void]$out.Add(@{ I = $I + 2; Name = $body; Value = $next })
            return ,@($out)
        }
        [void]$out.Add(@{ I = $I + 1; Name = $body; Value = $null })
        if (-not $Table['BL'].Contains($body) -and $hasNext) { [void]$out.Add(@{ I = $I + 2; Name = $body; Value = $next }) }
        return ,@($out)
    }
    $letters = $t.Substring(1)
    for ($k = 0; $k -lt $letters.Length; $k++) {
        $c = [string]$letters[$k]
        $rest = $letters.Substring($k + 1)
        $known = $Table['VS'].Contains($c)
        if ($known -or -not $Table['BS'].Contains($c)) {
            # Pismeno s hodnotou (nebo nezname - pak je to jedno ze dvou cteni): hodnota je zbytek tokenu, jinak dalsi token.
            if ($rest -ne '') { [void]$out.Add(@{ I = $I + 1; Name = $c; Value = $rest.TrimStart('=') }) }
            elseif ($hasNext) { [void]$out.Add(@{ I = $I + 2; Name = $c; Value = $next }) }
            else { [void]$out.Add(@{ I = $I + 1; Name = $c; Value = '' }) }
            if ($known) { return ,@($out) }
        }
    }
    # Cely shluk jako prepinace bez hodnoty (u nezname volby druhe cteni).
    [void]$out.Add(@{ I = $I + 1; Name = ''; Value = $null })
    return ,@($out)
}

# K3-1 (kolo 3 /code-review): Split-Arguments rozdeli nekvotovanou substituci na slova - `docker exec $(docker ps -q) dropdb x`
# dal tokeny `$(docker`, `ps`, `-q)`, cilem kontejneru byl `$(docker` a vnitrnim prikazem `ps`. Pro rozbor obalu se slova
# substituce `$(...)`, zavorky PowerShellu `(...)` / `@(...)` a (v Bashi) zpetnych apostrofu slepi zpet do JEDNOHO tokenu.
# K5-2 (kolo 5): slepuje se jen to, co je v TEXTU prikazu skutecne uzavrena substituce (Get-SubstitutionSpan), ne kazdy token
# s lichou zavorkou - kvotovana `(` v hodnote volby (K4-1) by jinak spolkla i cil zapsany substituci.
# K6-1/K6-2 (kolo 6): spany se berou z KAZDEHO textu, ktery beh hooku rozebira (hlavni prikaz, telo vnoreneho shellu,
# dekodovany `-EncodedCommand`), a kazdy s escape znakem, kterym se rozebiral - ne jen z $script:FullCommand v rezimu
# prvniho volani. Text zapisuje Get-CommandLineLeaves (gate.ps1) pred rozborem.
# K7-2 (kolo 7): tentyz seznam textu cte i Resolve-ContainerEnv (prirazeni promenne pro pruchozi `-e VAR`) - dekodovany
# `-EncodedCommand` v $script:FullCommand neni.
$script:ParsedTexts = New-Object System.Collections.ArrayList
$script:ParsedTextKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
function Register-ParsedText([string]$Text) {
    if ([string]::IsNullOrEmpty($Text)) { return }
    $esc = Get-ScannerEscape
    if (-not $script:ParsedTextKeys.Add($esc + [char]0 + $Text)) { return }
    [void]$script:ParsedTexts.Add(@{ Text = $Text; Esc = $esc })
}

# K7-1 (kolo 7): strop prace nad substitucemi za cely beh hooku (znaky vyrezanych spanu + porovnani ve slepovani). Hluboko
# vnorene UZAVRENE zavorky davaji spany, jejichz soucet delek roste se ctvercem hloubky - bez stropu by hook narazil na
# timeout z hooks.json (10 s) a prikaz by prosel bez verdiktu. Po prekroceni se dal nepocita a beh nese
# $script:SubstOverflow: gate.ps1 pak u prikazu s destruktivnim DB textem vrati aspon `ask` (fail-closed). Mez je vlastnost
# parseru jako hloubka zanoreni 5, ne politika - proto neni v konfiguraci.
$script:SubstWorkBudget = 200000
$script:SubstWork = 0
$script:SubstOverflow = $false
function Add-SubstitutionWork([int]$Units) {
    $script:SubstWork += $Units
    if ($script:SubstWork -gt $script:SubstWorkBudget) { $script:SubstOverflow = $true }
    return (-not $script:SubstOverflow)
}

# Uzavrene substituce jednoho textu jako retezce. K6-3/K6-4 (kolo 6): parovani zavorek zasobnikem (linearne, ne sken od kazde
# `(` do konce textu) a dvakrat - bez ohledu na uvozovky (kvotovana `(` v hodnote, K4-1) i s nimi (kvotovana `(` UVNITR
# substituce by jinak posunula jeji konec). Oba vysledky plati (slepeni je jen dalsi cteni obalu, smerem k prisnosti).
function Find-SubstitutionSpanText([string]$Text, [bool]$Bash) {
    $out = New-Object System.Collections.ArrayList
    $n = $Text.Length
    $esc = if ($Bash) { [char]'\' } else { [char]'`' }
    foreach ($quoted in $false, $true) {
        $stack = New-Object System.Collections.Stack
        $q = [char]0
        for ($i = 0; $i -lt $n; $i++) {
            $c = $Text[$i]
            if ($quoted) {
                if ($q -eq [char]"'") { if ($c -eq [char]"'") { $q = [char]0 }; continue }
                if ($c -eq $esc) { $i++; continue }
                if ($q -eq [char]'"') {
                    if ($c -eq [char]'"') { $q = [char]0; continue }
                    if ($c -ne [char]'$' -or ($i + 1) -ge $n -or $Text[$i + 1] -ne [char]'(') { continue }
                    # `"$(...)"`: substituce v uvozovkach ma vlastni kvotovani - stav uvozovek se vrati po jejim konci.
                    $stack.Push(@{ Start = $i; Ok = $true; Q = $q })
                    $q = [char]0
                    $i++
                    continue
                }
                if ($c -eq [char]"'" -or $c -eq [char]'"') { $q = $c; continue }
            }
            if ($c -eq [char]'(') {
                $pre = if ($i -gt 0) { $Text[$i - 1] } else { [char]0 }
                $sub = ($pre -eq [char]'$') -or (-not $Bash -and $pre -eq [char]'@')
                $stack.Push(@{ Start = $(if ($sub) { $i - 1 } else { $i }); Ok = ($sub -or -not $Bash); Q = [char]0 })
            } elseif ($c -eq [char]')' -and $stack.Count -gt 0) {
                $f = $stack.Pop()
                if ($f.Ok) {
                    if (-not (Add-SubstitutionWork ($i - $f.Start + 1))) { return ,@($out) }
                    [void]$out.Add($Text.Substring($f.Start, $i - $f.Start + 1))
                }
                if ($quoted) { $q = [char]$f.Q }
            }
        }
    }
    if ($Bash) {
        $ticks = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt $n; $i++) { if ($Text[$i] -eq [char]'`') { [void]$ticks.Add($i) } }
        for ($k = 0; ($k + 1) -lt $ticks.Count; $k++) {
            if (-not (Add-SubstitutionWork ($ticks[$k + 1] - $ticks[$k] + 1))) { break }
            [void]$out.Add($Text.Substring($ticks[$k], $ticks[$k + 1] - $ticks[$k] + 1))
        }
    }
    return ,@($out)
}

# Tytez texty se v jednom behu hooku ptaji vickrat (kazdy list a clanek s obalem). K7-6 (kolo 7): spany se pocitaji jen
# pro texty pribyle od minuleho volani a pripojuji se; tentyz retezec spanu (oba pruchody, vnoreny text jako cast rodice)
# se deli na slova jen jednou.
$script:SubstSpanValue = New-Object System.Collections.ArrayList
$script:SubstSpanWords = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
$script:SubstSpanStrings = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
$script:SubstSpanDone = 0
function Get-SubstitutionSpan {
    $prev = Get-ScannerEscape
    try {
        while ($script:SubstSpanDone -lt $script:ParsedTexts.Count -and -not $script:SubstOverflow) {
            $t = $script:ParsedTexts[$script:SubstSpanDone]
            $script:SubstSpanDone++
            if (([string]$t.Text).IndexOfAny([char[]]@('(', '`')) -lt 0) { continue }
            # Slova spanu deli Split-Arguments escapem textu, ze ktereho span je.
            Set-ScannerEscapeChar ([string]$t.Esc)
            foreach ($s in (Find-SubstitutionSpanText ([string]$t.Text) ([string]$t.Esc -ne '`'))) {
                if (-not $script:SubstSpanStrings.Add([string]$t.Esc + [char]0 + $s)) { continue }
                # Bez `@()` kolem volani: Split-Arguments vraci `,@(...)` (N-H10).
                $w = Split-Arguments $s
                if ($w.Count -ge 2 -and $script:SubstSpanWords.Add(($w -join [string][char]0))) { [void]$script:SubstSpanValue.Add($w) }
            }
        }
    } finally {
        Set-ScannerEscapeChar $prev
    }
    return ,@($script:SubstSpanValue)
}

function Join-SubstitutionToken($Tokens) {
    $out = New-Object System.Collections.ArrayList
    $arr = @($Tokens)
    # Bez zavorky nebo zpetneho apostrofu v ARGV neni co slepovat - spany se nepocitaji vubec.
    $any = $false
    foreach ($t in $arr) { if (([string]$t).IndexOfAny([char[]]@('(', ')', '`')) -ge 0) { $any = $true; break } }
    if (-not $any) { return ,@($arr) }
    $spans = Get-SubstitutionSpan
    $i = 0
    while ($i -lt $arr.Count) {
        $best = 0
        # K7-1: porovnani tokenu se vsemi spany je dalsi ctverec (tokeny x spany) - pocita se do tehoz stropu.
        if (-not (Add-SubstitutionWork $spans.Count)) { $spans = @() }
        foreach ($w in $spans) {
            $k = $w.Count
            if ($k -le $best -or ($i + $k) -gt $arr.Count) { continue }
            # Substituce muze stat uprostred tokenu (`--name=x$(a b)`): prvni slovo je konec tokenu, posledni jeho zacatek.
            if (-not ([string]$arr[$i]).EndsWith([string]$w[0], [System.StringComparison]::Ordinal)) { continue }
            if (-not ([string]$arr[$i + $k - 1]).StartsWith([string]$w[$k - 1], [System.StringComparison]::Ordinal)) { continue }
            # K8-3 (kolo 8): porovnani prostrednich slov (az k na kazdy span) se do stropu pocita taky.
            if (-not (Add-SubstitutionWork ($k - 2))) { break }
            $ok = $true
            for ($m = 1; $m -lt ($k - 1); $m++) { if (-not ([string]$arr[$i + $m] -ceq [string]$w[$m])) { $ok = $false; break } }
            if ($ok) { $best = $k }
        }
        if ($best -ge 2) {
            [void]$out.Add((@($arr[$i..($i + $best - 1)]) -join ' '))
            $i += $best
        } else {
            [void]$out.Add([string]$arr[$i])
            $i++
        }
    }
    return ,@($out)
}

# K5-6 (kolo 5): `-EncodedCommand <base64>` = UTF-16LE text skriptu - jedno dekodovani pro gate i secrets. Vraci '' = obsah
# neni videt (promenna, vadny base64, prazdny text); volajici z toho dela `ask` (fail-closed).
function ConvertFrom-EncodedCommandText([string]$Text) {
    $decoded = ''
    try { $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Text.Trim().Trim("'").Trim('"'))) } catch { $decoded = '' }
    if ([string]::IsNullOrWhiteSpace($decoded)) { return '' }
    # CR-Y1/Y3 (TASK-179, kolo 9): dekodovane telo s `#` potrebuje druhe cteni bez komentare - signal z mista dekodovani,
    # ne odhad nad textem prikazu (`pw''sh -ec ...` jmeno interpretu v textu neni).
    if ($decoded.IndexOf('#') -ge 0) { $script:DecodedHasHash = $true }
    return $decoded
}

# Rozbor kontejneroveho obalu. $Argv[0] je CLI (docker, podman, docker-compose, podman-compose). Vraci $null (neni obal)
# nebo @{ Tails = kandidati vnitrniho prikazu (ARGV); Env = hodnoty `-e/--env` predane vnitrnimu prikazu }. Prazdne
# Tails = obal bez vnitrniho prikazu (`docker ps`, `docker compose up`, `docker run img` s vychozim prikazem obrazu).
function Get-ContainerCommand($Argv) {
    # K4-1 (kolo 4 /code-review): Split-Arguments uvozovky zahodi, takze `(` nebo zpetny apostrof v KVOTOVANE hodnote volby
    # (`-e "MSG=bye :("`) od substituce nerozezname. Slepeni by pak spolklo cil i vnitrni prikaz. Proto se rozebira OBOJE -
    # ARGV jak je i se slepenou substituci - a kandidati se sjednoti (smerem k prisnosti).
    $raw = @(@($Argv) | ForEach-Object { [string]$_ })
    if ($raw.Count -eq 0) { return $null }
    $a = Get-ContainerCommandCore $raw
    if ($null -eq $a) { return $null }
    # Bez `@()` kolem volani: funkce vraci `,@(...)` (N-H10).
    $joined = Join-SubstitutionToken $raw
    if ($joined.Count -eq $raw.Count) { return $a }
    $b = Get-ContainerCommandCore @($joined)
    if ($null -eq $b) { return $a }
    $tails = New-Object System.Collections.ArrayList
    $keys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($t in @($a.Tails) + @($b.Tails)) { if ($keys.Add((Join-Argument @($t)))) { [void]$tails.Add(@($t)) } }
    return @{ Tails = @($tails); Env = @(@($a.Env) + @($b.Env) | Select-Object -Unique) }
}

function Get-ContainerCommandCore($Arr) {
    $arr = @($Arr)
    if ($arr.Count -eq 0) { return $null }
    $cli = Get-ExecutableName $arr[0]
    if ($cli -notmatch $script:ContainerCli) { return $null }
    if ($null -eq $script:CtDockerGlobal) { Initialize-ContainerOptionTables }
    $isPodman = $cli.StartsWith('podman')
    $tails = New-Object System.Collections.ArrayList
    $keys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $envs = New-Object System.Collections.ArrayList
    $queue = New-Object System.Collections.Queue
    $first = if ($cli.EndsWith('compose')) { 'cglobal' } else { 'global' }
    $queue.Enqueue(@{ I = 1; Stage = $first; Sub = ''; Entry = $null; NoTarget = $false; Positional = $false })
    # CR-10 (kolo 1 /code-review): stav = (pozice, faze, podprikaz, entrypoint, bez cile, pozicni). Dve cteni neznamych voleb
    # se sbihaji na tutez pozici; bez evidence navstivenych stavu rostl jejich pocet jako Fibonacci a strop rozpoctu
    # spoustel nahradni "kazda pozice je kandidat" uz u par desitek neznamych prepinacu (falesny dotaz z hodnoty volby).
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $budget = 256
    while ($queue.Count -gt 0) {
        $s = $queue.Dequeue()
        $budget--
        if ($budget -lt 0) {
            # Patologicky mnoho neznamych voleb: kazda pozice za CLI je kandidat (fail-closed smerem k prisnosti).
            for ($p = 1; $p -lt $arr.Count; $p++) {
                $tl = @($arr[$p..($arr.Count - 1)])
                if ($keys.Add((Join-Argument $tl))) { [void]$tails.Add($tl) }
            }
            break
        }
        $i = [int]$s.I
        while ($i -lt $arr.Count) {
            $tok = $arr[$i]
            $table = switch ([string]$s.Stage) {
                'global'  { if ($isPodman) { $script:CtPodmanGlobal } else { $script:CtDockerGlobal } }
                'mgmt'    { if ($isPodman) { $script:CtPodmanGlobal } else { $script:CtDockerGlobal } }
                'cglobal' { $script:CtComposeGlobal }
                'sub'     { if ($s.Sub -eq 'exec') { if ($isPodman) { $script:CtPodmanExec } else { $script:CtDockerExec } }
                            else { if ($isPodman) { $script:CtPodmanRun } else { $script:CtDockerRun } } }
                'csub'    { if ($s.Sub -eq 'exec') { $script:CtComposeExec } else { $script:CtComposeRun } }
            }
            $stKey = ('{0}|{1}|{2}|{3}|{4}|{5}' -f $i, $s.Stage, $s.Sub, $s.Entry, $s.NoTarget, $s.Positional)
            if (-not $seen.Add($stKey)) { break }   # tentyz stav uz rozebira jiny pruchod
            if (-not $s.Positional -and $tok -eq '--') { $s.Positional = $true; $i++; continue }
            if (-not $s.Positional -and $tok.Length -gt 1 -and $tok.StartsWith('-')) {
                # Bez `@()`: funkce vraci `,@(...)`, dalsi `@()` by pole zabalil podruhe (tataz past jako Split-Pipe, N-H10).
                $reads = Read-ContainerOption $arr $i $table ($s.Stage -eq 'cglobal' -or $s.Stage -eq 'csub')
                $base = $s.Clone()   # kazde dalsi cteni vychazi ze stavu PRED ctenim prvnim
                for ($r = 0; $r -lt $reads.Count; $r++) {
                    $rd = $reads[$r]
                    $st = if ($r -eq 0) { $s } else { $base.Clone() }
                    $nm = [string]$rd.Name
                    if ($null -ne $rd.Value) {
                        if ($nm -ceq 'e' -or $nm -ceq 'env') { [void]$envs.Add([string]$rd.Value) }
                        if ($nm -ceq 'entrypoint') { $st.Entry = [string]$rd.Value }
                    }
                    # `podman exec --latest|-l|--cidfile` bere kontejner odjinud - prvni pozicni token je uz vnitrni prikaz (M-b).
                    if ($isPodman -and $st.Stage -eq 'sub' -and $st.Sub -eq 'exec') {
                        if ($nm -ceq 'cidfile' -or ($nm -ceq 'latest' -and [string]$rd.Value -ne 'false')) { $st.NoTarget = $true }
                        if (-not $tok.StartsWith('--')) {
                            # Shluk kratkych voleb: `l` pred prvnim pismenem s hodnotou (`-il`, `-lu root`).
                            foreach ($ch in $tok.Substring(1).ToCharArray()) {
                                if ([string]$ch -ceq 'l') { $st.NoTarget = $true; break }
                                if ($table['VS'].Contains([string]$ch)) { break }
                            }
                        }
                    }
                    if ($r -gt 0) { $st.I = [int]$rd.I; $queue.Enqueue($st) }
                }
                $i = [int]$reads[0].I
                continue
            }
            # Pozicni token: podprikaz, nebo cil (kontejner / obraz / sluzba), za kterym stoji vnitrni prikaz.
            $stage = [string]$s.Stage
            if ($stage -eq 'global' -or $stage -eq 'mgmt' -or $stage -eq 'cglobal') {
                $s.Positional = $false
                if ($tok -ceq 'exec' -or $tok -ceq 'run') { $s.Sub = $tok; $s.Stage = $(if ($stage -eq 'cglobal') { 'csub' } else { 'sub' }); $i++; continue }
                if ($stage -eq 'global' -and $tok -ceq 'container') { $s.Stage = 'mgmt'; $i++; continue }
                if ($stage -eq 'global' -and $tok -ceq 'compose') { $s.Stage = 'cglobal'; $i++; continue }
                break   # jiny podprikaz (ps, logs, volume, up ...) - vnitrni prikaz nema
            }
            # Bez cile (`--latest`) je vnitrni prikaz uz tenhle token; obe cteni se vraci, kdyby `l` patrilo nezname volbe.
            $starts = if ($s.NoTarget) { @($i, ($i + 1)) } else { @($i + 1) }
            foreach ($from in $starts) {
                $tl = New-Object System.Collections.ArrayList
                if ($null -ne $s.Entry -and $s.Sub -eq 'run' -and ([string]$s.Entry).Trim() -ne '') {
                    foreach ($x in (Split-Arguments ([string]$s.Entry))) { [void]$tl.Add([string]$x) }
                }
                for ($p = $from; $p -lt $arr.Count; $p++) { [void]$tl.Add($arr[$p]) }
                if ($tl.Count -gt 0 -and $keys.Add((Join-Argument @($tl)))) { [void]$tails.Add(@($tl)) }
            }
            break
        }
    }
    return @{ Tails = @($tails); Env = @($envs) }
}

# Index kontejneroveho CLI v ARGV, ktere stoji v POZICI PRIKAZU za prefixovymi obaly (`sudo`, `env`, `timeout 60`, ...),
# nebo -1. Pozici rozhoduje tentyz pruchod jako vsude (Get-WrapperTail): CLI je v pozici prikazu, kdyz pruchod
# predpony konci presne na nem.
function Get-ContainerIndex($Argv) {
    $arr = @($Argv)
    for ($k = 0; $k -lt $arr.Count; $k++) {
        if ((Get-ExecutableName ([string]$arr[$k])) -notmatch $script:ContainerCli) { continue }
        if ($k -eq 0) { return 0 }
        # Bez `@()` kolem volani: Get-WrapperTail vraci `,@(...)` a dalsi `@()` by pole zabalil podruhe (N-H10).
        $probe = Get-WrapperTail (@($arr[0..($k - 1)]) + @('sinogard-probe'))
        if ($probe.Count -eq 1 -and [string]$probe[0] -ceq 'sinogard-probe') { return $k }
    }
    return -1
}

# Je token zkratkou daneho parametru PowerShellu? Prijima se kazda jednoznacna
# predpona, takze `-c`, `-co`, `-com` ... `-command` (nalez Metis 4, kolo 2).
function Test-ParameterPrefix([string]$Token, [string]$Full) {
    if ([string]::IsNullOrEmpty($Token)) { return $false }
    if (-not $Token.StartsWith('-')) { return $false }
    $body = $Token.Substring(1).ToLowerInvariant()
    if ($body -eq '') { return $false }
    return $Full.StartsWith($body)
}

# -EncodedCommand ma navic ZKRATKY, ktere predponou nejsou: `-ec` (a `-e`). `ec` neni
# predpona slova `encodedcommand` (to zacina na `en`), takze samotny predponovy test
# ho minul a `pwsh -ec <base64>` propadlo na allow (nalez Amber G5).
function Test-EncodedCommandFlag([string]$Token) {
    if ([string]::IsNullOrEmpty($Token)) { return $false }
    if ($Token.ToLowerInvariant() -eq '-ec') { return $true }
    return (Test-ParameterPrefix $Token 'encodedcommand')
}

# Telo obalu, ktery spousti TEXT jinym shellem: `bash|sh|zsh|dash|ksh -c '...'` (i slouceny `-lc`), `pwsh|powershell
# -Command ...` (kazda zkratka), `-EncodedCommand` (Kind = 'encoded', Text = hodnota), `cmd /c|/k ...`.
# $null = neni obal, skript souborem (`bash x.sh`, `pwsh -File x.ps1` - README omezeni 1) nebo obal bez tela.
# ShellTool rika, cimi pravidly se telo cte ('' = tyz shell jako hostitel, cmd).
function Get-ShellWrapperBody([string]$Exe, $Rest) {
    $r = @($Rest)
    if ($Exe -match '^(bash|sh|zsh|dash|ksh)$') {
        # Nalez Metis 4: `bash -lc '...'` - shell prijima slouceny kratky prepinac.
        for ($i = 0; $i -lt $r.Count; $i++) {
            if ([string]$r[$i] -cmatch '^-[a-z]*c$') {
                if (($i + 1) -ge $r.Count) { return $null }
                return @{ Kind = 'body'; Text = [string]$r[$i + 1]; ShellTool = 'Bash' }
            }
        }
        return $null
    }
    if ($Exe -match '^(pwsh|powershell)$') {
        for ($i = 0; $i -lt $r.Count; $i++) {
            $t = ([string]$r[$i]).ToLowerInvariant()
            if (Test-EncodedCommandFlag $t) {
                $v = if (($i + 1) -lt $r.Count) { [string]$r[$i + 1] } else { '' }
                return @{ Kind = 'encoded'; Text = $v; ShellTool = 'PowerShell' }
            }
            if (Test-ParameterPrefix $t 'file') { return $null }
            if (Test-ParameterPrefix $t 'command') {
                if (($i + 1) -ge $r.Count) { return $null }
                return @{ Kind = 'body'; Text = (Join-CommandString ($r | Select-Object -Skip ($i + 1))); ShellTool = 'PowerShell' }
            }
        }
        return $null
    }
    if ($Exe -eq 'cmd') {
        for ($i = 0; $i -lt $r.Count; $i++) {
            $t = ([string]$r[$i]).ToLowerInvariant()
            if ($t -eq '/c' -or $t -eq '/k') {
                if (($i + 1) -ge $r.Count) { return $null }
                return @{ Kind = 'body'; Text = (Join-CommandString ($r | Select-Object -Skip ($i + 1))); ShellTool = '' }
            }
        }
        return $null
    }
    return $null
}

# ------------------------------------------------------ uvod heredocu (sdileny) ---

$script:HeredocPattern = '<<-?\s*(?:''([A-Za-z_][A-Za-z0-9_]*)''|"([A-Za-z_][A-Za-z0-9_]*)"|\\?([A-Za-z_][A-Za-z0-9_]*))'

# Zacina na tomhle radku heredoc MIMO uvozovky? Nalez Amber E2: regex nad radkem
# nasel `<<` i uvnitr retezce (`echo "<<x>>"`) a zbytek prikazu se spolkl jako telo.
function Test-HeredocOutsideQuotes([string]$Line) {
    if ([string]::IsNullOrEmpty($Line)) { return $false }
    $esc = Get-ScannerEscape
    $inSingle = $false
    $inDouble = $false
    for ($i = 0; $i -lt $Line.Length - 1; $i++) {
        $c = $Line[$i]
        if ($inSingle) { if ($c -eq "'") { $inSingle = $false }; continue }
        # Escape pred uvozovkou uvozovku neotevira (nalez Amber G1).
        if ($c -eq $esc) { $i++; continue }
        if ($c -eq "'" -and -not $inDouble) { $inSingle = $true; continue }
        if ($c -eq '"') { $inDouble = -not $inDouble; continue }
        if ($inDouble) { continue }
        if ($c -eq '<' -and $Line[$i + 1] -eq '<') {
            # `<<<` je here-string, ne heredoc.
            if (($i + 2) -lt $Line.Length -and $Line[$i + 2] -eq '<') { return $false }
            return $true
        }
    }
    return $false
}
