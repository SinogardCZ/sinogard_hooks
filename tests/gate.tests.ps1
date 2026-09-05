#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Testy brany §6 (hooks/scripts/gate.ps1).

.DESCRIPTION
  Sev: skript hooku jako CELEK - vstupni JSON na stdin, ven navratovy kod a stdout
  JSON. Tvrdi se CHOVANI (deny / ask / allow), ne implementace regexu.

  Prazdny stdout = zadne rozhodnuti = 'allow' (plati normalni tok opravneni).

.EXAMPLE
  pwsh -NoProfile -File tests/gate.tests.ps1
  pwsh -NoProfile -File tests/gate.tests.ps1 -Interpreter powershell.exe -Full
#>
param(
    [switch]$Full,
    [string]$Interpreter = 'powershell.exe'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot '_harness.ps1')
$script:Interpreter = $Interpreter

if ($Full) {
    Write-Host ""
    Write-Host "gate.ps1 - brana §6   (interpret: $Interpreter)" -ForegroundColor Yellow
}

# Kazdy pripad: Nazev | Prikaz | Ocekavani | Nastroj | Rezim
function Case([string]$Name, [string]$Cmd, [string]$Expect, [string]$Tool = 'Bash', [string]$Mode = 'default') {
    return [pscustomobject]@{ Name = $Name; Cmd = $Cmd; Expect = $Expect; Tool = $Tool; Mode = $Mode }
}

# --------------------------------------------------------------- deny ① - ⑧ ---

$denyCases = @(
    # (1) force push na chranenou vetev
    (Case 'push --force main'          'git push --force origin main' 'deny')
    (Case 'push -f HEAD:main'          'git push -f origin HEAD:main' 'deny')
    (Case 'push +main'                 'git push origin +main' 'deny')
    (Case 'push --force-with-lease main' 'git push --force-with-lease origin main' 'deny')
    (Case 'push -f refs/heads/main'    'git push -f origin feature/x:refs/heads/main' 'deny')
    # (2) navrat pracovniho stromu
    (Case 'reset --hard'               'git reset --hard' 'deny')
    (Case 'reset --hard HEAD~1'        'git reset --hard HEAD~1' 'deny')
    (Case 'checkout -- .'              'git checkout -- .' 'deny')
    (Case 'restore .'                  'git restore .' 'deny')
    # (3) mazani vetvi
    (Case 'branch -D'                  'git branch -D feature/x' 'deny')
    (Case 'branch -d'                  'git branch -d feature/x' 'deny')
    (Case 'push --delete'              'git push --delete origin feature/x' 'deny')
    # (4) clean a stash
    (Case 'clean -fd'                  'git clean -fd' 'deny')
    (Case 'clean -f'                   'git clean -f' 'deny')
    (Case 'stash drop'                 'git stash drop' 'deny')
    (Case 'stash clear'                'git stash clear' 'deny')
    # (5) rekurzivni mazani mimo povolene slozky
    (Case 'rm -rf src'                 'rm -rf src' 'deny')
    (Case 'rm -r src'                  'rm -r src' 'deny')
    (Case 'rm -fr docs'                'rm -fr docs' 'deny')
    (Case 'Remove-Item -Recurse src'   'Remove-Item -Recurse -Force src' 'deny' 'PowerShell')
    (Case 'rmdir /s src'               'rmdir /s /q src' 'deny')
    (Case 'rd /s src'                  'rd /s src' 'deny' 'PowerShell')
    (Case 'del /s src'                 'del /s src' 'deny' 'PowerShell')
    (Case 'rm -rf abs mimo'            'rm -rf W:/dev/gsd/repo/src' 'deny')
    # (6) destruktivni DB mimo localhost
    (Case 'DROP DATABASE vzdalene'     'psql -c "DROP DATABASE gsd" "Host=db.firma.cz;Username=x"' 'deny')
    (Case 'DROP TABLE vzdalene'        'psql "Host=db.firma.cz" -c "DROP TABLE Record"' 'deny')
    (Case 'TRUNCATE vzdalene'          'psql "Host=db.firma.cz" -c "TRUNCATE Record"' 'deny')
    (Case 'dropdb vzdalene'            'dropdb -h db.firma.cz gsd' 'deny')
    (Case 'ef database drop vzdalene'  'dotnet ef database drop --connection "Host=db.firma.cz;Database=gsd"' 'deny')
    (Case 'DROP SCHEMA vzdalene PS'    'psql "Host=db.firma.cz" -c "DROP SCHEMA public CASCADE"' 'deny' 'PowerShell')
    # (7) ef database update proti cizimu hostiteli
    (Case 'ef update vzdalene'         'dotnet ef database update --connection "Host=db.firma.cz;Database=gsd"' 'deny')
    (Case 'ef update env vzdalene'     'ConnectionStrings__Default="Host=db.firma.cz;Database=gsd" dotnet ef database update' 'deny')
    # (8) prepis historie
    (Case 'filter-branch'              'git filter-branch --tree-filter x HEAD' 'deny')
    (Case 'filter-repo'                'git filter-repo --path x' 'deny')
    (Case 'reflog expire'              'git reflog expire --expire=now --all' 'deny')
    (Case 'gc --prune'                 'git gc --prune=now' 'deny')
    # retezeni a substituce
    (Case 'retez &&'                   'npm test && git branch -D x' 'deny')
    (Case 'substituce $()'             'echo $(git branch -D x)' 'deny')
    (Case 'substituce zpetny apostrof' 'echo `git reset --hard`' 'deny')
    (Case 'retez ;'                    'cd src ; rm -rf lib' 'deny')
    (Case 'roura'                      'echo x | xargs rm -rf src' 'deny')
)

# ------------------------------------------------ deny: obaly a tvary (N1) ---

$wrapperCases = @(
    (Case 'env prefix'                 'FOO=1 git reset --hard' 'deny')
    (Case 'bash -c'                    'bash -c "git push -f origin main"' 'deny')
    (Case 'sh -c'                      'sh -c "git reset --hard"' 'deny')
    (Case 'cmd /c'                     'cmd /c "rd /s /q src"' 'deny')
    (Case 'powershell -Command'        'powershell -Command "git branch -D x"' 'deny')
    (Case 'pwsh -c'                    'pwsh -c "git reset --hard"' 'deny')
    (Case 'eval s literalem'           'eval "git reset --hard"' 'deny')
    (Case 'xargs'                      'xargs git branch -D' 'deny')
    (Case 'find -exec'                 'find . -name x -exec rm -rf {} ;' 'deny')
    (Case 'absolutni cesta k exe'      '/usr/bin/git reset --hard' 'deny')
    (Case 'exe s priponou'             'git.exe reset --hard' 'deny')
    (Case 'exe v uvozovkach'           '"git" reset --hard' 'deny')
    (Case 'git -C'                     'git -C ../x reset --hard' 'deny')
    (Case 'git -c'                     'git -c a=b push -f origin main' 'deny')
    (Case 'git --git-dir'              'git --git-dir=../x/.git reset --hard' 'deny')
    (Case 'sudo'                       'sudo rm -rf /etc/x' 'deny')
    (Case 'alias rm -r -fo'            'rm -r -fo src' 'deny' 'PowerShell')
    (Case 'alias ri'                   'ri -Recurse -Force src' 'deny' 'PowerShell')
    (Case 'alias del /s'               'del /s src' 'deny' 'PowerShell')
    (Case 'alias rd /s'                'rd /s src' 'deny' 'PowerShell')
    (Case 'IO.Directory::Delete'       "[IO.Directory]::Delete('src',`$true)" 'deny' 'PowerShell')
    (Case 'IO.File::Delete'            "[IO.File]::Delete('src/a.cs')" 'deny' 'PowerShell')
    # Nalez councilu Metis 2026-09-05: PowerShell bere hodnotu parametru i pres
    # dvojtecku. Bez rozpadu tokenu by cesta zmizela i s prepinacem -> allow.
    (Case 'parametr s dvojteckou'      'Remove-Item -Recurse:$true -LiteralPath:src' 'deny' 'PowerShell')
    (Case 'parametr s dvojteckou 2'    'Remove-Item -Path:src -Recurse' 'deny' 'PowerShell')
    # nerozebiratelne obaly -> ask
    (Case 'bash -c s promennou'        'bash -c "$x"' 'ask')
    (Case 'cmd /c s promennou'         'cmd /c %X%' 'ask')
    (Case 'eval s promennou'           'eval $cmd' 'ask')
    (Case 'promenna misto exe'         '$TOOL git push' 'ask')
    # neprohledne, ale dokumentovane -> allow
    (Case 'skript souborem sh'         './cleanup.sh' 'allow')
    (Case 'skript souborem pwsh'       'pwsh -File x.ps1' 'allow')
    (Case 'skript souborem GSD'        'pwsh -File scripts/ci-local.ps1' 'allow')
)

# ------------------------------- nalezy councilu Metis (2026-09-05) ---

# Kazdy pripad nize je tvar, ktery council nasel jako propustny. Cislo odpovida
# poradi v jeho hlaseni; dalsi nalezy jsou VYJMENOVANE v hlaseni 01 a neresi se
# tady, protoze by rozsirily rozsah brany o nove operace nebo cizi stack.
$metisCases = @(
    (Case 'M1 rimraf'                  'rimraf src' 'deny')
    (Case 'M1 rimraf povolena'         'rimraf bin' 'allow')
    (Case 'M3 push :main'              'git push origin :main' 'deny')
    (Case 'M3 push :refs/heads/main'   'git push origin :refs/heads/main' 'deny')
    (Case 'M4 bash -lc'                'bash -lc "rm -rf src"' 'deny')
    (Case 'M5 command'                 'command rm -rf src' 'deny')
    (Case 'M6 -Recurse dvojtecka'      'Remove-Item src -Recurse:$true -Force:$true' 'deny' 'PowerShell')
    (Case 'M7 find -delete'            'find src -depth -delete' 'deny')
    (Case 'M7 find -delete povolena'   'find bin -delete' 'allow')
    (Case 'M8 mazani z roury'          'Get-ChildItem src -Recurse -Force -File | Remove-Item -Force' 'ask' 'PowerShell')
    (Case 'M10 dotnet-ef drop'         'dotnet-ef database drop --connection "Host=db.firma.cz;Database=gsd"' 'deny')
    (Case 'M10 dotnet-ef drop lokalne' 'dotnet-ef database drop' 'ask')
    (Case 'M12 update-ref -d'          'git update-ref -d refs/heads/feature/old' 'deny')
    (Case 'M13 branch -df'             'git branch -df feature/old' 'deny')
    (Case 'M14 push --mirror'          'git push --mirror origin' 'deny')
    (Case 'M15 push plus wildcard'     "git push origin '+refs/heads/*:refs/heads/*'" 'deny')
    (Case 'M16 python -c'              'python -c "import shutil; shutil.rmtree(''src'')"' 'ask')
    (Case 'M16 node -e'                'node -e "require(''fs'').rmSync(''src'')"' 'ask')
    (Case 'M17 DROP s komentarem'      'psql "Host=db.firma.cz" -c "DROP/**/TABLE users"' 'deny')
    (Case 'M25 Start-Process'          "Start-Process git -ArgumentList 'branch -D feature/old' -Wait" 'deny' 'PowerShell')
    (Case 'M26 clean.requireForce'     'git -c clean.requireForce=false clean -dx' 'deny')
    (Case 'M27 alias'                  "git -c alias.bd='branch -D' bd feature/old" 'ask')
    (Case 'M28 env -i'                 'env -i rm -rf src' 'deny')
    # Kontrolni skupina: bezna prace se timhle kolem zablokovat NESMI.
    (Case 'M kontrola python skript'   'python scripts/build.py' 'allow')
    (Case 'M kontrola find bez akce'   'find . -name "*.cs"' 'allow')
    (Case 'M kontrola push bez cile'   'git push' 'allow')
    (Case 'M kontrola clean -n'        'git -c core.pager=cat clean -n' 'allow')
    (Case 'M kontrola Start-Process'   "Start-Process git -ArgumentList 'status' -Wait" 'allow' 'PowerShell')
    (Case 'M kontrola env s prikazem'  'env FOO=1 npm test' 'allow')
)

# ----------------------------------------------------------------- ask (Z2) ---

$askCases = @(
    (Case 'rebase'                     'git rebase main' 'ask')
    (Case 'force-with-lease jina'      'git push --force-with-lease origin feature/x' 'ask')
    (Case 'force push jina vetev'      'git push --force origin feature/x' 'ask')
    (Case 'force push bez cile'        'git push --force origin' 'ask')
    (Case 'rm -rf s hvezdickou'        'rm -rf ./bin/*' 'ask')
    (Case 'rm -rf s ..'                'rm -rf bin/../obj' 'ask')
    (Case 'rm -rf s promennou'         'rm -rf $BUILD/bin' 'ask')
    (Case 'Invoke-Expression'          'Invoke-Expression $cmd' 'ask' 'PowerShell')
    (Case 'iex'                        'iex $cmd' 'ask' 'PowerShell')
    (Case 'ef migrations remove'       'dotnet ef migrations remove' 'ask')
    (Case 'clean -fdX'                 'git clean -fdX' 'ask')
    (Case 'DROP TABLE bez hostu'       'psql -c "DROP TABLE Record"' 'ask')
    (Case 'dropdb lokalni'             'dropdb gsd_test_e2e_1' 'ask')
    (Case 'ef database drop lokalni'   'dotnet ef database drop' 'ask')
    (Case 'ef drop Host=localhost'     'dotnet ef database drop --connection "Host=localhost;Database=gsd_dev"' 'ask')
    (Case 'TRUNCATE lokalni'           'psql -h 127.0.0.1 -c "TRUNCATE Record"' 'ask')
)

# --------------------------------------------------------------- allow (0) ---

$allowCases = @(
    (Case 'push -u feature'            'git push -u origin feature/task-36-sinogard-hooks' 'allow')
    (Case 'push bez force'             'git push origin main' 'allow')
    (Case 'rm -rf bin'                 'rm -rf bin' 'allow')
    (Case 'rm -rf obj node_modules'    'rm -rf obj node_modules' 'allow')
    (Case 'Remove-Item .\bin'          'Remove-Item -Recurse -Force .\bin' 'allow' 'PowerShell')
    (Case 'Remove-Item bez -Recurse'   'Remove-Item -LiteralPath src/a.cs -Force' 'allow' 'PowerShell')
    (Case 'dvojtecka v povolene slozce' 'Remove-Item -Recurse:$true -LiteralPath:bin' 'allow' 'PowerShell')
    (Case 'ef update bez connection'   'dotnet ef database update' 'allow')
    (Case 'ef update localhost'        'dotnet ef database update --connection "Host=localhost;Database=gsd_dev"' 'allow')
    (Case 'stash'                      'git stash' 'allow')
    (Case 'stash pop'                  'git stash pop' 'allow')
    (Case 'branch -m'                  'git branch -m stary novy' 'allow')
    (Case 'clean -n'                   'git clean -n' 'allow')
    (Case 'status'                     'git status --porcelain' 'allow')
    (Case 'commit'                     'git commit -m "TASK-36: hooky"' 'allow')
    (Case 'checkout vetve'             'git checkout -b feature/x' 'allow')
    (Case 'npm test'                   'npm test' 'allow')
    (Case 'ci-local'                   'pwsh -NoProfile -File scripts/ci-local.ps1' 'allow')
)

# --------------------------------------- ceske cesty (kodovani round-trip) ---

$czechCases = @(
    (Case 'ceska cesta deny'           'rm -rf docs/hlášení/září' 'deny')
    (Case 'ceska cesta allow'          'rm -rf bin/hlášení' 'allow')
    (Case 'ceska cesta ask'            'rm -rf bin/hlášení/*' 'ask')
)

# ------------------------------------------------------------- vyhodnoceni ---

function Test-Cases([string]$Section, $Cases) {
    Start-Case $Section
    foreach ($c in $Cases) {
        $template = if ($c.Tool -eq 'PowerShell') { 'pretooluse-powershell' } else { 'pretooluse-bash' }
        $json = New-HookInput $template @{
            'tool_input.command' = $c.Cmd
            'permission_mode'    = $c.Mode
        }
        $r = Invoke-Hook -Script 'gate.ps1' -InputJson $json
        $decision = Get-Decision $r
        Assert-Equal $c.Expect $decision ("[{0}] {1}" -f $c.Name, $c.Cmd)

        # navratovy kod je soucast kontraktu: deny = 2, jinak 0
        $expectedExit = if ($c.Expect -eq 'deny') { 2 } else { 0 }
        Assert-Equal $expectedExit $r.Exit ("[{0}] exit" -f $c.Name)

        # doba behu (T36-N4): tvrdy strop na jednu fixture; median resi Assert-TimingBudget
        Add-HookTime $r.Ms
        Assert-True ($r.Ms -lt (Get-HookCeilingMs)) ("[{0}] doba {1} ms < {2}" -f $c.Name, $r.Ms, (Get-HookCeilingMs))
    }
}

Test-Cases 'deny - tvary (1)-(8)' $denyCases
Test-Cases 'deny - obaly a tvary (T36-N1)' $wrapperCases
Test-Cases 'ask - seda zona (Z2, Z3)' $askCases
Test-Cases 'allow - bezna prace' $allowCases
Test-Cases 'nalezy councilu Metis (2026-09-05)' $metisCases
Test-Cases 'ceske cesty - round-trip kodovani' $czechCases

# Nestaci, ze rozhodnuti sedi - musi souhlasit i BAJTY duvodu. Cesky text prochazi
# stdin -> skript -> stdout/stderr; kterykoli clanek v OEM strance by ho rozsypal
# a rozhodnuti by pritom zustalo spravne.
Start-Case 'duvod dorazi presne tak, jak stoji v konfiguraci (UTF-8)'
$cfgText = [System.IO.File]::ReadAllText(
    (Join-Path $script:RepoRoot 'hooks/config/defaults.json'),
    ([System.Text.UTF8Encoding]::new($false))) | ConvertFrom-Json
$target = 'docs/hlášení/září'
$expectedShape = $cfgText.gate.shapes.recursiveDelete -replace '\{target\}', $target
$expectedReason = $cfgText.texts.gateReason -replace '\{shape\}', $expectedShape

$json = New-HookInput 'pretooluse-bash' @{ 'tool_input.command' = "rm -rf $target" }
$r = Invoke-Hook -Script 'gate.ps1' -InputJson $json
$parsed = $r.Stdout | ConvertFrom-Json
Assert-Equal $expectedReason $parsed.hookSpecificOutput.permissionDecisionReason 'duvod ve stdout JSON'
Assert-Equal $expectedReason $r.Stderr 'duvod na stderr'

# ------------------------------------------------- bypassPermissions (N2) ---

Start-Case 'bypassPermissions - ask se vydava jako deny'
foreach ($c in $askCases) {
    $template = if ($c.Tool -eq 'PowerShell') { 'pretooluse-powershell' } else { 'pretooluse-bash' }
    $json = New-HookInput $template @{
        'tool_input.command' = $c.Cmd
        'permission_mode'    = 'bypassPermissions'
    }
    $r = Invoke-Hook -Script 'gate.ps1' -InputJson $json
    Assert-Equal 'deny' (Get-Decision $r) ("[bypass] {0}" -f $c.Name)
    Assert-Equal 2 $r.Exit ("[bypass] {0} exit" -f $c.Name)
    Assert-True ($r.Stderr -match 'bypass') ("[bypass] {0} duvod jmenuje bypass" -f $c.Name)
}

Start-Case 'bypassPermissions - allow zustava allow'
foreach ($c in $allowCases) {
    $template = if ($c.Tool -eq 'PowerShell') { 'pretooluse-powershell' } else { 'pretooluse-bash' }
    $json = New-HookInput $template @{
        'tool_input.command' = $c.Cmd
        'permission_mode'    = 'bypassPermissions'
    }
    $r = Invoke-Hook -Script 'gate.ps1' -InputJson $json
    Assert-Equal 'allow' (Get-Decision $r) ("[bypass-allow] {0}" -f $c.Name)
    Assert-Equal 0 $r.Exit ("[bypass-allow] {0} exit" -f $c.Name)
}

Start-Case 'bypassPermissions - deny zustava deny'
foreach ($c in ($denyCases | Select-Object -First 5)) {
    $json = New-HookInput 'pretooluse-bash' @{
        'tool_input.command' = $c.Cmd
        'permission_mode'    = 'bypassPermissions'
    }
    $r = Invoke-Hook -Script 'gate.ps1' -InputJson $json
    Assert-Equal 'deny' (Get-Decision $r) ("[bypass-deny] {0}" -f $c.Name)
}

# --------------------------------------------------------- fail-closed (Z9) ---

Start-Case 'fail-closed - vadny vstup blokuje'
$badInputs = @(
    @{ Name = 'prazdny stdin';        Json = '' }
    @{ Name = 'nevalidni JSON';       Json = '{' }
    @{ Name = 'bez tool_input';       Json = '{"tool_name":"Bash","hook_event_name":"PreToolUse"}' }
    @{ Name = 'bez command';          Json = '{"tool_name":"Bash","hook_event_name":"PreToolUse","tool_input":{}}' }
    @{ Name = 'neznamy tool_name';    Json = '{"tool_name":"Foo","hook_event_name":"PreToolUse","tool_input":{"command":"ls"}}' }
    @{ Name = 'jen bile znaky';       Json = "   `n  " }
)
foreach ($b in $badInputs) {
    $r = Invoke-Hook -Script 'gate.ps1' -InputJson $b.Json
    Assert-Equal 2 $r.Exit ("[fail-closed] {0} exit 2" -f $b.Name)
    Assert-True ($r.Stderr -match 'gate\.ps1') ("[fail-closed] {0} stderr jmenuje skript" -f $b.Name)
}

# ------------------------------------------------------ vypnuti v projektu ---

Start-Case 'vypnuti hooku projektovym override'
$overrideDir = Join-Path $script:TempDir 'projekt/.claude'
[void][System.IO.Directory]::CreateDirectory($overrideDir)
[System.IO.File]::WriteAllText(
    (Join-Path $overrideDir 'sinogard-hooks.json'),
    '{"hooks":{"gate":false,"secrets":true,"resumeCost":true,"notify":true}}',
    ([System.Text.UTF8Encoding]::new($false)))
$json = New-HookInput 'pretooluse-bash' @{ 'tool_input.command' = 'git reset --hard' }
$r = Invoke-Hook -Script 'gate.ps1' -InputJson $json -Environment @{
    CLAUDE_PROJECT_DIR = (Join-Path $script:TempDir 'projekt')
}
Assert-Equal 'allow' (Get-Decision $r) '[override] vypnuty gate nerozhoduje'
Assert-Equal 0 $r.Exit '[override] vypnuty gate exit 0'

# --------------------------------------------------------- ASCII-only zdroj ---

Start-Case 'zdrojove .ps1 jsou ASCII-only (PS 5.1 cte bez BOM jako ANSI)'
foreach ($f in (Get-ChildItem (Join-Path $script:RepoRoot 'hooks/scripts') -Filter *.ps1)) {
    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
    $nonAscii = @($bytes | Where-Object { $_ -gt 127 }).Count
    Assert-Equal 0 $nonAscii ("[ascii] {0}" -f $f.Name)
}

Assert-TimingBudget

Write-TestSummary
if ($script:Fail -gt 0) { exit 1 }
exit 0
