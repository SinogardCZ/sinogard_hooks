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
    [switch]$Collect,
    [string]$Interpreter = 'powershell.exe'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot '_harness.ps1')
$script:Interpreter = $Interpreter
Assert-NoCollectEnv
Set-CollectMode ([bool]$Collect)

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
    # 0.1.9: ask · 0.1.10: audit (T36-O5 = A) · 0.1.11: zpatky ASK - a je to jina
    # veta nez v 0.1.9. Nalez Ady N34: rozlisovac "obsah promenne se spusti" v kodu
    # NEBYL. Skutecny rozlisovac byl "PS operator `&`" vs. vsechno ostatni, takze
    # `bash -c "$x"`, `cmd /c %X%` i `eval $cmd` spousteji obsah promenne uplne stejne
    # jako `& $cmd` - a koncily auditem. `$TOOL git push` je jiny pripad: promenna
    # stoji v pozici prikazu, ale zadny OBAL ji nespousti, takze audit drzi (T36-N34 i).
    (Case 'bash -c s promennou'        'bash -c "$x"' 'ask')
    (Case 'cmd /c s promennou'         'cmd /c %X%' 'ask')
    (Case 'eval s promennou'           'eval $cmd' 'ask')
    (Case 'promenna misto exe'         '$TOOL git push' 'allow')
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
    (Case 'force-with-lease jina'      'git push --force-with-lease origin feature/x' 'ask')
    (Case 'force push jina vetev'      'git push --force origin feature/x' 'ask')
    (Case 'force push bez cile'        'git push --force origin' 'ask')
    (Case 'rm -rf s hvezdickou'        'rm -rf ./bin/*' 'ask')
    (Case 'rm -rf s ..'                'rm -rf bin/../obj' 'ask')
    (Case 'rm -rf s promennou'         'rm -rf $BUILD/bin' 'ask')
    (Case 'Invoke-Expression'          'Invoke-Expression $cmd' 'ask' 'PowerShell')
    (Case 'iex'                        'iex $cmd' 'ask' 'PowerShell')
    (Case 'ef migrations remove'       'dotnet ef migrations remove' 'ask')
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
        # Nalez Amber H2: generator invariantu bere pripady odsud, ne rucnim vyberem.
        # Pripad s jinym nez vychozim rezimem opravneni se do invariantu NEDAVA -
        # radek nese jen prikaz a rezim by se pri prehrani ztratil.
        if ($c.Mode -eq 'default') { Add-CollectedCase 'gate' 'cmd' $c.Tool $c.Cmd $c.Expect $c.Name }
        if (Test-CollectOnly) { continue }

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
        Assert-True ($r.Ms -lt (Get-HookCeilingMs)) ("[{0}] doba {1} ms < {2}" -f $c.Name, $r.Ms, (Get-HookCeilingMs))
    }
}

Test-Cases 'deny - tvary (1)-(8)' $denyCases
Test-Cases 'deny - obaly a tvary (T36-N1)' $wrapperCases
Test-Cases 'ask - seda zona (Z2, Z3)' $askCases
Test-Cases 'allow - bezna prace' $allowCases
Test-Cases 'nalezy councilu Metis (2026-09-05)' $metisCases
Test-Cases 'ceske cesty - round-trip kodovani' $czechCases

# ================================================================================
#  Nalezy review Amber 2026-09-05 (osa 1 a 2) + rozhodnuti Toma T36-F1 T-1.
#  U kazdeho nalezu je i KONTROLNI SKUPINA - tvar, ktery se musi chovat opacne.
#  Bez ni by se neslo poznat, jestli oprava neprebila i beznou praci.
# ================================================================================

$amberCases = @(
    # --- A1: .NET mazani, kde cil je promenna. Drive allow, ted ask (par. 2.3). ---
    (Case 'A1 net-delete promenna'      '[IO.Directory]::Delete($p, $true)' 'ask' 'PowerShell')
    (Case 'A1 net-delete promenna File' '[System.IO.File]::Delete($target)' 'ask' 'PowerShell')
    (Case 'A1 kontrola literal src'     '[IO.Directory]::Delete(''src'', $true)' 'deny' 'PowerShell')
    (Case 'A1 kontrola literal bin'     '[IO.Directory]::Delete(''bin'', $true)' 'allow' 'PowerShell')

    # --- A2: navrat pracovniho stromu bez `--` a s holym `--`. ---
    (Case 'A2 checkout .'               'git checkout .' 'deny')
    (Case 'A2 checkout -- .'            'git checkout -- .' 'deny')
    (Case 'A2 restore -- .'             'git restore -- .' 'deny')
    # 🔴 V kole 1 tu stalo 'deny' a byl to FALESNY BLOK, ktery jsem si testem zafixovala
    # (nalez Amber C2). `git restore --staged .` jen odstaguje - prace se neztraci.
    # Ztrata je az s `--worktree`, na to je vlastni pripad v bloku kola 2.
    (Case 'A2 restore --staged neni ztrata' 'git restore --staged .' 'allow')
    (Case 'A2 checkout *'               'git checkout *' 'deny')
    # kontrolni skupina: prepnuti vetve a navrat JEDNOHO souboru je bezna prace
    (Case 'A2 kontrola vetev'           'git checkout main' 'allow')
    (Case 'A2 kontrola soubor'          'git checkout -- src/Program.cs' 'allow')
    (Case 'A2 kontrola restore soubor'  'git restore --staged src/Program.cs' 'allow')
    (Case 'A2 kontrola nova vetev'      'git checkout -b feature/x' 'allow')

    # --- A4: heredoc dedi hostitele z uvozujiciho prikazu. ---
    (Case 'A4 heredoc vzdaleny host'    "psql -h db.firma.cz <<SQL`nDROP TABLE users`nSQL" 'deny')
    (Case 'A4 heredoc quoted delim'     "psql -h db.firma.cz <<'SQL'`nTRUNCATE users`nSQL" 'deny')
    (Case 'A4 heredoc conn string'      "psql `"Host=db.firma.cz`" <<SQL`nDROP SCHEMA public CASCADE`nSQL" 'deny')
    # bez hosta = lokalni = ask (ne deny)
    (Case 'A4 heredoc lokalni'          "psql <<SQL`nDROP TABLE users`nSQL" 'ask')
    # kontrolni skupina: nedestruktivni SQL v heredocu je bezna prace
    (Case 'A4 kontrola SELECT'          "psql -h db.firma.cz <<SQL`nSELECT 1`nSQL" 'allow')
    (Case 'A4 kontrola cizi heredoc'    "cat <<EOF`nDROP TABLE users`nEOF" 'allow')

    # --- B1: prirazeni v PowerShellu neni promenna v pozici prikazu. ---
    (Case 'B1 prirazeni prikazu'        '$out = dotnet test' 'allow' 'PowerShell')
    (Case 'B1 prirazeni env'            '$env:FOO = ''x''' 'allow' 'PowerShell')
    (Case 'B1 prirazeni pak prikaz'     '$env:X = ''y''; git status' 'allow' 'PowerShell')
    (Case 'B1 viceradkovy snippet'      "`$out = dotnet test`nWrite-Host `$out" 'allow' 'PowerShell')
    (Case 'B1 prirazeni cisla'          '$i = 0' 'allow' 'PowerShell')
    (Case 'B1 prirazeni retezce'        '$msg = "ahoj"' 'allow' 'PowerShell')
    # KLICOVE: prirazeni nic nepere - destruktivni prikaz na prave strane zustava deny
    (Case 'B1 prirazeni neprere'        '$x = git branch -D feature/y' 'deny' 'PowerShell')
    (Case 'B1 prirazeni reset'          '$r = git reset --hard' 'deny' 'PowerShell')
    # Promenna v pozici prikazu je porad NEROZEBRATELNA - od 0.1.10 z toho ale neni
    # dotaz, ale audit (T36-O5 A). Nazev pripadu zustava, protoze na nej ukazuje
    # radek regresniho invariantu.
    (Case 'B1 Z3 zustava'               '$tool build' 'allow' 'PowerShell')
    # viceradkovy vstup nesmi destruktivni prikaz schovat
    (Case 'B1 viceradkovy destruktivni' "Write-Host 'a'`ngit reset --hard" 'deny' 'PowerShell')

    # --- B4: SQL vzory jen v SQL kontextu, ne nad kazdym textem. ---
    (Case 'B4 commit message'           'git commit -m "Add DROP TABLE migration"' 'allow')
    (Case 'B4 grep v kodu'              'grep -r "DROP TABLE" src' 'allow')
    # 🔴 Amber cekala allow. Merenim vyslo, ze tenhle jediny tvar konci ask - ale
    # UZ NE kvuli DB vzoru (ten je opraveny), nybrz kvuli Z3: `$x` je promenna,
    # takze prikaz je nerozebratelny. Z3 je deklarovany tvar zadani par. 2.3 a jeho
    # zuzeni je rozhodnuti zadavatele, ne oprava - viz hlaseni 02. Doklad, ze DB
    # vzor uz nehraje roli, je radek pod tim: s LITERALEM je vysledek allow.
    # 0.1.10: tentyz tvar, tataz pricina (`variable`), jine rozhodnuti - audit (T36-O5 A).
    (Case 'B4 Math Truncate promenna'   '[Math]::Truncate($x)' 'allow' 'PowerShell')
    (Case 'B4 Math Truncate literal'    '[Math]::Truncate(1.5)' 'allow' 'PowerShell')
    (Case 'B4 truncate logu'            'truncate -s 0 x.log' 'allow')
    (Case 'B4 echo textu'               'echo "TRUNCATE users"' 'allow')
    (Case 'B4 Select-String'            'Select-String "DROP TABLE" -Path src/x.sql' 'allow' 'PowerShell')
    # kontrolni skupina: v SQL kontextu to porad chytit MUSI
    (Case 'B4 psql -c vzdalene'         'psql -h db.firma.cz -c "DROP TABLE users"' 'deny')
    (Case 'B4 psql -c lokalne'          'psql -c "TRUNCATE users"' 'ask')

    # --- B5: Npgsql bere Server= i Data Source= jako hostitele. ---
    (Case 'B5 Server= vzdalene'         'dotnet ef database update --connection "Server=db.firma.cz;Database=gsd"' 'deny')
    (Case 'B5 Data Source= vzdalene'    'dotnet ef database update --connection "Data Source=db.firma.cz;Database=gsd"' 'deny')
    (Case 'B5 kontrola Server=local'    'dotnet ef database update --connection "Server=localhost;Database=gsd"' 'allow')

    # --- T-1 (Tom): DELETE FROM bez WHERE ma dopad TRUNCATE. ---
    (Case 'T1 delete bez where vzdal'   'psql -h db.firma.cz -c "DELETE FROM users"' 'deny')
    (Case 'T1 delete bez where lokal'   'psql -c "DELETE FROM users"' 'ask')
    (Case 'T1 delete heredoc'           "psql -h db.firma.cz <<SQL`nDELETE FROM users`nSQL" 'deny')
    # kontrolni skupina: s WHERE je to bezna prace
    (Case 'T1 kontrola s where'         'psql -c "DELETE FROM users WHERE id=1"' 'allow')
    (Case 'T1 kontrola where vzdalene'  'psql -h db.firma.cz -c "DELETE FROM users WHERE id=1"' 'allow')
    # WHERE musi byt v TOM SAMEM statementu, ne kdekoli v textu
    (Case 'T1 where v jinem statementu' 'psql -c "SELECT * FROM a WHERE id=1; DELETE FROM users"' 'ask')

    # --- B11 (Amber, zeleny): absolutni povolena cesta a tvar Git Bashe ---
    (Case 'B11 absolutni bin'           'rm -rf W:/dev/gsd/repo/bin' 'allow')
)

Test-Cases 'review Amber + rozhodnuti T-1' $amberCases

# ================================================================================
#  Review Amber kolo 2 (nalezy C a D). Vsech 22 tvaru bylo pred opravou ZMERENO
#  a chovalo se presne tak, jak Amber napsala - vcetne C7b, kde chtela mereni.
# ================================================================================

$amber2Cases = @(
    # --- C1: regrese, kterou zavedla oprava B4. Roura do SQL klienta. ---
    (Case 'C1 echo do psql'             'echo "DROP TABLE users" | psql -h db.firma.cz' 'deny')
    (Case 'C1 echo lokalne'             'echo "TRUNCATE users" | psql' 'ask')
    # T-10 A: SQL, ktere v prikazu neni videt, uz nezastavuje - zapise se do auditu.
    (Case 'C1 cat souboru do psql'      'cat drop.sql | psql -h db.firma.cz' 'allow')
    (Case 'C1 Get-Content do psql'      'Get-Content drop.sql | psql -h db.firma.cz' 'allow' 'PowerShell')
    # kontrolni skupina
    (Case 'C1 kontrola SELECT'          'echo "SELECT 1" | psql -h db.firma.cz' 'allow')
    (Case 'C1 kontrola cizi sink'       'echo "DROP TABLE x" | grep -i drop' 'allow')
    (Case 'C1 kontrola wc'              'cat x.sql | wc -l' 'allow')
    # --- C1: heredoc s redirectem za delimiterem ---
    (Case 'C1 heredoc 2>&1'             "psql -h db.firma.cz <<SQL 2>&1`nDROP TABLE users`nSQL" 'deny')
    (Case 'C1 heredoc > out.log'        "psql -h db.firma.cz <<SQL > out.log`nDROP TABLE users`nSQL" 'deny')

    # --- C7b: zavorkovy obal (Amber chtela zmerit - merenim potvrzeno) ---
    (Case 'C7b zavorka'                 '(git reset --hard)' 'deny' 'PowerShell')
    (Case 'C7b zavorka v prirazeni'     '$x = (git reset --hard)' 'deny' 'PowerShell')
    (Case 'C7b ampersand zavorka'       '& (git reset --hard)' 'deny' 'PowerShell')
    (Case 'C7b pole'                    '@(git branch -D x)' 'deny' 'PowerShell')
    (Case 'C7b kontrola'                '(Get-Date)' 'allow' 'PowerShell')
    (Case 'C7b kontrola prirazeni'      '$d = (Get-Date)' 'allow' 'PowerShell')

    # --- C2: hrany A2 + falesny blok na --staged ---
    (Case 'C2 checkout HEAD -- .'       'git checkout HEAD -- .' 'deny')
    (Case 'C2 checkout ./'              'git checkout ./' 'deny')
    (Case 'C2 checkout .\'              'git checkout .\' 'deny')
    (Case 'C2 restore --source HEAD .'  'git restore --source HEAD .' 'deny')
    (Case 'C2 restore --worktree .'     'git restore --worktree .' 'deny')
    (Case 'C2 restore obojí .'          'git restore --staged --worktree .' 'deny')
    # 🔴 falesny blok: odstagovani NENI ztrata prace
    (Case 'C2 staged neni ztrata'       'git restore --staged .' 'allow')
    (Case 'C2 kontrola vetev'           'git checkout main' 'allow')
    (Case 'C2 kontrola nova vetev'      'git checkout -b feature/x' 'allow')
    (Case 'C2 kontrola soubor'          'git checkout -- src/Program.cs' 'allow')

    # --- C4: obal pred SQL klientem + sqlcmd ---
    (Case 'C4 sudo psql'                "sudo -u postgres psql -h db.firma.cz <<SQL`nDROP TABLE x`nSQL" 'deny')
    (Case 'C4 docker exec psql'         "docker exec -i db psql -h db.firma.cz <<SQL`nDROP TABLE x`nSQL" 'deny')
    (Case 'C4 sqlcmd -S -Q'             'sqlcmd -S db.firma.cz -Q "DROP TABLE x"' 'deny')
    (Case 'C4 sqlcmd lokalne'           'sqlcmd -Q "TRUNCATE TABLE x"' 'ask')
    (Case 'C4 psql -f souborem'         'psql -h db.firma.cz -f migrace.sql' 'allow')
    (Case 'C4 sqlcmd -i souborem'       'sqlcmd -S db.firma.cz -i migrace.sql' 'allow')
    (Case 'C4 kontrola sudo SELECT'     "sudo -u postgres psql -h db.firma.cz <<SQL`nSELECT 1`nSQL" 'allow')

    # --- C7: prava strana prirazeni bez volani ---
    (Case 'C7 promenna do promenne'     '$a = $b' 'allow' 'PowerShell')
    (Case 'C7 PATH s interpolaci'       '$env:PATH = "$env:PATH;C:\x"' 'allow' 'PowerShell')
    (Case 'C7 retezec s interpolaci'    '$msg = "ahoj $name"' 'allow' 'PowerShell')
    (Case 'C7 kontrola volani zustava'  '$x = (git reset --hard)' 'deny' 'PowerShell')

    # --- D3: telo heredocu je DATA, ne prikazova radka ---
    (Case 'D3 poznamka o prikazu'       "cat > NOTES.md <<EOF`ngit reset --hard je nebezpecny`nEOF" 'allow')
    (Case 'D3 poznamka o rm'            "cat > NOTES.md <<EOF`nnikdy nepis rm -rf src`nEOF" 'allow')
    # kontrolni skupina: SQL klient nad telem se dal uplatnuje
    (Case 'D3 kontrola psql heredoc'    "psql -h db.firma.cz <<SQL`nDROP TABLE x`nSQL" 'deny')
)

Test-Cases 'review Amber kolo 2 (C, D)' $amber2Cases

# ================================================================================
#  Review Amber kolo 3 (nalezy E a F). Vsech 17 tvaru bylo pred opravou zmereno.
# ================================================================================

$amber3Cases = @(
    # --- E1: strednik/roura v UVOZOVKACH rozbily regexove deleni statementu ---
    (Case 'E1 strednik v SQL'           'echo "DROP TABLE users;" | psql -h db.firma.cz' 'deny')
    (Case 'E1 dva statementy'           'echo "DROP TABLE a; DROP TABLE b" | psql -h db.firma.cz' 'deny')
    # Roura UVNITR retezce nesmi rozdelit clanky. `DROP | TABLE` by nebylo platne SQL,
    # takze se testuje tvar, kde je roura v retezcovem literalu a SQL je platne.
    (Case 'E1 roura v retezci'          'echo "SELECT ''a|b''; DROP TABLE users" | psql -h db.firma.cz' 'deny')
    (Case 'E1 novy radek v retezci'     "echo `"DROP`nTABLE users`" | psql -h db.firma.cz" 'deny')
    (Case 'E1 kontrola cizi sink'       'echo "a;b" | grep a' 'allow')

    # --- E2: telo heredocu u SHELLU se spusti, takze se musi rozebrat ---
    (Case 'E2 bash heredoc'             "bash <<'EOF'`ngit reset --hard`nEOF" 'deny')
    (Case 'E2 sh heredoc'               "sh <<EOF`ngit reset --hard`nEOF" 'deny')
    (Case 'E2 pwsh heredoc'             "pwsh <<EOF`ngit branch -D x`nEOF" 'deny' 'PowerShell')
    (Case 'E2 bash heredoc neskodny'    "bash <<'EOF'`ngit status`nEOF" 'allow')
    # `<<` v uvozovkach NENI heredoc
    (Case 'E2 uvozovky nezacnou telo'   'echo "<<x>>"' 'allow')
    # neukonceny heredoc: nevime, kde telo konci -> pricina `heredocUnterminated`.
    # 0.1.10 na ni dala audit; 0.1.11 zpatky ASK (nalez Ady N35): ve vypisu 46 dotazu
    # ma tahle pricina NULA vyskytu, takze `ask` nestoji ani jeden dotaz navic - a
    # u tvaru, kde nevime ani kde telo konci, je audit tvrzeni bez opory.
    (Case 'E2 neukonceny heredoc'       "bash <<EOF`ngit status" 'ask')
    # kontrolni skupina D3 plati dal: telo u NE-shellu jsou data
    (Case 'E2 kontrola D3 poznamka'     "cat > NOTES.md <<EOF`ngit reset --hard je nebezpecny`nEOF" 'allow')

    # --- E3: navrat pracovniho stromu pres tokeny, ne regexem ---
    (Case 'E3 restore --source=HEAD'    'git restore --source=HEAD .' 'deny')
    (Case 'E3 restore -s HEAD'          'git restore -s HEAD .' 'deny')
    (Case 'E3 restore -W'               'git restore -W .' 'deny')
    (Case 'E3 restore -q'               'git restore -q .' 'deny')
    (Case 'E3 checkout -q HEAD -- .'    'git checkout -q HEAD -- .' 'deny')
    (Case 'E3 kontrola staged'          'git restore --staged .' 'allow')
    (Case 'E3 kontrola -b'              'git checkout -b feature/x' 'allow')
    (Case 'E3 kontrola soubor'          'git restore --source HEAD src/a.cs' 'allow')
    (Case 'E3 kontrola vetev'           'git checkout main' 'allow')

    # --- E4: prepinace obalu maji hodnotu podle OBALU, ne globalne ---
    (Case 'E4 sudo -n'                  "sudo -n psql -h db.firma.cz <<SQL`nDROP TABLE x`nSQL" 'deny')
    (Case 'E4 timeout 30'               "timeout 30 psql -h db.firma.cz <<SQL`nDROP TABLE x`nSQL" 'deny')
    (Case 'E4 nice -n 10'               "nice -n 10 psql -h db.firma.cz <<SQL`nDROP TABLE x`nSQL" 'deny')

    # --- F1: `-S` je hostitel jen u sqlcmd ---
    (Case 'F1 psql -S neni host'        'psql -S -c "TRUNCATE x"' 'ask')
    (Case 'F1 kontrola sqlcmd'          'sqlcmd -S db.firma.cz -Q "DROP TABLE x"' 'deny')

    # --- E6: substituce v upstream clanku roury ---
    (Case 'E6 substituce do psql'       '$(git reset --hard) | psql -h db.firma.cz' 'deny')
)

Test-Cases 'review Amber kolo 3 (E, F)' $amber3Cases

# ================================================================================
#  Council Metis, druhe kolo (2026-09-06) - nad opravenym stavem.
#  Vratil 7 nalezu a osmy (ANSI-C quoting `$'main'`) SAM STAHL jako neplatny.
#  Overila jsem i ten stazeny - mel pravdu, ze ho stahl.
#  Vsech 7 jsou parsovaci mezery v uz deklarovanych tvarech, takze se opravuji.
# ================================================================================

$metis2Cases = @(
    # M1 - find -exec sh -c: spojovani tokenu ztracelo uvozovky, takze vnitrni `-c`
    #      vzalo jen prvni slovo. S LITERALNIM cilem je to ted deny.
    (Case 'M1 find exec literal'        'find . -exec sh -c ''rm -rf /srv/data'' {} \;' 'deny')
    #      S promennou v cili plati Z3 (rozsah nezname) - stejne jako u [IO.Directory]::Delete($p).
    (Case 'M1 find exec promenna'       'find . -exec sh -c ''rm -rf "$0"'' {} \;' 'ask')
    (Case 'M1 kontrola'                 'find . -name "*.cs" -exec grep -l TODO {} \;' 'allow')

    # M2 - `<<\SQL` je treti zpusob potlaceni expanze vedle `'SQL'` a `"SQL"`
    (Case 'M2 heredoc escaped delim'    "psql -h prod.db <<\SQL`nDROP TABLE users;`nSQL" 'deny')

    # M3 - blok skriptu je obal stejne jako zavorka
    (Case 'M3 blok skriptu reset'       '& { git reset --hard }' 'deny' 'PowerShell')
    (Case 'M3 blok skriptu delete'      '& { Remove-Item -Recurse -Force C:\dulezite }' 'deny' 'PowerShell')
    (Case 'M3 kontrola'                 '& { Get-Date }' 'allow' 'PowerShell')

    # M4 - PowerShell bere kazdou jednoznacnou zkratku parametru
    (Case 'M4 -enc'                     'pwsh -enc UmVtb3ZlLUl0ZW0gLVJlY3Vyc2UgLUZvcmNlIEM6XA==' 'ask' 'PowerShell')
    (Case 'M4 -encod'                   'pwsh -encod UmVtb3ZlLUl0ZW0=' 'ask' 'PowerShell')
    (Case 'M4 kontrola -e neni enc'     'pwsh -NoProfile -Command "Get-Date"' 'allow' 'PowerShell')

    # M5 - procesova substituce je taky spusteny prikaz
    (Case 'M5 procesova substituce'     'cat <(psql -h prod -c "DROP TABLE x")' 'deny')
    (Case 'M5 kontrola'                 'diff <(ls a) <(ls b)' 'allow')

    # M6 - na jednom radku muze byt heredocu vic; tela se ctou v poradi
    (Case 'M6 dva heredocy'             "cat <<IGNORE && psql -h prod <<SQL`nignorovany text`nIGNORE`nDROP TABLE users;`nSQL" 'deny')

    # M7 - -ArgumentList jako POLE se rozlozi na tokeny
    (Case 'M7 ArgumentList pole'        "Start-Process pwsh -ArgumentList @('-enc', 'UmVtb3ZlLUl0ZW0gQzpc')" 'ask' 'PowerShell')
    (Case 'M7 kontrola'                 "Start-Process git -ArgumentList @('status')" 'allow' 'PowerShell')

    # M8 - Metis sam stahl; overuji, ze mel pravdu, ze to stahl
    (Case 'M8 ANSI-C quoting'           'git branch -D $''main''' 'deny')
)

Test-Cases 'council Metis kolo 2 (2026-09-06)' $metis2Cases

# ================================================================================
#  Review Amber, kolo 4 - nalezy G (falesne allow) a H.
#
#  Sjednoceny skener z kola 3 zadnou novou diru nezavedl, ale ODHALIL tri stare,
#  ktere minula vsechna review i oba councily. G1 je z nich nejnebezpecnejsi:
#  netyka se jednoho pravidla, ale toho, kde konci retezec - tedy uplne vseho.
# ================================================================================

$amber4Cases = @(
    # G1 - escape znak pred uvozovkou je LITERAL, ne otevreni retezce.
    #      Znak je JINY v kazdem shellu a zamena dela diru opacnym smerem, takze
    #      ke kazdemu pripadu stoji protipripad z toho DRUHEHO shellu.
    (Case 'G1 bash escape uvozovky'     'echo \" ; git reset --hard' 'deny')
    (Case 'G1 ps escape uvozovky'       'echo `" ; git reset --hard' 'deny' 'PowerShell')
    (Case 'G1 bash escape v retezci'    'echo "a\"b" && git status' 'allow')
    #      Protipripad 1: `\` v PowerShellu NEescapuje - `"C:\src\"` je uzavreny
    #      retezec a `;` deli dal. Kdyby se escape bral globalne, bylo by z toho allow.
    (Case 'G1 ps zpetne lomitko v ceste' 'echo "C:\src\" ; git reset --hard' 'deny' 'PowerShell')
    #      Protipripad 2: zpetny apostrof v Bashi je SUBSTITUCE, ne escape.
    (Case 'G1 bash zpetny apostrof'     'echo `"foo"` ; git reset --hard' 'deny')
    #      Cesta s `\` musi projit skenerem nedotcena, jinak by `W:\dev\src` ztratilo
    #      lomitka a shoda na chranenou cestu by prestala platit.
    (Case 'G1 cesta se zachova'         'rm -rf "W:\dev\src"' 'deny')
    (Case 'G1 kontrola cesty'           'ls "W:\dev\src"' 'allow')

    # G9 - pokracovani radku. `git reset \<konec radku> --hard` je JEDEN prikaz;
    #      driv se rozpadl na dva a `--hard` samo o sobe nic nespustilo -> allow.
    (Case 'G9 bash pokracovani radku'   "git reset \`n  --hard" 'deny')
    #      Tri zpetne apostrofy: dva davaji LITERALNI zpetny apostrof, treti s `n` konec radku.
    (Case 'G9 ps pokracovani radku'     "git reset ```n  --hard" 'deny' 'PowerShell')
    (Case 'G9 kontrola'                 "git status \`n  --short" 'allow')
    # G9 - pokracovani radku PRED heredocem: uvozujici prikaz stal na jinem radku
    #      nez `<<SQL`, takze vysel prazdny a telo se necetlo jako SQL.
    (Case 'G9 heredoc pres dva radky'   "psql -h prod.db \`n  <<SQL`nDROP TABLE users;`nSQL" 'deny')
    (Case 'G9 heredoc kontrola'         "cat \`n  <<EOF`nobycejny text`nEOF" 'allow')

    # G2 - prepinac obalu, ktery BERE HODNOTU. Druha kopie tabulky obalu primo ve
    #      vetvich Get-CommandLeaf ji neznala, takze argv[0] vyslo jako `-u`/`-n`/`-s`.
    #      Amberin priklad `sudo -u root rm -rf /srv` konci ASK, ne deny - `/srv` ma
    #      tri pismena a padne do STARE zabrany "kratke /xxx muze byt prepinac cmd,
    #      rozsah nezname" (Z3). Nalez to nevyvraci: pred opravou bylo ALLOW.
    #      Deny se dolozi tymz obalem nad cilem, ktery za prepinac vzit nejde.
    (Case 'G2 sudo -u'                  'sudo -u root rm -rf /srv' 'ask')
    (Case 'G2 sudo -u cesta'            'sudo -u root rm -rf /srv/data' 'deny')
    (Case 'G2 sudo -n'                  'sudo -n git reset --hard' 'deny')
    (Case 'G2 nice -n'                  'nice -n 10 rm -rf src' 'deny')
    (Case 'G2 timeout -s'               'timeout -s KILL 30 rm -rf src' 'deny')
    (Case 'G2 env -i'                   'env -i rm -rf src' 'deny')
    (Case 'G2 command -p'               'command -p rm -rf src' 'deny')
    (Case 'G2 kontrola sudo'            'sudo -u root ls -la /srv' 'allow')
    (Case 'G2 kontrola nice'            'nice -n 10 dotnet test' 'allow')
    (Case 'G2 kontrola env sam'         'env' 'allow')

    # G6 - tyz nalez u SQL: `timeout -s KILL 30 psql` davalo OuterExe `kill`.
    (Case 'G6 timeout -s pred psql'     "timeout -s KILL 30 psql -h prod.db <<SQL`nDROP TABLE users;`nSQL" 'deny')
    (Case 'G6 kontrola'                 "timeout 30 psql -h localhost <<SQL`nSELECT 1;`nSQL" 'allow')

    # G3 - xargs bere ARGV, ne prikazovou radku. Join-CommandString ztratilo hranice
    #      tokenu a vnitrni `-c` vzalo jen prvni slovo.
    (Case 'G3 xargs sh -c'              'echo . | xargs sh -c ''git reset --hard''' 'deny')
    (Case 'G3 xargs -I'                 'ls | xargs -I {} sh -c ''rm -rf /srv/data''' 'deny')
    (Case 'G3 kontrola'                 'ls | xargs echo' 'allow')

    # G4 - stredniku uvnitr bloku skriptu. Bez nej to deny bylo, s nim ne.
    (Case 'G4 blok se strednikem'       '& { rm -rf src; }' 'deny' 'PowerShell')
    (Case 'G4 blok dva prikazy'         '& { git status; rm -rf src }' 'deny' 'PowerShell')
    (Case 'G4 kontrola'                 '& { Get-Date; Get-Location }' 'allow' 'PowerShell')
    #      Nevyvazena zavorka nesmi skener oslepit - druhy pruchod ji ignoruje.
    (Case 'G4 nevyvazena zavorka'       'echo { ; git reset --hard' 'deny' 'PowerShell')

    # G5 - `-ec` NENI predpona slova `encodedcommand`; `-c`/`-command` se porovnavaly presne.
    (Case 'G5 -ec'                      'pwsh -ec UmVtb3ZlLUl0ZW0=' 'ask' 'PowerShell')
    (Case 'G5 -com'                     'pwsh -com "git reset --hard"' 'deny' 'PowerShell')
    (Case 'G5 -comm'                    'pwsh -comm "rm -rf src"' 'deny' 'PowerShell')
    (Case 'G5 kontrola'                 'pwsh -NoProfile -File build.ps1' 'allow' 'PowerShell')

    # G7 - cile, ktere git chape jako cely strom, ale ve vyctu nestaly.
    (Case 'G7 checkout :/'              'git checkout -- :/' 'deny')
    (Case 'G7 restore :(top)'           'git restore '':(top)''' 'deny')
    (Case 'G7 checkout ./*'             'git checkout ./*' 'deny')
    (Case 'G7 kontrola soubor'          'git checkout -- src/app.ts' 'allow')
    (Case 'G7 kontrola vetev'           'git checkout -b feature/x' 'allow')

    # G8 - telo heredocu, ktere se SPUSTI, ale rozebrat ho neumime (Z3 -> ask).
    (Case 'G8 python heredoc'           "python <<EOF`nimport shutil`nshutil.rmtree('src')`nEOF" 'ask')
    (Case 'G8 ssh heredoc'              "ssh prod <<EOF`nrm -rf /srv`nEOF" 'ask')
    (Case 'G8 kontrola data'            "cat > NOTES.md <<EOF`nrm -rf je nebezpecny`nEOF" 'allow')
)

Test-Cases 'review Amber kolo 4 (G, H)' $amber4Cases

# ================================================================================
#  Council Metis, treti kolo (2026-09-06) - UZKA otazka: jen obaly, escapovani
#  uvozovek a zkratky parametru PowerShellu (zadani Amber, kolo 4 bod 3).
#
#  Vratil 8 nalezu k obalum. ZMERENO: ctyri z nich (powershell -c, bash -lc,
#  xargs -n, xargs -I) uz opravene BYLY - council je nemohl vedet, protoze dostal
#  jen popis. Zbylych sedm tvaru (vcetne dvou nezavislych uvnitr jednoho nalezu)
#  propoustelo doopravdy. Vsechny jsou tataz trida: prepinac obalu, ktery BERE
#  HODNOTU a v tabulce nestal, takze se za prikaz vzala jeho HODNOTA.
# ================================================================================

$metis3Cases = @(
    # N1 - `env -S` nese v hodnote celou PRIKAZOVOU RADKU, ne parametr
    (Case 'N1 env -S'                   'env -S "rm -rf -- ./victim"' 'deny')
    (Case 'N1 env --split-string='      'env --split-string="git reset --hard"' 'deny')
    (Case 'N1 env -S v obalu'           'timeout --preserve-status --kill-after=5s 30s env -S "rm -rf -- ./victim"' 'deny')
    (Case 'N1 kontrola'                 'env -S "dotnet build"' 'allow')

    # N2 - GNU /usr/bin/time bere prepinace s hodnotou
    (Case 'N2 time -o'                  'time -o ./timing.txt rm -rf -- ./victim' 'deny')
    (Case 'N2 time -f'                  'time -f "%e" git reset --hard' 'deny')
    (Case 'N2 kontrola'                 'time dotnet test' 'allow')

    # N3 - dlouhe tvary prepinacu stdbuf
    (Case 'N3 stdbuf --output'          'stdbuf --output L rm -rf -- ./victim' 'deny')
    (Case 'N3 kontrola'                 'stdbuf -o L dotnet test' 'allow')

    # N4 - dlouhe tvary prepinacu xargs
    (Case 'N4 xargs --process-slot-var' 'xargs --process-slot-var SLOT rm -rf -- ./victim' 'deny')
    (Case 'N4 xargs --arg-file'         'xargs --arg-file /dev/null rm -rf -- ./victim' 'deny')
    (Case 'N4 xargs --max-args'         'xargs --max-args 1 git branch -D x' 'deny')
    (Case 'N4 kontrola'                 'xargs --verbose ls -la' 'allow')

    # N5 - `-okdir` je ctvrty tvar `-exec`
    (Case 'N5 find -okdir'              "find . -okdir rm -rf -- ./victim '{}' ';'" 'deny')
    (Case 'N5 kontrola'                 "find . -okdir grep -l TODO '{}' ';'" 'allow')

    # Tvary, ktere council oznacil, ale opravene uz BYLY. Zustavaji v sade jako
    # doklad, ze plati - ne jako nove nalezy.
    (Case 'N6 powershell -c'            'powershell -c "Remove-Item -LiteralPath .\victim -Recurse -Force"' 'deny' 'PowerShell')
    (Case 'N6 bash -lc'                 'bash -lc "rm -rf -- ./victim"' 'deny')
    (Case 'N6 xargs -n'                 'xargs -n 1 rm -rf -- ./victim' 'deny')
    (Case 'N6 xargs -I'                 'xargs -I X rm -rf -- ./victim' 'deny')
)

Test-Cases 'council Metis kolo 3 (2026-09-06)' $metis3Cases

# ================================================================================
#  Review Amber, kolo 5 - nalezy I a J.
#
#  I1 je REGRESE, kterou zavedla oprava G4: zanoreni slozenych zavorek drzelo blok
#  pohromade i pres konce radku, ale rozbaleni bloku delal regex ukotveny na ZACATEK
#  statementu. Viceradkovy blok za klicovym slovem tak schoval prikaz uplne - a pred
#  0.1.4 to deny bylo. Doklad, ze regresni invariant musi rust s kazdym kolem.
# ================================================================================

# CRLF se v testu sklada ze znaku, ne z escapove sekvence v uvozovkach - `n je LF
# a `r je CR, ale zaznam v souboru by se pri prevodu konců radku mohl zmenit.
$cr = [string][char]13
$lf = [string][char]10
$bt = [string][char]96   # zpetny apostrof = escape v PowerShellu

$amber5Cases = @(
    # I1 - blok skriptu nemusi stat na zacatku statementu ani na jednom radku
    (Case 'I1 viceradkovy if blok'      ("if (`$x) {" + $lf + "  git reset --hard" + $lf + '}') 'deny' 'PowerShell')
    (Case 'I1 foreach blok'             'foreach ($x in $y) { git reset --hard }' 'deny' 'PowerShell')
    (Case 'I1 while blok'               'while ($true) { rm -rf src }' 'deny' 'PowerShell')
    (Case 'I1 viceradkovy & blok'       ('& {' + $lf + '  rm -rf src' + $lf + '}') 'deny' 'PowerShell')
    # 🔴 kontrolni skupina: tytez tvary s neskodnym prikazem MUSI zustat allow,
    #    jinak by z toho byl falesny blok na kazde smycce.
    (Case 'I1 kontrola foreach'         'foreach ($x in $y) { git status }' 'allow' 'PowerShell')
    (Case 'I1 kontrola viceradkovy'     ("if (`$x) {" + $lf + '  git status' + $lf + '}') 'allow' 'PowerShell')
    (Case 'I1 kontrola hashtable'       "`$h = @{ Path = 'src' }" 'allow' 'PowerShell')
    (Case 'I1 kontrola format'          'git log --format=''{%h}''' 'allow')

    # I2 - escape znak patri tomu shellu, ktery text SPUSTI
    (Case 'I2 pwsh -c z Bash nastroje'  ("pwsh -c 'echo " + $bt + '" ; git reset --hard''') 'deny')
    (Case 'I2 bash -c z PS nastroje'    'bash -c ''echo \" ; git reset --hard''' 'deny' 'PowerShell')
    (Case 'I2 kontrola pwsh'            'pwsh -c ''echo "a" ; git status''' 'allow')
    (Case 'I2 kontrola bash'            'bash -c ''echo "a" ; git status''' 'allow' 'PowerShell')

    # I3 - apostrof uvnitr dvojitych uvozovek neni uvozovka
    (Case 'I3 apostrof v retezci'       'echo "it''s $(git reset --hard)"' 'deny')
    (Case 'I3 kontrola'                 'echo "it''s fine"' 'allow')

    # I4 - konec radku je na Windows CRLF, ne LF
    (Case 'I4 CRLF pokracovani bash'    ('git reset \' + $cr + $lf + '  --hard') 'deny')
    (Case 'I4 CRLF pokracovani PS'      ('git reset ' + $bt + $cr + $lf + '  --hard') 'deny' 'PowerShell')
    (Case 'I4 kontrola'                 ('git status \' + $cr + $lf + '  --short') 'allow')

    # J1 - H4 (uvozovky uvnitr substituce) byl opraven v 0.1.4 BEZ TESTU
    (Case 'J1 uvozovka v substituci'    'echo $(rm -rf ")" src)' 'deny')
    (Case 'J1 apostrof v substituci'    'echo $(git reset --hard '')'')' 'deny')
    (Case 'J1 kontrola'                 'echo $(git status '')'')' 'allow')
)

Test-Cases 'review Amber kolo 5 (I, J)' $amber5Cases

# ================================================================================
#  REVIEW AMBER, KOLO 5b - nalezy K a L (2026-09-06)
#
#  OBE JSOU REGRESE PO OPRAVE I1, a jdou proti sobe:
#    K1 propousti  - `{` se bralo za blok kdekoli, hlava se zahazovala
#    L1 blokuje    - telo bloku s `$_` se cetlo jako prikaz v pozici promenne
#  Zmereno na f8a8032 pred opravou i na klonu f25a8d2 (0.1.4) - vsech deset tvaru
#  se v 0.1.4 chovalo spravne. To je uz druhe kolo po sobe, kdy oprava zavedla
#  regresi; proto do invariantu jdou tvary Z OBOU SMERU, ne jen ty propoustejici.
# ================================================================================

$amber5bCases = @(
    # K1 - `{` za `@`, `$` nebo pismenem neni blok; hlava pred blokem se rozebira
    (Case 'K1 stash@{0}'                'git stash drop stash@{0}' 'deny')
    (Case 'K1 HEAD@{1}'                 'git reset --hard HEAD@{1}' 'deny')
    (Case 'K1 @{u}'                     'git reset --hard @{u}' 'deny')
    (Case 'K1 ${DIR}'                   'rm -rf ${DIR}' 'ask')
    (Case 'K1 src/${x}'                 'rm -rf src/${x}' 'ask')
    (Case 'K1 slozena zavorka jako arg' 'rm -rf {src,lib}' 'deny')
    (Case 'K1 neblokova zavorka driv'   'if ($a -eq ${env:X}) { git reset --hard }' 'deny' 'PowerShell')
    # 🔴 kontrolni skupina: blok se MUSI dal rozebirat (jinak by K1 vratilo I1)
    (Case 'K1 kontrola blok dal plati'  ("if (`$x) {" + $lf + '  git reset --hard' + $lf + '}') 'deny' 'PowerShell')
    (Case 'K1 kontrola & blok'          '& { rm -rf src }' 'deny' 'PowerShell')
    (Case 'K1 kontrola hashtable sama'  "@{ Path = 'src' }" 'allow' 'PowerShell')
    (Case 'K1 kontrola neskodny blok'   'if ($x) { git status }' 'allow' 'PowerShell')

    # L1 - telo bloku je VYRAZ, ne prikaz v pozici promenne (Z3 mysli `$VAR arg`)
    (Case 'L1 Where-Object'             'Get-ChildItem | Where-Object { $_.Name -like ''*.cs'' }' 'allow' 'PowerShell')
    (Case 'L1 ForEach-Object'           'Get-ChildItem | ForEach-Object { $_.x }' 'allow' 'PowerShell')
    (Case 'L1 Sort-Object'              'Get-ChildItem | Sort-Object { $_.Length }' 'allow' 'PowerShell')
    (Case 'L1 citac ve smycce'          'foreach ($f in $files) { $i++ }' 'allow' 'PowerShell')
    # 🔴 kontrolni skupina: vyraz smi projit, PRIKAZ v tele bloku ne
    (Case 'L1 kontrola prikaz v bloku'  'foreach ($f in $files) { git branch -D $f }' 'deny' 'PowerShell')
    # 🔴 Cena rozhodnuti T36-O5 A byla u techhle dvou tvaru pojmenovana v 0.1.10
    #    (pricina `variable` -> audit). 0.1.11 ji SNIZUJE, ne rusi (nalez Ady N35):
    #    hlavu porad rozebrat neumime, ale destruktivni LITERAL v ni videt je
    #    (`Delete(`, `git reset --hard`), takze `rawDestructiveTokens` dela token-test
    #    nad `Raw` a vyjde z toho `ask`, ne `deny` - kontext neznáme. Cena nad
    #    vypisem 46 dotazu: 0.
    (Case 'L1 kontrola volani metody'   'Get-ChildItem | ForEach-Object { $_.Delete() }' 'ask' 'PowerShell')
    (Case 'L1 kontrola podvyraz'        'Where-Object { $_.Name -eq ''x'' -or (git reset --hard) }' 'ask' 'PowerShell')
    #    Naproti tomu mazani z roury je POJMENOVANY tvar, ne nerozebratelny - zustava ask.
    (Case 'L1 kontrola roura z $_'      'Get-ChildItem | ForEach-Object { $_ | Remove-Item -Recurse -Force }' 'ask' 'PowerShell')
    # 🔴 v BASHi vyrazove pravidlo NEPLATI - `$cmd -rf src` se tam spousti, takze tvar
    #    zustava NEROZEBRATELNY; od 0.1.10 z toho ale neni dotaz, ale audit.
    (Case 'L1 kontrola Bash zustava'    '$_.Name -like "*.cs"' 'allow')

    # K3 - tataz trida jako I2, ale pro telo heredocu
    (Case 'K3 bash heredoc z PS'        ("bash <<'EOF'" + $lf + 'echo \" ; git reset --hard' + $lf + 'EOF') 'deny' 'PowerShell')
    (Case 'K3 pwsh heredoc z Bash'      ("pwsh <<'EOF'" + $lf + 'echo ' + $bt + '" ; git reset --hard' + $lf + 'EOF') 'deny')
    (Case 'K3 pokracovani radku v tele' ("bash <<'EOF'" + $lf + 'git reset \' + $lf + '  --hard' + $lf + 'EOF') 'deny' 'PowerShell')
    (Case 'K3 kontrola bez escapu'      ("bash <<'EOF'" + $lf + 'git reset --hard' + $lf + 'EOF') 'deny' 'PowerShell')
    (Case 'K3 kontrola neskodne telo'   ("bash <<'EOF'" + $lf + 'git status' + $lf + 'EOF') 'allow' 'PowerShell')
)

Test-Cases 'review Amber kolo 5b (K, L)' $amber5bCases

# ================================================================================
#  REVIEW ADA, KOLO 6 - nalezy N19-N23 (2026-09-06)
#
#  Sousedni trida k obalum: NE "co se rozebira", ale "KDE SE KTERY PRUCHOD SPOUSTI".
#  Hlavni beh mel tri pruchody (heredoc -> roura do SQL klienta -> prikazova radka),
#  rekurze znala jen posledni. Vzdaleny DROP pritom nema zalozni siet v
#  `permissions.deny` - prefixove pravidlo rouru neumi - takze ho drzel JEN hook.
#
#  N23 je muj vlastni nalez, ktery vypadl az z mereni N19: jednoclankova roura
#  v uvozovkach shodila hook na `.Count` pod StrictMode. Fail-closed, ale falesny
#  blok na uplne bezne praci.
# ================================================================================

$ada6Cases = @(
    # N19 - specialni pruchody se musi spustit i v zanoreni
    (Case 'N19 roura do psql v bash -c'  'bash -c ''echo "DROP TABLE users" | psql -h prod''' 'deny')
    (Case 'N19 heredoc v sh -c'          ('sh -c "psql -h prod <<SQL' + $lf + 'DROP TABLE x;' + $lf + 'SQL"') 'deny')
    (Case 'N19 roura do psql v eval'     'eval ''echo "DROP TABLE x" | psql -h prod''' 'deny')
    # 🔴 kontrolni skupina: bezna roura v zanoreni MUSI projit
    (Case 'N19 kontrola bezna roura'     'bash -c ''git log | head''' 'allow')
    (Case 'N19 kontrola holy tvar drzi'  'echo "DROP TABLE users" | psql -h prod' 'deny')
    (Case 'N19 kontrola -c v zanoreni'   'bash -c ''psql -h prod -c "DROP TABLE x"''' 'deny')

    # N23 - jednoclankova roura v uvozovkach shazovala hook (fail-closed = falesny blok)
    (Case 'N23 roura jen v uvozovkach'   'bash -c ''git log | head''' 'allow')
    (Case 'N23 roura v -c retezci'       'psql -h localhost -c "SELECT ''a|b''"' 'allow')

    # N20 - presmerovani stdin do SQL klienta
    (Case 'N20 stdin ze souboru'         'psql -h prod < drop.sql' 'allow')
    (Case 'N20 here-string z promenne'   'psql -h prod <<< $SQL' 'allow')
    (Case 'N20 here-string literal'      'psql -h prod <<< "DROP TABLE x"' 'deny')
    # 🔴 kontrolni skupina: `<` UVNITR retezce neni presmerovani
    (Case 'N20 kontrola < v dotazu'      'psql -h prod -c "SELECT * FROM t WHERE a < 5"' 'allow')
    (Case 'N20 kontrola -f drzi'         'psql -h prod -f drop.sql' 'allow')

    # N22 - UPDATE ... SET bez WHERE (rozsireni rozsahu, rozhodl Tom T-9 A)
    (Case 'N22 update bez where prod'    'psql -h prod -c "UPDATE users SET active=0"' 'deny')
    (Case 'N22 update bez where local'   'psql -h localhost -c "UPDATE users SET active=0"' 'ask')
    # 🔴 kontrolni skupina: s WHERE je to bezna prace
    (Case 'N22 kontrola s where'         'psql -h prod -c "UPDATE t SET a=1 WHERE id=1"' 'allow')
    (Case 'N22 kontrola delete drzi'     'psql -h prod -c "DELETE FROM t"' 'deny')

    # N21 - prikaz jako argument vzdaleneho shellu
    (Case 'N21 ssh s prikazem'           'ssh host "rm -rf /"' 'ask')
    (Case 'N21 ssh s SQL prikazem'       'ssh host "psql -c ''DROP TABLE x''"' 'ask')
    # 🔴 kontrolni skupina: ssh BEZ prikazu je bezna prace
    (Case 'N21 kontrola ssh bez prikazu' 'ssh host' 'allow')
    (Case 'N21 kontrola ssh -T'          'ssh -T git@github.com' 'allow')
)

Test-Cases 'review Ada kolo 6 (N19-N23)' $ada6Cases

# ================================================================================
#  REVIZE ADY NAD KOLEM 6 - N24, N25 (2026-09-07)
#
#  Obe jsou nasledky OPRAV z kola 6, ne noveho tvaru:
#    N24 - oprava N21 pocitala prepinac s hodnotou jako pozicionalni argument
#    N25 - vzor N22 bral jmeno tabulky jako JEDEN token
# ================================================================================

$ada6bCases = @(
    # N24 - prepinace ssh s hodnotou nesmi vypadat jako prikaz
    (Case 'N24 ssh -i s klicem'          'ssh -i key.pem host' 'allow')
    (Case 'N24 ssh -p s portem'          'ssh -p 2222 host' 'allow')
    (Case 'N24 ssh -o s volbou'          'ssh -o BatchMode=yes host' 'allow')
    (Case 'N24 ssh -l s uzivatelem'      'ssh -l tomas host' 'allow')
    # 🔴 kontrolni skupina: s PRIKAZEM to ask zustava, i kdyz jsou prepinace pritomne
    (Case 'N24 kontrola s prikazem'      'ssh -i key.pem host "rm -rf /"' 'ask')
    (Case 'N24 kontrola bez prepinacu'   'ssh host "rm -rf /"' 'ask')
    (Case 'N24 kontrola holy ssh'        'ssh host' 'allow')

    # N25 - UPDATE ONLY / UPDATE ... AS
    (Case 'N25 update only'              'psql -h prod -c "UPDATE ONLY users SET active=0"' 'deny')
    (Case 'N25 update s aliasem'         'psql -h prod -c "UPDATE users AS u SET active=0"' 'deny')
    # 🔴 kontrolni skupina: s WHERE je to porad bezna prace
    (Case 'N25 kontrola only s where'    'psql -h prod -c "UPDATE ONLY users SET active=0 WHERE id=1"' 'allow')
    (Case 'N25 kontrola alias s where'   'psql -h prod -c "UPDATE users AS u SET active=0 WHERE u.id=1"' 'allow')
)

Test-Cases 'revize Ady nad kolem 6 (N24, N25)' $ada6bCases

# ================================================================================
#  ROZHODNUTI TOMA 2026-09-07/T36-F1 T-10 A - tridy `ask` prehodnocene nad cisly
#
#  Sekce "Dotazy a bloky" v hlaseni 08 dala pocty misto dojmu; Tom nad nimi rozhodl,
#  ktere tridy `ask` uz branou byt nemaji. NENI to zmekceni pravidla - je to zmena
#  ROZSAHU brany, kterou vydal zadavatel, a u SQL ji doprovazi EVIDENCE.
# ================================================================================

$t10Cases = @(
    # git rebase a git clean -fdX -> ALLOW (bezna prace)
    (Case 'T10 rebase'                  'git rebase main' 'allow')
    (Case 'T10 rebase -i'               'git rebase -i HEAD~3' 'allow')
    (Case 'T10 clean -fdX'              'git clean -fdX' 'allow')
    # !! kontrolni skupina: `-x` je jine pismeno a jine rozhodnuti
    (Case 'T10 kontrola clean -fdx'     'git clean -fdx' 'deny')
    (Case 'T10 kontrola clean -fd'      'git clean -fd' 'deny')

    # SQL, ktere v prikazu NENI videt -> ALLOW + zapis do JSONL
    (Case 'T10 psql -f'                 'psql -h prod -f migrace.sql' 'allow')
    (Case 'T10 stdin ze souboru'        'psql -h prod < drop.sql' 'allow')
    (Case 'T10 here-string z promenne'  'psql -h prod <<< $SQL' 'allow')
    (Case 'T10 cat do psql'             'cat drop.sql | psql -h prod' 'allow')
    # !! kontrolni skupina: SQL, ktere VIDET JE, se rozhoduje dal podle hostitele
    (Case 'T10 kontrola literal v roure' 'echo "DROP TABLE users" | psql -h prod' 'deny')
    (Case 'T10 kontrola -c na prod'      'psql -h prod -c "DROP TABLE x"' 'deny')
    (Case 'T10 kontrola -c na localhost' 'psql -h localhost -c "DROP TABLE x"' 'ask')
    (Case 'T10 kontrola here-string literal' 'psql -h prod <<< "DROP TABLE x"' 'deny')

    # !! tridy, ktere ask ZUSTAVAJI (rozhodnuti T-10 A jmenuje i to, co se NEMENI)
    # 🔴 Az na jednu, a ta se otocila dvakrat: obal s promennou T-10 A ask NECHALO,
    #    T36-O5 A z nej udelalo audit a N34 (i) ho v 0.1.11 vraci na ask - protoze
    #    obsah promenne se v nem SPUSTI. Nazev pripadu zustava, ukazuje na nej radek
    #    regresniho invariantu.
    (Case 'T10 zustava obal s promennou' 'bash -c "$CMD"' 'ask')
    (Case 'T10 zustava ssh s prikazem'   'ssh host "rm -rf /"' 'ask')
    (Case 'T10 zustava kratka cesta'     'rm -rf /srv' 'ask')
    (Case 'T10 zustava spusteni promenne' '& $cmd' 'ask' 'PowerShell')
)

Test-Cases 'rozhodnuti Toma T-10 A (tridy ask)' $t10Cases

# --------------------------------------------- evidence misto brany (T-10 A) ---
#
# "allow + audit" je jine tvrzeni nez "allow". Kdyby se radek nezapsal, zmenilo by se
# rozhodnuti a NEZUSTALA by po nem stopa - a presne to Tom timhle rozhodnutim nechtel.
# Tvrdi se proto OBOJI: ze radek vznikne, a ze v nem NENI text prikazu.

Start-Case 'T-10 A: SQL neviditelne v prikazu se ZAPISE do auditu'
$auditDir = Join-Path $script:TempDir ('audit-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
$auditPath = Join-Path $auditDir 'gate-audit.jsonl'
$jsonAudit = New-HookInput 'pretooluse-bash' @{ 'tool_input.command' = 'psql -h prod -f migrace.sql' }
$rAudit = Invoke-Hook -Script 'gate.ps1' -InputJson $jsonAudit -Environment @{ 'CLAUDE_PLUGIN_DATA' = $auditDir }
Assert-Equal 'allow' (Get-Decision $rAudit) '[audit] rozhodnuti je allow'
Assert-True ([System.IO.File]::Exists($auditPath)) '[audit] radek se zapsal'
if ([System.IO.File]::Exists($auditPath)) {
    $auditLine = [System.IO.File]::ReadAllText($auditPath, ([System.Text.UTF8Encoding]::new($false)))
    Assert-True ($auditLine -match '"shape":"sqlFromFile"') '[audit] nese id tvaru'
    Assert-True ($auditLine -match '"decision":"allow"') '[audit] nese rozhodnuti'
    Assert-True ($auditLine -match '"tool":"Bash"') '[audit] nese nastroj'
    # 🔴 zadani par. 4 bod 8: obsah prikazu se NELOGUJE (riziko uniku)
    Assert-True ($auditLine -notmatch 'migrace\.sql') '[audit] NEOBSAHUJE text prikazu'
    Assert-True ($auditLine -notmatch 'psql') '[audit] NEOBSAHUJE jmeno klienta z prikazu'
}

# 🔴 kontrolni skupina: bez datoveho adresare se nezapisuje NIC a hook se tim nezastavi
Start-Case 'T-10 A: bez CLAUDE_PLUGIN_DATA se nezapisuje nic (fail-open)'
$auditDir2 = Join-Path $script:TempDir ('audit-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
$rAudit2 = Invoke-Hook -Script 'gate.ps1' -InputJson $jsonAudit -Environment @{ 'CLAUDE_PLUGIN_DATA' = '' }
Assert-Equal 'allow' (Get-Decision $rAudit2) '[audit/kontrola] rozhodnuti je porad allow'
Assert-Equal 0 $rAudit2.Exit '[audit/kontrola] navratovy kod 0'
Assert-True (-not [System.IO.Directory]::Exists($auditDir2)) '[audit/kontrola] zadny soubor nevznikl'

# ================================================================================
#  ROZHODNUTI TOMA 2026-09-07/T36-O5 = A - "nerozebratelne" uz neni dotaz
#
#  Do 0.1.9 koncil KAZDY nerozebratelny tvar na `ask`. Nad realnymi cisly ze 7. 9.
#  (tri sessions, 46 dotazu) to znamenalo 45 dotazu pri DVOU skutecnych zasazich §6.
#  Trida se proto rozpadla na PRICINY a politiku k nim urcuje konfigurace.
#
#  🔴 Tahle sekce tvrdi TICHO, ne 'allow'. Get-Decision vraci 'allow' i pro
#  `permissionDecision: allow`, jenze to je JINA vec: `allow` z hooku preskoci vrstvu
#  opravneni Claude Code, kdezto ticho ji necha rozhodnout. Mutant "1A vraci allow
#  misto $null" by pres tvrzeni o rozhodnuti PROSEL - proto se tvrdi prazdny stdout.
# ================================================================================

$t36Cases = @(
    # --- kontrolni skupina: co ask ZUSTAVA. Bez ni by sada merila jen to, ze se neco
    #     zmenilo, ne ze se zmenilo to spravne.
    (Case 'T36 spusteni promenne'       '& $cmd' 'ask' 'PowerShell')
    (Case 'T36 spusteni promenne arg'   '& $cmd -Force' 'ask' 'PowerShell')
    (Case 'T36 -enc'                    'pwsh -enc UmVtb3ZlLUl0ZW0=' 'ask' 'PowerShell')
    (Case 'T36 ssh s prikazem'          'ssh prod "rm -rf /"' 'ask')
    (Case 'T36 git alias'               "git -c alias.bd='branch -D' bd x" 'ask')
    (Case 'T36 ssh heredoc'             ("ssh prod <<EOF" + $lf + 'rm -rf /srv' + $lf + 'EOF') 'ask')

    # --- pricina `variable` -> audit (jadro zmeny 0.1.10)
    # 🔴 0.1.11 / N34 (i): tri z techto ctyr jsou OBALY, ktere obsah promenne SPUSTI -
    #    tedy `invoked`, ne `variable`. Audit u nich znamenal, ze se rozlisovac tvaril
    #    jako "spusti se" x "nespusti se", ale ve skutecnosti delil "PS operator `&`"
    #    x zbytek. Ctvrty (`$TOOL git push`) obal nema a auditem zustava.
    (Case 'T36 obal s promennou'        'bash -c "$CMD"' 'ask')
    (Case 'T36 cmd s promennou'         'cmd /c %X%' 'ask')
    (Case 'T36 eval s promennou'        'eval $cmd' 'ask')
    (Case 'T36 promenna misto exe'      '$TOOL git push' 'allow')
    (Case 'T36 retezec s promennou'     '"EXIT=$LASTEXITCODE"' 'allow' 'PowerShell')
    (Case 'T36 Math Truncate promenna'  '[Math]::Truncate($x)' 'allow' 'PowerShell')
    (Case 'T36 ReadAllText promenna'    '[System.IO.File]::ReadAllText($f)' 'allow' 'PowerShell')
    #     `$x = <prikaz>` neprere dal: destruktivni prava strana zustava deny
    (Case 'T36 prirazeni neprere'       '$x = git branch -D feature/y' 'deny' 'PowerShell')

    # --- pricina `heredocUnterminated` a `depth`: 0.1.10 audit, 0.1.11 zpatky ASK
    #     (N35: obe maji ve vypisu 46 dotazu 0 vyskytu, takze default `ask` nestoji nic)
    (Case 'T36 neukonceny heredoc'      ("bash <<EOF" + $lf + 'git status') 'ask')

    # --- pricina `interpreter`: bez destruktivniho tokenu audit, s nim ask (1C)
    (Case 'T36 python neskodny'         'python -c "print(1)"' 'allow')
    (Case 'T36 python read_text'        'python -c "import io; io.open(''x'').read()"' 'allow')
    (Case 'T36 python rmtree'           'python -c "import shutil; shutil.rmtree(''src'')"' 'ask')
    (Case 'T36 python os.remove'        'python -c "import os; os.remove(''x'')"' 'ask')
    (Case 'T36 node rmSync'             'node -e "require(''fs'').rmSync(''src'')"' 'ask')
    (Case 'T36 node neskodny'           'node -e "console.log(require(''./p.json'').name)"' 'allow')
    (Case 'T36 python heredoc neskodny' ("python <<EOF" + $lf + 'print(1)' + $lf + 'EOF') 'allow')
    (Case 'T36 python heredoc rmtree'   ("python <<EOF" + $lf + 'import shutil' + $lf + "shutil.rmtree('src')" + $lf + 'EOF') 'ask')
    #     token se porovnava CASE-SENSITIVNE - jinak by seznam chytal bezna slova
    (Case 'T36 token jinou velikosti'   'python -c "x.remove_item(1)"' 'allow')

    # --- 1B: Microsoft.VisualBasic je druhe jmeno teze operace
    (Case 'T36 VB promenna'             '[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($p, $true)' 'ask' 'PowerShell')
    (Case 'T36 VB literal src'          '[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory(''src'')' 'deny' 'PowerShell')
    (Case 'T36 VB literal bin'          '[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory(''bin'')' 'allow' 'PowerShell')
    (Case 'T36 VB DeleteFile literal'   '[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile(''src/a.cs'')' 'deny' 'PowerShell')
    (Case 'T36 VB recycle bin'          '[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($p, [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs, [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin)' 'ask' 'PowerShell')
    #     kontrolni skupina: stara cesta [IO.*]::Delete se nezmenila
    (Case 'T36 IO.File promenna'        '[IO.File]::Delete($f)' 'ask' 'PowerShell')
    (Case 'T36 IO.Directory literal'    '[IO.Directory]::Delete(''src'', $true)' 'deny' 'PowerShell')

    # --- v bypassu: audit ZUSTAVA auditem (neni to `ask`, tak se z neho nema co stat
    #     `deny`), `invoked` na deny padne dal.
    # 🔴 0.1.11: `bash -c "$CMD"` uz auditem NENI (N34 i -> `invoked`), takze v bypassu
    #    padne na deny stejne jako `& $cmd`. Auditni tvar drzi `$TOOL git push` nize.
    (Case 'T36 bypass obal s promennou' 'bash -c "$CMD"' 'deny' 'Bash' 'bypassPermissions')
    (Case 'T36 bypass audit zustava'    '$TOOL git push' 'allow' 'Bash' 'bypassPermissions')
    (Case 'T36 bypass spusteni'         '& $cmd' 'deny' 'PowerShell' 'bypassPermissions')
    (Case 'T36 bypass VB literal'       '[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory(''src'')' 'deny' 'PowerShell' 'bypassPermissions')
)

Test-Cases 'rozhodnuti Toma T36-O5 A (opaque -> audit)' $t36Cases

# ------------------------------------------- audit misto dotazu: radek JSONL ---
#
# "audit" je jine tvrzeni nez "nic". Kdyby se radek nezapsal, zmizela by po tvaru
# stopa uplne - a to je presne to, co rozhodnuti T36-O5 A nechtelo.

Start-Case 'T36-O5 A: nerozebratelny obal MLCI a zapise se do auditu'
$auditDirO = Join-Path $script:TempDir ('audit-op-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
$auditPathO = Join-Path $auditDirO 'gate-audit.jsonl'
# 0.1.11: nositelem auditu uz nemuze byt `bash -c "$CMD"` - ten je od N34 (i) `invoked`,
# tedy ask. Auditni tvar je promenna v pozici prikazu BEZ spousteciho obalu.
$jsonO = New-HookInput 'pretooluse-bash' @{ 'tool_input.command' = '$TOOL git push' }
$rO = Invoke-Hook -Script 'gate.ps1' -InputJson $jsonO -Environment @{ 'CLAUDE_PLUGIN_DATA' = $auditDirO }
Assert-Equal '' ($rO.Stdout.Trim()) '[opaque-audit] hook MLCI - prazdny stdout, ne permissionDecision'
Assert-Equal 0 $rO.Exit '[opaque-audit] exit 0'
Assert-True ([System.IO.File]::Exists($auditPathO)) '[opaque-audit] radek se zapsal'
if ([System.IO.File]::Exists($auditPathO)) {
    $lineO = [System.IO.File]::ReadAllText($auditPathO, ([System.Text.UTF8Encoding]::new($false)))
    Assert-True ($lineO -match '"shape":"opaque:variable"') '[opaque-audit] nese id tvaru vcetne priciny'
    Assert-True ($lineO -match '"decision":"allow"') '[opaque-audit] nese rozhodnuti'
    Assert-True ($lineO -match '"tool":"Bash"') '[opaque-audit] nese nastroj'
    # 🔴 zadani par. 4 bod 8: obsah prikazu se NELOGUJE
    Assert-True (-not $lineO.Contains('TOOL')) '[opaque-audit] NEOBSAHUJE text prikazu'
}

# 🔴 kontrolni skupina: tvar, ktery ask ZUSTAVA, se do auditu nezapisuje - jinak by
# radek v JSONL netvrdil nic o tom, co se doopravdy pustilo dal.
Start-Case 'kontrolni skupina: & $cmd je ask, ne audit'
$auditDirI = Join-Path $script:TempDir ('audit-inv-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
$auditPathI = Join-Path $auditDirI 'gate-audit.jsonl'
$jsonI = New-HookInput 'pretooluse-powershell' @{ 'tool_input.command' = '& $cmd' }
$rI = Invoke-Hook -Script 'gate.ps1' -InputJson $jsonI -Environment @{ 'CLAUDE_PLUGIN_DATA' = $auditDirI }
Assert-Equal 'ask' (Get-Decision $rI) '[opaque-ask] rozhodnuti je ask'
Assert-True (-not [System.IO.File]::Exists($auditPathI)) '[opaque-ask] radek auditu NEVZNIKL'

# ================================================================================
#  v0.1.11 - nalezy Ady N28, N33-N35, N39, N40, N49, N50
# ================================================================================

# N40: pripad pro pricinu `depth` (`Depth > 5`) dosud v sade nebyl.
# 🔴 Zmereno, ne odhadnuto: retez OBALU (`sudo nice nohup time doas timeout rm -rf src`)
# hloubku NEZVYSI - `Get-WrapperTail` strhne vsechny obaly najednou a rekurze je jedna,
# takze takovy tvar konci `deny` jako obycejne mazani. Hloubku pridava kazda ZAVORKA
# a kazde prirazeni, protoze ty se rozebiraji po jedne urovni.
$deepDestr = '(((((((rm -rf src)))))))'
$deepPlain = '(((((((rm -rf bin)))))))'

$v0111Cases = @(
    # --- 1A / N28: marker "SQL ze souboru" uz NEPREBIJI viditelne destruktivni SQL.
    #     Do 0.1.10 stacilo k libovolnemu destruktivnimu `-c` prilepit `< /dev/null`
    #     nebo `-f x.sql` a vetev markeru rozhodla driv, nez se nekdo podival na text.
    (Case 'N28 -c a redirect na prod'   'psql -h prod -c "DROP TABLE x" < /dev/null' 'deny')
    (Case 'N28 -f vedle -c na prod'     'psql -h prod -f m.sql -c "DROP TABLE x"' 'deny')
    (Case 'N28 -c a redirect localhost' 'psql -h localhost -c "DROP TABLE x" < x' 'ask')
    #     další viditelné tvary vedle markeru
    (Case 'N28 truncate vedle -f'       'psql -h prod -f m.sql -c "TRUNCATE users"' 'deny')
    (Case 'N28 delete bez where'        'psql -h prod -c "DELETE FROM users" < /dev/null' 'deny')
    # --- A-1 (review Amber, kolo 1): tataz trida o radek niz. Destruktivnost nese
    #     jeste jmeno spustitelneho souboru (`dropdb`), ne jen TEXT SQL - a `dropdb`
    #     je v `sqlClients`, takze mu Get-SqlText marker taky prida. Prvni oprava N28
    #     se ptala na `$sqlDestructive`, pravidlo se pta na `$destructive`.
    (Case 'A-1 dropdb prod + redirect'  'dropdb -h prod mydb < /dev/null' 'deny')
    (Case 'A-1 dropdb prod + -f'        'dropdb -h prod mydb -f x.sql' 'deny')
    (Case 'A-1 dropdb localhost + redir' 'dropdb -h localhost x < /dev/null' 'ask')
    # 🔴 kontrolni skupina A-1: bez markeru se nic nemeni
    (Case 'A-1 kontrola dropdb prod'    'dropdb -h prod x' 'deny')
    (Case 'A-1 kontrola dropdb local'   'dropdb -h localhost x' 'ask')
    #     `dotnet ef` v `sqlClients` NENI, takze marker nedostane - zmereno, ne
    #     odhadnuto: presmerovani na jeho rozhodnuti nema vliv (obojí `ask`, protoze
    #     bez `--connection` nema hostitele a plati "lokalni").
    (Case 'A-1 kontrola ef drop'        'dotnet ef database drop' 'ask')
    (Case 'A-1 kontrola ef drop redir'  'dotnet ef database drop < /dev/null' 'ask')
    (Case 'A-1 kontrola ef update prod' 'dotnet ef database update --connection "Host=prod" < /dev/null' 'deny')

    # 🔴 kontrolni skupina: marker SAM (bez viditelneho SQL) zustava auditem - jinak
    #    by oprava zabila bezne `psql -f migrace.sql` a brana by se do tydne vypnula
    (Case 'N28 kontrola samotny -f'     'psql -h prod -f m.sql' 'allow')
    (Case 'N28 kontrola samotny redirect' 'psql -h prod < drop.sql' 'allow')
    (Case 'N28 kontrola here-string'    'psql -h prod <<< $SQL' 'allow')
    (Case 'N28 kontrola neskodne -c'    'psql -h prod -c "SELECT 1" < /dev/null' 'allow')

    # --- 1B / N34 (i): obal, ktery SPOUSTI obsah promenne -> `invoked` -> ask
    (Case 'N34 eval'                    'eval $cmd' 'ask')
    (Case 'N34 bash -c'                 'bash -c "$x"' 'ask')
    (Case 'N34 sh -c'                   'sh -c "$x"' 'ask')
    (Case 'N34 cmd /c'                  'cmd /c %X%' 'ask')
    (Case 'N34 pwsh -c'                 'pwsh -c $x' 'ask' 'PowerShell')
    (Case 'N34 Start-Process promenna'  'Start-Process $x' 'ask' 'PowerShell')
    (Case 'N33 dot-source promenne'     '. $x' 'ask' 'PowerShell')
    #     `iex 'literal'` se ROZEBERE jako telo `bash -c` (N33 zuzeny)
    (Case 'N33 iex literal destruktivni' 'iex ''git reset --hard''' 'deny' 'PowerShell')
    (Case 'N33 iex literal neskodny'    'iex ''git status''' 'allow' 'PowerShell')
    (Case 'N33 iex -Command literal'    'Invoke-Expression -Command ''git branch -D x''' 'deny' 'PowerShell')
    (Case 'N33 iex promenna'            'iex $cmd' 'ask' 'PowerShell')
    # 🔴 kontrolni skupina N49: promenna jako CESTA neni kod. Bez teto skupiny by
    #    "obal s promennou = ask" znamenalo ask u kazdeho spousteni skriptu s cestou
    #    v promenne, coz je bezna prace.
    (Case 'N49 pwsh -File promenna'     'pwsh -File $p' 'allow' 'PowerShell')
    (Case 'N49 bash skript promennou'   'bash $script' 'allow')
    (Case 'N49 Start-Process literal'   'Start-Process -FilePath ''pwsh'' -ArgumentList ''-File'',''x.ps1'' -RedirectStandardOutput $log' 'allow' 'PowerShell')
    # 🔴 kontrolni skupina: HODNOTA a VYRAZ s promennou zustavaji auditem (ticho)
    (Case 'N34 kontrola retezec'        '"EXIT=$x"' 'allow' 'PowerShell')
    (Case 'N34 kontrola roura hodnoty'  '$out | Select-String x' 'allow' 'PowerShell')
    (Case 'N34 kontrola vyraz'          '[Math]::Truncate($x)' 'allow' 'PowerShell')
    (Case 'N33 kontrola relativni cesta' './cleanup.sh' 'allow')
    (Case 'N33 kontrola nadrazeny adresar' 'ls ..' 'allow')

    # --- 1C / N35: destruktivni LITERAL pod nerozebratelnou hlavou -> ask
    (Case 'N35 podvyraz v Where-Object' 'Where-Object { $_.Name -eq ''x'' -or (git reset --hard) }' 'ask' 'PowerShell')
    (Case 'N35 volani metody Delete'    'Get-ChildItem | ForEach-Object { $_.Delete() }' 'ask' 'PowerShell')
    (Case 'N35 promenna v hlave'        '$SUDO git reset --hard' 'ask')
    # 🔴 Zmereno: neukonceny heredoc s destruktivnim TELEM konci `deny`, ne `ask` -
    #    telo se rozebere jako prikazova radka a `deny` z nej prebije `ask` z priciny
    #    `heredocUnterminated`. Tvrdi se tedy silnejsi vec, nez zadani predpokladalo.
    #    Kontrolni skupina o radek niz ukazuje, ze prazdna cesta konci `ask`.
    (Case 'N35 neukonceny heredoc destr' ("bash <<EOF" + $lf + 'git reset --hard') 'deny')
    (Case 'N35 neukonceny heredoc plain' ("bash <<EOF" + $lf + 'git status') 'ask')
    #     `depth`: destruktivni literal chytne 1C, cisty tvar chytne default `ask`
    (Case 'N40 zanoreni depth s rm'     $deepDestr 'ask' 'PowerShell')
    (Case 'N40 zanoreni depth bez rm'   $deepPlain 'ask' 'PowerShell')
    # 🔴 kontrolni skupina: bez destruktivniho literalu zustava audit (ticho).
    #    Bez ni by "1C funguje" znamenalo jen "vse je ask" - to uz umel 0.1.9.
    (Case 'N35 kontrola bez tokenu'     '"EXIT=$x"' 'allow' 'PowerShell')
    (Case 'N35 kontrola Where bez tokenu' 'Get-ChildItem | Where-Object { $_.Name -like ''*.cs'' }' 'allow' 'PowerShell')
    (Case 'N35 kontrola git push'       '$TOOL git push' 'allow')
    # 🔴 N50: `DELETE FROM` je v `rawDestructiveTokens`, ale NE v tokenech interpretu -
    #    telo interpretu bezne nese SQL s WHERE, ktere overit nejde.
    (Case 'N50 raw DELETE FROM'         '$SQL DELETE FROM users' 'ask')
    (Case 'N50 interpret DELETE FROM'   'python -c "q = ''DELETE FROM t WHERE id=1''"' 'allow')

    # --- 1F / N40: dva tvary, ktere dosud nemely pripad
    (Case 'N40 -EncodedCommand bypass'  'pwsh -enc UmVtb3ZlLUl0ZW0=' 'deny' 'PowerShell' 'bypassPermissions')
)

Test-Cases 'v0.1.11 - nalezy Ady N28, N33-N35, N49, N50' $v0111Cases

# ------------------------ K-2: tvary v auditu u "SQL neni videt" (review Amber) ---
#
# 🔴 README ted nese TABULKU tvaru, ne vetu - a tabulka je tvrzeni, ktere musi jit
# vyvratit. Puvodni veta ("dotaz zustava jen u `$sql | psql`, tvar `sqlFromPipe`")
# byla dvakrat nepravdiva: dotaz tam nezustal zadny a `$sql | psql` nese `opaque:variable`
# (hlava je promenna), zatimco `sqlFromPipe` nese `cat x.sql | psql`.
# TASK-106 bod 8 (L2) to popisoval SPRAVNE - lhala README.

function Test-AuditShape([string]$Name, [string]$Cmd, [string]$Shape) {
    $dir = Join-Path $script:TempDir ('audit-k2-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
    $path = Join-Path $dir 'gate-audit.jsonl'
    $json = New-HookInput 'pretooluse-bash' @{ 'tool_input.command' = $Cmd }
    $r = Invoke-Hook -Script 'gate.ps1' -InputJson $json -Environment @{ 'CLAUDE_PLUGIN_DATA' = $dir }
    Assert-Equal 'allow' (Get-Decision $r) ("[K-2/{0}] hook mlci" -f $Name)
    Assert-True ([System.IO.File]::Exists($path)) ("[K-2/{0}] radek auditu vznikl" -f $Name)
    if ([System.IO.File]::Exists($path)) {
        $line = [System.IO.File]::ReadAllText($path, ([System.Text.UTF8Encoding]::new($false)))
        Assert-True ($line -match ('"shape":"' + [regex]::Escape($Shape) + '"')) `
                    ("[K-2/{0}] tvar je {1}" -f $Name, $Shape)
    }
}

Start-Case 'K-2: "SQL neni videt" - ktery tvar nese ktery zapis'
Test-AuditShape 'psql -f'        'psql -h prod -f m.sql'          'sqlFromFile'
Test-AuditShape 'psql < soubor'  'psql -h prod < drop.sql'        'sqlFromFile'
Test-AuditShape 'cat do psql'    'cat drop.sql | psql -h prod'    'sqlFromPipe'
Test-AuditShape 'promenna do psql' '$sql | psql -h prod'          'opaque:variable'
# 🔴 kontrolni skupina: literal VIDET JE, takze se nerozhoduje auditem, ale hostitelem
$jsonK2 = New-HookInput 'pretooluse-bash' @{ 'tool_input.command' = 'echo "DROP TABLE x" | psql -h prod' }
Assert-Equal 'deny' (Get-Decision (Invoke-Hook -Script 'gate.ps1' -InputJson $jsonK2)) `
             '[K-2/kontrola] literal v roure je deny, ne audit'

# ------------------------------------------ T36-Q7 = A: audit v bypassu se PRIZNA ---
#
# V `bypassPermissions` nad pluginem uz zadna vrstva neni - audit tam znamena
# "proslo bez druhe kontroly", ne "rozhodne o tom vrstva opravneni Claude Code".
# Nic se neblokuje (rozhodl Tom 2026-09-08/T36-Q7 = A); radek auditu to jen rekne.

Start-Case 'T36-Q7 A: audit v bypassu nese decision allow-bypass'
$auditDirB = Join-Path $script:TempDir ('audit-byp-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
$auditPathB = Join-Path $auditDirB 'gate-audit.jsonl'
$jsonB = New-HookInput 'pretooluse-powershell' @{ 'tool_input.command' = '"EXIT=$x"'
                                                  'permission_mode'    = 'bypassPermissions' }
$rB = Invoke-Hook -Script 'gate.ps1' -InputJson $jsonB -Environment @{ 'CLAUDE_PLUGIN_DATA' = $auditDirB }
Assert-Equal 'allow' (Get-Decision $rB) '[bypass-audit] nic se neblokuje'
Assert-True ([System.IO.File]::Exists($auditPathB)) '[bypass-audit] radek se zapsal'
if ([System.IO.File]::Exists($auditPathB)) {
    $lineB = [System.IO.File]::ReadAllText($auditPathB, ([System.Text.UTF8Encoding]::new($false)))
    Assert-True ($lineB -match '"decision":"allow-bypass"') '[bypass-audit] rozhodnuti je allow-bypass'
}

# 🔴 kontrolni skupina: BEZ bypassu nese tyz tvar `allow`. Bez ni by `allow-bypass`
# mohl stat v kazdem radku a test by byl porad zeleny.
Start-Case 'kontrolni skupina: bez bypassu nese radek allow'
$auditDirN = Join-Path $script:TempDir ('audit-nob-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
$auditPathN = Join-Path $auditDirN 'gate-audit.jsonl'
$jsonN = New-HookInput 'pretooluse-powershell' @{ 'tool_input.command' = '"EXIT=$x"' }
$rN = Invoke-Hook -Script 'gate.ps1' -InputJson $jsonN -Environment @{ 'CLAUDE_PLUGIN_DATA' = $auditDirN }
Assert-True ([System.IO.File]::Exists($auditPathN)) '[bypass-kontrola] radek se zapsal'
if ([System.IO.File]::Exists($auditPathN)) {
    $lineN = [System.IO.File]::ReadAllText($auditPathN, ([System.Text.UTF8Encoding]::new($false)))
    Assert-True ($lineN -match '"decision":"allow"') '[bypass-kontrola] rozhodnuti je allow'
    Assert-True (-not ($lineN -match 'allow-bypass')) '[bypass-kontrola] NENI allow-bypass'
}

# ------------------------------------------------ politika je KONFIGURACE ---
#
# Slouceni je MELKE na nejvyssi urovni, takze override musi dodat cely klic `gate`.
# Ostatni hodnoty pak berou vestavene fallbacky - pro tohle tvrzeni to staci, protoze
# tvrdi ROZHODNUTI, ne text duvodu.

function Test-OpaquePolicy([string]$Name, [string]$Value, [string]$Expect) {
    $dir = Join-Path $script:TempDir ('policy-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
    [void][System.IO.Directory]::CreateDirectory((Join-Path $dir '.claude'))
    [System.IO.File]::WriteAllText(
        (Join-Path $dir '.claude/sinogard-hooks.json'),
        ('{"gate":{"opaque":{"variable":"' + $Value + '"}}}'),
        ([System.Text.UTF8Encoding]::new($false)))
    $json = New-HookInput 'pretooluse-powershell' @{ 'tool_input.command' = '"EXIT=$x"' }
    $r = Invoke-Hook -Script 'gate.ps1' -InputJson $json -Environment @{ CLAUDE_PROJECT_DIR = $dir }
    Assert-Equal $Expect (Get-Decision $r) ("[politika/{0}] gate.opaque.variable = {1}" -f $Name, $Value)
}

Start-Case 'gate.opaque je konfigurace (a neznama hodnota je fail-closed)'
Test-OpaquePolicy 'audit' 'audit' 'allow'
Test-OpaquePolicy 'ask'   'ask'   'ask'
# 🔴 Neznama hodnota NESMI znamenat audit: preklep v override by branu tise otevrel.
Test-OpaquePolicy 'neznama' 'maybe' 'ask'

# -------------------------- JEDNOUROVNOVE slucovani top-level objektu (K2-1) ---
#
# 🔴 Do 0.1.10 tady stal DOKLAD OMEZENI: slouceni bylo melke na nejvyssi urovni, takze
# override s jednou hodnotou z `gate` zahodil cely zbytek klice - `denyPatterns`,
# `allowedRemoveRoots`, `shapes` - a ty padly na vestavene fallbacky. Slo to OBEMA
# smery a prave proto to bylo zradne:
#   `git reset --hard` PRESTAL byt deny (pravidlo bylo v `denyPatterns`)
#   `rm -rf bin`       ZACAL byt deny   (povolena slozka byla v `allowedRemoveRoots`)
# Brana dal neco blokovala, takze "porad funguje" bylo pravdive pozorovani a zaroven
# falesny zaver.
#
# 0.1.11 (N37, TASK-106 bod 10) to OPRAVUJE: objekt se slucuje o JEDNU uroven, pole
# a skalary se nahrazuji cele. Tenhle blok proto zmenil ROLI - z dokladu omezeni je
# doklad opravy. Ocekavani se otocila, protoze se zmenilo chovani; puvodni znenl
# zustava vys jako citace toho, co platilo do 0.1.10.
function Test-PartialGateOverride([string]$Name, [string]$Tool, [string]$Cmd, [string]$Expect,
                                  [string]$Override = '{"gate":{"opaque":{"variable":"audit"}}}') {
    $dir = Join-Path $script:TempDir ('partial-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
    [void][System.IO.Directory]::CreateDirectory((Join-Path $dir '.claude'))
    [System.IO.File]::WriteAllText(
        (Join-Path $dir '.claude/sinogard-hooks.json'),
        $Override,
        ([System.Text.UTF8Encoding]::new($false)))
    $template = if ($Tool -eq 'PowerShell') { 'pretooluse-powershell' } else { 'pretooluse-bash' }
    $json = New-HookInput $template @{ 'tool_input.command' = $Cmd }
    $r = Invoke-Hook -Script 'gate.ps1' -InputJson $json -Environment @{ CLAUDE_PROJECT_DIR = $dir }
    Assert-Equal $Expect (Get-Decision $r) ("[K2-1/{0}] {1}" -f $Name, $Cmd)
}

Start-Case 'K2-1 opraveno: castecny override `gate` uz zbytek klice NEZTRATI'
$ovVariableAsk = '{"gate":{"opaque":{"variable":"ask"}}}'
Test-PartialGateOverride 'reset --hard drzi'  'Bash' 'git reset --hard' 'deny' $ovVariableAsk
Test-PartialGateOverride 'branch -D drzi'     'Bash' 'git branch -D feature/x' 'deny' $ovVariableAsk
Test-PartialGateOverride 'filter-branch drzi' 'Bash' 'git filter-branch --tree-filter x HEAD' 'deny' $ovVariableAsk
# 🔴 druhy smer teze ztraty: povolena slozka uz taky nemizi, takze zadny falesny blok
Test-PartialGateOverride 'rm -rf bin neblokuje' 'Bash' 'rm -rf bin' 'allow' $ovVariableAsk
# a hodnota, kvuli ktere se override psal, PLATI - jinak by slouceni bylo k nicemu
Test-PartialGateOverride 'prepsana politika plati' 'PowerShell' '"EXIT=$x"' 'ask' $ovVariableAsk
# 🔴 kontrolni skupina: pravidla, ktera ziji v KODU (ne v konfiguraci), drzi dal
Test-PartialGateOverride 'rm -rf src drzi'    'Bash' 'rm -rf src' 'deny' $ovVariableAsk
Test-PartialGateOverride 'DB podle hosta drzi' 'Bash' 'psql -h db.firma.cz -c "DROP TABLE users"' 'deny' $ovVariableAsk
Test-PartialGateOverride 'invoked drzi'       'PowerShell' '& $cmd' 'ask' $ovVariableAsk

# 🔴 A POLE se porad nahrazuje CELE - to je smysl "jednourovnove", ne "hluboke".
#    Bez tohohle radku by se nedalo poznat, jestli se neslucuje i dovnitr poli, a
#    duvod melkeho slucovani (polozku seznamu jde jen pridat, nikdy odebrat) by padl.
Start-Case 'K2-1: pole se nahrazuje CELE (slouceni je jednourovnove, ne hluboke)'
Test-PartialGateOverride 'prazdne denyPatterns' 'Bash' 'git reset --hard' 'allow' '{"gate":{"denyPatterns":[]}}'
# kontrolni skupina k temuz override: co nezije v `denyPatterns`, drzi dal
Test-PartialGateOverride 'kod drzi i pri prazdnem poli' 'Bash' 'rm -rf src' 'deny' '{"gate":{"denyPatterns":[]}}'

# ================================================================================
#  VYPIS DOTAZU 7. 9. 2026 - 46 PRIKAZU ZE TRI SESSIONS (GSD 31, HRMS 5, Utraty 10)
#
#  Fixtura nese prikaz DOSLOVNE. Merenim nad 9e4720b (v0.1.9) vyslo 45 ask a 1 ticho
#  (blok "Inventura MCP" - tam se ptal hook secrets, ne gate), takze cervenych tvrzeni
#  bylo 45: 43 x rozhodnuti misto ticha + 2 x duvod "nejde rozebrat" misto tvaru
#  netDeleteVariable.
#
#  Radky NEJDOU do regresniho invariantu: invariant nese jednoradkove tvary a tyhle
#  prikazy maji az 50 radku. Drzi je vlastni fixtura, prehrava se stejne pri kazdem behu.
# ================================================================================

Start-Case 'vypis dotazu 7. 9. 2026: 46 prikazu -> 44 x allow (ticho), 2 x ask'
$vypisPath = Join-Path $PSScriptRoot 'fixtures/ask-vypis-2026-09-07.json'
if (-not (Test-SafePath $vypisPath)) {
    $script:Skip++
    Write-Host '    SKIP fixtures/ask-vypis-2026-09-07.json chybi' -ForegroundColor Yellow
} elseif (Test-CollectOnly) {
    $script:Skip++
} else {
    $vypis = [System.IO.File]::ReadAllText($vypisPath, ([System.Text.UTF8Encoding]::new($false))) | ConvertFrom-Json
    $vRows = @($vypis.rows)
    Assert-Equal 46 $vRows.Count '[vypis] radku ve fixture'
    Assert-Equal 2 (@($vRows | Where-Object { $_.expect -eq 'ask' }).Count) '[vypis] tvaru s dotazem'
    foreach ($vr in $vRows) {
        $vid = "{0}/{1}" -f $vr.source, $vr.order
        $template = if ([string]$vr.tool -eq 'PowerShell') { 'pretooluse-powershell' } else { 'pretooluse-bash' }
        $json = New-HookInput $template @{ 'tool_input.command' = [string]$vr.cmd }
        $r = Invoke-Hook -Script 'gate.ps1' -InputJson $json
        # N46: slovnik je jeden. `allow` = hook MLCI a Get-Decision to od
        # `permissionDecision: allow` odlisi sam (vraci 'DECISION-ALLOW'), takze
        # tvrzeni o tichu drzi dal a nepotrebuje k tomu druhe jmeno.
        if ([string]$vr.expect -eq 'allow') {
            Assert-Equal 'allow' (Get-Decision $r) ("[vypis/{0}] hook mlci" -f $vid)
            Assert-Equal '' ($r.Stdout.Trim()) ("[vypis/{0}] hook mlci (prazdny stdout)" -f $vid)
            Assert-Equal 0 $r.Exit ("[vypis/{0}] exit 0" -f $vid)
        } else {
            Assert-Equal 'ask' (Get-Decision $r) ("[vypis/{0}] rozhodnuti ask" -f $vid)
            # Duvod musi jmenovat MAZANI. Bez 1B by tenhle tvar spadl do tridy
            # `variable`, tedy do auditu - a to by byla dira, ne automatizace.
            # !! Cte se ze STDOUT: `ask` se na stderr nevypisuje vubec (Write-AskDecision),
            #    takze tvrzeni nad `$r.Stderr` by bylo zelene i pro uplne jiny tvar.
            $reasonV = ''
            if (-not [string]::IsNullOrWhiteSpace($r.Stdout)) {
                $reasonV = [string]($r.Stdout | ConvertFrom-Json).hookSpecificOutput.permissionDecisionReason
            }
            Assert-True ($reasonV -match 'mazání \.NET') ("[vypis/{0}] duvod jmenuje mazani .NET volanim" -f $vid)
        }
    }
}

# ================================================================================
#  REGRESNI INVARIANT (Amber, bod 2 kola 3)
#
#  Kazdy tvar, ktery kdy byl deny, jim ZUSTAVA - a kazdy tvar, ktery byl kdy
#  oznacen za falesny blok, zustava allow. Duvod je konkretni: v kole 1 jsem si
#  falesny blok (`git restore --staged .`) zafixovala testem, a v kole 2 oprava
#  jednoho nalezu (B4) rozbila jiny (C1). Sada, ktera roste jen o nove pripady,
#  tohle nechyti.
#
#  Soubor je APPEND-ONLY: radek z nej odchazi jen s citovanym rozhodnutim.
# ================================================================================

# Prehrani radku zije v _harness.ps1 - od kola 4 ho vola i sada secrets (nalez H2).
Invoke-InvariantRows 'gate'

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

# ------------------------------------------------- cesta na cizi jednotce ---

# Regrese po CI: hook dostava cwd cizi session i CLAUDE_PROJECT_DIR z prostredi.
# Kdyz jednotka neexistuje, Join-Path/Test-Path VYHODI vyjimku misto "neni" -
# a fail-closed pak zablokoval uplne vsechno, vcetne neskodnych prikazu.
Start-Case 'cwd i CLAUDE_PROJECT_DIR na neexistujici jednotce hook nesloz'
$missing = Get-MissingDrivePath
if ($null -eq $missing) {
    $script:Skip++
    Write-Host '    SKIP vsechna pismena jednotek jsou obsazena - pripad nema jak vzniknout' -ForegroundColor Yellow
} else {
    # (a) cesta prijde payloadem jako cwd
    $json = New-HookInput 'pretooluse-bash' @{ 'tool_input.command' = 'git reset --hard'; 'cwd' = $missing }
    $r = Invoke-Hook -Script 'gate.ps1' -InputJson $json
    Assert-Equal 'deny' (Get-Decision $r) '[cizi disk / cwd] destruktivni prikaz porad deny'

    # (b) cesta prijde prostredim
    $json = New-HookInput 'pretooluse-bash' @{ 'tool_input.command' = 'git status' }
    $r = Invoke-Hook -Script 'gate.ps1' -InputJson $json -Environment @{ CLAUDE_PROJECT_DIR = $missing }
    Assert-Equal 'allow' (Get-Decision $r) '[cizi disk / env] neskodny prikaz porad projde'
    Assert-Equal 0 $r.Exit '[cizi disk / env] exit 0, ne pad do fail-closed'

    # Kontrolni skupina: tataz cesta na EXISTUJICI jednotce se chova stejne -
    # jinak by test merl neco jineho nez chybejici disk.
    $existing = Join-Path $script:TempDir 'projekt-bez-override'
    [void][System.IO.Directory]::CreateDirectory($existing)
    $r = Invoke-Hook -Script 'gate.ps1' -InputJson $json -Environment @{ CLAUDE_PROJECT_DIR = $existing }
    Assert-Equal 'allow' (Get-Decision $r) '[kontrolni skupina] existujici disk bez override taky allow'
}

# --------------------------------------------------------- ASCII-only zdroj ---

Start-Case 'zdrojove .ps1 jsou ASCII-only (PS 5.1 cte bez BOM jako ANSI)'
foreach ($f in (Get-ChildItem (Join-Path $script:RepoRoot 'hooks/scripts') -Filter *.ps1)) {
    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
    $nonAscii = @($bytes | Where-Object { $_ -gt 127 }).Count
    Assert-Equal 0 $nonAscii ("[ascii] {0}" -f $f.Name)
}

# ================================================================================
#  J2: rezim sberu z PROSTREDI musi sadu shodit, ne ji tise vyprazdnit.
#  Meri se skutecnym procesem - tvrzeni je o tom, co udela CELA sada, ne o tom,
#  co vraci jedna funkce.
# ================================================================================

Start-Case 'SINOGARD_HOOKS_COLLECT z prostredi sadu SHODI (nalez Amber J2)'
$notifySuite = Join-Path $PSScriptRoot 'notify.tests.ps1'
$psiJ2 = New-Object System.Diagnostics.ProcessStartInfo
$psiJ2.FileName = $script:Interpreter
$psiJ2.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $notifySuite + '"'
$psiJ2.UseShellExecute = $false
$psiJ2.RedirectStandardOutput = $true
$psiJ2.RedirectStandardError = $true
$psiJ2.WorkingDirectory = $script:RepoRoot
$psiJ2.EnvironmentVariables['SINOGARD_HOOKS_COLLECT'] = '1'
$pJ2 = [System.Diagnostics.Process]::Start($psiJ2)
$outJ2 = $pJ2.StandardOutput.ReadToEnd()
[void]$pJ2.StandardError.ReadToEnd()
$pJ2.WaitForExit()
Assert-Equal 1 $pJ2.ExitCode '[J2] sada s COLLECT v prostredi konci nenulove'
Assert-True ($outJ2 -match 'SINOGARD_HOOKS_COLLECT') '[J2] duvod je v vystupu, ne jen v navratovem kodu'
Assert-True ($outJ2 -notmatch 'passed /') '[J2] souhrnny radek se NEVYPISE - jinak by verdikt cetl zelenou'

# 🔴 kontrolni skupina: tataz sada BEZ te promenne musi normalne dobehnout.
# Bez ni by tvrzeni vyse platilo i tehdy, kdyby sada padala vzdycky.
Start-Case 'kontrolni skupina k J2: bez promenne sada dobehne'
$psiJ2b = New-Object System.Diagnostics.ProcessStartInfo
$psiJ2b.FileName = $script:Interpreter
$psiJ2b.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $notifySuite + '"'
$psiJ2b.UseShellExecute = $false
$psiJ2b.RedirectStandardOutput = $true
$psiJ2b.RedirectStandardError = $true
$psiJ2b.WorkingDirectory = $script:RepoRoot
$psiJ2b.EnvironmentVariables['SINOGARD_HOOKS_COLLECT'] = ''
$pJ2b = [System.Diagnostics.Process]::Start($psiJ2b)
$outJ2b = $pJ2b.StandardOutput.ReadToEnd()
[void]$pJ2b.StandardError.ReadToEnd()
$pJ2b.WaitForExit()
Assert-Equal 0 $pJ2b.ExitCode '[J2/kontrola] bez promenne sada konci nulou'
Assert-True ($outJ2b -match 'passed /') '[J2/kontrola] souhrnny radek se vypise'

# Kontrolni skupina spousti CIZI sadu, takze jeji pad se sem promitne jako holy
# navratovy kod - a "cekano <0>, dostano <1>" nerekne, co se rozbilo. Vypis
# potomka proto pri padu jde do logu; jinak by se pricina hledala jen znovu-
# spustenim na CI, kde uz muze byt jina zatez.
if ($pJ2b.ExitCode -ne 0) {
    Write-Host '    --- vystup potomka (notify.tests.ps1) ---' -ForegroundColor Yellow
    foreach ($line in ($outJ2b -split "`r?`n")) {
        if ($line.Trim() -ne '') { Write-Host ("    | " + $line) -ForegroundColor Yellow }
    }
    Write-Host '    --- konec vystupu potomka ---' -ForegroundColor Yellow
}

# ================================================================================
#  OPAKOVANI PO PREKROCENI TVRDEHO STROPU (zmena mimo rozsah, vynucena CI)
#
#  Tvrdi se: beh, ktery strop prekroci, se JEDNOU zopakuje; tvrdi se druhe mereni,
#  ale do medianu jde mereni PRVNI. A kdyz je pomalost SKUTECNA (opakuje se), druhe
#  mereni je nad stropem taky - tedy cervena zustava cervenou.
# ================================================================================

if (-not (Test-CollectOnly)) {
    Start-Case 'opakovani po prekroceni stropu (kolo 5b)'
    $jsonRetry = New-HookInput 'pretooluse-bash' @{ 'tool_input.command' = 'git status' }

    # 🔴 kontrolni skupina NEJDRIV: pri normalnim stropu se neopakuje nic.
    $retriesBefore = Get-HookRetryCount
    $timesBefore = Get-HookTimeCount
    $rNorm = Invoke-Hook -Script 'gate.ps1' -InputJson $jsonRetry
    Assert-Equal $retriesBefore (Get-HookRetryCount) '[retry/kontrola] pod stropem se neopakuje'
    Assert-Equal ($timesBefore + 1) (Get-HookTimeCount) '[retry/kontrola] jedno mereni do medianu'
    Assert-True (-not $rNorm.PSObject.Properties['Retried']) '[retry/kontrola] vysledek neni znacen jako opakovany'

    # Strop se snizi pod skutecnou dobu behu, takze opakovani MUSI nastat.
    $ceiling = Get-HookCeilingMs
    try {
        Set-HookCeilingMs 1
        $retriesBefore = Get-HookRetryCount
        $timesBefore = Get-HookTimeCount
        $rSlow = Invoke-Hook -Script 'gate.ps1' -InputJson $jsonRetry
        Assert-Equal ($retriesBefore + 1) (Get-HookRetryCount) '[retry] nad stropem se opakuje prave jednou'
        Assert-Equal ($timesBefore + 1) (Get-HookTimeCount) '[retry] do medianu jde jen PRVNI mereni'
        Assert-True ([bool]$rSlow.PSObject.Properties['FirstMs']) '[retry] prvni mereni zustava k dispozici'
        # Pomalost je tu skutecna (strop = 1 ms), takze ani druhe mereni pod nej nejde -
        # tvrzeni sady by tedy dal padalo. Opakovani cervenou NEPRETIRA na zelenou.
        Assert-True ($rSlow.Ms -ge 1) '[retry] skutecna pomalost zustava nad stropem i podruhe'
        Assert-Equal 'allow' (Get-Decision $rSlow) '[retry] rozhodnuti se opakovanim nemeni'
    } finally {
        Set-HookCeilingMs $ceiling
    }
}

Write-CollectedCases
Assert-TimingBudget

Write-TestSummary
if ($script:Fail -gt 0) { exit 1 }
exit 0
