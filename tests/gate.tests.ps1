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
    # a Z3 dal plati: promenna v pozici prikazu (bez `=`) je porad nerozebratelna
    (Case 'B1 Z3 zustava'               '$tool build' 'ask' 'PowerShell')
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
    (Case 'B4 Math Truncate promenna'   '[Math]::Truncate($x)' 'ask' 'PowerShell')
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
    (Case 'C1 cat souboru do psql'      'cat drop.sql | psql -h db.firma.cz' 'ask')
    (Case 'C1 Get-Content do psql'      'Get-Content drop.sql | psql -h db.firma.cz' 'ask' 'PowerShell')
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
    (Case 'C4 psql -f souborem'         'psql -h db.firma.cz -f migrace.sql' 'ask')
    (Case 'C4 sqlcmd -i souborem'       'sqlcmd -S db.firma.cz -i migrace.sql' 'ask')
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
    # neukonceny heredoc: nevime, kde telo konci (Z3)
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
)

Test-Cases 'review Amber kolo 4 (G, H)' $amber4Cases

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

Start-Case 'regresni invariant (fixtures/invariants.json)'
$invPath = Join-Path $script:RepoRoot 'tests/fixtures/invariants.json'
if (-not (Test-SafePath $invPath)) {
    $script:Skip++
    Write-Host '    SKIP invariants.json chybi' -ForegroundColor Yellow
} else {
    $invDoc = [System.IO.File]::ReadAllText($invPath, ([System.Text.UTF8Encoding]::new($false))) | ConvertFrom-Json
    $rowsProp = $invDoc.PSObject.Properties['rows']
    $inv = if ($null -eq $rowsProp) { @() } else { @($rowsProp.Value) }
    Assert-True ($inv.Count -ge 100) ("invariantu je {0} (ceka se aspon 100)" -f $inv.Count)
    foreach ($row in $inv) {
        $fx = if ($row.tool -eq 'PowerShell') { 'pretooluse-powershell' } else { 'pretooluse-bash' }
        $json = New-HookInput $fx @{ 'tool_input.command' = $row.cmd }
        $r = Invoke-Hook -Script 'gate.ps1' -InputJson $json
        Assert-Equal $row.expect (Get-Decision $r) ("[invariant/{0}] {1}" -f $row.since, $row.cmd)
    }
}

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

Assert-TimingBudget

Write-TestSummary
if ($script:Fail -gt 0) { exit 1 }
exit 0
