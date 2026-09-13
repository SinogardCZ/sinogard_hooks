#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Testy secrets guardu (hooks/scripts/secrets.ps1).

.DESCRIPTION
  Tyz sev jako u gate: skript jako celek, vstup na stdin, ven navratovy kod
  a stdout JSON.

  Pripad `web/.env.development` je zamerne MERENI, ne konstanta: vysledek zavisi
  na tom, jestli je soubor v GSD repu skutecne trackovany gitem. Kdyz repo na
  stroji neni, pripad se PRESKOCI (skipped), ne zezelena podvodem.

.EXAMPLE
  pwsh -NoProfile -File tests/secrets.tests.ps1
#>
param(
    [switch]$Full,
    [switch]$Collect,
    [string]$Interpreter = 'powershell.exe',
    [string]$GsdRepo = 'W:/dev/gsd/repo'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot '_harness.ps1')
$script:Interpreter = $Interpreter
Assert-NoCollectEnv
Set-CollectMode ([bool]$Collect)

if ($Full) {
    Write-Host ""
    Write-Host "secrets.ps1 - ochrana souboru se secrets   (interpret: $Interpreter)" -ForegroundColor Yellow
}

function PathCase([string]$Name, [string]$Path, [string]$Expect, [string]$Tool = 'Read') {
    return [pscustomobject]@{ Name = $Name; Value = $Path; Expect = $Expect; Tool = $Tool; Kind = 'path' }
}
function CmdCase([string]$Name, [string]$Cmd, [string]$Expect, [string]$Tool = 'Bash') {
    return [pscustomobject]@{ Name = $Name; Value = $Cmd; Expect = $Expect; Tool = $Tool; Kind = 'cmd' }
}

# ------------------------------------------------- deny: cesty se secrets ---

$denyPaths = @(
    (PathCase 'env'                 '.env' 'deny')
    (PathCase 'env.local'           '.env.local' 'deny')
    (PathCase 'env.prod.local'      '.env.production.local' 'deny')
    (PathCase 'envrc'               '.envrc' 'deny')
    (PathCase 'pem'                 'certs/server.pem' 'deny')
    (PathCase 'key'                 'certs/server.key' 'deny')
    (PathCase 'pfx'                 'certs/server.pfx' 'deny')
    (PathCase 'p12'                 'certs/server.p12' 'deny')
    (PathCase 'jks'                 'certs/store.jks' 'deny')
    (PathCase 'ppk'                 'certs/putty.ppk' 'deny')
    (PathCase 'asc'                 'keys/key.asc' 'deny')
    (PathCase 'gpg'                 'keys/key.gpg' 'deny')
    (PathCase 'id_rsa'              'C:/Users/tomas/.ssh/id_rsa' 'deny')
    (PathCase 'id_ed25519.pub'      'C:/Users/tomas/.ssh/id_ed25519.pub' 'deny')
    (PathCase 'ssh slozka'          'C:/Users/tomas/.ssh/config' 'deny')
    (PathCase 'usersecrets'         'C:/Users/tomas/AppData/Roaming/Microsoft/UserSecrets/abc/secrets.json' 'deny')
    (PathCase 'secrets.json'        'src/secrets.json' 'deny')
    (PathCase 'secrets.yaml'        'deploy/secrets.yaml' 'deny')
    (PathCase 'secrets.toml'        'deploy/secrets.toml' 'deny')
    (PathCase 'dot secrets.json'    'src/app.secrets.json' 'deny')
    (PathCase 'pubxml'              'Properties/PublishProfiles/prod.pubxml' 'deny')
    (PathCase 'publishsettings'     'deploy/prod.publishsettings' 'deny')
    (PathCase 'npmrc'               'C:/Users/tomas/.npmrc' 'deny')
    (PathCase 'pypirc'              'C:/Users/tomas/.pypirc' 'deny')
    (PathCase 'netrc'               'C:/Users/tomas/.netrc' 'deny')
    (PathCase 'git-credentials'     'C:/Users/tomas/.git-credentials' 'deny')
    (PathCase 'aws credentials'     'C:/Users/tomas/.aws/credentials' 'deny')
    (PathCase 'azure'               'C:/Users/tomas/.azure/azureProfile.json' 'deny')
    (PathCase 'kube config'         'C:/Users/tomas/.kube/config' 'deny')
    (PathCase 'docker config'       'C:/Users/tomas/.docker/config.json' 'deny')
    # zpetna lomitka a promenne prostredi
    (PathCase 'zpetna lomitka'      'C:\Users\tomas\.ssh\id_rsa' 'deny')
    (PathCase 'APPDATA promenna'    '%APPDATA%\Microsoft\UserSecrets\abc\secrets.json' 'deny')
    (PathCase 'tilda'               '~/.aws/credentials' 'deny')
    # tyz vzor pres zapisove nastroje
    (PathCase 'zapis .env'          '.env' 'deny' 'Write')
    (PathCase 'edit .env'           '.env' 'deny' 'Edit')
)

# ------------------------------------------------------------ allow: cesty ---

$allowPaths = @(
    (PathCase 'env.example'         '.env.example' 'allow')
    (PathCase 'env.sample'          '.env.sample' 'allow')
    (PathCase 'env.template'        '.env.template' 'allow')
    (PathCase 'appsettings'         'src/Gsd.Api/appsettings.json' 'allow')
    (PathCase 'appsettings.Dev'     'src/Gsd.Api/appsettings.Development.json' 'allow')
    (PathCase 'bezny soubor'        'src/Gsd.Domain/Record.cs' 'allow')
    (PathCase 'cesta s ceskym nazvem' 'docs/logs/session/hlášení-01.md' 'allow')
)

# ------------------------------------------------------------- ask: cesty ---

$askPaths = @(
    (PathCase 'settings.local.json' '.claude/settings.local.json' 'ask')
    (PathCase 'netrackovany env'    '.env.staging' 'ask')
)

# ------------------------------------------ ask: sebeochrana (T36-N6 (5)) ---

$selfProtect = @(
    (PathCase 'zapis settings.json'      '.claude/settings.json' 'ask' 'Write')
    (PathCase 'edit settings.json'       '.claude/settings.json' 'ask' 'Edit')
    (PathCase 'zapis sinogard-hooks'     '.claude/sinogard-hooks.json' 'ask' 'Write')
    (PathCase 'edit hooks.json'          'hooks/hooks.json' 'ask' 'Edit')
    (PathCase 'edit config pluginu'      'hooks/config/defaults.json' 'ask' 'Edit')
    # cteni settings.json neni sebeochrana - jen zapis
    (PathCase 'cteni settings.json'      '.claude/settings.json' 'allow' 'Read')
)

# ------------------------------------------------------ prikazy nad secrets ---

$denyCommands = @(
    (CmdCase 'cat .env'              'cat .env' 'deny')
    (CmdCase 'type .env'             'type C:\x\.env' 'deny' 'PowerShell')
    (CmdCase 'Get-Content .env.local' 'Get-Content .\.env.local' 'deny' 'PowerShell')
    (CmdCase 'gc .env'               'gc .env' 'deny' 'PowerShell')
    (CmdCase 'Select-String -Path'   'Select-String -Path .env -Pattern KEY' 'deny' 'PowerShell')
    (CmdCase 'findstr'               'findstr KEY .env' 'deny')
    (CmdCase 'grep'                  'grep KEY .env' 'deny')
    (CmdCase 'head'                  'head -5 .env' 'deny')
    (CmdCase 'tail'                  'tail -5 .env' 'deny')
    (CmdCase 'less'                  'less .env' 'deny')
    (CmdCase 'more'                  'more .env' 'deny')
    (CmdCase 'git show'              'git show HEAD:.env' 'deny')
    (CmdCase 'cp'                    'cp .env /tmp/x' 'deny')
    (CmdCase 'Copy-Item'             'Copy-Item .env C:\tmp\x' 'deny' 'PowerShell')
    (CmdCase 'Compress-Archive'      'Compress-Archive -Path .env -DestinationPath x.zip' 'deny' 'PowerShell')
    (CmdCase 'presmerovani vstupu'   'openssl < .env' 'deny')
    (CmdCase 'presmerovani vystupu'  'echo x > .env' 'deny')
    (CmdCase 'presmerovani append'   'echo x >> .env' 'deny')
    (CmdCase 'cat id_rsa'            'cat ~/.ssh/id_rsa' 'deny')
    (CmdCase 'cat aws'               'cat ~/.aws/credentials' 'deny')
    # ----- nalezy councilu Metis (2026-09-05) -----
    (CmdCase 'M2 hole jmeno id_rsa'  'Get-Content id_rsa' 'deny' 'PowerShell')
    (CmdCase 'M2 hole jmeno pem'     'cat private.pem' 'deny')
    (CmdCase 'M2 hole jmeno p12'     'cat client.p12' 'deny')
    (CmdCase 'M22 presmerovani bez mezery' 'cat<.env' 'deny')
    (CmdCase 'M23 IO.File literal'   "[IO.File]::ReadAllText('.env')" 'deny' 'PowerShell')
    (CmdCase 'M24 python open'       'python -c "print(open(''.env'').read())"' 'deny')
    # Nalez councilu Metis 2026-09-05: -Path:.env je token zacinajici pomlckou,
    # takze bez rozpadu na jmeno a hodnotu by cesta z kontroly vypadla.
    (CmdCase 'Get-Content -Path:.env' 'Get-Content -Path:.env' 'deny' 'PowerShell')
    (CmdCase 'gc -LiteralPath:.env'  'gc -LiteralPath:.env' 'deny' 'PowerShell')
    (CmdCase 'Select-String dvojtecka' 'Select-String -Path:.env -Pattern:KEY' 'deny' 'PowerShell')
)

$askCommands = @(
    (CmdCase 'printenv'              'printenv' 'ask')
    (CmdCase 'hole env'              'env' 'ask')
    (CmdCase 'hole set'              'set' 'ask' 'PowerShell')
    (CmdCase 'Get-ChildItem env:'    'Get-ChildItem env:' 'ask' 'PowerShell')
    (CmdCase 'gci env:'              'gci env:' 'ask' 'PowerShell')
    (CmdCase 'dir env:'              'dir env:' 'ask' 'PowerShell')
    (CmdCase 'ls env:'               'ls env:' 'ask' 'PowerShell')
    # Nalez councilu Metis 2026-09-05: vypis prostredi jde i pres Get-Content.
    (CmdCase 'Get-Content Env:*'     'Get-Content Env:*' 'ask' 'PowerShell')
    (CmdCase 'gc env:*'              'gc env:*' 'ask' 'PowerShell')
    (CmdCase 'cat env:'              'cat env:' 'ask' 'PowerShell')
    (CmdCase 'echo $env:KEY'         'echo $env:NVIDIA_API_KEY' 'ask' 'PowerShell')
    (CmdCase 'bash $KEY'             'echo $NVIDIA_API_KEY' 'ask')
    (CmdCase 'GetEnvironmentVariable' '[Environment]::GetEnvironmentVariable("GITHUB_TOKEN")' 'ask' 'PowerShell')
    (CmdCase 'Get-Item env:TOKEN'    'Get-Item env:GITHUB_TOKEN' 'ask' 'PowerShell')
    (CmdCase 'PASSWORD promenna'     'echo $DB_PASSWORD' 'ask')
    (CmdCase 'CREDENTIAL promenna'   'echo $env:AZURE_CREDENTIAL' 'ask' 'PowerShell')
    (CmdCase 'cteni settings.local'  'cat .claude/settings.local.json' 'ask')
    # M21 (glob, ktery MUZE padnout na chranene jmeno): do 0.1.11 `ask`. Od 0.2.0 (TASK-106
    # bod 11, vyroky 7 + 8 Amber 2026-09-12 v mandatu Toma) je jmenna trida u globu `audit`
    # (zapise se, mlci) - pripady stoji v $allowCommands; glob na chranenou CESTU se pta dal.
)

$allowCommands = @(
    (CmdCase 'echo PATH'             'echo $env:PATH' 'allow' 'PowerShell')
    (CmdCase 'echo HOME'             'echo $HOME' 'allow')
    (CmdCase 'env s prirazenim'      'env FOO=1 npm test' 'allow')
    (CmdCase 'cat .env.sample'       'cat .env.sample' 'allow')
    (CmdCase 'cat appsettings'       'cat src/Gsd.Api/appsettings.Development.json' 'allow')
    (CmdCase 'git status'            'git status --porcelain' 'allow')
    (CmdCase 'cat bezny soubor'      'cat README.md' 'allow')
    # Kontrolni skupina k M21: bezny glob se ptat NESMI, jinak se brana do tydne vypne.
    (CmdCase 'M21 glob md'           'ls *.md' 'allow')
    (CmdCase 'M21 glob ts'           'grep neco src/*.ts' 'allow')
    (CmdCase 'M2 bezne jmeno'        'cat Program.cs' 'allow')
    # M21: glob na chranene JMENO od 0.2.0 mlci a zapise audit (TASK-106 bod 11, vyroky 7 + 8);
    # doklad auditu je v sekci "TASK-106 D2". Radek invariantu prosel `-Prijmout` s citaci.
    (CmdCase 'M21 glob .en?'         'Get-Content .en?' 'allow' 'PowerShell')
    (CmdCase 'M21 glob hvezdicka'    'cat *' 'allow')
)

# ------------------------------------------------------------- vyhodnoceni ---

function Test-Cases([string]$Section, $Cases) {
    Start-Case $Section
    foreach ($c in $Cases) {
        # Nalez Amber H2: invariant se od kola 4 tyka i teto sady. Generator bere
        # pripady odsud, ne rucnim vyberem.
        Add-CollectedCase 'secrets' $c.Kind $c.Tool $c.Value $c.Expect $c.Name
        if (Test-CollectOnly) { continue }

        if ($c.Kind -eq 'path') {
            $template = switch ($c.Tool) {
                'Write' { 'pretooluse-write' }
                'Edit'  { 'pretooluse-edit' }
                default { 'pretooluse-read' }
            }
            $json = New-HookInput $template @{ 'tool_input.file_path' = $c.Value }
        } else {
            $template = if ($c.Tool -eq 'PowerShell') { 'pretooluse-powershell' } else { 'pretooluse-bash' }
            $json = New-HookInput $template @{ 'tool_input.command' = $c.Value }
        }
        $r = Invoke-Hook -Script 'secrets.ps1' -InputJson $json
        Assert-Equal $c.Expect (Get-Decision $r) ("[{0}] {1}" -f $c.Name, $c.Value)
        $expectedExit = if ($c.Expect -eq 'deny') { 2 } else { 0 }
        Assert-Equal $expectedExit $r.Exit ("[{0}] exit" -f $c.Name)
        Assert-True ($r.Ms -lt (Get-HookCeilingMs)) ("[{0}] doba {1} ms < {2}" -f $c.Name, $r.Ms, (Get-HookCeilingMs))
    }
}

Test-Cases 'deny - cesty se secrets' $denyPaths
Test-Cases 'allow - bezne soubory a vyjimky' $allowPaths
Test-Cases 'ask - seda zona cest' $askPaths
Test-Cases 'ask - sebeochrana brany (T36-N6 (5))' $selfProtect
Test-Cases 'deny - prikazy ctouci secrets (T36-N7)' $denyCommands
Test-Cases 'ask - prostredi a promenne (T36-N7)' $askCommands
Test-Cases 'allow - prikazy bez secrets' $allowCommands

# ================================================================================
#  Nalezy review Amber 2026-09-05 - osa 2 (falesne bloky na bezne praci).
#  Kazdy ma kontrolni skupinu: tvar, ktery se dal chytit MUSI.
# ================================================================================

$amberSecretCases = @(
    # --- B2: vzor jmen promennych byl neukotveny a bral kus slova. ---
    (CmdCase 'B2 PWD je adresar'      'echo $PWD' 'allow' 'PowerShell')
    (CmdCase 'B2 keys'                'echo $keys' 'allow' 'PowerShell')
    (CmdCase 'B2 tokens'              'echo $tokens' 'allow' 'PowerShell')
    (CmdCase 'B2 keyFile'             'Get-Content $keyFile' 'allow' 'PowerShell')
    (CmdCase 'B2 monkey'              'echo $monkey' 'allow' 'PowerShell')
    # kontrolni skupina: skutecne citlive jmeno se chytit MUSI
    (CmdCase 'B2 kontrola API_KEY'    'echo $env:API_KEY' 'ask' 'PowerShell')
    (CmdCase 'B2 kontrola DB_PWD'     'echo $env:DB_PWD' 'ask' 'PowerShell')
    (CmdCase 'B2 kontrola SECRET'     'echo $env:CLIENT_SECRET' 'ask' 'PowerShell')
    (CmdCase 'B2 kontrola TOKEN'      'echo $env:GITHUB_TOKEN' 'ask' 'PowerShell')

    # --- B3: kanonicka jmena `config.json`, `config`, `credentials` odesla. ---
    (CmdCase 'B3 glob config hvezda'  'ls config*' 'allow')
    (CmdCase 'B3 cat config.json'     'cat config.json' 'allow')
    # kontrolni skupina: chranene JE az s adresarem
    (CmdCase 'B3 kontrola docker'     'cat .docker/config.json' 'deny')
    (CmdCase 'B3 kontrola kube'       'cat .kube/config' 'deny')
    (CmdCase 'B3 kontrola aws'        'cat .aws/credentials' 'deny')
)

Test-Cases 'review Amber - osa 2' $amberSecretCases

# ================================================================================
#  Review Amber kolo 2: C6 (falesna negativa po ukotveni B2) a C3 (`credentials`).
# ================================================================================

$amber2SecretCases = @(
    # --- C6: ukotveni B2 zavedlo falesna NEGATIVA (propoustelo citliva jmena) ---
    (CmdCase 'C6 API_KEYS'            'echo $env:API_KEYS' 'ask' 'PowerShell')
    (CmdCase 'C6 AZURE_CREDENTIALS'   'echo $env:AZURE_CREDENTIALS' 'ask' 'PowerShell')
    (CmdCase 'C6 DB_PASSWD'           'echo $env:DB_PASSWD' 'ask' 'PowerShell')
    (CmdCase 'C6 camelCase apiKey'    'echo $env:apiKey' 'ask' 'PowerShell')
    (CmdCase 'C6 camelCase secretKey' 'echo $secretKey' 'ask' 'PowerShell')
    (CmdCase 'C6 TOKENS'              'echo $env:GITHUB_TOKENS' 'ask' 'PowerShell')
    # 🔴 kontrolni skupina - tohle musi ZUSTAT allow, jinak jsem si vyrobila zpatky B2
    (CmdCase 'C6 kontrola PWD'        'echo $PWD' 'allow' 'PowerShell')
    (CmdCase 'C6 kontrola keys'       'echo $keys' 'allow' 'PowerShell')
    (CmdCase 'C6 kontrola tokens'     'echo $tokens' 'allow' 'PowerShell')
    (CmdCase 'C6 kontrola keyFile'    'Get-Content $keyFile' 'allow' 'PowerShell')
    (CmdCase 'C6 kontrola Path'       'echo $env:Path' 'allow' 'PowerShell')
    (CmdCase 'C6 kontrola USERPROFILE' 'echo $env:USERPROFILE' 'allow' 'PowerShell')

    # --- C3: `credentials` zustalo v kanonickych jmenech, ac dokumentace tvrdila opak ---
    (CmdCase 'C3 glob cred'           'ls cred*' 'allow')
    (CmdCase 'C3 cat credentials'     'cat credentials' 'allow')
    # kontrolni skupina: s adresarem se chytit MUSI
    (CmdCase 'C3 kontrola aws'        'cat .aws/credentials' 'deny')
)

Test-Cases 'review Amber kolo 2 (C3, C6)' $amber2SecretCases

# ================================================================================
#  Review Amber kolo 4: H1 - oprava E5 (dva vzory, dva rezimy velikosti pismen)
#  nemela ANI JEDEN test na male podtrzitkove jmeno. Merilo se jen VELKE
#  (GITHUB_TOKEN) a camelCase (apiKey), takze prave ta cast opravy, kvuli ktere
#  je vzor s IgnoreCase, nebyla dolozena nicim.
# ================================================================================

$amber4SecretCases = @(
    (CmdCase 'H1 db_password'         'echo $db_password' 'ask' 'PowerShell')
    (CmdCase 'H1 env:github_token'    'echo $env:github_token' 'ask' 'PowerShell')
    (CmdCase 'H1 api_key'             'echo $api_key' 'ask' 'PowerShell')
    (CmdCase 'H1 Mixed_Secret_Key'    'echo $env:Mixed_Secret_Key' 'ask' 'PowerShell')
    # 🔴 kontrolni skupina: podtrzitkove jmeno, ktere citlive NENI. Kdyby se vzor
    #    rozsiril na "cokoli s podtrzitkem", zustalo by tohle allow uz jen nahodou.
    (CmdCase 'H1 kontrola db_port'    'echo $db_port' 'allow' 'PowerShell')
    (CmdCase 'H1 kontrola build_num'  'echo $env:build_number' 'allow' 'PowerShell')
    (CmdCase 'H1 kontrola user_name'  'echo $user_name' 'allow' 'PowerShell')
)

Test-Cases 'review Amber kolo 4 (H1)' $amber4SecretCases

# ================================================================================
#  NALEZ N26 (Tom, ziva ukazka z konzole, 2026-09-07)
#
#  Glob se vyhodnocoval nad KAZDYM kandidatem - i nad textem, ktery zadna cesta
#  neni. `git commit -m "**2**"` dalo glob `**2**`, ten sedne na `server.p12`
#  a hook se zeptal na COMMIT MESSAGE. V Bashi se `*` v uvozovkach nerozvine
#  a v PowerShellu retezec negloboval nikdy.
#
#  Nove: glob jen nad NEUVOZENYM tokenem v pozici cesty u prikazu, ktery soubory
#  cte nebo kopiruje.
# ================================================================================

$n26SecretCases = @(
    (CmdCase 'N26 markdown v commitu'   'git commit -m "**2**"' 'allow')
    (CmdCase 'N26 markdown s textem'    'git commit -m "**2 opravy**"' 'allow')
    (CmdCase 'N26 markdown uprostred'   'git commit -m "fix **2**: nalez"' 'allow')
    (CmdCase 'N26 echo neuvozene'       'echo **2**' 'allow')
    (CmdCase 'N26 echo hvezdicka'       'echo "a*b"' 'allow')
    (CmdCase 'N26 Write-Host'           'Write-Host "**2**"' 'allow' 'PowerShell')
    (CmdCase 'N26 grep vzor'            'grep "x*" src/a.cs' 'allow')
    # 🔴 kontrolni skupina: glob v pozici CESTY u cteciho prikazu se vyhodnocuje dal.
    #    Do 0.1.11 tu stalo `ask` - glob se srovnaval jen se JMENEM (`protectedBaseNames`).
    #    Od 0.2.0 (TASK-106 bod 11, vyroky 7 + 8 Amber 2026-09-12 v mandatu Toma) je trida
    #    chranena JMENEM u globu `audit` (zapise se, mlci), trida chranena CESTOU zustava
    #    `ask` - viz sekce "TASK-106 D2" nize, kde je i doklad auditu. Radek invariantu
    #    prosel `-Prijmout` s touto citaci.
    # 🔴 C1 (delta review Amber 2026-09-13): `*.env` MIRI na secret vzorem (jmeno globu sedne na
    #    `envFile.denyNames`) - zustava ask jako `*.pem`. Prvni tvar 0.2.0 ho poslal do auditu = regrese.
    (CmdCase 'N26 kontrola cat glob'    'cat *.env' 'ask')
    #    `.en?` (zastupny znak UVNITR jmena) deterministicky rozlisit nejde - pojmenovana mez (README 9), audit.
    (CmdCase 'N26 kontrola Get-Content' 'Get-Content .en?' 'allow' 'PowerShell')
    # `*.pem` sedne DOSLOVA na vzor `denyPathPatterns` (pripona) -> trida chranena VZOREM cesty, ask dal
    (CmdCase 'N26 kontrola cp glob'     'cp *.pem /tmp/x' 'ask')
    (CmdCase 'N26 kontrola glob na chranenou CESTU' 'cat ~/.aws/*' 'ask')
    # 🔴 a presne jmeno se pta dal bez ohledu na uvozovky
    (CmdCase 'N26 kontrola presne jmeno' 'cat .env' 'deny')
    (CmdCase 'N26 kontrola literal'      '[IO.File]::ReadAllText(''.env'')' 'deny' 'PowerShell')
)

Test-Cases 'nalez N26 - glob jen v pozici cesty' $n26SecretCases

# ================================================================================
#  v0.2.0 - TASK-106 faze 2, davka D2 (secrets.ps1): bod 9 + N-H3, bod 11, bod 12
#  + N-H1 + N-H2 + N-H4, N-H6 (druhy nositel). Vyroky Amber 2026-09-12 (mandat Toma).
#
#  🔴 Kazdy pripad jmenuje mutanta a ma kontrolni skupinu v JINEM stavu (zadani §7).
# ================================================================================

# --- bod 9 + N-H3: `isWrite` byl JEDEN priznak na cely prikaz (`secrets.ps1` ř. 273 v 0.1.11):
#     `cat ~/.claude/settings.json 2>/dev/null` melo `>` v `2>/dev/null`, takze CTENI skoncilo
#     jako "zapis do souboru, kterym se brana vypina" (2x ve vzorku faze 1). Od 0.2.0 je zapis
#     vlastnost KANDIDATA: cil presmerovani `>`/`>>` (vcetne `2> soubor`), argument zapisoveho
#     prikazu (`tee`, `Set-Content`, `Out-File`, `Add-Content`); vse ostatni je cteni.
#     Mutant (N-H3): vratit jeden priznak na prikaz -> `cat ... 2>/dev/null` zcervena.
#     Mutant (bod 9): zamenit texty cteni<->zapis -> parova kontrola nize zcervena.
$bod9Cases = @(
    (CmdCase 'NH3 cteni settings.json s 2>/dev/null'  'cat ~/.claude/settings.json 2>/dev/null | head -80' 'allow')
    (CmdCase 'NH3 cteni settings.json s 2>&1'         'cat .claude/settings.json 2>&1' 'allow')
    (CmdCase 'NH3 git checkout -- s 2>&1'             'git checkout -- .claude/settings.json 2>&1; git status --porcelain' 'allow')
    (CmdCase 'NH3 cteni defaults.json s 2>/dev/null'  'cat hooks/config/defaults.json 2>/dev/null' 'allow')
    # 🔴 kontrolni skupina: SKUTECNY zapis do souboru brany se pta dal
    (CmdCase 'NH3 kontrola presmerovani do settings'  'git show HEAD:.claude/settings.json > .claude/settings.json' 'ask')
    (CmdCase 'NH3 kontrola append do settings'        'echo x >> .claude/settings.json' 'ask')
    (CmdCase 'NH3 kontrola tee do settings'           'cat x | tee .claude/settings.json' 'ask')
    (CmdCase 'NH3 kontrola Set-Content'               'Set-Content -Path .claude/sinogard-hooks.json -Value x' 'ask' 'PowerShell')
    (CmdCase 'NH3 kontrola Out-File'                  '$j | Out-File hooks/hooks.json' 'ask' 'PowerShell')
    (CmdCase 'NH3 kontrola 2> do souboru brany'       'dotnet build 2> .claude/settings.json' 'ask')
    # 🔴 a `deny` trida se s presmerovanim nemeni (cteni i zapis .env je deny)
    (CmdCase 'NH3 kontrola cteni .env s 2>/dev/null'  'grep -i port .env 2>/dev/null | head' 'deny')
)

Test-Cases 'TASK-106 D2 - bod 9 / N-H3: zapis je vlastnost kandidata' $bod9Cases

function Get-SecretsReason($Result) {
    if ([string]::IsNullOrWhiteSpace($Result.Stdout)) { return '' }
    return [string]($Result.Stdout | ConvertFrom-Json).hookSpecificOutput.permissionDecisionReason
}
$cfgD2 = [System.IO.File]::ReadAllText(
    (Join-Path $script:RepoRoot 'hooks/config/defaults.json'), ([System.Text.UTF8Encoding]::new($false))) | ConvertFrom-Json
$textRead  = [string]$cfgD2.secrets.shapes.settingsLocal
$textWrite = [string]$cfgD2.secrets.shapes.selfProtect -replace '\{path\}', '.claude/settings.local.json'

Start-Case 'bod 9 (TASK-106): TYZ soubor, jednou cteni a jednou zapis - obe ask, texty ruzne'
$r9r = Invoke-Hook -Script 'secrets.ps1' -InputJson (New-HookInput 'pretooluse-bash' @{ 'tool_input.command' = 'cat .claude/settings.local.json 2>/dev/null' })
$r9w = Invoke-Hook -Script 'secrets.ps1' -InputJson (New-HookInput 'pretooluse-bash' @{ 'tool_input.command' = 'echo x > .claude/settings.local.json' })
Assert-Equal 'ask' (Get-Decision $r9r) '[bod9/cteni] cat settings.local.json 2>/dev/null je ask'
Assert-Equal 'ask' (Get-Decision $r9w) '[bod9/zapis] echo x > settings.local.json je ask'
$reason9r = Get-SecretsReason $r9r
$reason9w = Get-SecretsReason $r9w
Assert-True ($reason9r.Contains($textRead))  ("[bod9/cteni] duvod jmenuje CTENI: {0}" -f $reason9r)
Assert-True (-not $reason9r.Contains($textWrite)) '[bod9/cteni] duvod NEMLUVI o zapisu'
Assert-True ($reason9w.Contains($textWrite)) ("[bod9/zapis] duvod jmenuje ZAPIS: {0}" -f $reason9w)
Assert-True (-not $reason9w.Contains($textRead)) '[bod9/zapis] duvod NEMLUVI o cteni'
Assert-True ($reason9r -ne $reason9w) '[bod9] texty se lisi (jinak by par nic nemeril)'

# --- bod 11 (N16, vyrok 8 Amber = navrh Hestie prijat): glob se posuzuje podle CELE
#     normalizovane cesty, ne jen podle jmena. `*` a `?` neprekracuji `/`, `**` ano, kotvi se na
#     hranici adresare. Trida chranena JMENEM (`protectedBaseNames`) u globu -> `audit`
#     (vyrok 7: zapise se, mlci); trida chranena CESTOU (`denyPathPatterns`, kanonicke
#     `protectedPaths`) -> `ask` dal. Ve vzorku faze 1: `head -25 .github/workflows/*.yml`
#     a `ls docs/technical/*.json` = 2 falesne dotazy (`*.yml` sedlo na `secrets.yml`).
#     Mutant: vratit `Get-BaseName` (glob jen nad jmenem) -> `allow` radky zcervenaji.
$bod11Cases = @(
    (CmdCase 'B11 glob yml v adresari (vzorek)'       'head -25 .github/workflows/*.yml' 'allow')
    (CmdCase 'B11 glob json v adresari (vzorek)'      'ls docs/technical/*.json' 'allow')
    (CmdCase 'B11 kontrola ①: *.txt v tomtez adresari' 'cat .github/workflows/*.txt' 'allow')
    (CmdCase 'B11 Get-Content glob yml'               'Get-Content config/*.yml' 'allow' 'PowerShell')
    (CmdCase 'B11 glob bez adresare (jmenna trida)'   'cat *' 'allow')
    # 🔴 kontrolni skupina ②: glob MIRICI na cestu z `denyPathPatterns` zustava ask
    (CmdCase 'B11 kontrola ② ~/.aws/*'                'cat ~/.aws/*' 'ask')
    (CmdCase 'B11 kontrola ② .docker/*.json'          'cat .docker/*.json' 'ask')
    (CmdCase 'B11 kontrola ② ~/.ssh/*'                'ls ~/.ssh/*' 'ask')
    (CmdCase 'B11 kontrola ② ~/.kube/*'               'Get-Content ~/.kube/*' 'ask' 'PowerShell')
    (CmdCase 'B11 kontrola ② .claude/*'               'cat .claude/*' 'ask')
    (CmdCase 'B11 kontrola ② **/credentials'          'cat **/credentials' 'ask')
    (CmdCase 'B11 kontrola ② UserSecrets/*/secrets.json' 'cat ~/AppData/Roaming/Microsoft/UserSecrets/*/secrets.json' 'ask')
    # 🔴 presne jmeno v tomtez adresari je deny dal - mez je jen u globu
    (CmdCase 'B11 kontrola presne jmeno v adresari'   'cat .github/workflows/secrets.yml' 'deny')
    # 🔴 C1 (delta review Amber 2026-09-13): glob, ktery na secret MIRI VZOREM, je ask - jmeno globu
    #    sedne na `envFile.denyNames` nebo glob bez zastupnych znaku vypisuje chranene jmeno. Mutant:
    #    vratit Test-GlobAimsAtProtectedPath bez (c)+(d) -> `cat *.env` allow -> cervena.
    (CmdCase 'C1 cat *.env'                           'cat *.env' 'ask')
    (CmdCase 'C1 cat .env*'                           'cat .env*' 'ask')
    (CmdCase 'C1 cat *.env.local'                     'cat *.env.local' 'ask')
    (CmdCase 'C1 cat *secrets.json'                   'cat *secrets.json' 'ask')
    (CmdCase 'C1 Get-Content src/*.env'               'Get-Content src/*.env' 'ask' 'PowerShell')
    #    kontrolni skupina C1: glob, ktery na jmeno narazi NAHODOU, mlci dal (pripad vyroku 7)
    (CmdCase 'C1 kontrola *.yml v adresari'           'head .github/workflows/*.yml' 'allow')
    (CmdCase 'C1 kontrola *.json'                     'ls docs/technical/*.json' 'allow')
    (CmdCase 'C1 kontrola *.md'                       'ls *.md' 'allow')
    # ③ N26 kontrolni skupina (git commit -m "**2**", echo **2**, Write-Host "**2**") je v sekci N26 vyse.
)

Test-Cases 'TASK-106 D2 - bod 11: glob nad celou cestou' $bod11Cases

# 🔴 Vyrok 7 (N26): trida chranena jmenem u globu MLCI a ZAPISE se do auditu - ne ticho bez
#    stopy. Doklad = radek `secrets:wildcardName` v gate-audit.jsonl. Kontrolni skupina:
#    glob, na ktery zadne chranene jmeno nesedne, radek NEZAPISE; glob na chranenou CESTU
#    se pta a radek taky nezapise (dotaz je stopa sam o sobe).
function Test-SecretsAudit([string]$Name, [string]$Cmd, [string]$Expect, [bool]$RowExpected) {
    $dir = Join-Path $script:TempDir ('audit-sec-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
    $path = Join-Path $dir 'gate-audit.jsonl'
    $json = New-HookInput 'pretooluse-bash' @{ 'tool_input.command' = $Cmd }
    $r = Invoke-Hook -Script 'secrets.ps1' -InputJson $json -Environment @{ 'CLAUDE_PLUGIN_DATA' = $dir }
    Assert-Equal $Expect (Get-Decision $r) ("[audit/{0}] {1}" -f $Name, $Cmd)
    if ($RowExpected) {
        Assert-True ([System.IO.File]::Exists($path)) ("[audit/{0}] radek auditu vznikl" -f $Name)
        if ([System.IO.File]::Exists($path)) {
            $line = [System.IO.File]::ReadAllText($path, ([System.Text.UTF8Encoding]::new($false)))
            Assert-True ($line -match '"shape":"secrets:wildcardName"') ("[audit/{0}] tvar je secrets:wildcardName" -f $Name)
            Assert-True ($line -match '"decision":"allow"') ("[audit/{0}] rozhodnuti allow (= mlci)" -f $Name)
        }
    } else {
        Assert-True (-not [System.IO.File]::Exists($path)) ("[audit/{0}] radek auditu NEVZNIKL" -f $Name)
    }
}

Start-Case 'vyrok 7 (N26): jmenna trida u globu zapise audit a mlci; ostatni radek nezapisou'
Test-SecretsAudit 'jmenna trida yml'   'head -25 .github/workflows/*.yml' 'allow' $true
Test-SecretsAudit 'jmenna trida *'     'cat *' 'allow' $true
Test-SecretsAudit 'kontrola txt'       'cat .github/workflows/*.txt' 'allow' $false
Test-SecretsAudit 'kontrola cesta'     'cat ~/.aws/*' 'ask' $false
Test-SecretsAudit 'kontrola C1 *.env'  'cat *.env' 'ask' $false
Test-SecretsAudit 'kontrola bezny glob' 'ls *.md' 'allow' $false

# --- bod 12 + N-H1 + N-H2 + N-H4 + N-H6 (druhy nositel): chranene JMENO v TEXTU prikazu
#     (mimo pozici cesty) nekonci deny. Pripady ziji v tests/fixtures/task106-bod12.json -
#     🔴 zadani §7: test se pise tak, aby jeho vlastni zapis nebyl tim, co branu spusti
#     (token `.Key` nebo `id_rsa` v prikazove radce testu by spustil secrets hook nad
#     samotnym testem; N-H1 ve vzorku: 3 z 7 deny, vcetne mericiho prikazu faze 1).
#     Pozice cesty = cil presmerovani, hodnota `--opt=`, pozicni argument prikazu z
#     `pathCommands`, a u ostatnich prikazu jen token, ktery VYPADA jako cesta (lomitko,
#     `~`, `%`, tecka na zacatku, `id_*`, nebo presne chranene jmeno). Telo heredocu, jehoz
#     host neni shell ani interpret, jsou DATA (`cat >> x <<EOF`, `git commit -F - <<EOF`).
#     N14 je podminka, ne bonus: cesta, ktera neprijde jako prosty pozicni argument
#     (`< ~/.ssh/id_rsa`, `--file=...`, roura, xargs, heredoc pro shell) MUSI zustat deny.
Start-Case 'TASK-106 D2 - bod 12 / N-H1 / N-H2 / N-H4: jmeno v textu neni cesta (fixtures/task106-bod12.json)'
$bod12Path = Join-Path $script:RepoRoot 'tests/fixtures/task106-bod12.json'
$bod12 = [System.IO.File]::ReadAllText($bod12Path, ([System.Text.UTF8Encoding]::new($false))) | ConvertFrom-Json
$bod12Rows = @($bod12.rows)
Assert-True ($bod12Rows.Count -ge 20) ("[bod12] fixture nese pripady: {0}" -f $bod12Rows.Count)
foreach ($row in $bod12Rows) {
    Add-CollectedCase 'secrets' 'cmd' ([string]$row.tool) ([string]$row.cmd) ([string]$row.expect) ([string]$row.name)
    if (Test-CollectOnly) { continue }
    $template = if ([string]$row.tool -eq 'PowerShell') { 'pretooluse-powershell' } else { 'pretooluse-bash' }
    $json = New-HookInput $template @{ 'tool_input.command' = [string]$row.cmd }
    $r = Invoke-Hook -Script 'secrets.ps1' -InputJson $json
    Assert-Equal ([string]$row.expect) (Get-Decision $r) ("[bod12/{0}] {1}" -f $row.name, (([string]$row.cmd) -replace '\r?\n', ' / '))
    if ($row.PSObject.Properties['reasonContains']) {
        $reason = Get-SecretsReason $r
        Assert-True ($reason.Contains([string]$row.reasonContains)) ("[bod12/{0}] duvod nese doslova <{1}>: {2}" -f $row.name, $row.reasonContains, $reason)
    }
    if ($row.PSObject.Properties['reasonNotContains']) {
        $reason = Get-SecretsReason $r
        Assert-True (-not $reason.Contains([string]$row.reasonNotContains)) ("[bod12/{0}] duvod NEnese <{1}>" -f $row.name, $row.reasonNotContains)
    }
}

# ---------------------------------- trackovany .env.<x> je MERENI, ne fixture ---

Start-Case 'trackovany .env.<x> v GSD repu -> allow'
# Join-SafePath/Test-SafePath i tady: $GsdRepo je cesta specificka pro muj stroj
# a na CI zadne W: neni. S Join-Path pripad SPADL jeste driv, nez se dostal ke
# svemu vlastnimu preskoceni - test se rozbil o presne tu vec, kterou meri.
$devEnv = Join-SafePath $GsdRepo 'web/.env.development'
$gitOk = $false
if (Test-SafePath $devEnv) {
    $null = & git -C $GsdRepo ls-files --error-unmatch 'web/.env.development' 2>$null
    $gitOk = ($LASTEXITCODE -eq 0)
}
if (-not $gitOk) {
    $script:Skip++
    Write-Host "    SKIP  GSD repo nebo trackovany web/.env.development neni k dispozici" -ForegroundColor Yellow
} else {
    $json = New-HookInput 'pretooluse-read' @{
        'tool_input.file_path' = 'web/.env.development'
        'cwd'                  = $GsdRepo
    }
    $r = Invoke-Hook -Script 'secrets.ps1' -InputJson $json
    Assert-Equal 'allow' (Get-Decision $r) '[tracked] web/.env.development je verzovany -> allow'

    # kontrolni skupina: tyz tvar, ale netrackovane jmeno musi skoncit ask
    $json2 = New-HookInput 'pretooluse-read' @{
        'tool_input.file_path' = 'web/.env.neexistujici'
        'cwd'                  = $GsdRepo
    }
    $r2 = Invoke-Hook -Script 'secrets.ps1' -InputJson $json2
    Assert-Equal 'ask' (Get-Decision $r2) '[tracked] netrackovany .env.<x> -> ask (kontrolni skupina)'
}

# --------------------------------------------------------- fail-closed (Z9) ---

Start-Case 'fail-closed - vadny vstup blokuje'
$badInputs = @(
    @{ Name = 'prazdny stdin';     Json = '' }
    @{ Name = 'nevalidni JSON';    Json = '{' }
    @{ Name = 'bez tool_input';    Json = '{"tool_name":"Read","hook_event_name":"PreToolUse"}' }
    @{ Name = 'bez cesty';         Json = '{"tool_name":"Read","hook_event_name":"PreToolUse","tool_input":{}}' }
    @{ Name = 'neznamy tool_name'; Json = '{"tool_name":"Foo","hook_event_name":"PreToolUse","tool_input":{"file_path":"a"}}' }
)
foreach ($b in $badInputs) {
    $r = Invoke-Hook -Script 'secrets.ps1' -InputJson $b.Json
    Assert-Equal 2 $r.Exit ("[fail-closed] {0} exit 2" -f $b.Name)
    Assert-True ($r.Stderr -match 'secrets\.ps1') ("[fail-closed] {0} stderr jmenuje skript" -f $b.Name)
}

# ------------------------------------------------------- vypnuti v projektu ---

Start-Case 'vypnuti hooku projektovym override'
$overrideDir = Join-Path $script:TempDir 'projekt-secrets/.claude'
[void][System.IO.Directory]::CreateDirectory($overrideDir)
[System.IO.File]::WriteAllText(
    (Join-Path $overrideDir 'sinogard-hooks.json'),
    '{"hooks":{"gate":true,"secrets":false,"resumeCost":true,"notify":true}}',
    ([System.Text.UTF8Encoding]::new($false)))
$json = New-HookInput 'pretooluse-read' @{ 'tool_input.file_path' = '.env' }
$r = Invoke-Hook -Script 'secrets.ps1' -InputJson $json -Environment @{
    CLAUDE_PROJECT_DIR = (Join-Path $script:TempDir 'projekt-secrets')
}
Assert-Equal 'allow' (Get-Decision $r) '[override] vypnuty secrets nerozhoduje'
Assert-Equal 0 $r.Exit '[override] vypnuty secrets exit 0'

# --------------------- N43: castecny override `secrets` uz zbytek klice NEZTRATI ---
#
# 🔴 Nalez Ady N43: `secrets` ma tutez stavbu jako `gate` - pole (`denyPathPatterns`,
# `askPathPatterns`, `selfProtectPathPatterns`, `protectedBaseNames`, `pathCommands`)
# vedle objektu (`envFile`, `shapes`). Do 0.1.10 by proto override, ktery nese jen
# `envFile`, zahodil `denyPathPatterns` - a `id_rsa`, `.envrc` i `secrets.json` by
# prestaly byt deny, aniz by o tom kdokoli vedel.
#
# Oprava v `Get-HookConfig` (0.1.11) je GENERICKA pro kazdy top-level objekt, ne
# vyjmenovana pro `gate` - a prave tenhle pripad ten rozdil tvrdi.
function Test-PartialSecretsOverride([string]$Name, [string]$Path, [string]$Expect, [string]$Override) {
    $dir = Join-Path $script:TempDir ('sec-partial-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
    [void][System.IO.Directory]::CreateDirectory((Join-Path $dir '.claude'))
    [System.IO.File]::WriteAllText(
        (Join-Path $dir '.claude/sinogard-hooks.json'),
        $Override,
        ([System.Text.UTF8Encoding]::new($false)))
    $j = New-HookInput 'pretooluse-read' @{ 'tool_input.file_path' = $Path }
    $res = Invoke-Hook -Script 'secrets.ps1' -InputJson $j -Environment @{ CLAUDE_PROJECT_DIR = $dir }
    Assert-Equal $Expect (Get-Decision $res) ("[N43/{0}] {1}" -f $Name, $Path)
}

Start-Case 'N43: override jednoho klice `secrets` nezahodi `denyPathPatterns`'
$ovAskEmpty = '{"secrets":{"askPathPatterns":[]}}'
Test-PartialSecretsOverride 'id_rsa drzi' 'id_rsa' 'deny' $ovAskEmpty
Test-PartialSecretsOverride '.env drzi'   '.env'   'deny' $ovAskEmpty
$ovEnvFile = '{"secrets":{"envFile":{"maxBytes":1024}}}'
Test-PartialSecretsOverride 'id_rsa drzi i pri override envFile' 'id_rsa' 'deny' $ovEnvFile
# 🔴 kontrolni skupina: co override skutecne prepsal, PLATI - jinak by "nic se
#    neztratilo" mohlo znamenat "override se vubec nenacetl"
Test-PartialSecretsOverride 'prazdne askPathPatterns plati' '.claude/settings.local.json' 'allow' $ovAskEmpty

# ------------------------------------------------- cesta na cizi jednotce ---

# Tataz regrese jako u gate: secrets.ps1 navic saha na cwd pri zjistovani, jestli
# je soubor verzovany gitem. Neexistujici jednotka nesmi hook slozit ani ho
# nesmi zmekcit - .env zustava deny.
Start-Case 'cwd na neexistujici jednotce secrets nesloz ani nezmekci'
$missing = Get-MissingDrivePath
if ($null -eq $missing) {
    $script:Skip++
    Write-Host '    SKIP vsechna pismena jednotek jsou obsazena - pripad nema jak vzniknout' -ForegroundColor Yellow
} else {
    $json = New-HookInput 'pretooluse-read' @{ 'tool_input.file_path' = '.env'; 'cwd' = $missing }
    $r = Invoke-Hook -Script 'secrets.ps1' -InputJson $json
    Assert-Equal 'deny' (Get-Decision $r) '[cizi disk] .env porad deny'

    $json = New-HookInput 'pretooluse-read' @{ 'tool_input.file_path' = 'README.md'; 'cwd' = $missing }
    $r = Invoke-Hook -Script 'secrets.ps1' -InputJson $json
    Assert-Equal 'allow' (Get-Decision $r) '[cizi disk / kontrolni skupina] README.md porad allow'
    Assert-Equal 0 $r.Exit '[cizi disk] exit 0, ne pad do fail-closed'
}

Invoke-InvariantRows 'secrets'

Write-CollectedCases
Assert-TimingBudget

Write-TestSummary
if ($script:Fail -gt 0) { exit 1 }
exit 0
