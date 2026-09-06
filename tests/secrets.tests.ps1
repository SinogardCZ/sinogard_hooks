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
    # M21: glob, ktery MUZE padnout na chranene jmeno
    (CmdCase 'M21 glob .en?'         'Get-Content .en?' 'ask' 'PowerShell')
    (CmdCase 'M21 glob hvezdicka'    'cat *' 'ask')
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
