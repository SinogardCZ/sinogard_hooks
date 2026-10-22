# Changelog

Formát vychází z [Keep a Changelog](https://keepachangelog.com/cs/1.1.0/);
verzování je [semver](https://semver.org/lang/cs/).

## [0.3.1] — 2026-10-18

**TASK-179 (GSD): destruktivní DB příkaz uvnitř kontejnerového obalu — oprava DB části README omezení 11.** Zadání
Amber v1.1 (`2026-10-18-zadani-task-179.md`, revize Grace `T179-N1`–`N12`), rozhodnutí `ZOPT-Q82`, `ZOPT-Q89` (Tom)
a `AOPT-O22`–`O28` (Amber). Bezpečnostní oprava brány §6 → patch verze. Doklady: `docs/logs/mutants/task-179/` v repu GSD
(krok 0 s tabulkami voleb CLI, červená fáze, mutanti).

**A v témže vydání (A179-O2, jedno vydání místo dvou): plugin už nikdy nevrací `ask` (`ZOPT-Q102`, Tom 2026-10-20).**
Hook ve všech projektech nečeká na člověka: každé místo, které do 0.3.0 vracelo `ask`, je od 0.3.1 buď **ticho + řádek
auditu**, nebo **`deny`** — podle mapy Toma (`ZOPT-Q102`) a rozhodnutí Amber `A179-O1` a `A179-O3` (Q1–Q16). Výčet míst
s řádky kódu a měření dnešních zaseknutí: `predavka-task-179/2026-10-20-37…40` v GSD.

### Bezpečnost — oprava chyby 0.3.0: komentář s apostrofem vypínal bránu (CR-S8, `A179-O5`)

Skener příkazů neznal komentář. Apostrof v komentáři (`# don't` na řádku před dalším příkazem, případně `<# it's #>`)
otevřel „řetězec“, který trval až do konce příkazu. Další příkazy se proto nerozebraly a prošly tichem, a to v gate
(`git reset --hard`, `rm -rf …`) i v secrets (`cat .env`). Chyba se změřila v nasazené 0.3.0 i ve verzích 0.2.0 a 0.1.9
(cache pluginu, PowerShell, 2026-10-21). Od 0.3.1 skener zná komentář `#` (Bash i PowerShell) a `<# … #>` (PowerShell), ale z textu ho **nic
nezahazuje**. V komentáři jen uvozovky a závorky přestanou být speciální. Oddělovače (`;`, `&`, `|`, konec řádku) dál
dělí příkaz a skener navíc spojí výsledek čtení s komentářem i bez něj (CR-T). Tam, kde `#` komentářem není (cmd,
`${x:- #}`, zpětné apostrofy), tak skener vidí víc příkazů, ne méně. Cenou je, že `;` uvnitř komentáře taky dělí,
třeba `true # pak ; rm -rf x` → `deny`. Případy hlídá skupina `CR-S` v `tests/fixtures/task179-gate.json` a `task179-secrets.json`.

### Bezpečnost — oprava chyby 0.3.0: příkaz za řídicím slovem Bashe a za substitucí v přiřazení (CR-AA1, CR-AA9, CR-AA10, `A179-O8`)

Gate bral jako jméno příkazu první slovo statementu. Za rezervovaným slovem Bashe (`then`, `else`, `elif`, `do`, `if`,
`while`, `until`, `!`, `coproc`), za vzorem větve `case` (`a) …`) a za přiřazením nebo přesměrováním se substitucí
s mezerou (`X=$(echo a b) …`, i za `env`/`sudo`) proto skutečný příkaz nesedl na žádné pravidlo a prošel tichem:
`if true; then rm -rf src; fi`, `for f in a; do git reset --hard; done`, `case x in a) rm -rf src;; esac`. Chyba se
změřila v nasazené 0.3.0 i ve verzích 0.2.0 a 0.1.9 (cache pluginu, Bash, 2026-10-22). Secrets čte tokeny bez ohledu
na pozici a chybu neměl. Od 0.3.1 gate tato slova a vzory strhne a rozebere příkaz za nimi. Co před příkazem stojí, musí
být **prosté slovo** (`A179-O9`–`O11`, oddíl níž): hodnota přiřazení, cíl přesměrování, slovo a vzor `case`, i hlava
příkazu. Jinak `deny`. Případy hlídají skupiny `CR-AA`, `CR-AB`, `O9` a `O11` v `tests/fixtures/task179-gate.json`.

### Bezpečnost — slovo před příkazem v Bashi: jedno fail-closed pravidlo místo gramatiky (`A179-O9`)

Kola `/code-review` 10–13 nad ručním rozborem slova Bashe (substituce, `${…}`, uvozovky, `case`, rezervovaná slova)
nekonvergovala: každé našlo 7–10 dalších konstrukcí a 2–3 regrese předchozího kola. Kód slova se proto vrátil na stav
kola 11 a nad ním platí jedno pravidlo (`Get-BashCommandStart`, `Test-WrapperPrefixUnplain` v `gate.ps1`):

- **Hlava příkazu a všechno před ní musí být v Bashi prosté slovo.** Před hlavou může stát hodnota přiřazení, cíl
  přesměrování, slovo a vzor `case` nebo přiřazení za obalem (`env`, `sudo` …). Prosté slovo nemá `$`, zpětný apostrof,
  závorku, escape ani uvozovku uprostřed. Prostý je i celý řetězec v apostrofech nebo uvozovkách (v uvozovkách bez `$`,
  zpětného apostrofu a escape, který něco znamená). Nekvotovaná hlava navíc nesmí mít `*`, `?` ani `[` (glob vybere
  program až shell). Slovo `case` smí být i holá proměnná (`case "$1" in`).
- **Výjimky hlavy bez prefixu (`A179-O11`):** holá proměnná (`$X`, `${X}`, `"$X"`, `"${X}"`, i za obalem) zůstává
  `opaque:variable` (ticho + audit, T36 / `ZOPT-Q102`). Dále začátek bloku `{ …; }` a subshellu `( … )`, aritmetika
  `(( … ))`, definice funkce `f()` a komentář. Bloky a subshelly se rozebírají dál jako dřív.
- **Jinak `deny`** s příčinou `opaque:shellWord` a hláškou, která jmenuje náhradu: hlava jako doslovná cesta, hodnota
  jako prosté slovo, substituce v argumentu příkazu, nebo výsledek spočítaný samostatným příkazem.
- **Cena (vědomě, `A179-O9`–`O11`):** `deny` i u běžných tvarů:
  - proměnná nebo substituce v hlavě za přiřazením (`NODE_ENV=test ${HOME}/bin/tool`, `PYTHONPATH=. $(pwd)/venv/bin/python`);
  - substituce nebo uvozovka uprostřed v hodnotě přiřazení (`X=$(echo a b) git status`, `X=a"b c" git status`);
  - **samostatné přiřazení se substitucí** bez příkazu za ním (`n=$(basename "$f" .md)`; `A179-O10`). Hook bez gramatiky
    nepozná, že za hodnotou nic nestojí. Náhrada je substituce v argumentu příkazu;
  - substituce nebo cesta s proměnnou jako hlava bez prefixu (`$(which python) x.py`, `"$(pwd)/bin/x"`; `A179-O11`).
- **Zavřené tvary:**
  - nálezy CR-AB1–AB5 a CR-AC6–AC8 (větev `case` začínající přesměrováním, vzor s escapem nebo substitucí, přiřazení
    pole `NAME=(…)`);
  - regrese kola 12 CR-AC1–AC3 (kód kola 12 je pryč);
  - hlavy, které 0.3.0 propouštěla tichem nebo jen auditem: brace expanze, zpětné apostrofy a `$( … )` jako hlava, glob
    v hlavě, i za obalem (`A179-O11`).
- **Doba K7-1:** kolo 11 zpomalilo řádky `K7-1` (3000 vnořených substitucí, Bash) z ~2 s na ~6 s. `Find-CloseParen`
  totiž volal `Get-CommentStart` na každý znak a od CR-AA1 běží pro každou substituci. Teď se volá jen u `#` a `<`, kde
  může vrátit nenulu. Sémantika je beze změny a doba je zpět ~2 s (změřeno 2026-10-22 bez zátěže).
- **Doba:** regex prefixu (už jen pro PowerShell) má slovo jako atomickou skupinu. Hodnota s mnoha substitucemi bez
  mezery za ní dřív zkoušela každé rozdělení a hook přetekl timeout, tedy prošel **bez verdiktu**. Červená fáze ukázala
  20 s u Bashe (regrese kola 11) i u PowerShellu, teď je to pod 2 s (řádky `maxMs` ve skupinách `CR-AB` a `O9`).
- **Co pravidlo nezavře:** README omezení 27 (uvozovky a substituce v **argumentech**, ANSI-C `$'…'`, druhá gramatika
  slova v `Split-Arguments`). Oprava je jeden tokenizér Bashe ve verzi 0.3.2.

### Změněno — žádné `ask` (`ZOPT-Q102`, `A179-O3`)

| místo (id v auditu) | do 0.3.0 | od 0.3.1 | rozhodnutí |
|---|---|---|---|
| force push na nechráněnou větev (`forcePushOther`) | `ask` | ticho + audit | Q2 (zakázaný je jen přepis historie `main`) |
| force push bez cíle (`forcePushUnknown`) | `ask` | `deny` | Q1 (může mířit na `main`) |
| `git -c alias.…` (`gitAlias`) | `ask` | `deny` | Q3 (alias spustí cokoli) |
| `git branch -d` (git sám odmítne nesloučenou větev) | `deny` | **ticho** | Q11, mění `ZOPT-Q40` |
| `git branch -D`, `-d -f`, `--delete --force` | `deny` | `deny` (vzor `git-branch-delete-force`) | Q11 |
| mazání s cílem v proměnné, s `..`, `.NET` mazání s proměnnou, krátká absolutní cesta (`recursiveDeleteVariable`, `recursiveDeleteDotDot`, `netDeleteVariable`, `shortAbsolutePath`) | `ask` | `deny` | Q4 (cíl nejde doložit) |
| hvězdička uvnitř povolené složky (`recursiveDeleteWildcard`), mazání z roury (`deleteFromPipeline`) | `ask` | ticho + audit | Q4, mapa |
| kód interpretu s destruktivním voláním (`interpreterDestructive`) | `ask` | ticho + audit | Q6 |
| kód interpretu s DB tokenem — `DROP TABLE/DATABASE/SCHEMA`, `TRUNCATE` (`interpreterDestructiveDb`, nový seznam `gate.interpreterDbTokens`) | `ask` | `deny` | Q6 (jméno DB nečitelné) |
| nerozebratelný tvar s destruktivním literálem (`opaqueDestructive`) | `ask` | `deny` | Q5 |
| totéž u **spuštění** nerozbalené hlavy (příčina `invoked`, např. hlava po vícenásobném přiřazení) — kontrola literálu nově i tady; nový literál `reset --hard` (bez `git`) | `ask` (sama příčina) | `deny` | Q5 — bez toho by `invoked` = ticho pustilo destruktivní příkaz |
| nerozebratelné: spuštění proměnné, `-EncodedCommand`, neukončený heredoc (`opaque:invoked/encoded/heredocUnterminated`) | `ask` | ticho + audit | mapa |
| zanoření nad 5 (`opaque:depth`), neznámá příčina (`opaque:unknown`) | `ask` | `deny` | `A179-O1` (N31), Q8, Q9 |
| `ssh host "příkaz"`, `ssh prod <<EOF` (`remoteShell`) | `ask` | ticho + audit | mapa |
| `dotnet ef migrations remove`, `Invoke-Expression` (`auditPatterns`, do 0.3.0 `askPatterns`) | `ask` | ticho + audit | Q7 |
| `Invoke-Expression` / `iex` **bez argumentu** (text z roury) — vzor `askPatterns` na něj v 0.3.0 nikdy nedosáhl | ticho **bez auditu** | ticho + audit `gate:invoke-expression` | `A179-O4` (mezera v auditu, žádný deny) |
| destruktivní DB operace na **místním** hostiteli, jméno DB čitelné a ve vzoru `*_test_*`, `*_test`, `*_dev` | `ask` | ticho + audit `gate:dbDestroyLocal` | Q10 |
| totéž mimo vzory, se jménem, které nejde přečíst, `sqllocaldb delete` | `ask` | `deny` | Q10 |
| destruktivní DB operace uvnitř kontejneru (i nerozebratelná, i po stropu práce substitucí) | `ask` | `deny` | Q10 + `AOPT-O26` (v kontejneru nikdy povoleno) |
| glob mířící na chráněnou cestu (`secrets:wildcardPath`), netrackovaný `.env.*` (`envFileUntracked`), čtení `.claude/settings.local.json` (`settingsLocal`), výpis prostředí (`envDump`), citlivá proměnná (`envVarRead`), nedekódovatelný `-EncodedCommand` (`wrapperEncoded`) | `ask` | ticho + audit | mapa |
| **zápis** do `.claude/settings*.json`, `.claude/sinogard-hooks.json`, `hooks.json` a `hooks/config/*` nainstalované kopie (`secrets:selfProtect`) | `ask` | **`deny`** s textem „změnu nastavení provede Tom — zapiš ji do dávky" | Q16 (agent nesmí umět vypnout vlastní pojistku) |
| `ask` v režimu `bypassPermissions` (vydával se jako `deny`, audit `ask-bypass`) | `deny` | podle mapy výše | — (`ask` neexistuje) |

Jména DB se čtou doslova z příkazu (`-d`, `--dbname`, `dbname=`, URI, `Database=`/`Initial Catalog=`, `PGDATABASE`, první
poziční argument `psql`, cíl `dropdb`, jméno v `DROP DATABASE`); u `DROP DATABASE`/`dropdb`/`ef database drop` rozhoduje
rušená databáze. `USE`, meta-příkaz psql, dynamické SQL a trojdílné jméno = nečitelné → `deny`. Přepis
`gate.dbDestroyLocal.databases` smí vzory jen zúžit; `decision` má hodnoty `allow` (výchozí) | `deny`; `hosts` se nečte.
⚠️ Ticho u `secrets:wildcardPath` platí i pro glob, který míří na adresář s klíči — čtení přesného jména (`~/.ssh/id_rsa`)
je `deny` dál (mapa `ZOPT-Q102`, „wildcard cesty = povolit").

**Konfigurace (0.3.1):** nové objekty politik `gate.decisions` a `secrets.decisions` (hodnoty `audit` | `deny`, chybějící =
`deny`); `gate.opaque` má hodnoty `audit` | `deny`. H-c pravidlo `policy`: přepis smí jen zpřísnit (`audit` → `deny`).
Přejmenováno: `gate.askPatterns` → `gate.auditPatterns`, `secrets.askPathPatterns` → `secrets.auditPathPatterns`,
`secrets.envFile.otherPolicy` = `trackedAllowElseAudit`; projektový přepis se starým jménem H-c odmítne (platí výchozí).
⚠️ Migrace: přepis `gate.opaque` s `depth: audit` (tvar dřívějšího zúžení GSD) je od 0.3.1 uvolnění → celý klíč
`gate.opaque` odmítnut (platí výchozí, audit `config:overrideRejected:gate.opaque`). Hodnoty `ask` H-c odmítne také.
Text `texts.bypassSuffix` zmizel. „Nasazení do produkce" jako `deny` není v 0.3.1 — tvar neexistuje (Q13, nositel GSD TASK-53).

**Po `/code-review` změny `ZOPT-Q102` (CR-Q, řádky `tests/fixtures/task179-gate.json` / `task179-secrets.json`, skupina `CR-Q`):**
lokální destruktivní DB operace je `deny` (jméno nečitelné) i se seznamem jmen v `DROP DATABASE a, b` (CR-Q1b), s trojdílným
jménem v hranatých závorkách (CR-Q2), se SQL ze souboru nebo stdin vedle viditelného (CR-Q3), s příkazem `sqlcmd`
(`:connect`, `:r`, `!!` …, CR-Q4) a s hostitelem z proměnné prostředí (`PGHOST`, `PGHOSTADDR`, `PGSERVICE`, `SQLCMDSERVER`
v textu příkazu nebo nemístní hodnota v prostředí hooku, CR-Q7). Přepis `gate.dbDestroyLocal` s `decision: deny` platí i se
vzory mimo strop (dřív odmítnut → výchozí `allow`, CR-Q5). Zpřísněná politika `envDump` / `envVarRead` přebije dřívější
audit téhož příkazu (CR-Q6). `iex` bez argumentu s destruktivním literálem v příkazu = `deny` jako `iex '…'` (CR-Q9, Q5;
bez literálu dál `A179-O4`). Vědomě beze změny: přejmenované klíče přepisu (CR-Q8, migrace výše; na stroji žádný přepis
není) a nečtené `gate.dbDestroyLocal.hosts` (CR-Q10, popsáno výše).

**Druhé kolo `/code-review` nad CR-Q (CR-R, skupina `CR-R`):** SQL s komentářem (`/**/`, `--`) je pro lokální destruktivní
operaci nečitelné → `deny`. Komentář před čárkou seznamu nebo mezi částmi jména obcházel CR-Q1b i CR-Q2 (CR-R1, CR-R2).
Trojdílné jméno se pozná i s mezerou v závorkách nebo uvozovkách (CR-R2). SQL ze souboru se pozná i z `--file=x`, `--file x`,
slepeného `-fx` (psql/pgcli) a z `-ix` / `--input-file` (sqlcmd) (CR-R3). U `dropdb` přestaly `-f` (`--force`) a `-i`
(`--interactive`) znamenat soubor, takže `dropdb -f gsd_test_1` je zase ticho + audit (CR-R4, regrese CR-Q3).
`… | iex` rozebere každý řetězcový literál příkazu stejně jako `iex '…'` (plný rozbor místo hledání tokenů). Lze tak zachytit
`'rm -r -fo C:\x' | iex`, a destruktivní text mimo literál (`git log --grep "reset --hard"; 'git status' | iex`) už nevede
k zákazu (CR-R6, CR-R10). Hostitele z prostředí mění i příkaz bez doslovného jména proměnné, proto vede k `deny`
načtení souboru (`. ./x`, `source x`), `SetEnvironmentVariable`, `Set-Item`/`New-Item` na `env:` a `export`/`declare`
se substitucí (CR-R7). Hodnota z prostředí hooku se týká jen klienta, který ji čte: PG* platí pro psql/pgcli/dropdb
a `SQLCMDSERVER` pro sqlcmd. Výslovný hostitel v příkazu přebije `PGHOST` i `SQLCMDSERVER`, `PGHOSTADDR` ani soubor
služby ne. `PGHOST` s cestou k socketu je místní (CR-R8). Testy čištění prostředí hooku: sada nuluje PG*/`SQLCMDSERVER`,
řádek fixtury je nastaví polem `env` (takový řádek nejde do invariantu).
Vědomě beze změny: `service=` / `hostaddr=` v conninfo končí `deny` už dnes, protože řetězec s mezerou je nečitelné jméno
(CR-R5, změřeno, hlídají řádky). Tečky v textu SQL (`'A. B. C'`) jsou nečitelné ve směru `deny` (CR-R9). Profil shellu,
který nastaví `PGHOST` mimo prostředí hooku, hook nevidí (zbytek CR-R7, README).

**Třetí kolo `/code-review` nad CR-R (CR-S, skupina `CR-S`):**
- **Komentáře v příkazech (CR-S8).** Skener příkazů nově zná komentář `#` (Bash i PowerShell) a `<# … #>` (PowerShell).
  Apostrof v komentáři (`# don't` + nový řádek + `git reset --hard`) dosud otevřel „řetězec“ až do konce příkazu. Další
  příkazy se pak vůbec nerozebraly a prošly tichem, a to v gate i v secrets, **i v nasazené 0.3.0**. Tvar opravy z tohoto
  kola (zahazování komentáře) nahradilo kolo CR-T.
- **Rozbor `… | iex` (CR-S1, S4, S8).** Literály se berou z textu, který se právě rozebírá, ne z celého příkazu (vnořený
  `pwsh -c "'x' | iex"`). Čte je tokenizer PowerShellu a každý se rozebere jen jednou. Holé `iex` uvnitř rozebíraného
  literálu je `depth` (deny), takže rozbor už neroste exponenciálně (dřív 9–69 s → timeout hooku).
- **`allow` z `gate.dbDestroyLocal` (CR-S2, S5, S6).** Ostatní příkazy v téže řádce musí patřit do krátké množiny, která
  prostředí nemění: `cd`, výpis, další volání SQL klienta, `export` s literálem. Výčet tvarů z CR-R7 třídu nezavřel
  (`./setenv.ps1`, `eval`, `if …; then . x; fi`), proto ho nahradila tato množina. Výslovný hostitel se čte jen
  z argumentů, ne z textu SQL. Zkratky dlouhých voleb psql/dropdb (`--fil=`, `--ho=`; getopt_long) vedou k `deny`.
- **Proměnné prostředí hooku (CR-S3, S10).** `PGHOST` se seznamem (`/tmp,db.firma.cz`) je místní, jen když je místní
  každá položka. Klient z `gate.sqlClients`, kterého hook nezná, čte z prostředí hooku PG* i `SQLCMDSERVER`.
- **Ostatní (CR-S7, S9).** Volby psql `-Ufred`, `-dfoo` nejsou soubor SQL. Escape `]]` / `""` ve jménu je nečitelný → `deny`.

**Čtvrté kolo `/code-review` nad CR-S (CR-T, skupina `CR-T`):**
- **Komentář podruhé (CR-T2 až T6).** První oprava komentář zahazovala, a kde `#` komentářem není, zahodila i spouštěný
  příkaz: `Start-Process cmd '/c echo # & rd …'`, `cmd /c "echo # & type .env"` v secrets, `` `true # x`; rm … ``,
  `${x:- #}; rm …`. Komentář teď nic nezahazuje (viz Bezpečnost výše). Začíná i hned za `|`, `&`, `(`, `{` a uvnitř bloku
  `{ }` a substituce `$( )` se v něm nepočítají závorky.
- **`allow` z `gate.dbDestroyLocal` (CR-T1, T7 až T10).**
  - DB příkaz rozebraný vnořeně, například v těle `bash <<EOF`, `allow` nemá. Jeho sousední statementy hook nevidí.
  - Neutrální příkazy kolem testovací DB nově zahrnují `createdb`, `pg_restore`, `| cat`, `Select-String` a podobné. Přesměrování
    do souboru (`printf … > ~/.psqlrc`) neutrální není, povolené jsou jen `2>&1`, `> /dev/null`, `> $null` a `> nul`.
  - Jméno proměnné se hledá i po odstranění escapů a uvozovek (`PGHO\ST`), nově i `PSQLRC`.
  - Argumenty SQL klienta čte jeden rozbor podle tabulky voleb s hodnotou: hodnota `-v` není hostitel, `psql -q` hodnotu nebere.

**Páté kolo `/code-review` nad CR-T (CR-U, skupina `CR-U`) — konec záplatování:**
- **`allow` z `gate.dbDestroyLocal` jen pro jednoduchý příkaz (CR-U3, U5, U6, U10).** Kola CR-R až CR-T hledala, které
  okolní příkazy a hodnoty prostředí hostitele nemění: výčty tvarů, množinu neutrálních příkazů, výslovného hostitele
  přebíjejícího `PGHOST`, `PGHOST` se socketem. Každé kolo našlo další obchvat. Nově platí: jediný statement, všechny listy
  jsou tentýž SQL klient (nebo tělo heredocu pro něj), v textu žádné jméno proměnné hostitele (ani se escapem) a
  `PGHOST`, `PGHOSTADDR`, `PGSERVICE`, `PGSERVICEFILE`, `SQLCMDSERVER` a `PSQLRC` v prostředí hooku prázdné. `cd x; …`,
  `dropdb x && createdb x`, `… | cat` a `… # komentář` tedy končí `deny`, `2>&1` a prefix `PGPASSWORD=x` ne. Kód
  rozboru argumentů, množiny neutrálních příkazů a pravidel pro hodnoty proměnných z kola CR-S a CR-T zmizel.
  **Zúžení potvrdila Amber jako `A179-O7`**: `allow` z `gate.dbDestroyLocal` platí v 0.3.1 jen pro samostatný příkaz
  jednoho SQL klienta bez proměnných hostitele. Složený tvar se jménem ve vzoru končí novým tvarem
  `gate:dbDestroyLocalCompound`. Jeho hláška jmenuje povolený tvar (`psql -d <db> -c "…"` nebo `dropdb <db>`).
  Zúžení platí i pro SQL rourou (`echo "TRUNCATE t" | psql -d gsd_dev` → `deny`).
- **Komentář potřetí (CR-U1, U2, U4, U7–U9).**
  - Blokový komentář bez oddělovače je mezera. S oddělovačem uvnitř (`git reset <# ; #> --hard`) je nerozebratelný → `deny`.
  - `${#x}` není komentář.
  - `&>` je v cmd oddělovač (`echo hi &>nul rd …`) a přesměrování před příkazem (`>nul rd …`, `>out rm …`) se strhává.
  - Sjednocení čtení s komentářem a bez něj místo čtyř kopií: hook gate rozebere příkaz s `#` podruhé bez komentáře
    a z druhého čtení bere jen `deny` (bez auditu), `Split-CommandLine` sjednocuje segmenty pro secrets.

**Šesté kolo `/code-review` nad CR-U (CR-V, skupina `CR-V`):**
- **Příkaz uvnitř výrazu PowerShellu (CR-V2, chyba i v 0.3.0).** Statement, který začíná výrazem, třeba
  `[IO.Path]::GetTempPath() + (git reset --hard)` nebo `[Environment]::X(...) + (psql …)`, gate nerozebíral a příkaz
  v závorce prošel tichem. V PowerShellu teď rozhoduje i parser PowerShellu: každý příkaz (`CommandAst`), jehož text
  žádný list nemá, se rozebere navíc. `allow` z `gate.dbDestroyLocal` navíc vyžaduje, aby statement byl přesně ten DB
  příkaz.
- **Přesměrování a přiřazení před příkazem (CR-V1).** Strhávají se v libovolném pořadí a bez mezery
  (`>out X=1 rm …`, `2>/dev/null>out rm …`, `<>f`, `>|f`, `<<<x`). Zbytek `<`/`>` na začátku je nerozebíratelný → `deny`.
- **Ostatní (CR-V3 až V9).**
  - Blokový komentář mezi statementy (hlavička `<# .SYNOPSIS … #>`) zákaz nespouští.
  - `&>soubor` v Bashi neruší jednoduchost DB příkazu.
  - Proměnná `PGSYSCONFDIR` patří mezi proměnné hostitele.
  - Druhé čtení bez komentáře má vlastní rozpočet práce a dělá ho i hook secrets.
  - Sada nuluje všech sedm proměnných hostitele.
  - Rekurzivní sjednocení ve `Split-CommandLine` zmizelo.

**Sedmé kolo `/code-review` nad CR-V (CR-W, skupina `CR-W`):** toto kolo nenašlo žádný potvrzený obchvat.
- **Regrese CR-V2 (W1, W6).** Porovnání textu statementu s listem zakázalo i jednoduché příkazy v obalu, například
  `sudo -u postgres dropdb x`, `env PGPASSWORD=x psql …`, `bash -c "psql …"` a `(psql …)`. Příkaz uvnitř výrazu teď
  pozná přímo parser: list z parseru nese příznak `FromAst` a `allow` nemá. Porovnávání textu zmizelo.
- **Hláška u proměnné v prostředí hooku (W4).** Nový tvar `gate:dbDestroyLocalEnv` jmenuje proměnnou (jen jméno,
  ne hodnotu). Hláška složeného tvaru by tu radila přesně ten příkaz, který agent napsal.
- **Druhé čtení bez komentáře (W2, W3, W8).** Pro gate i secrets je to jedna funkce (`Invoke-PlainCommentReading`).
  Spouští se i u zakódovaného příkazu (`-EncodedCommand`), protože dekódované tělo `#` mít může. Rozpočet práce se
  nenuluje a hook tak drží timeout. Když druhé čtení na rozpočet narazí, výsledek je `deny`.
- **Parser PowerShellu (W5).** Běží jen tam, kde text má závorku, a nezvyšuje hloubku. Při porovnání ignoruje `&` a obalové závorky.
- **Vědomě beze změny (W7).** Segment, který je jen přesměrováním (`>soubor`), nemá list. `allow` pro DB ho odmítne
  kontrolou počtu statementů.

**Osmé kolo `/code-review` nad CR-W (CR-X, skupina `CR-X`):**
- **Moje regrese z CR-W (X1, X2).**
  - Parser PowerShellu znovu běží vždy. Podmínka „text má závorku“ pouštěla `return git reset --hard` a `throw …`.
  - CR-W1 dovolil `allow` i v obalu. Obal ale načítá startovní soubory (`BASH_ENV`, profil pwsh, AutoRun cmd,
    `sudo -i`/`-E`), které mohou nastavit `PGHOST`. Statement proto musí začínat tím SQL klientem. Před klientem smí
    stát jen přiřazení neškodných proměnných libpq (`PGPASSWORD`, `PGUSER`, `PGDATABASE`, `PGPORT`, `PGCONNECT_TIMEOUT`,
    `PGAPPNAME`) nebo obalová závorka PowerShellu. `HOME=/x psql …` (přesune `~/.psqlrc`) a `env PGHO\ST=x dropdb …`
    vedou k `deny`.
- **Druhé čtení bez komentáře (X3, X5, X6, X7).**
  - Spouští se, když příkaz obsahuje `#` nebo jmenuje `pwsh`/`powershell`. Regex na `-EncodedCommand` minul mezeru
    v uvozovkách i slepené uvozovky a zároveň chytal `grep -e …`.
  - Při přetečení rozpočtu se už nezakazuje celý příkaz. Platí záloha K7-1 pro DB literál, stejně v gate i secrets.
- **Ostatní (X8, X10).**
  - Obalová závorka se strhává jen jako jeden pár, `(a) + (b)` se nezdvojí.
  - U složeného příkazu má hláška složeného tvaru přednost před hláškou o proměnné prostředí.

**Deváté kolo `/code-review` nad CR-X (CR-Y, skupina `CR-Y`):**
- **Spouštěč druhého čtení (Y1, Y3, Y4).** Druhé čtení bez komentáře spouští `#` v příkazu, nebo `#` v těle
  `-EncodedCommand`, které dekódovalo první čtení. Signál vzniká v místě dekódování, ne odhadem nad textem. Jméno
  interpretu rozdělené uvozovkami (`pw''sh -ec …`) odhad z CR-X minul, a naopak každá zmínka slova „powershell“
  spouštěla druhé čtení zbytečně.
- **Přetečení rozpočtu v druhém čtení (Y2).** V gate je to znovu `deny` (nerozebíratelné). Secrets žádnou zálohu pro
  přetečení nemá. Věta „stejně v gate i secrets“ výše neplatí.
- **Ostatní (Y5, Y6).**
  - Parser PowerShellu běží jen tam, kde příkaz může stát ve výrazu: závorka, `@{`, nebo `return`/`throw`/`exit`.
  - Přiřazení před SQL klientem se čtou z tokenů, takže `PGPASSWORD=a"b c" psql …` je jedno přiřazení.

**Desáté kolo `/code-review` nad CR-Y (CR-Z, skupina `CR-Z`):**
- **Moje regrese z CR-Y5 (Z1, Z2).** Odhad „závorka, `@{` nebo `return`/`throw`/`exit` za oddělovačem“ minul statement
  za zavírací složenou závorkou (`try {} catch {} …`, `function f {} …`, `trap {} …`) i za samotným CR. Parser
  PowerShellu proto znovu běží pro každý text PowerShellu, jako v CR-X. Věta o Y5 výše už neplatí.
- **Přiřazení a přesměrování před příkazem (Z3, Z4).** Hodnota přiřazení i cíl přesměrování se čtou jako celé slovo
  shellu (kvotované části, escape a nekvotované znaky v libovolném pořadí). Do teď `X=a"b c" <příkaz>` skrylo příkaz
  pro všechna pravidla, nejen pro DB. Řádek CR-Y6 díky tomu skutečně testuje čtení přiřazení; přibyly řádky `deny`.
- **Rozpočet druhého čtení (Z5, Z6).** Druhé čtení bez komentáře má vlastní rozpočet práce na substituce. Když na strop
  narazilo už první čtení, příkaz s `#` je `deny` (nerozebíratelné). Dřív druhé čtení po vyčerpaném rozpočtu nic
  nenašlo a mlčelo, a neškodný příkaz s komentářem mohl přetéct jen součtem obou čtení.
- **Ostatní (Z7, Z8, Z9).**
  - Druhé čtení spouští `#` v kterémkoli rozebíraném textu (`Register-ParsedText`), ne jen v dekódovaném těle.
  - Pravidlo „token je přiřazení“ je jedna funkce (`Get-AssignmentName`) pro obaly i pro DB `allow`.
  - Věta o `texts.bypassSuffix` je zpět u konfigurace.

**Jedenácté kolo `/code-review` nad CR-Z (CR-AA, skupina `CR-AA`):**
- **Substituce v přiřazení a přesměrování před příkazem (AA1–AA3, díra i v 0.3.0).** Oprava Z3 znala jen uvozovky
  a escape. Substituce s mezerou uvnitř (`X=$(echo a b) <příkaz>`, `$((1 + 2))`, `${Y:-a b}`, zpětné apostrofy
  v Bashi) proto dál skrývala příkaz všem pravidlům, i za obalem (`env X=$(echo a b) <příkaz>`). Slovo shellu teď tvoří
  i substituce, jak v přiřazení před příkazem, tak v tokenech (`Split-Arguments`). Zbyde-li za přiřazením nebo
  přesměrováním slovo se závorkou z neuzavřené substituce, tvar je nerozebíratelný (`deny`). Věta „pro všechna
  pravidla“ u Z3 platila jen pro uvozovky.
- **Rozpočet druhého čtení (AA4, AA5).** Vlastní rozpočet z Z5/Z6 je pryč, strop práce zase platí pro celý běh hooku
  (drží timeout). Druhé čtení už rozdělené substituce nepočítá znovu (změřeno: 12 jednotek u 400 vnořených závorek),
  takže součet obou čtení falešné `deny` nedává. Přetečení v prvním čtení u příkazu s `#` zůstává `deny`; bez `#`
  platí dál záloha K7-1 (jen DB literál) — u příkazu bez komentáře není druhé čtení, které by chybělo.
- **Parser PowerShellu (AA6, AA8).** Nespouští se jen u textu bez jakékoli závorky `( ) { }`, bez `@`, bez CR a bez
  slov `return`/`throw`/`exit` (kdekoli v textu). Regex přiřazení před příkazem se sestaví jednou pro každý escape znak.
- **Řídicí konstrukce Bashe (AA9, AA10, díry i v 0.3.0 — nalezeno při ověřování AA1).** Příkaz za rezervovaným slovem
  (`then`, `else`, `elif`, `do`, `if`, `while`, `until`, `!`, `coproc`) i za vzorem větve `case` (`a) <příkaz>`) neviděla
  žádná pravidla: `if true; then rm -rf src; fi`, `for f in a; do git reset --hard; done`, `case x in a) rm -rf src;; esac`
  a `X=$(case x in a) echo;; esac) <příkaz>` prošly. Brána slova strhne a rozebere příkaz za nimi. Konec subshellu
  (`(cd x; ls) > out`) zůstává beze změny. Secrets čte tokeny bez ohledu na pozici a díru neměl.
- **Známá mez (AA7) → 0.3.2.** Gramatika slova shellu je na dvou místech: prefix před příkazem (v Bashi od `A179-O9`
  `Get-BashCommandStart`) a `Split-Arguments`. Jeden tokenizér Bashe je kostra verze 0.3.2 (README omezení 27).

**Dvanácté a třinácté kolo `/code-review` (CR-AB, CR-AC) → návrat a jedno pravidlo (`A179-O9`):**
- Kolo 12 přepsalo slovo shellu na lineární průchod (`Split-CommandPrefix`, `Get-ShellWordEnd`, `Find-CloseBrace`).
  Kolo 13 nad ním našlo 10 nálezů, z toho 3 regrese kola 12 (CR-AC1–AC3) a časovou regresi řádků `K7-1`. Kód kola 12
  je **vrácen** na stav kola 11 a nálezy CR-AB1–AB5 a CR-AC6–AC8 zavírá pravidlo z oddílu „Bezpečnost — slovo před
  příkazem“ výš (skupiny `CR-AB` a `O9`). Řádky „kontrola … ticho“ s neprostou hlavou za přiřazením (CR-AA1, CR-AA2,
  CR-AB5, CR-Y6, CR-Z3 a výpis 7. 9. `gsd/24`) jsou teď `deny` s hláškou — to je cena pravidla. Totéž platí pro kontrolu
  `L1` v Bashi (hlava `$_.Name`).
- **Vědomě beze změny (AB6).** Sdílený rozpočet obou čtení může falešně přetéct jen v okně, kdy první čtení skončí
  méně než ~12 jednotek pod stropem 200 000 (druhé čtení rozdělené substituce znovu nepočítá; změřeno u 400 vnořených
  závorek: první čtení 160 833, druhé 12, u 450 už přeteklo první čtení samo).

### Opraveno — díra 0.3.0 (všechny projekty na stroji)

README omezení 11 tvrdilo, že destrukce databáze v kontejneru je krytá. Platilo to jen pro tělo heredocu a rouru do
klienta; vnitřní příkaz s `-c` i `dropdb` hook **neviděl** (`docker|podman` byl list bez SQL klienta).

| třída tvaru | 0.3.0 | 0.3.1 |
|---|---|---|
| `docker\|podman exec\|run … <kontejner> psql\|sqlcmd … -c/-Q "<destruktivní SQL>"`, `dropdb`, `dotnet ef database drop`, `sqllocaldb delete` uvnitř — místní | ticho | `deny` (v kontejneru nikdy povoleno, `AOPT-O26`; do `ZOPT-Q102` `ask`) |
| totéž s vzdáleným hostitelem ve **vnitřním** příkazu (`-h`, `Host=`, URI) nebo v proměnné prostředí obalu (`-e PGHOST=…`, průchozí `-e PGHOST` s hodnotou v témže příkazu, i v dekódovaném `-EncodedCommand`) | ticho | `deny` |
| `podman-remote` (tentýž klient podmana) | ticho | jako řádky výše |
| cíl kontejneru substitucí (`$(docker ps -q)`, zpětné apostrofy, `(docker ps -q)` v PowerShellu), zkratky dlouhých voleb `podman-compose` | ticho | jako řádky výše |
| heredoc do shellu v `docker exec -i c sh` (tvar, který 0.3.0 rozbalovala): s přepisem `gate.dbDestroyLocal = allow` | ticho | `deny` (tvar v kontejneru nikdy `allow`) |
| totéž s `-e PGHOST=<vzdálený>` | `ask` | `deny` |
| management podpříkaz `container exec\|run`, compose (`docker compose`, `podman compose`, `docker-compose`, `podman-compose`), globální volby před podpříkazem (podman i za ním), `run --entrypoint`, `podman exec --latest\|--cidfile`, volby s hodnotou ve všech zápisech (`--x=h`, `-xh`, shluk `-iu h`, `--`) | ticho | jako řádky výše |
| volba, kterou tabulka CLI nezná (čte se s hodnotou i bez); tělo heredocu a roury se posoudí pro **každé** čtení obalu (i proti staršímu průchodu, který `--entrypoint` / `--detach-keys` nezná) a platí nejpřísnější | ticho | jako řádky výše |
| vnořený `bash -c` / `sh -c` uvnitř kontejneru, `xargs … dropdb` uvnitř, obal za `sudo` / `env` / `timeout` s globální volbou | ticho | jako řádky výše |
| heredoc a roura do klienta v kontejneru za globální volbou nebo management podpříkazem, heredoc do shellu v kontejneru (compose, globální volba, `env -S "…"`) | ticho | jako řádky výše (heredoc do shellu jen DB pravidlem) |
| nerozebratelná hlava uvnitř kontejneru (`sh -c "$PSQL -c '…'"`) s destruktivním DB literálem | ticho | `deny` (tvar `dbDestroyContainerOpaque`) |
| uvozovaná závorka nebo zpětný apostrof v hodnotě volby obalu, vnořený kontejner s vlastním `-e PGHOST=…` | ticho | jako řádky výše (proměnné obou obalů se sčítají) |
| heredoc do interpretu (`python`, `node` …) v kontejneru, který 0.3.0 nerozbalila (compose, globální volba), s destruktivním DB literálem | ticho | `deny` |
| heredoc do interpretu v `docker exec` (tvar, který 0.3.0 rozbalovala): verdikt 0.3.0 (destruktivní volání `ask`, jinak audit) | audit | podle tabulky „žádné `ask`" výše; navíc destruktivní DB literál v těle → `deny` |
| `-EncodedCommand` v kontejneru | ticho | dekódované tělo jde DB pravidlem (v kontejneru `deny`) |
| `-EncodedCommand` v kontejneru, které nejde dekódovat nebo dává prázdný text (i bez DB textu) | ticho | ticho + audit `opaque:encoded` (politika `gate.opaque.encoded`, jako na hostiteli) |
| obal kontejneru se substitucí v příkazu, jehož rozbor substitucí narazí na strop práce (tisíce vnořených uzavřených závorek), s destruktivním DB literálem | ticho nebo timeout hooku | `deny` (jméno DB nejde přečíst; s přepisem `gate.dbDestroyLocal = deny` tvar `dbDestroyLocalDenied`; přebije i ticho jiného listu; literál se hledá v každém rozebíraném textu příkazu, i v datech) |
| cíl enginu jinde (volba nebo proměnná prostředí CLI) + destruktivní příkaz s místním vnitřním hostitelem | ticho | `deny` — nová README mez 26 |

Tvar uvnitř kontejneru **nikdy** nedostane `allow` z `gate.dbDestroyLocal` (`AOPT-O26`) — od `ZOPT-Q102` je proto `deny`.

### Beze změny (kontrolní skupiny, `AOPT-O25`)

- Mazání cest a destruktivní git **uvnitř** kontejneru: verdikt 0.3.0 (ticho), README omezení 11 — cestová část a její
  spouštěč přehodnocení zůstávají. Obal za prefixem (`sudo docker exec …`) dál posuzuje vnitřní příkaz všemi pravidly jako v 0.3.0.
- Hook **`secrets`: žádná změna verdiktu.** `_common.ps1` dostal nový rozbor kontejneru, ale `Get-WrapperTail` a jeho volání
  v `secrets.ps1` se nemění; dekódování `-EncodedCommand` se jen přesunulo do sdílené funkce (verdikt `secrets` beze změny; gate ji používá pro
  `-EncodedCommand` v kontejneru, viz řádek tabulky výše); sada `secrets` + kontrolní řádky `tests/fixtures/task179-secrets.json` (8) zelené.
- Tentýž SQL bez kontejneru, tělo heredocu a roura do `docker exec -i … psql -h …` (už v 0.3.0 `deny`), `scripts/…ps1`
  spuštěný souborem (README omezení 1): beze změny.
- Nový řádek auditu (verdikt beze změny = ticho): `sqlFromFile` / `sqlFromPipe` i pro klienta uvnitř kontejneru. Obal,
  který hook čte víckrát (neznámá volba, tělo heredocu a roury pro každé čtení), zapíše událost tolikrát, kolikrát ji nese
  jeho nejbohatší čtení — ne jednou za každé čtení (i pro tělo shellu, které se rozebírá znovu pro každé čtení vnějšího
  obalu); jiný výskyt v témže příkazu se počítá zvlášť.
- Heredoc do interpretu v `docker exec` (tvar 0.3.0) s destruktivním voláním interpretu nese dál id tvaru
  `interpreterDestructive` i tehdy, když tělo má navíc destruktivní DB literál.
- Coreutils `truncate` a volání `truncate(` (`os.truncate`, `f.truncate()`) v kódu interpretu nejsou SQL `TRUNCATE` → ticho.
- `dotnet ef database drop|update` v obalu: DB pravidlo dál posuzuje i celý příkaz obalu jako v 0.3.0 (přísnější verdikt
  zůstává; README omezení 11).

### Konfigurace

Nový text tvaru `gate.shapes.dbDestroyContainerOpaque` (výchozí konfigurace). Nová příčina `gate.opaque.shellWord`
(výchozí `deny`; přepis smí jen zpřísnit, takže zůstává `deny`) a text `gate.shapes.opaqueShellWord` (`A179-O9`).

### Testy

`tests/fixtures/task179-gate.json` (207 řádků: tvary 17–24, třída `AOPT-O27`, členové M-a–M-d z kroku 0, kontrolní skupiny,
nálezy `/code-review` kol 1–9 a rozlišující řádky mutantů), `tests/fixtures/task179-secrets.json` (8); červená fáze nad 0.3.0:
59 z prvních 105 řádků gate červených ze správného důvodu (čekáno `ask`/`deny`, dostáno ticho), nálezy review vlastní červenou
fází nad předchozí verzí opravy. Invariant 1152 → 1347 řádků (jen přidání). `Invoke-Task117Rows` bere předponu fixtury
a nově umí `auditAbsentShape` / `auditAbsentDecision` (tvar, který v auditu být nesmí; audit přitom musí mít aspoň jeden
řádek), `auditShapeCount` (počet řádků auditu), `maxMs` (doba jednoho běhu hooku, nejvýš tvrdý strop sady; běh
nad `maxMs` se jednou opakuje a druhý běh píše audit do nové složky) a `{REP}` / `{REP2}` + `repText` / `repCount` / `repText2` / `repCount2` (dlouhý příkaz bez tisíců znaků ve
fixtuře; takový řádek nejde do invariantu).

### Meze TASK-161 přecházejí na 0.3.2

Meze vydání 0.3.0 (`Z117-Q29`, README omezení 1 a 25) se opravují ve verzi **0.3.2** (GSD TASK-161), ne 0.3.1.

## [0.3.0] — 2026-10-08

**TASK-117 (GSD): `secrets` jen u čtení obsahu, tři díry 0.2.0 zavřené, H-a–H-g.** Zadání
Amber v6 (`2026-10-01-zadani-task-117.md`, revize Grace `T117-N1`–`N22`), fáze 1 (krok 0, výčet
tvarů posunutých k mlčení, návrh H-a/H-c/H-f/H-g, červené testy, council Codex + Poolside)
a rozhodnutí Toma `Z117-Q1`–`Q22` + Amber `A117-O1`–`O8`. Mění se rozhodnutí brány → minor
verze (`A117-O3`). Doklady: `docs/logs/mutants/task-117/` v repu GSD (výčet `00-…`, návrh
`01-…`, sondy `02-…`, červená fáze `03-…`, council `05-…`, mutanti, H-d návnada `10-…`).

### Zpřísněno — díry 0.2.0 (všechny projekty na stroji)

| tvar | 0.2.0 | 0.3.0 | rozhodnutí |
|---|---|---|---|
| `Get-Content (Get-ChildItem .env)`, `cat (ls .env)`, `-Body (Get-Content -Raw .env)` — seskupení | ticho | `deny` | `Z117-Q16`, nález N-C |
| `curl -d @.env`, `--data-binary @.env`, `-F f=@.env`, `ls <(curl --data-binary @.env …)` | ticho | `deny` | `Z117-Q16`, nález N-D (council Codex) |
| `$x = 'git'; & $x reset --hard` (pod zúžením projektu `gate.opaque.invoked = audit`) | ticho + audit | `deny` | `Z117-Q17`, nález N-B |
| `dotnet ef database update --connection "Addr=…"` / `Address=` / `Network Address=` vzdálený | ticho | `deny` | `Z117-Q16`, `T117-N13` |
| `ef database drop` s `Addr=` vzdáleným, `sqlcmd -S "vzdálený"`, `-Svzdálený`, `dropdb -h "…"`, `psql -h '…'`, URI bez uživatele, návnada `Server=localhost;Addr=db.firma.cz` | `ask` | `deny` | `Z117-Q16` |
| přepis `localDbHosts` se vzdáleným hostitelem | `ask` | `deny` (klíč odmítnut) | `Z117-Q21`, `T117-N12` |
| `sqllocaldb delete <instance>`, `SqlLocalDB.exe delete …`, `sqllocaldb d …` | ticho | `ask` | `Z117-Q20`, nález Amber A117-N4 |
| `openssl rsa -in private.pem`, `ssh-keygen -y -f key.pem`, `keytool -keystore app.jks`, `certutil -dump cert.pfx`, `gpg --decrypt x.gpg` | ticho | `deny` | `Z117-Q6` (položka 4) |
| `printenv API_KEY`, `Get-Content Env:\API_KEY`, `Env:/…`, `gc Env:\…`, `(Get-Item Env:\…).Value` | ticho | `ask` | `Z117-Q15`, `A117-O5` |
| projektový přepis, který bránu uvolňuje (`denyPatterns: []`, kratší `protectedBranches`, delší `allowedRemoveRoots`, prázdné `askPathPatterns`, `opaque.encoded: audit`, `shapes`, neznámý klíč) | platil | odmítnut (výchozí hodnota) | `Z117-Q21` (H-c) |

### Uvolněno — rozhodnutá ticha

| tvar | 0.2.0 | 0.3.0 | rozhodnutí |
|---|---|---|---|
| jmenující tvar bez toku výstupu: `git ls-files X`, `git check-ignore [-v] X`, `git ls-tree --name-only <tree> X`, `Test-Path X`, `ls`/`dir`/`Get-ChildItem X` (i `ls ~/.ssh/*`, A131-N5 doslova) — pro **všechny** chráněné soubory | `deny`/`ask` | ticho + audit `secrets:nameOnly` | `Z117-Q1/Q2/Q3/Q5` (položka 7) |
| jméno citlivé proměnné jen jako text ve vzoru `grep`/`rg`/`git grep`/`Select-String` (vzorový `grep -n "^\$env:GSD_E2E_PASSWORD" …` v Bash nástroji) | `ask` | ticho + audit `secrets:nameOnly:envVarText` | `Z117-Q14/Q22` (H-g, varianta A) |
| `& $m` / `& "$sp\x.ps1"` / `. $m` po jediném literálním přiřazení v témže příkazu (PowerShell) | `ask` (`invoked`) | podle rozbaleného literálu (skript souborem = ticho) | `Z117-Q17` (H-a, varianta 1) |
| LocalDB `(localdb)\<instance>` v `--connection` | `deny` | `ask` | `Z117-Q18` |
| lokální destruktivní DB operace s přepisem `gate.dbDestroyLocal = allow` přesně pokrytým tvarem (`sqlcmd -S … -Q "DROP DATABASE [X]"`, `ef database drop --connection …`) | `ask` | ticho + audit `gate:dbDestroyLocal` | `Z117-Q13/Q19` (H-f); výchozí `ask` beze změny |
| zápis do `hooks/hooks.json` / `hooks/config/*` mimo nainstalovanou kopii (`.claude/plugins/`) | `ask` (`selfProtect`) | ticho | `Z117-Q23` (a), Tom 2026-10-08 18:43 |
| výpis prostředí filtrovaný podle jména s projekcí na jméno / počet (`Get-ChildItem Env: \| Where-Object Name -like 'X*' \| Select-Object -ExpandProperty Name`) | `ask` (`envDump`) | ticho | `Z117-Q23` (c) |
| `{"gate":{"opaque":{"variable":"maybe"}}}` (neznámá hodnota) | `ask` (fail-closed v kódu) | klíč odmítnut → výchozí `variable = audit` | `Z117-Q21` — test `politika/neznama` překlopen |

### Opraveno po `/code-review` fáze 2 (CR-P1–P10)

- CR-P1: hostitelé DB se slili do jednoho řetězce (dvojí obal pole) — dva místní hostitelé vyšli jako vzdálený `deny`.
- CR-P2: rozbalení H-a vypne i `${x} = …`, `Set-Item variable:x`, `(Get-Variable x).Value = …`, `PSVariable.Set`,
  vícenásobné přiřazení (`$a, $x = …`) — do opravy rozbalilo starou hodnotu a `git reset --hard` prošel tiše.
- CR-P4: hodnota přepínače začínající pomlčkou není hostitel (`sqlcmd -h -1`, `psql -H -c`).
- CR-P5: N-D i se slepeným krátkým přepínačem (`curl -d@.env`, `-Ff=@.env`).
- CR-P6: H-c porovnává pravidlo `denyPatterns`/`askPatterns` podle `id` + `pattern`, ne celým JSON.
- CR-P7: H-a rozhoduje první výskyt použití mimo přiřazení (ne poslední); náhrada proměnné s hranicí jména.
- CR-P8: posun začátku výskytu u `GetEnvironmentVariable`. CR-P9: sdílené vzory LocalDB a synonym serveru.
- CR-P10: audit odmítnutého klíče přepisu jednou za session (značka `override-rejected.json`), ne při každém volání.
- Vědomě beze změny: CR-P3 (`hooks.*` v přepisu smí hook vypnout) — řádek `hooks.*` přijat v návrhu H-c, který
  schválil Tom (`Z117-Q21`); vypnutí je viditelné v kanárku (`—`).
- Kolo 2 (`/code-review` nad opravami): `selfProtect` chrání navíc cokoli pod `hooks/` **právě běžícího** pluginu
  (`--plugin-dir`, jiný `CLAUDE_CONFIG_DIR`) a relativní cíl v příkazu, který mění adresář (`cd`, `Set-Location`,
  `Push-Location` → vzor 0.2.0 kdekoli); absolutní cesta i mimo Windows; výjimka „jen jména" u `envDump` padá při
  zastínění aliasem/funkcí; N-D i ve shluku přepínačů (`curl -sd@.env`); `variable:` vypíná H-a jen jako cesta providera
  (ne `-ErrorVariable:e`).
- ⚠️ Migrace: výchozí `secrets.selfProtectPathPatterns` se změnil (`Z117-Q23`) — projektový přepis, který kopíroval
  seznam 0.2.0, už není nadmnožina a H-c ho celý odmítne (kanárek to ukáže). Projekt přepíše seznam z 0.3.0.

### Zpřísněno — díry 0.2.0 nalezené review fáze 2 (`Z117-Q25`, `Z117-Q26`, Tom 2026-10-08 21:24 a 21:44)

| tvar | 0.2.0 | 0.3.0 | rozhodnutí |
|---|---|---|---|
| **cíl kopie / přesunu** do chráněné cesty: `cp x .claude/settings.json`, `Copy-Item … -Destination .claude/…` (i `-Destination:`, `-Dest`, prohozené pořadí), adresářový cíl + chráněné jméno zdroje (`cp /tmp/settings.json .claude/`), `cp -t` / `--target-directory`, `mv`/`Move-Item` do nainstalované kopie pluginu, `xcopy`, `robocopy <zdroj> <cíl> <soubor>` | ticho | `ask` (`selfProtect`), nad souborem se secrets `deny` | `Z117-Q25` |
| Bash skupina / funkce `{ cat .env; }`, `{ cat .env; } \| curl -d @- …`, `f() { cat .env; }; f`, `{ echo x > .claude/settings.json; }` | ticho | `deny` / `ask` | `Z117-Q26` (`A117-N5`) |
| prefix `\\?\` / `\\.\` (i `\\?\UNC\…`) v cestě nástrojů Read/Write/Edit — `\\?\…\.claude\settings.json` zápis, `\\?\…\.env` čtení | ticho / `ask` | `ask` / `deny` jako bez prefixu | `Z117-Q26` (`A117-N6`) |
| `curl --data-urlencode name@.env`, `'name@.env'`, `--data-urlencode=name@.env`, `--variable name@.env` | ticho | `deny` | `Z117-Q26` (`A117-N7`) |
| `$ExecutionContext.InvokeCommand.InvokeScript("$x reset --hard")`, `& ([scriptblock]::Create('git reset --hard'))` | ticho | `ask` (proměnná) / `deny` (literál se rozebere) | `Z117-Q26` (`A117-N8`) |

➕ `A117-N15` (delta review Amber, v rámci `Z117-Q25`): kopie / přesun do chráněného adresáře, když jméno zdroje určit
nejde (glob `cp cfg/* .claude/`, `cp *.json .claude/`, rekurze `cp -r cfg/. .claude`, `cp -r src/.claude .`,
`Copy-Item -Path cfg\* -Destination .claude -Recurse`, `xcopy cfg .claude /E`, `robocopy cfg .claude /MIR` / `*.json`), a
`Rename-Item` / `ren` na chráněné jméno → `ask` (do cíle se dosadí každé chráněné jméno); `cp -r src dist` dál mlčí.
Adresář bez přepínače rekurze taky: `mv src/.claude .`, `mv cfg .claude`, `Move-Item cfg .claude`, `Rename-Item cfg .claude`,
`xcopy cfg .claude /Y` → `ask`; cena: `mv x.json .claude` se ptá (hook nepozná, jestli cíl existuje).
`\??\` (NT prefix) se strhne jako `\\?\` (`A117-N19`).
➕ `A117-N22`–`N24`, `N26` (delta review Amber 04): PowerShell zkratky `-Recurse` (`Copy-Item cfg .claude -r`), zdroj z roury
(`Get-ChildItem cfg | Copy-Item -Destination .claude`, `Get-Item x | Rename-Item -NewName settings.json`), výraz / proměnná ve
zdroji, zástupné znaky `[…]` / `{a,b}`, glob v cíli (`cp x.json .claude/settings.js*`) a rekurzivní kopie s neznámými jmény do
kořene projektu nebo domova (`cp -r ../sablona/. .`, `robocopy X . /E`) → `ask`; `cp -r src .`, `Copy-Item cfg .claude
-Recurse:$false` mlčí. Mez: jiný předek `.claude` (README 25).
➕ `Z117-Q27 = B` (Tom 2026-10-09 07:41, „opravit v 0.3.0 i obě menší díry"):

| tvar | 0.2.0 | 0.3.0 | nález |
|---|---|---|---|
| `bash -c 'cat .env'`, `sh -c`, `zsh -c`, `pwsh -c "Get-Content .env"`, `powershell -Command`, `sudo bash -c`, vnořené, `pwsh -EncodedCommand <Get-Content .env>` | ticho | `deny` | `A117-N16` (hook `secrets`; rozpoznání obalu sdílí s `gate`, `Get-ShellWrapperBody`) — jen vyjmenované tvary, **ne úplné** (meze `A117-N29`–`N31` níž) |
| `bash -c 'cp x.json .claude/settings.json'`, `pwsh -enc $e` (nejde dekódovat) | ticho | `ask` | `A117-N16` |
| `install`, `ln -sf`, `rsync`, `dd of=`, `New-Item` (i link), `ni`, `mklink`, `[IO.File]::Copy/Move/WriteAllText`, `Copy-Item x (Join-Path .claude settings.json)`, `cmd /c copy\|move` do `.claude/settings.json` | ticho | `ask` | `A117-N17` |
| `dd if=.env of=/tmp/x` | ticho | `deny` | `A117-N17` |
| `Start-Process git -ArgumentList 'reset','--hard'`, `Start-Process git 'reset','--hard'`, `-f git -a …`, `-Verb RunAs git …` | ticho | `deny` | `A117-N18` (hook `gate`) |

⚠️ Mez: `xargs cp -t .claude`, `find … -exec cp {} .claude/ \;` (`A117-N25`, rozhodla Amber `A117-O11`); cíl celý v proměnné.

### ⚠️ Známé meze vydání 0.3.0 — oprava ve verzi 0.3.1 (`Z117-Q29 = A`)

Rozhodnutí Toma 2026-10-09 18:50: 0.3.0 se vydá a nasadí bez dalších oprav kódu; nálezy delta review Amber 05
(`2026-10-09-review-amber-117-delta-05.md`) se zapisují jako známé meze a opraví se v samostatné verzi **po jednom nálezu
na session** (GSD TASK-161). Mění `Z117-Q28` („opravit vše") pro 0.3.0. Popis třídou — tvary drží review.

- `A117-N29` — rozbor obalu (`Get-ShellWrapperBody`, oba hooky) nezná část zápisů obalu, které shell skutečně spustí;
  řádek `A117-N16` výš proto neznamená „každý obal" (README omezení 1).
- `A117-N30` — hook `secrets` nerozebírá literál předaný příkazům, které text spouštějí; gate ano.
- `A117-N31` — nad stropem zanoření se tělo obalu nerozhoduje a hook mlčí (fail-open; má být `ask`).
- `A117-N32` — odkaz / junction na místě chráněného adresáře, kopie metodou souborového objektu, složená cesta u jiných
  zápisových příkazů než rodiny kopie.
- `A117-N33` — zápis chráněného souboru stahovacím, rozbalovacím nebo verzovacím příkazem; shell čtoucí příkazy ze vstupu
  (i v gate); další obalové programy; alias gitu spouštějící shell; nepřímý zápis přes dříve založený odkaz.
- `A117-N25`, `A117-N27` — skládání příkazů a pevný seznam sondovaných jmen (README omezení 25).

### ⚠️ Co H-a uvolňuje i bez projektového přepisu (`A117-N9`)

Rozbalení literální hlavy (`Z117-Q17`) posuzuje **rozbalený** příkaz jako literální — a literální `git @('reset','--hard')`
nebo `git $y --hard` mlčely už v 0.2.0 (proměnná v argumentu = `opaque:variable`, audit). Proto `$x = 'git'; & $x $y --hard`,
`& $x @('reset','--hard')`, `& $x @a` (destruktivní ocas v proměnné) od 0.3.0 **mlčí ve všech projektech bez přepisu**
(HRMS, Útraty) — v 0.2.0 se ptaly jako `invoked`. `$x = 'git'; & $x reset --hard` (ocas viditelný) je `deny`.

### Přidáno

- **H-b — audit i `ask`/`deny`** (`Z117-Q8 = B`): řádek nese id tvaru (`gate:<id pravidla>`,
  `gate:opaque:<příčina>`, `secrets:<tvar>`) a vydané rozhodnutí; `ask` v bypassu = `ask-bypass`.
  Nikdy text příkazu, cestu ani jméno proměnné. Kontrolní testy *„ask nezapíše řádek"* (gate
  `opaque-ask`, secrets `audit/kontrola …`) překlopeny na *„řádek nese skutečné rozhodnutí, ne
  allow"*.
- **H-c — `_overridePolicy`** ve výchozí konfiguraci; odmítnutý klíč = výchozí hodnota, kanárek
  `· přepis: odmítnuto N klíčů (…)`, audit `config:overrideRejected:<klíč>`. Testy
  `K2-1 prazdne denyPatterns` a `N43 prazdne askPathPatterns` překlopeny (`allow` → `deny`/`ask`)
  s novou kontrolní skupinou *„zpřísňující přepis platí"*.
- **H-f — `gate.dbDestroyLocal`** (`decision`, `databases`, `hosts`), tvar `dbDestroyLocalDenied`.
- Sbírají se **všechny** hodnoty hostitele DB (`Get-DbHosts`), kterýkoli vzdálený = `deny`.

### Opraveno textem

- `defaults.json` `_comment`: „MĚLKÉ sloučení" → jednoúrovňové od 0.1.11 (H-e, `A117-O1`).
- `_common.ps1`: poznámka o dvojím obalení pole u `Expand-ColonParameter` (N-H10, `A117-O1`).
- `_generate-invariants.ps1`: popis doby běhu režimu sběru podle měření (N-H8, `A117-O1`).
- README omezení 9 (H-d, `Z117-Q9`): přeměřeno návnadou — `Read` deny Claude Code 2.1.286 kryje
  v PowerShell nástroji přímé `cat`/`Get-Content <soubor>`, ne glob, `head`, `sed` ani seskupení;
  omezení 1 (H-a), 22 (položka 4, N-C, N-D), nová 23 (H-g) a 24 (jmenující výjimka).

### Testy

- `tests/fixtures/task117-{secrets,gate}.json` (případy v datovém souboru, ne v příkazové řádce),
  harness: výchozí **prázdný projekt** a **žádný audit** pro každý běh hooku (sada na stroji
  s repem GSD měřila jeho skutečný přepis), fáze řádku se kontroluje **před** sběrem do invariantu,
  řádky s přepisem nebo režimem do invariantu nejdou, mimo-ASCII v sběru jako `\uXXXX` (typografická
  uvozovka rozbila JSON v konzoli `powershell.exe`).
- Invariant: nové řádky generátorem; `ls ~/.ssh/*` `ask` → `allow` přijato `-Prijmout "Z117-Q5"`.

### Neopraveno (rozhodnuto)

- Refaktor `Get-CommandLeaf` + N-H11 (`Z117-Q7 = A`) — spouštěč *„první změna seznamu interpretů,
  nebo první oprava v `Split-Heredoc` / `Remove-DataHeredocBody`"*.
- `cmd /c` (README 15) a kontejner (README 11) — spouštěče přeměřeny v kroku 0, nesepnuty.
- Doba hooku (položka 6, `A117-O2`) — změřena, beze změny výkonu.

## [0.2.0] — 2026-09-13

**TASK-106 (GSD): deset bodů nad měřením, ne nad dojmem.** Fáze 1 (2026-09-12) změřila
**157 událostí brány nad 156 tool calls** ze **73 transkriptů** (2026-09-06 → 09-12,
146 `ask` + 11 `deny`) a každý dotaz překlasifikovala funkcemi 0.1.11 — příčinu totiž
z textu hlášky poznat nejde (jeden text `opaque` sdílí devět příčin). Výroky Amber
2026-09-12 v mandátu Toma (§1 = A: deset bodů, dvě dávky podle skriptu — D1 `gate.ps1`,
D2 `secrets.ps1`). TDD: 29 (D1) + 27 (D2) červených tvrzení před opravou, mutanti
a kontrolní skupiny u každého bodu (zadání §7). Politika `gate.opaque` se **nemění**.

### D1 — `gate.ps1`

#### Zúženo — obal s literální hlavou už není spuštění proměnné (bod 15, N-H5)

`bash -c`, `pwsh -Command`, `cmd /c`, `eval`, `iex` a `Start-Process` dělaly
`Test-Unexpandable` nad **celým** vnitřkem, takže proměnná kdekoli v těle
(`pwsh -Command "git status; Write-Host $x"`) udělala z obalu `invoked` → `ask`.
Ve vzorku: **44 dotazů `invoked`, 41 tohoto tvaru, pravých 0** (`3/n` = 6,8 %).
Od 0.2.0 se vnitřek **rozebere** týmž řetězem jako hlavní běh (`Get-InvokedLeaves`,
`$script:InvokedContext`) a `invoked` je jen statement s proměnnou nebo substitucí
**v hlavě**. Přesná simulace nad vzorkem: 40 ticho · 3 `ask` beze změny · 1 `ask`
s pravdivou hláškou.

| tvar | do 0.1.11 | od 0.2.0 |
|---|---|---|
| `pwsh -NoProfile -Command "git status; Write-Host $x"` | ask | **allow** |
| `bash -c "echo $HOME; git status"`, `cmd /c "echo %PATH% && dir"`, `eval "echo $x"` | ask | **allow** |
| `bash -c "$x"`, `bash -c "$cmd arg"`, `pwsh -c "$x"`, `cmd /c %X%`, `eval $cmd`, `iex $cmd` | ask | ask |
| `bash -c "echo hi; $cmd"` (proměnná v druhém statementu), `bash -c "$(cat cmd.txt)"` | ask | ask |
| `pwsh -Command "git reset --hard; Write-Host $x"` | ask | **deny** (literál je vidět) |

#### Opraveno — 🔴 blok, kterým statement nekončí, se nerozebíral (bod 6, nález Amber K2)

`Get-ScriptBlockBody` hledal tělo jen tehdy, když statement závorkou **končil**;
`if ($x) { rm -rf src } else { git status }`, `try { git reset --hard } catch { … }`,
`{ rm -rf src } # pozn.` i `ForEach-Object -Begin { $i = 0 } -Process { $_.Delete() }`
procházely **nerozebrané → allow**. Stará díra (0.1.4), ne regrese. Nová
`Get-ScriptBlockBodies` vrací **všechny** bloky statementu; hlava před blokem se
rozebírá dál (K1 drží: `rm -rf {src,lib}` deny, `git stash drop stash@{0}` deny,
`@{ Path = 'src' }` allow). Výrok 2 Amber: práh „bez vzorku se brána nemění" chrání před
**zúžením**, ne před zavřením díry; cena je **neznámá** (`n = 0` říkalo, že brána tvar
nezachytila), kontrolní skupina je podmínka: `if ($x) { git status } else { git log }`,
`try { dotnet build } catch { … }` se ptát nesmějí.

#### Opraveno — hláška u `rm -rf /srv` lhala o příčině (bod 4, nález Amber I6)

`/xxx` do tří znaků je od přepínače `cmd` (`/s`, `/q`) k nerozeznání, cíl se nebere —
a prázdný seznam cílů padal do větve „mazání z roury". Nový tvar `shortAbsolutePath`
říká skutečnou příčinu; rozhodnutí `ask` beze změny. Kontrolní skupina: skutečné
mazání z roury (`Get-ChildItem src -Recurse -File | Remove-Item -Force`, Metis 8) nese
`deleteFromPipeline` dál.

#### Brána — seznam interpretů na dvou místech (bod 1, N15)

`gate.codeInterpreters` a hardcoded list v `Get-CommandLeaf` hlídá test: **rovnost**
množin a **neprázdnost** obou stran (prázdná = prázdná by byla neviditelný fail-open).
Mutanti: `lua` jen v konfiguraci → červená; prázdná extrakce → červená. Refaktor
podpisů zůstává v backlogu — brána kryje tutéž škodu za jedno kolo.

#### Opraveno — zpětné apostrofy se braly regexem bez escapu a uvozovek (N-H6)

`git merge -m "… \`& \$cmd\` …"` skončil `invoked`: `Split-CommandLine` hledal páry
zpětných apostrofů regexem, `\`` (literál v Bashi) i jednoduché uvozovky ignoroval.
Nový `Get-BacktickSubstitution` čte escape a jednoduché uvozovky; v PowerShellu je
zpětný apostrof escape a substituce se nepřebírá vůbec. `echo "\`git reset --hard\`"`
zůstává `deny`.

#### Opraveno — dosazení do hlášek přes `-replace` rozvíjelo `$_`, `$1`, `${x}` (N-H2)

Všech 16 míst v `gate.ps1` (a 8 v `secrets.ps1`) dosazuje `{placeholder}` přes
`.Replace()`. Do 0.1.11 hláška `secretFile` s cestou `$_.Key` zněla
„…(čtení/zápis souboru se secrets ({path}).Key)" — `$_` je v regex náhradě celý vstup.

### D2 — `secrets.ps1`

#### Zúženo — chráněné jméno se posuzuje jen v pozici cesty (bod 12, N-H1, N-H6)

Kandidátem byl každý token s tečkou a každý řetězec v uvozovkách: identifikátory
`$_.Key`, `SelectOption.Key` končily **`deny secretFile`** (3 ze 7 `deny` ve vzorku,
včetně měřicího příkazu fáze 1 a prvního pokusu o commit), próza v těle heredocu se
jmény `id_rsa`, `secrets.json` taky (1 ze 7). Pozice cesty od 0.2.0: cíl přesměrování,
hodnota `--opt=`, poziční argument `secrets.pathCommands`, argument
`secrets.writeCommands`, u ostatních příkazů jen token vypadající jako cesta (lomítko,
`~`, `%`, tečka na začátku, `id_*`, přesné chráněné jméno). Tělo heredocu s datovým
hostem (`secrets.dataHeredocHosts`: `cat`, `tee`, `git`, …) jsou data. **N14 drží**
(podmínka, ne bonus): `< ~/.ssh/id_rsa`, `--file=~/.ssh/id_rsa`, cesta v rouře,
`xargs cat`, `bash <<EOF` / `python - <<PY` s příkazem čtoucím secret → `deny`.
Případy žijí v `tests/fixtures/task106-bod12.json` (26 řádků), ne v příkazové řádce
sady. ⚠️ Mez: `openssl -in private.pem` (nelistovaný program, jméno mimo
`protectedBaseNames`) projde — rozšíření je `secrets.pathCommands`, ne kód.

#### Opraveno — `isWrite` byl jeden příznak na celý příkaz (bod 9, N-H3)

`cat ~/.claude/settings.json 2>/dev/null` mělo `>` v `2>/dev/null`, takže **čtení**
skončilo „zápis do souboru, kterým se brána vypíná" (2× ve vzorku; u
`settings.local.json` jen špatná věta, u `settings.json` falešný dotaz). Zápis je od
0.2.0 vlastnost **kandidáta**: cíl `>`/`>>` (i `2> soubor`; `2>&1` je deskriptor), argument
`tee`/`Set-Content`/`Out-File`/`Add-Content`. Pár nad týmž souborem: `cat
.claude/settings.local.json 2>/dev/null` → `ask` „čtení…", `echo x >
.claude/settings.local.json` → `ask` „zápis…" — obojí ask, texty různé.

#### Změněno — glob podle celé cesty; jmenná třída u globu → audit (bod 11, N16, N26)

Glob se srovnával jen se **jménem**: `head -25 .github/workflows/*.yml` a
`ls docs/technical/*.json` končily `ask` (`*.yml` ~ `secrets.yml`; 2 ze 3 dotazů
`wildcardPath`). Od 0.2.0 (výroky 7 + 8): glob → regex nad **celou** normalizovanou
cestou (`*`/`?` nepřekračují `/`, `**` ano). Glob **míří na chráněnou cestu** → `ask`
dál, když `denyPathPatterns` sedne doslova na jeho text (`ls ~/.ssh/*`, `cp *.pem x`)
nebo když jmenuje adresář kanonické cesty ze `secrets.protectedPaths` (`cat ~/.aws/*`,
`cat .claude/*`, `cat **/credentials`). Glob jen na chráněné **jméno** (`cat *`,
`.github/workflows/*.yml`) → **audit** `secrets:wildcardName` a ticho.
🔴 **`C1` (delta review Amber 2026-09-13, vada výroku 7):** první tvar poslal do auditu i glob,
který na secret **míří vzorem** (`cat *.env`, `cat .env*`, `cat *secrets.json`) — regrese
proti 0.1.11 (`ask`). Opraveno v témž vydání: jméno globu proti `envFile.denyNames` a glob
bez zástupných znaků rovný chráněnému jménu → `ask`. Mez, která zůstává pojmenovaná
(README 9): `cat *` a `.en?` — 🔴 **bez druhé vrstvy** (`N32`, revize Ady): `permissions.deny`
kryje jen nástroj `Read`, na shellový tvar nedosáhne; auto-mode klasifikátor není pravidlo
(12 zásahů za měsíc, 0 za poslední tři sessions). Bash `*` tečkové soubory nerozvíjí,
PowerShell ano (`N40`). Spouštěč má dvě cesty: fixture adresář, nebo textové kritérium
„vzor vypisuje jméno, ne jen příponu" (Ada). `N38`: rozdíl `openssl -in server.key` (deny)
× `openssl -in private.pem` (projde) je seznam jmen, ne nástroj (README 22).
`Write-GateAudit` se přesunul do `_common.ps1` (sdílený). 🔴 **Dosah — 3 řádky
invariantu mění očekávání `ask` → `allow`** (`cat *`, `cat *.env`, `Get-Content .en?`),
přijato `-Prijmout` s citací výroků; `cat ~/AppData/…/UserSecrets/*/secrets.json`
z `deny` (vedlejší efekt jmenné logiky) na `ask` (glob = neznámý cíl).

#### Opraveno — `…KeyId` není secret (N-H4)

`envVarNameCamelPattern` vylučuje příponu `Id`/`Ids`: `$env:Gsd__Cursor__ActiveKeyId`
(4 z 5 dotazů `envVarRead` ve vzorku) mlčí; `apiKey`, `ActiveKey`, `apiKeyIndex` se
ptají dál.

### Audit má čtenáře (výrok 6 Amber)

Soubor `gate-audit.jsonl` měl 2026-09-12 **1 197 řádků a nula čtenářů**. Od 0.2.0:
① kanárek na `SessionStart` hlásí **přírůstek řádků od minulého startu** (značka
`audit-canary.json`; bez audit souboru se nic nepřipojí) — i u zprávy o ceně resume;
② `tests/_audit-report.ps1` (rozpad per tvar × rozhodnutí, `-Since`, `-Json`) volá krok
uzávěry v GSD. Teprve tím platí výrok 7 (`audit` místo ticha u jmenné třídy).

### Invariant — `-Prijmout` je bajtově neutrální (bod 14)

Hlavička `_zmeneno` se už neserializuje `ConvertTo-Json` (PS 5.1 escapuje `&`, `'`;
pwsh 7 ne — stará část hlavičky měnila bajty podle interpretu); nová věta se
**připisuje** do literálu. Generátor má `-InvariantsPath` (test nad kopií). Čtyři řádky
s rozsypaným českým textem (bod 7, výrok 4) po D1 + D2 **přeměřeny — drží**; poznámka
o původu v hlavičce `_ponechano`.

### Rozhodnutí bez kódu (README „Známá omezení")

- **bod 2** `cmd /c` escape — **prozatímně neopraveno** (výrok 9): 2 výskyty z 11 861
  příkazů, obojí 2026-08-23 (před pluginem), od 09-05 N = 0. Spouštěč: *první session,
  ve které se `cmd /c` vyskytne (N > 0).*
- **bod 3** kontejner — **přiznáno jako omezení** (výrok 3) se spouštěčem: *první
  session, která uvnitř kontejneru sahá na adresář namountovaný z hostitele.*
- **bod 5** council — text doslova; spustit, jak kvóta naběhne.
- **bod 13** `permissions.defaultMode` — **není úkol pluginu**; zápis do globálu se
  neprovádí (výrok 5). GSD zavádí `--debug-file` do postupu spouštění, aby cena
  klasifikátoru šla změřit.

### Dosah nasazení

Plugin běží v user scope: opravy dorazí i do **HRMS a Útrat**, které si je neobjednaly.
Nejsilnější změna chování tam: bod 6 (bloky s ocasem — nové `deny`/`ask` tam, kde bylo
ticho) a bod 12 (identifikátory `.Key` už neblokují). Kanárek v těch dvou projektech je
položka Toma.

## [0.1.11] — 2026-09-08

Kolo nálezů **Ady** (N28, N30, N33–N43, N45, N46, N48–N51) nad `93a50eb`, rozhodnutí
Toma `2026-09-07/T36-Q6a = (a)`, `2026-09-08/T36-Q7 = A`, `T36-Q10 = A`, `T36-Q12 = B`.
Společné jádro tří z nich: **výjimka vyhodnocená před pravidlem je bypass** —
klasifikace rozhodla dřív, než se kdokoli podíval na text.

### Opraveno — 🔴 obcházení `deny` → `allow` (N28)

`Test-DatabaseRule` vyhodnocovala marker *„SQL ze souboru"* **před** destruktivností
viditelného SQL. Marker přitom `Get-SqlText` přidává **vedle** textu z `-c`, takže
k libovolnému destruktivnímu příkazu stačilo přilepit `< /dev/null` nebo `-f x.sql`:

| tvar | do 0.1.10 | od 0.1.11 |
|---|---|---|
| `psql -h prod -c "DROP TABLE x" < /dev/null` | **allow + audit** | `deny` |
| `psql -h prod -f m.sql -c "DROP TABLE x"` | **allow + audit** | `deny` |
| `psql -h localhost -c "DROP TABLE x" < x` | **allow + audit** | `ask` |
| `psql -h prod -f m.sql` (kontrolní) | allow + audit | beze změny |

Do 0.1.8 přednost markeru degradovala `deny` jen na `ask`, proto si toho nikdo
nevšiml; `T-10` z ní udělala `allow`. Oprava je **pořadí**, ne nové pravidlo:
destruktivnost se počítá nad SQL **bez markeru**, audit se uplatní až když nic
viditelného nestřílí. Hláška a tvar u `deny` beze změny.

🔴 **A-1 (review Amber, kolo 1) — táž třída o jeden řádek níž.** První oprava zavřela
bypass jen pro SQL v **textu**. Destruktivnost ale nese ještě **jméno programu**
(`dropdb` — a ten je v `sqlClients`, takže marker dostane taky) a `dotnet ef database
drop`. Audit byl podmíněný **užší** veličinou (`$sqlDestructive`), než na kterou se
ptá pravidlo (`$destructive`):

| tvar | do 0.1.10 i po první opravě | od 0.1.11 |
|---|---|---|
| `dropdb -h prod mydb < /dev/null` | **allow + audit** | `deny` |
| `dropdb -h prod mydb -f x.sql` | **allow + audit** | `deny` |
| `dropdb -h localhost x < /dev/null` | **allow + audit** | `ask` |

`$destructive` i `$update` se teď počítají **před** větví auditu. Poučení je obecnější
než ten řádek: *„vyhodnotit výjimku až po pravidle" nestačí — musí se vyhodnotit po
**celém** pravidle; zúžená podmínka vypadá jako táž podmínka.*
ℹ️ `dotnet ef` v `sqlClients` **není**, takže marker nikdy nedostane — ověřeno měřením
(`drop` i `drop < /dev/null` dávají shodně `ask`); v podmínce stojí pro úplnost.

### Opraveno — rozlišovač „obsah proměnné se spustí" neodpovídal kódu (N34, volba i)

README od 0.1.10 tvrdilo, že `ask` zůstává tam, kde se obsah proměnné **spustí**.
Skutečný rozlišovač v kódu byl **„PowerShell operátor `&`"** proti všemu ostatnímu,
takže `eval $cmd`, `bash -c "$x"`, `sh -c "$x"`, `cmd /c %X%`, `pwsh -c $x`
i `Start-Process $x` spouštěly obsah proměnné stejně — a končily auditem.
Všechny nesou nově příčinu **`invoked`** → `ask`.

- ➕ **`. $x`** (dot-source, N33) se řeší jako operátor vedle `&`, ne jako `exe` —
  kdyby se čekalo na `Split-Arguments`, byl by argv[0] jen tečka a příznak by se ztratil.
- ➕ **`iex` / `Invoke-Expression`** (N33 zúžený): literál se **rozebere** jako tělo
  `bash -c` (`iex 'git reset --hard'` → `deny`, `iex 'git status'` → nic), proměnná
  spadne do `invoked`. `askPatterns.invoke-expression` zůstává jako pás pro tvary,
  které sem nedojdou (`"x" | iex`, `iex` bez argumentu).
- 🔴 **Proměnná jako CESTA není kód** (N49): `pwsh -File $p`, `bash $script`
  i `Start-Process -FilePath 'pwsh' … -RedirectStandardOutput $log` zůstávají beze
  změny — platí omezení 1 (skript souborem je neprůhledný).
- **Hodnota a výraz** (`"EXIT=$x"`, `$out | Select-String`, `[Math]::Truncate($x)`,
  `$TOOL git push`) zůstávají auditem.

### Opraveno — destruktivní literál pod nerozebratelnou hlavou (N35, N50)

Sourozenec N28: klasifikace před pohledem na text. Nový klíč
`gate.rawDestructiveTokens` dělá nad `Leaf.Raw` týž token-test, jaký 0.1.10 zavedla
nad tělem interpretu — pro příčiny `variable`, `heredocUnterminated` a `depth`.
`ask`, ne `deny`: hlavu rozebrat neumíme, takže kontext neznáme.

Tím se **ruší** cena pojmenovaná v 0.1.10: `Where-Object { … -or (git reset --hard) }`
a `ForEach-Object { $_.Delete() }` jsou zase `ask`. **Cena nad výpisem 46 skutečných
dotazů ze 7. 9.: 0.**

- `opaque.depth` a `opaque.heredocUnterminated` → **`ask`** (obě mají ve výpisu
  46 dotazů **0 výskytů**, takže default `ask` nestojí ani jeden dotaz navíc).
- **N50, asymetrie s důvodem:** `DELETE FROM` je v `rawDestructiveTokens`, ale
  **není** v `interpreterDestructiveTokens` — tělo interpretu běžně nese SQL řetězce
  s `WHERE`, které token-test ověřit neumí.

### Opraveno — 🔴 částečný override zahazoval zbytek klíče (N37, N42, N43; TASK-106 bod 10)

`Get-HookConfig` slučuje **jednoúrovňově nad každým top-level objektem**: objekt se
sloučí o jednu úroveň, pole a skaláry se nahrazují celé. Do 0.1.10 zahodilo
`{"gate":{"opaque":{"variable":"ask"}}}` i `denyPatterns` a `allowedRemoveRoots` —
takže `git reset --hard` přestal být `deny` a zároveň `rm -rf bin` **začal** být
`deny`. Šlo to oběma směry, proto se to nepoznalo.

**N43:** táž stavba je u `secrets` — `{"secrets":{"envFile":{…}}}` by zahodilo
`denyPathPatterns`, tedy `id_rsa`, `.envrc` i `secrets.json`. Pravidlo je proto
**generické**, ne vyjmenované pro `gate`. Sekce `K2-1` v sadě změnila roli
z **dokladu omezení** na **doklad opravy**; `secrets.tests.ps1` nese případ N43.
ℹ️ Věta *„tvar hlubšího slučování je rozhodnutí do v0.2"* (N42) tím **přestala platit**.

### Změněno — audit v `bypassPermissions` se přizná (N36 / `T36-Q7 = A`)

V `bypassPermissions` nad pluginem už žádná vrstva není, takže audit tam neznamená
„rozhodne o tom Claude Code". Řádek proto nese `"decision":"allow-bypass"` místo
`"allow"`. **Nic se neblokuje** — evidence jen přestává tvrdit, co v tom režimu
neplatí. Mapuje se ve `Write-GateAudit`, aby na to nešlo u jednoho volání zapomenout.

### Změněno — sada rozlišuje ticho od `permissionDecision: allow` (N46)

Plugin **žádný allow writer nemá** (`_common.ps1` umí jen `Write-DenyDecision`
a `Write-AskDecision`), takže každý řádek `allow` v invariantu je tvrzení o **tichu**
(prázdný stdout + `exit 0`). `Get-Decision` vrací pro `permissionDecision: allow`
nově `DECISION-ALLOW`, což se nerovná žádnému očekávání — takový hook zčervená na
**každém** řádku, ne jen tam, kde si toho někdo všimne. Slovo `silent` se nezavádí
(jeden slovník); fixtura 46 příkazů ho přejmenovala na `allow`.

### Přidáno — `-Prijmout` u generátoru invariantu (N38)

Změna **očekávání** byla dosud jediný úkon nad invariantem bez nástroje a bez stopy.
`tests/_generate-invariants.ps1 -Prijmout "<citace>"` přepíše jen řádky, na kterých
generátor hlásí **spor**, a do hlavičky `_zmeneno` doplní datum, citaci, směr a výčet.
Bez citace se nezapíše nic. Ruční editace `expect` je v README pojmenovaná jako zakázaná.

### Neuděláno vědomě — sloučení `gate` + `secrets` do jednoho procesu (`T36-Q10 = A`)

`Q10 = A` padlo nad **součtem** dvou studených startů. Claude Code ale spouští hooky
téhož matcheru **paralelně**, takže úsporu musí ukázat **wall-time**. Změřeno
(12 běhů po zahřívacím kole, `powershell.exe` 5.1, payload `git status --short`, medián):

| veličina | ms |
|---|---|
| společná část (start + `_common.ps1` + `defaults.json`) | 432 |
| `gate.ps1` sám | 752 |
| `secrets.ps1` sám | 595 |
| **oba souběžně (dnešní skutečnost)** | **762** |
| odhad sloučeného (`gate + secrets − společná část`) | 915 |

Souběžný běh stojí ≈ **max** z obou, ne součet. Sloučení by bylo o **152 ms
pomalejší**; hranice „úspora ≥ 300 ms" nesepnula, takže `hooks/hooks.json` zůstává
se dvěma záznamy `PreToolUse`. Skutečná páka je **432 ms společné části na hook**,
ne sloučení → v0.2.

### Opraveno — dokumentace, která lhala

- **Omezení 10** tvrdilo *„SQL, které v příkazu není vidět, končí `ask`"* — od 0.1.9
  to platilo jen pro `$sql | psql`; `-f`, `<`, `<<<` i `cat x.sql | psql` končily
  auditem, a táž README to o pár obrazovek výš říkala správně (N30).
  🔴 **A oprava toho omezení lhala podruhé** (nález Amber K-2): napsala jsem
  *„dotaz zůstává jen u `$sql | psql` (tvar `sqlFromPipe`)"* — nepravda dvakrát.
  Dotaz v té třídě **nezůstal žádný** a `$sql | psql` nese `opaque:variable`
  (hlava je proměnná), zatímco `sqlFromPipe` nese `cat x.sql | psql`. Věta je
  nahrazená **tabulkou tvarů** a tu drží sekce `K-2` v `gate.tests.ps1`, která
  kontroluje **id tvaru v auditu**, ne jen rozhodnutí. TASK-106 bod 8 to přitom celou
  dobu popisoval správně — lhala README.
- **Omezení 2 a 8** popisovala rozlišovač, který v kódu nebyl (N34).
- **Omezení 6** neslo cenu, kterou N35 zrušila — citováno jako zrušené, ne smazáno.
- **Omezení 19** přiznává, že v bypassu druhá vrstva není (`T36-Q7 = A`).
- **Omezení 20** vysvětluje asymetrii `DELETE FROM` (N50); **21** je nové (N35).
- **§Konfigurace** popisuje jednoúrovňové slučování; **§Regresní invariant** nese
  `allow` = ticho a `-Prijmout`.

### Testy

Invariant: **7 řádků** `allow` → `ask` nástrojem `-Prijmout` (`T36-N34 (i) / T36-N35`),
**žádný `deny` řádek se nezměnil**; 44 nových řádků v prvním kole a 7 v kole po review
(A-1), tedy **548 → 599** (deny 288 / ask 117 / allow 194). Přírůstek kola 1 je
`42 vloženo / 0 smazáno` — čistě append, žádné existující očekávání se nezměnilo.

🔴 **Změřeno, ne odhadnuto** (opravená očekávání proti zadání):
- řetěz **obalů** (`sudo nice nohup … rm -rf src`) hloubku nezvyšuje —
  `Get-WrapperTail` je strhne najednou; `depth` vyrábí každá **závorka** a přiřazení.
- neukončený heredoc s destruktivním **tělem** končí `deny`, ne `ask` — tělo se
  rozebere a `deny` přebije `ask` z příčiny `heredocUnterminated`.

## [0.1.10] — 2026-09-07

**Rozhodnutí Toma 2026-09-07/`T36-O5 = A`:** *„chci, abychom budovali automatizaci,
ne že se vše zasekne, protože musím 50× potvrdit; udělej to dle best practices
s cílem na automatizaci a výkon."* Volbu varianty (audit + vrstva Claude Code)
udělala Amber v jeho pověření.

Přehodnocuje **T-10 A** z 0.1.9, kde se u nerozebratelného obalu rozhodlo *„nechat
ask"*. To padlo nad session, kde plugin měl **0** dotazů. Nad reálnými čísly ze
7. 9. (tři sessions — GSD, HRMS, Útraty) to vypadá jinak: **45 dotazů ze 46** byla
třída „nejde rozebrat", a skutečné zásahy §6 mezi nimi byly **dva**.

### Změněno — „nerozebratelné" už není jedna třída

Nerozebratelný list nese **příčinu** a politiku k ní určuje `gate.opaque`:

| příčina | co to je | 0.1.9 | 0.1.10 |
|---|---|---|---|
| `variable` | proměnná v pozici příkazu, obal s proměnnou (`bash -c "$x"`, `cmd /c %X%`, `"EXIT=$code"`) | ask | **audit** |
| `interpreter` | `python -c` / `node -e`, tělo heredocu interpretu | ask | **audit** (s výjimkou níže) |
| `heredocUnterminated` | neukončený heredoc | ask | **audit** |
| `depth` | zanoření hlubší než 5 | ask | **audit** |
| `invoked` | `& $cmd` — obsah proměnné se **spustí** | ask | **ask** |
| `encoded` | `-EncodedCommand` a jeho zkratky | ask | **ask** |

🔴 **`audit` znamená, že hook MLČÍ** — zapíše řádek do
`${CLAUDE_PLUGIN_DATA}/gate-audit.jsonl` (`opaque:<příčina>`) a **nevydá rozhodnutí**.
Není to `permissionDecision: allow`: ten by přeskočil vrstvu oprávnění Claude Code
(klasifikátor auto režimu, `permissions.*`), a právě ta má nadále rozhodovat.
Plugin přestává být **poslední** instancí parseru a stává se první — viz README
*„Tři rozhodnutí, ne dvě"*. Sada ten rozdíl tvrdí **prázdným stdout**, ne slovem
„allow"; jinak by mutant *„vracej `allow` místo ticha"* prošel.

Hodnoty jsou `audit | ask`; **cokoli jiného se čte jako `ask`** (fail-closed — překlep
v projektovém override nesmí bránu tiše otevřít). Projektový override nahrazuje celý
klíč `gate` (mělké slučování).

### Přidáno — destruktivní token v kódu interpretu → `ask` (`gate.interpreterDestructiveTokens`)

Kód interpretu se nerozebírá, ale **jméno destruktivního volání v něm vidět je**.
Prostý **case-sensitivní** výskyt tokenu v těle vrací `ask` (tvar
`interpreterDestructive`), takže `python -c "shutil.rmtree('x')"` se ptá dál, kdežto
`python -c "print(1)"` projde. Je to test na **token, ne parser jazyka**.

`.rmSync(`, `.rmdirSync(` a `.unlinkSync(` jsou v seznamu proto, že Node se píše
`require('fs').rmSync(`, ne `fs.rmSync` — seznam postavený jen na druhém tvaru by
minul invariantní řádek `node -e "require('fs').rmSync('src')"`.

**Kontrolní skupina:** 15 příkazů HRMS a Útrat ze 7. 9. (`pathlib`,
`read_text`/`write_text`, `io.open`, `node -e require(…)`) nenese ani jeden token
a končí auditem.

### Přidáno — `[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory/DeleteFile` = mazání ⑤

Druhé jméno téže operace jako `[IO.Directory]::Delete`. Do 0.1.9 propadalo do třídy
„nerozebratelné" — a jakmile ta třída přestala být dotazem, byla by z toho **díra**:
jsou to **jediné dva pravé zásahy §6** ze 46 dotazů 7. 9. Prochází teď stávajícím
pravidlem: cíl v proměnné → `ask` (`netDeleteVariable`), literál mimo povolené složky
→ `deny`, literál v `bin` → `allow`.

`SendToRecycleBin` se **nerozlišuje** — brána §6 zní „mazání", ne „nevratné mazání";
rozlišení je rozhodnutí zadavatele, ne pluginu.

### Beze změny — co ask zůstává

`& $cmd` · `-enc` / `-EncodedCommand` · `ssh host "příkaz"` i `ssh prod <<EOF` ·
`git -c alias.…` · krátká absolutní cesta `/xxx` · mazání z roury · čtení
`.claude/settings.local.json`.

🔴 `ssh prod <<EOF` a `python <<EOF` sdílely do 0.1.9 **jednu podmínku**. Rozdělily se:
kód interpretu jde politikou `opaque.interpreter`, cizí stroj zůstává `ask` — pravidla
nad cestami tam neplatí a audit na našem stroji o cizím stroji netvrdí nic.

### Regresní invariant — 11 řádků změnilo očekávání

Soubor je append-only a řádek z něj odchází **jen s citovaným rozhodnutím**. Tady
neodešel žádný: jedenácti řádkům se změnilo `expect` z `ask` na `allow`, seznam
i citace jsou v hlavičce `tests/fixtures/invariants.json` (klíč `_zmeneno`).
**Žádný řádek s `deny` se nezměnil** — doklad je prázdný výstup
`git diff tests/fixtures/invariants.json | grep '^-.*"deny"'`, celý diff je
`12 vložených / 11 odebraných` řádků.

🔴 **Dva z těch jedenácti stojí za pojmenování**, protože je zadání nejmenovalo:
`Get-ChildItem | ForEach-Object { $_.Delete() }` a
`Where-Object { $_.Name -eq 'x' -or (git reset --hard) }`. Obojí je třída `variable`,
takže po téhle změně je plugin nezastaví. Je to **důsledek `T36-O5 A`**, ne díra
navíc — ale patří to do textu, ne jen do součtu.

### Opraveno — `&` přežije dělení příkazové řádky (jinak by `invoked` byla mrtvá větev)

Změřeno při implementaci: `Split-CommandLine '& $cmd'` vracelo `$cmd` — `&` je
v seznamu oddělovačů, takže informace „obsah proměnné se **spustí**" se ztrácela
ještě před rozborem. Do 0.1.9 to nevadilo (obojí končilo `ask`); od 0.1.10 na tom
rozdílu stojí celá kontrolní skupina, a bez opravy padlo `& $cmd` z `ask` na audit.
CHANGELOG 0.1.9 tenhle mechanismus popsal (*„informace o `&` se ztrácí už ve
`Split-CommandLine`"*) — teď je opravený, ne jen zaznamenaný.

`Split-Unquoted` / `Split-CommandLine` proto přijímají `KeepSeparators`: oddělovač
z toho seznamu **přežije a připojí se k následujícímu segmentu**. 🔴 Výchozí hodnota
je **prázdná** a `secrets.ps1` ji nemění — segment začínající na `&` by mu posunul
`argv[0]` a `& cat secrets.json` by přestal být vidět. Marker si vyžádá jen
`Get-CommandLineLeaves`, protože `Get-CommandLeaf` vedoucí `&` strhává hned na
začátku. Kontrolní skupina: `& { rm -rf src }`, `& { git status; rm -rf src }`,
`& (git reset --hard)` a `foo & rm -rf src` zůstávají `deny`, `& { Get-Date }`
a `dotnet test &` zůstávají bez rozhodnutí.

### Dokumentováno — mělké slučování + rostoucí klíč `gate` (nález K2-1 review Amber)

`Get-HookConfig` nahrazuje **celý** top-level klíč. Override, který nese jen jednu
hodnotu z `gate`, tedy zahodí `denyPatterns`, `askPatterns`, `allowedRemoveRoots`,
`shapes`, `sqlClients`, `codeInterpreters` i `interpreterDestructiveTokens`. Je to
**stará vlastnost** (0.1.x), ale 0.1.10 do `gate` přidává dva klíče a README dosud
takový částečný override sám předváděl.

Změřeno s override `{"gate":{"opaque":{"variable":"audit"}}}`:

| příkaz | bez override | s ním |
|---|---|---|
| `git reset --hard`, `git branch -D x`, `git filter-branch` | `deny` | **žádné rozhodnutí** |
| `rm -rf bin` (povolená složka) | žádné rozhodnutí | **`deny`** |
| `rm -rf src`, `psql -h prod -c "DROP TABLE x"`, `& $cmd` | deny / deny / ask | beze změny |

🔴 Jde to **oběma směry**: brána ztratí tvary, které měla držet, a zároveň začne
blokovat běžnou práci. Pravidla žijící v kódu drží dál — proto se ztráta nepozná podle
toho, že by „přestalo fungovat všechno".

**Kód se nemění.** README §Konfigurace dostal vlastní 🔴 sekci s tou tabulkou a příklad
už částečný `gate` nepředvádí; sada nese sedm případů jako **doklad omezení**
(`K2-1: override gate bez denyPatterns`), včetně kontrolní skupiny pro pravidla v kódu.
Tvar hlubšího slučování (per podklíč `gate.*`, nebo `opaque` a
`interpreterDestructiveTokens` na top-level) je rozhodnutí do **v0.2** — nese ho
TASK-106 bod 10.

### Přidáno — fixtura `tests/fixtures/ask-vypis-2026-09-07.json`

Všech **46** příkazů, na které se 0.1.9 ptal v sessions 7. 9. (GSD 31, HRMS 5,
Útraty 10), doslovně. Naměřeno nad `9e4720b`: **45 ask, 1 ticho** (to jedno je blok
*„Inventura MCP"* — tam se ptal hook `secrets`, ne `gate`). Po 0.1.10:
**44 × ticho, 2 × ask**.

## [0.1.9] — 2026-09-07

**Rozhodnutí Toma 2026-09-07/T36-F1 T-10 A** nad čísly ze sekce *Dotazy a bloky*
(hlášení 08). Není to změkčení pravidel, ale **změna rozsahu brány, kterou vydal
zadavatel** — a u SQL ji doprovází evidence.

### Změněno — `git rebase` a `git clean -fdX` → `allow`

| příkaz | 0.1.8 | 0.1.9 |
|---|---|---|
| `git rebase main`, `git rebase -i HEAD~3` | ask | **allow** |
| `git clean -fdX` (jen ignorované soubory) | ask | **allow** |

**Kontrolní skupina:** `git clean -fdx` a `git clean -fd` zůstávají `deny`. Rozdíl je
**case-sensitivní** a drží ho `-ccontains`.

### Změněno — SQL, které v příkazu není vidět → `allow` + zápis do JSONL

| příkaz | 0.1.8 | 0.1.9 |
|---|---|---|
| `psql -h prod -f migrace.sql` | ask | **allow** + audit |
| `psql -h prod < drop.sql` | ask | **allow** + audit |
| `psql -h prod <<< $SQL` | ask | **allow** + audit |
| `cat drop.sql \| psql -h prod` | ask | **allow** + audit |

Zapisuje se do `${CLAUDE_PLUGIN_DATA}/gate-audit.jsonl` (`gate.auditFile`), a to
**událost, ne obsah**: čas, nástroj, id tvaru, rozhodnutí. Text příkazu do souboru
nejde (zadání §4 bod 8 — riziko úniku). Bez `CLAUDE_PLUGIN_DATA` se nezapisuje nic
a hook mlčí; evidence je **fail-open** a nesmí být důvod, proč brána spadne.

🔴 **Kontrolní skupina je tu nejdůležitější část:** SQL, které v příkazu **vidět je**,
se rozhoduje dál podle hostitele — `echo "DROP TABLE users" | psql -h prod` a
`psql -h prod -c "DROP TABLE x"` zůstávají `deny`, `psql -h localhost -c "DROP TABLE x"`
zůstává `ask`, `psql -h prod <<< "DROP TABLE x"` zůstává `deny`.

### Beze změny — třídy `ask`, které zůstávají

`.claude/settings.local.json` (čtení) · nerozebratelný obal (`bash -c "$CMD"`) ·
`ssh host "…"` · krátká absolutní cesta `/xxx` · spuštění proměnné (`& $cmd`).
Rozhodnutí T-10 A jmenuje i to, co se **nemění**, a sada to drží fixturami.

### Opraveno — N27 (vlastní nález): generátor invariantu neodlišil `-fdX` od `-fdx`

Hashtable `@{}` je v PowerShellu **case-insensitive**, takže klíč
`gate|Bash|git clean -fdX` a `…-fdx` splynuly v jeden a generátor hlásil **falešný spor**
(„invariant říká allow, sada deny"). A je to přesně ten rozdíl, na kterém tahle brána
stojí. Porovnává se nově **ordinálně**.

### 🔴 Co se z T-10 A NEPODAŘILO dodat

`$sql | psql -h prod` (PowerShell) zůstává **`ask`**. Změřeno: ten dotaz nepochází ze
SQL pravidla, ale z pravidla Z3 („proměnná v pozici příkazu"), protože `$sql` je
samostatný článek roury. Pokus rozšířit `Test-ExpressionStatement` o holou proměnnou
jsem **zavedla a zase vzala zpět** — změřeno, že tím `& $cmd` spadlo z `ask` na `allow`
(informace o `&` se ztrácí už ve `Split-CommandLine`). Otevřít tenhle tvar bez otevření
spuštění proměnné vyžaduje přepis toho, jak `Split-SqlPipeline` vrací `Rest` — to je víc
než tenhle bod. → **v0.2**.

### Invariant

Devět řádků **změnilo očekávání**. Append-only pravidlo dovoluje řádek změnit jen
s citovaným rozhodnutím, takže citace stojí **přímo v řádku** (pole `since`:
`… | zmeneno rozhodnutim Toma 2026-09-07/T36-F1 T-10 A`). 536 → **548** řádků.

## [0.1.8] — 2026-09-07

Revize Ady nad kolem 6. Obě položky jsou **následky oprav z kola 6**, ne nové tvary —
což je přesně ta třída, kterou tenhle projekt už dvakrát zaplatil regresí.

### Opraveno — N24: přepínače `ssh` s hodnotou nafukovaly počet pozicionálů

Oprava N21 počítala „host + příkaz" jako dva pozicionální argumenty. Jenže přepínač
**s hodnotou** vypadá stejně:

| příkaz | 0.1.7 | 0.1.8 |
|---|---|---|
| `ssh -i key.pem host` | **ask** | allow |
| `ssh -p 2222 host` | **ask** | allow |
| `ssh -o BatchMode=yes host` | **ask** | allow |
| `ssh -l tomas host` | **ask** | allow |

V `bypassPermissions` by z toho bylo `deny` — falešný blok na úplně běžné práci.
Tabulka value-flagů je vedená stejně jako u obalů (`Get-WrapperTail`); jinak se ty dvě
rozejdou, což je přesně nález G2.

**Kontrolní skupina:** `ssh -i key.pem host "rm -rf /"` a `ssh host "rm -rf /"` = `ask`
(příkaz tam pořád je), `ssh host` = `allow`.

### Opraveno — N25: `UPDATE ONLY t SET` a `UPDATE t AS x SET` míjely vzor

`\S+` je **jeden token**, takže vzor z N22 neviděl ani `ONLY`, ani alias. Obojí je
platný SQL a obojí přepíše celý obsah tabulky:

| příkaz | 0.1.7 | 0.1.8 |
|---|---|---|
| `psql -h prod -c "UPDATE ONLY users SET active=0"` | allow | **deny** |
| `psql -h prod -c "UPDATE users AS u SET active=0"` | allow | **deny** |

**Kontrolní skupina:** tytéž tvary **s `WHERE`** zůstávají `allow`.

### Opraveno — N26: `secrets` se ptal na `*` uvnitř řetězce

🔴 **Našel to Tom na živé konzoli**, ne review ani test — a je to nejnepříjemnější druh
falešného bloku, protože trefil úplně obyčejnou práci: **hvězdičky z markdownu v commit
message.**

| příkaz | 0.1.7 | 0.1.8 |
|---|---|---|
| `git commit -m "**2**"` | **ask** | allow |
| `echo **2**` | **ask** | allow |
| `Write-Host "**2**"` | **ask** | allow |

Mechanismus: kandidátem na cestu byl **každý** řetězec v uvozovkách, a glob `**2**`
sedne na `server.p12` ze seznamu chráněných jmen. Hook se pak ptal na text commitu.

Nově se zástupný znak vyhodnocuje **jen tam, kde ho shell doopravdy rozvine**:
nad **neuvozeným** tokenem v **pozici cesty** u příkazu, který soubory čte nebo kopíruje
(`secrets.pathCommands`). V Bashi se `*` v uvozovkách nerozvine a v PowerShellu řetězec
negloboval nikdy — pravidlo tedy odpovídá tomu, co se stane.

**Kontrolní skupina:** `cat *.env` a `Get-Content .en?` = `ask` (drží), `cp *.pem /tmp/x`
= `ask`, `cat .env` = `deny`, `[IO.File]::ReadAllText('.env')` = `deny` (literál
v uvozovkách se pořád čte — jen se u něj neřeší glob).

### Konvence — kontrolní skupina je fixtura, ne věta

Doporučila Ada, přijato: **každý řádek kontrolní skupiny, na který se odvolává review
nebo hlášení, musí existovat jako případ v sadě.** Věta v hlášení je tvrzení; případ
v `gate.tests.ps1` je doklad, který se přehraje při příštím kole. Zapsáno do README,
sekce *Testy*.

## [0.1.7] — 2026-09-06

Kolo 6. Nálezy **Ady** (N19–N22) — sousední třída k obalům: ne *„co se rozebírá"*, ale
**„kde se který průchod spouští"**. Plus jeden vlastní nález (N23), který z měření vypadl.

### Opraveno — N19: řetěz průchodů se v zanoření nespouštěl

Hlavní běh proháněl příkaz **třemi** průchody — `Split-Heredoc` → `Split-SqlPipeline` →
`Split-CommandLine`. Rekurze (`bash -c`, `cmd /c`, `eval`, tělo bloku, tělo heredocu
do shellu) volala **jen poslední článek**, takže dva speciální průchody v zanoření
neexistovaly:

| příkaz | 0.1.6 | 0.1.7 |
|---|---|---|
| `bash -c 'echo "DROP TABLE users" \| psql -h prod'` | CRASH | deny |
| `sh -c "psql -h prod <<SQL … DROP TABLE x … SQL"` | allow | deny |
| `eval 'echo "DROP TABLE x" \| psql -h prod'` | CRASH | deny |

🔴 **Vzdálený `DROP` nemá zálohu v `permissions.deny`** — prefixové pravidlo rouru neumí —
takže ho držel **jen hook**. Řetěz proto žije v jediné funkci (`Get-CommandLineLeaves`)
a volají ji obě strany; čtvrtý průchod se do zanoření dostane sám.

Kontrolní skupina: `bash -c 'git log | head'` = `allow`, `echo … | psql -h prod` (holý
tvar) = `deny`, `bash -c 'psql -h prod -c "DROP TABLE x"'` = `deny`.
**Mutant** (zanoření zpět na `Split-CommandLine`): první dva řádky tabulky zezelenají.

### Opraveno — N20: přesměrování stdin do SQL klienta se nečetlo jako SQL

| příkaz | 0.1.6 | 0.1.7 |
|---|---|---|
| `psql -h prod < drop.sql` | allow | ask |
| `psql -h prod <<< $SQL` | allow | ask |
| `psql -h prod <<< "DROP TABLE x"` | deny | deny |

Obsah souboru ani proměnné v příkazu vidět není → platí Z3 (`__SQL_ZE_SOUBORU__` → `ask`),
stejně jako u `-f` (známé omezení 10). **Literál** za `<<<` vidět je a čte se jako SQL.

🔴 **Regexem to nejde:** `psql -c "SELECT * FROM t WHERE a < 5"` má `<` **uvnitř** řetězce
a vzor nad surovým textem by z běžného dotazu udělal falešný `ask`. `Test-StdinRedirect`
proto rozhoduje nad znaky **mimo uvozovky**, včetně escapu podle shellu.
**Mutant** (funkce vrací vždy `$false`): oba první řádky zezelenají.

### Opraveno — N22: `UPDATE … SET` bez `WHERE` (rozšíření rozsahu, rozhodl Tom T-9 A)

Týž dopad jako `DELETE FROM` bez `WHERE` (T-1) a jako `TRUNCATE`: přepíše každý řádek.
Mimo lokálního hostitele `deny`, na `localhost` `ask`; `UPDATE t SET a=1 WHERE id=1`
zůstává `allow`. `WHERE` se hledá **v témž statementu**, ne kdekoli v textu.
**Mutant** (podmínka vyřazena): oba tvary zezelenají.

### Opraveno — N21: příkaz jako argument vzdáleného shellu

`ssh host "rm -rf /"` a `ssh host "psql -c 'DROP TABLE x'"` → `ask` (Z3: běží na cizím
stroji, kde pravidla nad cestami ani seznam lokálních hostů neplatí).
Podmínka je úzká schválně: `ssh host` i `ssh -T git@github.com` zůstávají `allow`.

### Opraveno — N23 (vlastní nález): jednočlánková roura v uvozovkách **shazovala hook**

`bash -c 'git log | head'` končilo `interní chyba, blokováno`. Příčina: `Split-Pipe`
vrací `return (Split-Unquoted …)`, což **zahodí čárku**, kterou si `Split-Unquoted` hlídá —
jednoprvkový výsledek se rozbalí na **řetězec** a `.Count` nad ním pod `StrictMode`
vyhodí výjimku. Fail-closed, takže ne díra — ale **falešný blok na úplně běžné práci**,
a to je cesta k vypnuté bráně.

🔴 **Opravou nebylo přidat `,@(…)` do `Split-Pipe`** — to jsem zkusila a změřila: kolem
už zabaleného pole to přidá **další úroveň** a dvoučlánková roura vyjde jako jeden prvek
(`count=1`), takže `echo … | psql -h prod` propadl na `allow`. Čárka patří tam, kde pole
**vzniká**; volající si výsledek zabaluje `@(…)`.
**Mutant** (`@()` odebráno): `bash -c 'git log | head'` zase spadne.

### Poznámka k rozporu se zprávou Ady

Ada uvedla u `bash -c 'echo … | psql -h prod'` a `eval '…'` výsledek **allow**. Naměřeno
na `3ea4571`: **CRASH → fail-closed deny** (a padal i kontrolní `bash -c 'git log | head'`).
Průchod to tedy nebyl; byl to N23. Nález N19 tím **neztrácí platnost** — dokládá ho
`sh -c "psql … <<SQL"`, který `allow` skutečně byl, a po opravě N23 i zbylé dva tvary.

## [0.1.6] — 2026-09-06

Kolo 5b. Rozsah dal Tom (rozhodnutí 2026-09-06/T36-F1 **T-7**): **jen K1 a L1**, plus K3,
pokud vyjde na pár řádků — vyšlo. Obě 🔴 jsou **regrese po opravě I1** a jdou **proti
sobě**: jedna propouštěla, druhá blokovala běžnou práci. To je podruhé za sebou, kdy
oprava zavedla regresi, takže do invariantu jdou tvary z **obou** směrů.

### Opraveno — K1: `{` není blok všude a hlava se nesmí zahazovat

Oprava I1 hledala tělo bloku u **první** `{` kdekoli a po jeho rozboru se vracela, takže
text před závorkou zmizel. Naměřeno na `f8a8032`, ve všech případech **0.1.4 rozhodovala
správně**:

| příkaz | 0.1.4 | 0.1.5 | 0.1.6 |
|---|---|---|---|
| `git stash drop stash@{0}` | deny | **allow** | deny |
| `git reset --hard HEAD@{1}` | deny | **allow** | deny |
| `git reset --hard @{u}` | deny | **allow** | deny |
| `rm -rf ${DIR}` | ask | **allow** | ask |
| `rm -rf src/${x}` | ask | **allow** | ask |
| `rm -rf {src,lib}` | deny | **allow** | deny |
| `if ($a -eq ${env:X}) { git reset --hard }` | allow | allow | **deny** |

Dvě změny, každá zavírá jinou půlku:

- **Pozice.** `{` za `@`, `$`, písmenem nebo číslicí je hashtable (`@{ … }`), proměnná
  (`${DIR}`) nebo revize (`stash@{0}`) — do zanoření se **počítá**, blok ale neotevírá.
  Kdyby jen „bailovala", zůstal by poslední řádek tabulky propustný.
- **Hlava.** Když před závorkou něco stojí, statement se po rozboru těla rozebírá
  **dál jako běžný příkaz**. `rm -rf {src,lib}` je jeden příkaz s literálním argumentem;
  tělo `src,lib` neznamená nic. Rozbalení složených závorek Bashe hook nedělá, takže
  `rm -rf {bin,obj}` je `deny` — tak to bylo i v 0.1.4.

### Opraveno — L1: tělo bloku je výraz, ne příkaz v pozici proměnné

Protisměrná regrese: od I1 se tělo bloku rozebírá vždycky, a **nejběžnější idiom
PowerShellu** tím začal končit na `ask` (v bypassu `deny`).

| příkaz | 0.1.4 | 0.1.5 | 0.1.6 |
|---|---|---|---|
| `Get-ChildItem \| Where-Object { $_.Name -like '*.cs' }` | allow | **ask** | allow |
| `Get-ChildItem \| ForEach-Object { $_.x }` | allow | **ask** | allow |
| `Get-ChildItem \| Sort-Object { $_.Length }` | allow | **ask** | allow |
| `foreach ($f in $files) { $i++ }` | allow | **ask** | allow |

Z3 („proměnná v pozici příkazu → `ask`") míří na tvar `$VAR arg`, kde se **obsah
proměnné spustí**. Čtení vlastnosti ani `$i++` nespouští nic. `Test-ExpressionStatement`
proto propustí `$_`, `$var.Prop`, `$var[…]`, `$i++` a porovnání operátorem —
a **jakákoli závorka výjimku ruší**, protože `$_.Delete()` maže a
`… -or (git reset --hard)` spustí podvýraz. Pravidlo platí **jen v PowerShellu**
(řídí se escapem skeneru): v Bashi je `$cmd -rf src` příkaz.

Kontrolní skupina drží: `foreach ($f in $files) { git branch -D $f }` = `deny`,
`{ $_.Delete() }` a `{ $_ | Remove-Item -Recurse -Force }` = `ask`,
`$_.Name -like "*.cs"` z **Bash** nástroje = `ask`.

### Opraveno — K3: escape se nepřepínal ani u heredocu

Táž třída jako I2, jen jiná větev. `bash <<'EOF' … EOF` psaný z PowerShellu se rozebíral
s backtickem místo `\`:

| nástroj | tělo heredocu | 0.1.5 | 0.1.6 |
|---|---|---|---|
| PowerShell | `bash`, `echo \" ; git reset --hard` | allow | deny |
| Bash | `pwsh`, ``echo `" ; git reset --hard`` | allow | deny |
| PowerShell | `bash`, `git reset \`+konec řádku+`--hard` | allow | deny |

Poslední řádek je bonus: `Split-Heredoc` slepuje pokračování řádku vnějším escapem,
takže se tělo rozpadlo na dva příkazy. Přepnutí escapu zavírá i to. `cmd` zůstává na
escapu hostitele — známé omezení 12.

### Opraveno — L2, L3, L4 (drobnosti z téže třídy)

- **L3** souhrn v režimu sběru tiskl `N passed / M failed` a **verdikt čte právě ten
  řádek** — režim, který nic neměří, uměl vydat zelenou. Nově řádek v režimu sběru
  **nevznikne** a verdikt hlásí „souhrnný řádek CHYBÍ". Je to čtvrtý výskyt třídy
  „hodnota z okolí", tentokrát zevnitř.
- **L2** `.DESCRIPTION` generátoru invariantu jmenoval `SINOGARD_HOOKS_COLLECT=1` jako
  způsob, jak režim zapnout. Ta proměnná od 0.1.5 sadu naopak **shodí**.
- **L4** doplněny odkazy `[0.1.4]` a `[0.1.5]`.

### Testy — opakování po překročení tvrdého stropu (změna mimo rozsah kola)

🔴 **Vynutilo si ji CI, ne nález.** Tvrdý strop 5000 ms na jeden běh hooku shodil job
`pwsh` **třikrát po sobě, pokaždé na jiném tvaru** (9001 ms, 5015 ms uvnitř potomka,
a jeden běh, kde příčina v logu nebyla) — zatímco `powershell.exe` byl zelený pokaždé
a týž tvar běží doma na `pwsh` 1,1 s. Přesně před tím varuje komentář u
`HookCeilingMs`: absolutní strop měří **zátěž stroje**, ne hook.

- běh nad stropem se **jednou zopakuje** a tvrdí se druhé měření; běh, který se
  _skutečně_ zasekl, se zasekne i podruhé (doloženo kontrolní skupinou se stropem
  dočasně sníženým na 1 ms — tvrzení tam dál padá)
- do **mediánu** jde vždycky měření **první**, aby zůstal poctivým pozorováním stroje
- řádek `doba hooku: median … max … nad 3000 ms … opakování …` se tiskne **vždy**,
  ne jen v `-Full`; dřív na CI nebyl vidět nikdy, a proto tři cykly CI hledaly příčinu,
  kterou měl říct první z nich
- měření sbírá `Invoke-Hook` sám (explicitní `Add-HookTime` v sadách zrušen), takže
  se na ně nedá zapomenout a počítají se i běhy invariantu

Opakování hook znovu **spustí**: na CI je `DRYRUN=1`, doma by u `notify` znamenalo
druhý toast — k překročení stropu tam ale nedochází (max 1671 ms / 1893 ms).
Vrací se jedním revertem.

### Neopraveno vědomě

**K2** — blok s ocasem (`if {…} else {…}`, `try {…} catch {…}`, `{…} # poznámka`) se
nerozebírá vůbec: `Get-ScriptBlockBody` chce, aby statement závorkou **končil**. Je to
stará díra, ne regrese, a leží mimo rozsah, který Tom dal. → známé omezení 16 a TASK-106.

## [0.1.5] — 2026-09-06

Páté opravné kolo, poslední před nasazením. Nejdůležitější věc není nový tvar, ale to,
že **jedna z oprav minulého kola sama otevřela díru** — a chytilo to až review, ne
regresní invariant. Proto invariant roste o oba tvary.

### Opraveno — I1: regrese po G4

🔴 G4 naučila skener držet `{ … }` pohromadě **i přes konce řádků**, ale rozbalení bloku
dělal regex ukotvený na **začátek** statementu. Víceřádkový blok za klíčovým slovem tak
příkaz schoval úplně:

```powershell
if ($x) {
  git reset --hard
}
```

→ jeden statement, `exe = if` → **allow**. Před 0.1.4 to bylo `deny`. Jednořádkové
`foreach (…) { git reset --hard }` byla stará díra téže třídy. Nově se tělo bloku hledá
kvótově korektně **kdekoli** (`Get-ScriptBlockBody`), takže na pozici bloku nezáleží;
`if ($x) { git status }` i hashtable `@{ Path = 'src' }` zůstávají `allow`.

> 🔴 **Oprava zápisu (0.1.6):** věta „na pozici bloku nezáleží" je **nepravdivá** a byla
> příčinou nálezů K1 a L1. Na pozici záleží: `{` za `@`, `$` nebo písmenem blok
> neotevírá a hlava před blokem se musí rozebrat taky. Viz [0.1.6].

### Opraveno — I2: escape se nepřepínal při sestupu do vnořeného shellu

Escape znak patří tomu shellu, který text **spustí**, ne tomu, který ho předal dál.
Bez přepnutí propadly oba směry:

| nástroj | příkaz |
|---|---|
| Bash | ``pwsh -c 'echo `" ; git reset --hard'`` |
| PowerShell | `bash -c 'echo \" ; git reset --hard'` |

Nově `Get-NestedShellLeaf`: znak se na dobu rozboru přepne a v `finally` vrátí.
`cmd /c` se dál rozebírá escapem hostitele (skutečný escape `cmd.exe` je `^`) → v0.2.

### Opraveno — I3, I4

- **I3** apostrof **uvnitř** dvojitých uvozovek není uvozovka:
  `echo "it's $(git reset --hard)"` → substituce se nenašla → allow.
- **I4** konec řádku je na Windows **CRLF**. Escape spolkl jen CR a LF zůstalo
  separátorem, takže `git reset \`+CRLF+`--hard` se rozpadlo na dva příkazy.

### Změněno — J2: režim sběru je parametr, ne proměnná prostředí

🔴 **Potřetí táž třída „hodnota z okolí"** (po `W:` a po `DRYRUN`). `SINOGARD_HOOKS_COLLECT=1`
nastavený globálně vyprázdnil sady **tiše**: bloky mimo případová pole běžely dál, `passed`
zůstalo nenulové, verdikt zelený — a **nic z ~1500 tvarů se nezměřilo**. Nově se režim
zapíná parametrem `-Collect`; proměnná prostředí sadu **shodí** (a `_ci-verdict.ps1` ji
odmítne jako druhá závora). Souhrn v režimu sběru navíc říká, že nic netvrdí.

### Přidáno — testy k J1

H4 (uvozovky uvnitř substituce) byl v 0.1.4 opraven **bez testu**, ačkoli ho CHANGELOG
hlásil opravený. Doplněno včetně kontrolní skupiny.

### Sady

gate 1485 → s rozšířeným invariantem, secrets 588, resume-cost 27, notify 39 — vše
0 failed / 0 skipped na obou interpretech. Invariant **451 → 471** řádků.

## [0.1.4] — 2026-09-06

Čtvrté opravné kolo. Sjednocený skener z 0.1.3 nezavedl žádnou novou díru — ale
**odhalil tři staré**, které minula všechna review i oba councily. Všech 15 tvarů bylo
změřeno před opravou; jedna odchylka od zadání je přiznána níže.

### Opraveno — kde končí řetězec (G1)

🔴 Skener neznal **escape znak před uvozovkou**. `echo \" ; git reset --hard` v Bashi
řetězec neotvírá, ale skener si myslel opak, spolkl zbytek řádku *do řetězce* a zbyl
jediný list `echo` → **allow**. Netýká se to jednoho pravidla, ale toho, kde končí
řetězec — tedy všeho. Proto samostatný commit.

Escape znak je **jiný podle shellu** a záměna dělá novou díru opačným směrem — obě
možnosti stojí v sadě jako kontrolní skupina: v PowerShellu `\` neescapuje
(`echo "C:\src\" ; git reset --hard` je uzavřený řetězec), v Bashi zpětný apostrof
neescapuje (je to substituce). Znak se proto bere z `tool_name`.

### Opraveno — jeden zdroj pravdy pro obaly (G2, G6)

Tabulka přepínačů obalů existovala **dvakrát**. Oprava E4 z kola 3 došla jen do jedné
kopie, takže `sudo -u root rm -rf /srv/data`, `nice -n 10 rm -rf src` i
`timeout -s KILL 30 rm -rf src` dávaly `argv[0]` jako `-u` / `-n` / `-s` → allow.
Nově `Get-WrapperTail` nad jedinou tabulkou; čtyři větve `Get-CommandLeaf` se slily
do jedné, která ji volá.

### Opraveno — další tvary

- **G3** `xargs` bere ARGV, ne příkazovou řádku — `xargs sh -c 'git reset --hard'`
- **G4** `{ }` je zanoření jako `$( )` — `& { rm -rf src; }` (se středníkem)
- **G5** `-ec` není předpona `encodedcommand`; `-com` je platná zkratka `-Command`
- **G7** `:/`, `:(top)`, `./*` git chápe jako celý strom
- **G8** tělo heredocu u `python` / `ssh` se **spustí** → `ask` (Z3), ne allow
- **G9** pokračování řádku před heredocem
- **H4** vnitřní hledání závorky v `Get-Substitution` neumělo uvozovky (`$(echo ')')`)

### Opraveno — třetí council Métis (úzká otázka)

Vrátil 8 nálezů k obalům. **Změřeno: čtyři z nich už opravené byly** — council dostal
jen popis rozboru, ne kód. Zbylých **sedm tvarů propouštělo doopravdy** a všechny jsou
táž třída: přepínač obalu, který bere hodnotu a v tabulce nestál, takže se za příkaz
vzala jeho **hodnota**.

- `env -S "rm -rf src"` — hodnota není parametr, ale **příkazová řádka**
- `time -o log rm -rf src` — GNU `/usr/bin/time` bere `-o -f --output --format`
- `stdbuf --output L rm -rf src` — chyběly dlouhé tvary
- `xargs --process-slot-var` / `--arg-file` / `--max-args` — dlouhé tvary už známých
- `find -okdir` — čtvrtý tvar `-exec`

🔴 **Oblasti „escapování uvozovek" a „zkratky parametrů PowerShellu" council nevrátil.**
Selhali poskytovatelé, ne otázka (codex CLI chybuje i po zkrácení, gemini vyčerpal denní
kvótu, nvidia vrací HTTP 504); kontrolní otázka u codexu i gemini prošla. **Netvrdím, že
ty dvě oblasti byly councilem prověřeny — nebyly.**

### Přidáno — generátor invariantu (H2)

`tests/_generate-invariants.ps1`. Soubor se na generátor odvolával, ale ten v repu
nebyl. Invariant vzrostl ze **142 na 451** řádků a nově ho přehrává i sada `secrets`;
všech 142 původních řádků je v souboru doslova a na svém místě. Generátor **jen
přidává**; při sporu (týž tvar, jiné očekávání) nezapíše nic a skončí nenulově.

### Změněno — konfigurace

`gate.codeInterpreters` a `gate.remoteShells` v `hooks/config/defaults.json` (řídicí
soubor; změna vyvolaná nálezem G8 v zadání kola 4).

### Opraveno — nepravdivá věta v README (H3)

🔴 „Chyba směřuje k falešnému `ask`, ne k falešnému `allow`" — G1–G3 to vyvrátily.
Platí slabší a pravdivé: chyba v **pravidle** směřuje k `ask`, chyba ve **skeneru**
může propustit.

### Známá omezení (nově vypsána, vědomé rozhodnutí)

- Příkaz uvnitř kontejneru se nerozebírá (`/tmp` v obrazu není pracovní strom).
- Krátká absolutní cesta `/xxx` končí `ask` — od přepínače `cmd` k nerozeznání.
  Proto Amberin příklad `sudo -u root rm -rf /srv` končí `ask`, ne `deny`; před opravou
  to bylo `allow` a `deny` je doloženo týmž obalem nad `/srv/data`.

### Sady

gate 1420, secrets 588, resume-cost 27, notify 39 — vše 0 failed / 0 skipped na obou
interpretech. Červená proti klonu `2e5354f`: gate **62 FAIL**. Invariant 142 → **451** řádků.

## [0.1.3] — 2026-09-06

Třetí opravné kolo. Tentokrát ale hlavně **strukturální oprava společné příčiny**: tři kola
po sobě šla oprava → nová díra na témže místě (B4 → C1, D3 → E2, C2 → E3). Společnou příčinou
nebyla ani jedna z těch oprav — bylo to **dělení příkazové řádky regexem**.

### Změněno — jeden skener místo regexů

`[regex]::Split` neumí uvozovky, takže `echo "DROP TABLE users;" | psql -h db` se rozpadlo
uprostřed řetězce a destruktivní příkaz propadl. Nově má `_common.ps1` jediný znakový skener
`Split-Unquoted` se stavem uvozovek a zanoření `$( )`; nad ním jsou tenké obaly
`Split-Statement`, `Split-Pipe` a `Split-CommandLine`. Druhá kopie skeneru v `gate.ps1` je pryč.

**Tento refaktor neměnil žádné pravidlo** a byl doložen tím, že sada `gate` dala přesně
tentýž výsledek jako před ním (790/0/0). Změřeno i tempo, protože tři průchody mohly zpomalit:
medián hooku **1653 ms před** proti **1541 ms po**, 60 měření na čtyřech tvarech.

### Přidáno — regresní invariant

`tests/fixtures/invariants.json` (142 řádků, **generováno z případových polí, ne ručním
výběrem**): každý tvar, který kdy byl `deny`, jím zůstává; každý tvar označený jako falešný
blok zůstává `allow`. Soubor je append-only. Důvod je konkrétní: v kole 1 jsem si falešný blok
(`git restore --staged .`) zafixovala testem a v kole 2 oprava jednoho nálezu rozbila jiný —
sada, která roste jen o nové případy, tohle nechytí.

### Opraveno — nálezy review

- **Roura do SQL klienta se rozpadala na středníku v řetězci** (`echo "DROP TABLE users;" | psql`).
- **Tělo heredocu u shellu bylo slepé místo.** `bash <<'EOF' / git reset --hard / EOF` se
  zahazovalo. Tělo se nově rozebírá jako příkazy, když uvozující příkaz je shell; u ostatních
  zůstává daty. Neukončený heredoc → `ask`.
- **`<<` uvnitř uvozovek** (`echo "<<x>>"`) zakládalo heredoc a spolklo zbytek příkazu.
- **`git checkout`/`git restore` se rozhodují nad TOKENY**, ne regexem — regex neuměl
  `git restore -s HEAD .` (`-s` bere hodnotu, takže `HEAD` není přepínač).
- **Přepínače obalů mají hodnotu podle obalu, ne globálně.** `sudo -n` hodnotu nebere,
  `nice -n` ano; `timeout 30 psql` přeskakuje číslo.
- **Vzor jmen proměnných má dva režimy velikosti písmen.** Podtržítkový zápis ignore-case
  (chytí `db_password`), camelCase case-sensitive (nechá `monkey` a `keyFile` na pokoji).
- **`-S` je hostitel jen u `sqlcmd`** — u `psql` je to single-line bez hodnoty.
- **Substituce v článku roury** (`$(git reset --hard) | psql`) se vyhodnocuje.

### Opraveno — nálezy councilu Métis (druhé kolo)

Council dostal opravený stav a vrátil 7 nálezů; osmý sám stáhl jako neplatný (ověřeno, že
ho stáhl právem). Všech 7 jsou parsovací mezery v už hlídaných tvarech:

- **`find -exec sh -c '…'`** ztrácelo uvozovky při skládání tokenů zpět, takže vnitřní `-c`
  vzalo jen první slovo. Nové `Join-Argument` hranice zachová.
- **`<<\SQL`** — třetí způsob potlačení expanze vedle `'SQL'` a `"SQL"`.
- **`& { … }`** — blok skriptu je obal stejně jako závorka.
- **`pwsh -enc`, `-enco`, `-encod`** — PowerShell bere každou jednoznačnou zkratku parametru;
  vyjmenovat tři z nich nestačilo.
- **Procesová substituce `<( … )`** je taky spuštěný příkaz.
- **Dva heredocy na jednom řádku** — bral se jen první.
- **`-ArgumentList @('-enc', …)`** — pole se rozloží na tokeny.

---

## [0.1.2] — 2026-09-05

Druhé opravné kolo po review Amber (nálezy C a D). **Všech 22 tvrzených tvarů bylo před
opravou změřeno** a chovalo se přesně tak, jak review popsala.

### Opraveno — regrese, kterou zavedla verze 0.1.1

- **Roura do SQL klienta propouštěla.** Oprava B4 (SQL jen ze SQL kontextu) rozbila
  `echo "DROP TABLE users" | psql -h db.firma.cz`: `echo` není SQL klient, takže se jeho
  argument nečetl jako SQL, a `psql` už žádné SQL neměl — výsledek `allow`, přitom
  před 0.1.1 to byl `ask`. Nově se roura vyhodnocuje jako celek: literál z `echo`/`printf`
  se čte jako SQL, `cat soubor | psql` a `$sql | psql` končí `ask` (obsah není vidět).

### Opraveno — díry v pokrytí

- **Heredoc s přesměrováním se nerozpoznal.** `<<SQL 2>&1` a `<<SQL > out.log` neodpovídaly,
  protože vzor kotvil delimiter na konec řádku. Tělo se pak rozpadlo na řádky a vzdálená
  destruktivní operace propadla na `allow`.
- **Závorkový obal propouštěl.** `(git reset --hard)`, `$x = (git reset --hard)`,
  `& (git reset --hard)` i `@(git branch -D x)` dávaly `argv[0] = "(git"` a žádné pravidlo
  se nechytlo. Obal se strhne a vnitřek rozebere. `(Get-Date)` zůstává `allow`.
- **Obal před SQL klientem se nerozbaloval.** `sudo -u postgres psql <<SQL` a
  `docker exec -i db psql <<SQL` daly `OuterExe` `sudo`/`docker`, tělo se proto nečetlo
  jako SQL. Rozbalení nově přeskakuje přepínače s hodnotou i jméno kontejneru.
- **`sqlcmd` byl v seznamu klientů, ale nepodporovaný.** `-S` (hostitel) a `-Q` (dotaz)
  se nečetly, takže `sqlcmd -S db.firma.cz -Q "DROP TABLE x"` končilo `ask` místo `deny`.
- **`git checkout HEAD -- .`, `git checkout ./`, `git checkout .\` a
  `git restore --source HEAD .`** propouštěly.
- **`credentials`** zůstalo mezi kanonickými jmény, ačkoli komentář, CHANGELOG i README
  tvrdily, že odešlo. Teď odešlo doopravdy.
- **Ukotvení vzoru jmen proměnných zavedlo falešná negativa:** `API_KEYS`,
  `AZURE_CREDENTIALS`, `DB_PASSWD`, `$env:apiKey` a `$secretKey` propouštěly. Vzor má nově
  dvě větve (UPPER_SNAKE a camelCase) a **porovnává se case-sensitivně** — na tom stojí
  rozlišení `API_KEYS` (citlivé) od `tokens` (běžná proměnná).

### Opraveno — falešné bloky

- **`git restore --staged .` končilo `deny`.** Odstagování není ztráta práce; ztráta je
  až s `--worktree`. Tohle byl falešný blok, který si verze 0.1.1 navíc **zafixovala testem**.
- **Přiřazení bez volání končilo `ask`.** `$a = $b` a `$env:PATH = "$env:PATH;C:\x"`
  nic nespouštějí. Pravá strana složená jen z proměnných a řetězců už list nevytváří.
- **Tělo heredocu procházelo pravidly pro příkazy.** `cat > NOTES.md <<EOF` s textem
  „git reset --hard je nebezpečný" končilo `deny` — zápis poznámky *o* příkazu blokován
  jako příkaz. Tělo je data; pravidla se na něj uplatní jen když uvozující příkaz je SQL klient.

### Změněno

- **Toast: doplněna deklarace WinRT typu `XmlDocument`.** Po přechodu na vlastní XML by
  bez ní `::new()` vyhodilo a `catch` by toast **tiše zahodil**. Živá sonda toastu patří
  do fáze 2 — dosud ho nikdo neviděl.
- **Kanárek přiznává `dry-run`.** `SINOGARD_HOOKS_DRYRUN` je globální proměnná; kdyby
  prosákla do produkce, upozornění by tiše přestala chodit a kanárek by dál hlásil
  `notify` jako zapnuté.
- **`secrets.ps1` má diagnostiku `SINOGARD_HOOKS_DEBUG`** — README ji sliboval, kód neměl.

---

## [0.1.1] — 2026-09-05

Opravné kolo po review Amber (osy 0–2) a rozhodnutí Toma T36-F1. Ke každé opravě
existuje test i **kontrolní skupina** — tvar, který se musí chovat opačně.

### Opraveno — falešné bloky na běžné práci

Tohle je nejdůležitější část vydání. Brána, která blokuje běžnou práci, se do týdne
vypne, a pak nechrání nic.

- **Přiřazení v PowerShellu končilo `ask`** (v `bypassPermissions` `deny`).
  `$out = dotnet test` i `$env:FOO = 'x'` se braly jako proměnná v pozici příkazu.
  Nově se rozebírá pravá strana přiřazení — ale **přiřazení nic nepere**:
  `$x = git branch -D y` zůstává `deny`.
- **SQL vzory běžely nad surovým textem včetně řetězců.**
  `git commit -m "Add DROP TABLE migration"`, `grep -r "DROP TABLE" src`,
  `truncate -s 0 x.log` i `echo "TRUNCATE users"` končily dotazem. SQL se nově čte
  jen ze skutečného SQL kontextu (nový seznam `gate.sqlClients`, hodnoty `-c`/`--command`,
  těla heredoců).
- **Vzor jmen proměnných nebyl ukotvený.** `$PWD` (pracovní adresář), `$keys`,
  `$tokens` a `$keyFile` končily dotazem. Ukotveno na hranice slova; holé `PWD`
  vyňato, `DB_PWD` chycené zůstává.
- **`config.json`, `config` a `credentials`** odešly z kanonických jmen — chráněné
  jsou až s adresářem (`.docker/`, `.kube/`, `.aws/`). `ls config*` a `cat config.json`
  se už neptají. `*.json` se ptá dál, protože kanonicky zůstává `secrets.json`.

### Opraveno — díry v pokrytí

- **`git checkout .` a `git restore -- .` propouštěly.** Vzor vyžadoval `--`
  s neprázdným pokračováním, takže holé `--` ani úplně chybějící `--` neodpovídaly.
  *(Upřesnění po nálezu Amber C8: `git checkout -- .` starý vzor chytal — díra byla
  v `git checkout .` bez `--` a v `git restore -- .` s holým `--`.)*
- **`[IO.Directory]::Delete($p, $true)` propouštělo.** Cíl byl proměnná a regex hledal
  literál v uvozovkách. Nově `ask` (§2.3: obal s proměnnou → `ask`).
- **Heredoc ztrácel hostitele.** `psql -h db.firma.cz <<SQL / DROP TABLE x / SQL` se
  dělil po řádcích, tělo zůstalo bez hosta a vzdálená operace se četla jako lokální
  (`ask` místo `deny`). Tělo heredocu nově dědí uvozující příkaz.
- **`Server=` a `Data Source=`** se nečetly jako hostitel, ačkoli je Npgsql bere jako
  synonymum `Host=`. `--connection "Server=db.firma.cz;…"` se četlo jako lokální.

### Přidáno

- **`DELETE FROM` bez `WHERE`** mezi hlídané tvary (rozhodnutí Toma T36-F1 T-1):
  má stejný dopad jako `TRUNCATE`. S `WHERE` je to běžná práce a projde; `WHERE`
  se hledá v tomtéž statementu, ne kdekoli v textu.
- **`SINOGARD_HOOKS_DRYRUN=1`** — `toast` i `messagebox` místo odeslání napíšou na
  stderr, co by poslaly. Sada tím přestala střílet skutečná okna.
- **`tests/_ci-verdict.ps1`** — CI čte verdikt ze **souhrnného řádku** sady, ne
  z návratového kódu. Selže, když řádek chybí, když `failed > 0` nebo když `passed = 0`.
  Dřív by `0 passed / 0 failed` prošlo zeleně.

### Změněno

- **Toast je tichý** (`<audio silent="true"/>`) — zadání §2.3 říká „Zvuk ne", šablona
  `ToastText02` ho ale hrála. XML se skládá jako řetězec, takže tvrzení o tichosti umí
  ověřit sada i pod `pwsh 7`, kde WinRT vůbec neexistuje.
- README: doplněny hranice metody (timeout propouští, hook čte text příkazu a ne to,
  co z něj shell vyrobí) a tabulka proměnných prostředí.

---

## [0.1.0] — 2026-09-05

První verze. Čtyři hooky, Windows-first, bez externích závislostí.

### Přidáno

- **`gate.ps1`** (`PreToolUse` nad `Bash`/`PowerShell`) — schvalovací brána.
  - **deny:** force push na chráněnou větev (včetně `+main`, `HEAD:main`,
    `refs/heads/main` a `--force-with-lease`) · `git reset --hard` ·
    `git checkout -- .` / `git restore .` · `git branch -d|-D` · `git push --delete` ·
    `git clean -f*` · `git stash drop|clear` · rekurzivní mazání mimo povolené složky
    (`rm -rf`, `Remove-Item -Recurse`, `rd /s`, `del /s`, `[IO.Directory]::Delete`) ·
    `DROP TABLE|DATABASE|SCHEMA`, `TRUNCATE`, `dropdb`, `dotnet ef database drop`
    mimo lokálního hostitele · `dotnet ef database update` proti cizímu hostiteli ·
    `git filter-branch`, `git filter-repo`, `git reflog expire`, `git gc --prune`.
  - **ask:** `git rebase` · force push na jinou než chráněnou větev · rekurzivní mazání
    v povolené složce s hvězdičkou, `..` nebo proměnnou v cestě ·
    `dotnet ef migrations remove` · `git clean -X` bez `-x` · destruktivní DB operace
    na lokální databázi · `Invoke-Expression` · příkaz, který nejde rozebrat.
  - Rozbaluje obaly: `FOO=1 …`, `bash -c`, `sh -c`, `cmd /c`, `powershell -Command`,
    `pwsh -c`, `eval`, `xargs`, `find -exec`, `sudo`, `env`, `timeout`, `$( )`
    a páry zpětných apostrofů. Přeskakuje globální přepínače gitu (`-C`, `-c`,
    `--git-dir`, …) a normalizuje jméno spustitelného souboru (`/usr/bin/git`,
    `git.exe`, `"git"`).
- **`secrets.ps1`** (`PreToolUse` nad soubory i příkazy) — ochrana souborů se secrets.
  Verzovaný `.env.<x>` je povolený (ověřuje se `git ls-files`), netrackovaný končí `ask`.
  Sebeochrana: zápis do souborů, kterými se brána vypíná, končí `ask`.
- **`resume-cost.ps1`** (`SessionStart`) — počítaný kanárek při startu a hlášení ceny
  obnovení session s řádkem JSONL v `${CLAUDE_PLUGIN_DATA}`.
- **`notify.ps1`** (`Notification`) — upozornění kanálem `osc9` / `toast` /
  `messagebox` / `none`. Výchozí je `toast` **z měření**: měřicí stroj běží ve VS Code
  (`TERM_PROGRAM=vscode`, žádný `WT_SESSION`), takže OSC 9 tam nemá kdo zobrazit,
  zatímco WinRT toast se pod `powershell.exe` 5.1 načte a `Show()` projde. Pod `pwsh` 7
  typ `Windows.UI.Notifications.ToastNotificationManager` neexistuje vůbec.
- Projektový override `.claude/sinogard-hooks.json` s mělkým slučováním.
- Testové sady bez Pesteru přes hranici procesu, pro `powershell.exe` i `pwsh`;
  GitHub Actions nad `windows-latest` v matici obou interpretů.

### Rozhodnutí, která stojí za zapsání

- **`ask` se v `bypassPermissions` vydává jako `deny`.** V bypassu se dotaz nezobrazí,
  takže šedá zóna by tiše propadla.
- **deny = JSON `permissionDecision` + `exit 2` + týž důvod na stderr.** Exit 2 blokuje
  i tehdy, kdyby JSON neprošlo validací schématu, a Claude v tom případě čte stderr.
- **Fail-closed u brány, fail-open u evidence.** `gate` a `secrets` při jakékoli chybě
  blokují; `resume-cost` a `notify` mlčí a pouštějí dál.
- **`timeout: 10`** u brány. Timeout u `PreToolUse` znamená **propuštění**, ne pomalejší
  bránu — podstřelená hodnota by bránu tiše vypnula. Nejhorší z pěti studených startů:
  1234 ms (`powershell.exe`), 1270 ms (`pwsh`).
- **Zdroje hooků jsou čistě ASCII bez BOM**, lidské texty v `defaults.json` čteném jako
  UTF-8. Windows PowerShell 5.1 čte `.ps1` bez BOM jako ANSI.
- **`userConfig` pluginu se nepoužívá** — ukládá se do globálních user settings,
  tedy společně pro všechny projekty na stroji.

[0.1.9]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.9
[0.1.8]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.8
[0.1.7]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.7
[0.1.6]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.6
[0.1.5]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.5
[0.1.4]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.4
[0.1.3]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.3
[0.1.2]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.2
[0.1.1]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.1
[0.1.0]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.0
