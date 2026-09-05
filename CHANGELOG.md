# Changelog

Formát vychází z [Keep a Changelog](https://keepachangelog.com/cs/1.1.0/);
verzování je [semver](https://semver.org/lang/cs/).

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

[0.1.3]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.3
[0.1.2]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.2
[0.1.1]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.1
[0.1.0]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.0
