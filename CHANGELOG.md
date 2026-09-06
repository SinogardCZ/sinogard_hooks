# Changelog

Formát vychází z [Keep a Changelog](https://keepachangelog.com/cs/1.1.0/);
verzování je [semver](https://semver.org/lang/cs/).

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

[0.1.6]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.6
[0.1.5]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.5
[0.1.4]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.4
[0.1.3]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.3
[0.1.2]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.2
[0.1.1]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.1
[0.1.0]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.0
