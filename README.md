# sinogard-hooks

Zábradlí pro Claude Code sessions: **destruktivní git a DB operace, soubory se secrets,
cena obnovení session a upozornění, když se čeká na člověka.** Windows-first, PowerShell,
bez externích závislostí.

Plugin vznikl proto, že schvalovací brána („nic destruktivního bez výslovného souhlasu")
byla do té doby vynucená jen chováním modelu. Hook ji posouvá do harness vrstvy, kterou
si **model nemůže rozmyslet** — rozhodnutí padá mimo něj.

To ale neznamená, že selhat nemůže **vůbec**. Může, a stojí za to vědět jak: hook, který
překročí `timeout`, Claude Code **nezablokuje** — příkaz projde. Rozklad příkazové řádky
je navíc tokenizér, ne shell, takže **hook čte text příkazu, ne to, co z něj shell vyrobí.**
Úplný seznam hranic je v [Známá omezení](#známá-omezení).

---

## Co plugin dělá

| Hook | Událost | Co dělá |
|---|---|---|
| `gate.ps1` | `PreToolUse` nad `Bash`/`PowerShell` | Destruktivní git (force push na chráněnou větev, `reset --hard`, mazání větví, `clean -f`, přepis historie), rekurzivní mazání mimo povolené složky (včetně `[IO.Directory]::Delete` a `[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory`) a destruktivní DB operace → **deny**. Šedá zóna → **ask**. Tvar, který nejde rozebrat, → **audit** (viz níže). |
| `secrets.ps1` | `PreToolUse` nad `Read`/`Edit`/`Write`/`MultiEdit`/`NotebookEdit`/`Bash`/`PowerShell` | Čtení, zápis i výpis souborů se secrets → **deny**. Výpis prostředí, čtení citlivé proměnné a zápis do souborů, kterými se brána vypíná → **ask**. |
| `resume-cost.ps1` | `SessionStart` (`startup`/`resume`/`fork`) | Při startu **kanárek** („plugin běží, tyhle čtyři hooky jsou živé"). Při obnovení session hlásí cenu a zapisuje řádek do JSONL. Nic neblokuje. |
| `notify.ps1` | `Notification` | Upozorní, že se čeká na člověka. Nic neblokuje. |

### Tři rozhodnutí, ne dvě

- **deny** — nástroj se neprovede vůbec; důvod se vrátí modelu. Platí **i v režimu
  `bypassPermissions`** a s `--dangerously-skip-permissions`.
- **ask** — zobrazí se běžný dotaz na oprávnění. Tohle je vynucený souhlas člověka:
  rozhoduje ten, kdo sedí u terminálu, ne model.
- **žádné rozhodnutí** — hook mlčí a platí normální tok oprávnění.

V režimu `bypassPermissions` se **`ask` vydává jako `deny`**: v bypassu by se dotaz
nezobrazil, takže šedá zóna by tiše propadla. Důvod to říká nahlas.

### Třídy `ask` — a jak se měnily od 0.1.8

Rozsah brány je **rozhodnutí zadavatele**, ne technická nutnost. Po prvních ostrých
sessions se spočítalo, co se doopravdy ptalo, a nad těmi čísly padla rozhodnutí
Toma 2026-09-07/T36-F1 `T-10 A`, 2026-09-07/`T36-O5 A` a 2026-09-08/`T36-Q7 A`.
V 0.1.11 pak nálezy Ady N28, N34 a N35 ukázaly, že tři z těch tříd byly popsané
**jinak, než jak se chovaly**:

| třída | do 0.1.8 | od 0.1.9 | od 0.1.10 | od 0.1.11 | proč |
|---|---|---|---|---|---|
| `git rebase` | ask | **allow** | allow | allow | běžná práce s historií vlastní větve |
| `git clean -fdX` (jen ignorované) | ask | **allow** | allow | allow | úklid buildu; `-fdx` zůstává `deny` |
| SQL, které v příkazu **není vidět** (`-f`, `<`, `<<< $VAR`, `cat x.sql \| psql`) | ask | **allow + audit** | allow + audit | allow + audit | rozsah neznáme, ale je to běžná práce — místo dotazu se událost **zapíše** |
| 🔴 **viditelné destruktivní SQL vedle `-f` / `<`** (`psql -h prod -c "DROP TABLE x" < /dev/null`) | ask | allow + audit | allow + audit | **deny** | N28: marker „ze souboru" se vyhodnocoval **dřív** než pravidlo — obcházení `deny` → `allow` |
| 🔴 **`dropdb` vedle `-f` / `<`** (`dropdb -h prod mydb < /dev/null`) | ask | allow + audit | allow + audit | **deny** | A-1: táž třída o řádek níž — destruktivnost nese i **jméno programu**, nejen text SQL |
| **obal, ve kterém se obsah proměnné SPUSTÍ** (`bash -c "$x"`, `eval $cmd`, `cmd /c %X%`, `pwsh -c $x`, `Start-Process $x`, `. $x`, `iex $cmd`) | ask | ask | **audit** | **ask** | N34: rozlišovač v kódu dělil „PS operátor `&`" × zbytek, ne „spustí se" × „nespustí se" |
| **hodnota / výraz s proměnnou** (`"EXIT=$code"`, `$out \| Select-String`, `[Math]::Truncate($x)`, `$TOOL git push`) | ask | ask | **audit** | audit | slepé místo pluginu; rozhodne o něm normální tok oprávnění Claude Code |
| **nerozebratelný tvar s destruktivním literálem** (`Where-Object { … -or (git reset --hard) }`, `$_.Delete()`, `$SUDO git reset --hard`) | ask | ask | **audit** | **ask** | N35: hlavu rozebrat neumíme, ale literál v ní **vidět je** |
| neukončený heredoc, zanoření > 5 | ask | ask | **audit** | **ask** | N35: obě mají ve výpisu 46 dotazů **0 výskytů**, takže `ask` nestojí nic |
| kód interpretu s destruktivním voláním (`python -c "shutil.rmtree(…)"`) | ask | ask | **ask** | ask | jméno volání v těle vidět **je** |
| `python -c` bez destruktivního tokenu | ask | ask | **audit** | audit | kód nerozebereme, ale token v něm není |
| čtení `.claude/settings.local.json` | ask | ask | ask | ask | nese hodnoty secrets |
| `ssh host "příkaz"`, `ssh prod <<EOF` | ask | ask | ask | ask | cizí stroj, kde naše pravidla neplatí |
| krátká absolutní cesta `/xxx` | ask | ask | ask | ask | od přepínače `cmd` k nerozeznání |
| spuštění proměnné (`& $cmd`) | ask | ask | ask | ask | obsah se spustí, a ten nevidíme |
| `-EncodedCommand` a jeho zkratky | ask | ask | ask | ask | příkaz je zakódovaný, ne skrytý omylem |

**Cena 0.1.11 nad reálnými čísly: žádná.** Výpis 46 příkazů, na které se plugin ptal
7. 9., dává po všech třech opravách pořád **2 `ask`** a **0 `deny`** — sada to drží
jako fixturu (`tests/fixtures/ask-vypis-2026-09-07.json`), ne jako větu.

🔴 **„audit" není totéž co „allow".** Hook **mlčí** — zapíše řádek do
`${CLAUDE_PLUGIN_DATA}/gate-audit.jsonl` (čas, nástroj, id tvaru, rozhodnutí —
**nikdy obsah příkazu**) a **nevydá rozhodnutí**. Kdyby vydal
`permissionDecision: allow`, přeskočil by tím vrstvu oprávnění Claude Code; ticho ji
nechá rozhodnout. Bez `CLAUDE_PLUGIN_DATA` se nezapisuje nic a hook mlčí dál:
evidence je fail-open a nesmí být důvod, proč brána spadne.

🔴 **Co se tím NEotevřelo:** SQL, které v příkazu **vidět je**, se rozhoduje dál podle
hostitele. `echo "DROP TABLE users" | psql -h prod` je pořád `deny`.

Politika je konfigurace (`gate.opaque`), hodnoty `audit | ask`; **cokoli jiného se čte
jako `ask`** — fail-closed.

---

## Instalace

```jsonc
// .claude/settings.json vašeho projektu
{
  "extraKnownMarketplaces": {
    "sinogard-hooks": {
      "source": { "source": "github", "repo": "SinogardCZ/sinogard_hooks" }
    }
  },
  "enabledPlugins": {
    "sinogard-hooks@sinogard-hooks": true
  }
}
```

Ověření, že plugin běží: spusťte `/hooks` — čtyři události se zdrojem `Plugin Hooks`.
Druhý doklad přijde sám: **při startu session se objeví kanárek** se stavem všech
čtyř hooků. Když kanárek chybí, brána neběží.

---

## Konfigurace

Výchozí hodnoty jsou v [`hooks/config/defaults.json`](hooks/config/defaults.json).
Projekt je může přepsat souborem `.claude/sinogard-hooks.json` ve své složce:

```jsonc
{
  "hooks": { "gate": true, "secrets": true, "resumeCost": true, "notify": false },
  "notify": { "channel": "osc9" }
}
```

### Slučování je JEDNOÚROVŇOVÉ (od 0.1.11)

**Pravidlo je jedno a platí pro každý klíč nejvyšší úrovně stejně** — `gate`, `secrets`,
`notify`, `hooks`, `resumeCost`:

- je-li hodnota na obou stranách **objekt**, sloučí se **o jednu úroveň** (klíč po klíči),
- **pole a skaláry se nahrazují CELÉ**.

Takže `{"gate":{"opaque":{"variable":"ask"}}}` přepíše `gate.opaque` a **nechá být**
`denyPatterns`, `allowedRemoveRoots` i `shapes`; `{"gate":{"denyPatterns":[]}}` naopak
ten seznam vyprázdní celý. Důvod původního mělkého slučování tím drží — položku seznamu
pořád nejde jen odebrat — jen kvůli jednomu klíči už nemizí zbytek objektu.
Hlouběji než o jednu úroveň se **vědomě nejde**.

<details>
<summary>🔴 Do 0.1.10 to tak nebylo — a bylo to past (nález K2-1 review Amber)</summary>

Slučování bylo mělké na nejvyšší úrovni, takže override s jednou hodnotou z `gate`
**zahodil všechno ostatní** a ty klíče padly na vestavěné fallbacky.
Změřeno (0.1.10) s override `{"gate":{"opaque":{"variable":"audit"}}}`:

| příkaz | bez override | s tímhle override |
|---|---|---|
| `git reset --hard` | `deny` | **žádné rozhodnutí** |
| `git branch -D feature/x` | `deny` | **žádné rozhodnutí** |
| `git filter-branch …` | `deny` | **žádné rozhodnutí** |
| `rm -rf bin` (povolená složka) | žádné rozhodnutí | **`deny`** |
| `rm -rf src`, `psql -h prod -c "DROP TABLE x"` | `deny` | `deny` |

Šlo to **oběma směry**: brána ztratila tvary, které měla držet, a zároveň začala
blokovat běžnou práci, protože `allowedRemoveRoots` zmizely s ní. Pravidla, která žijí
v kódu (rekurzivní mazání, DB podle hostitele), držela dál — proto se ta ztráta
nepoznala podle toho, že by „přestalo fungovat všechno".

Táž stavba je u `secrets` (nález Ada N43): `{"secrets":{"envFile":{…}}}` by zahodilo
`denyPathPatterns`, tedy `id_rsa`, `.envrc` i `secrets.json`. Právě proto je oprava
generická pro každý top-level objekt, ne vyjmenovaná pro `gate`.

Sada nesla tenhle stav jako **doklad omezení**; od 0.1.11 nese tytéž příkazy jako
**doklad opravy** (sekce `K2-1` v `tests/gate.tests.ps1`, `N43` v `tests/secrets.tests.ps1`).
ℹ️ Věta *„tvar hlubšího slučování je rozhodnutí do v0.2"* platila do 0.1.10;
rozhodlo se v **0.1.11** (TASK-106 bod 10, nález Ada N42).

</details>

`userConfig` pluginu se vědomě nepoužívá: ukládá se do globálních user settings, tedy
společně pro všechny projekty na stroji. Zábradlí musí jít nastavit **per projekt**.

### Kanály upozornění (`notify.channel`)

| Hodnota | Co dělá |
|---|---|
| `osc9` | `terminalSequence` OSC 9 — Windows Terminal, ConEmu, WezTerm, iTerm2 |
| `toast` (výchozí) | WinRT toast přes `Windows.UI.Notifications` |
| `messagebox` | `MessageBox` v **odděleném** procesu (modální okno by jinak drželo hook do timeoutu) |
| `none` | nedělá nic |

Výchozí `toast` je **volba z měření, ne preference**. OSC 9 umí Windows Terminal, ConEmu,
WezTerm a iTerm2; měřicí stroj ale běžel ve VS Code (`TERM_PROGRAM=vscode`, `WT_SESSION`
neexistuje), takže tam OSC 9 nemá kdo zobrazit. WinRT toast se pod `powershell.exe`
(Windows PowerShell 5.1 — interpret, kterým se hooky spouští) načte a `Show()` projde;
**pod `pwsh` 7 ten typ vůbec neexistuje**, takže `toast` funguje jen na produkční cestě.
Kdo pracuje v terminálu, který OSC 9 umí, ať přepne na `osc9` — je levnější a nezávisí
na nastavení oznámení Windows.

---

## Známá omezení

Tohle nejsou nedodělky, ale hranice, které plugin **nemá jak** překročit. Patří sem,
aby si je nikdo nemusel objevit sám.

1. **Skript volaný souborem je pro hook neprůhledný.** Hook vidí jen příkaz, který
   nástroj spouští — `./cleanup.sh` nebo `pwsh -File deploy.ps1` propustí, i kdyby
   uvnitř byl `git reset --hard`. Obal s literálem (`bash -c "…"`) se rozebere,
   obal se souborem ne.
   ➕ **A platí to i tehdy, když je ta cesta v proměnné** (0.1.11, nález Ada N49):
   `pwsh -File $p`, `bash $script` ani `Start-Process -FilePath 'pwsh' …
   -RedirectStandardOutput $log` nejsou spuštění obsahu proměnné — proměnná je tam
   **cesta**, ne kód. Rozdíl proti omezení 2 je právě tenhle: `-c $x` je kód, `-File $p`
   je soubor.
2. **Obal, ve kterém se obsah proměnné SPUSTÍ, končí `ask`; hodnota a výraz končí
   auditem.** Od 0.1.11 (nález Ada N34, volba **(i)**) je rozlišovač ten, který se
   celou dobu tvrdil: rozhoduje, jestli se obsah proměnné **provede jako kód**.
   `ask` proto dávají `& $cmd`, `. $x`, `eval $cmd`, `bash -c "$x"`, `sh -c "$x"`,
   `cmd /c %X%`, `pwsh -c $x`, `Start-Process $x` i `iex $cmd`; auditem
   (`opaque:variable`, hook mlčí) končí **hodnota a výraz** — `"EXIT=$code"`,
   `$out | Select-String`, `[Math]::Truncate($x)`, `$TOOL git push`.
   🔴 **Do 0.1.10 to tak nebylo a README to říkalo nepravdivě.** Skutečný rozlišovač
   v kódu byl „PowerShell operátor `&`" proti všemu ostatnímu, takže `bash -c "$x"`
   spouštěl obsah proměnné úplně stejně jako `& $cmd` — a končil auditem.
   `-EncodedCommand` zůstává `ask` beze změny.
3. **Windows-first.** Handlery volají `powershell.exe`. Na Linuxu a macOS plugin
   nefunguje; portace by znamenala druhý běhový tvar, ne jen jinou cestu.
4. **Rozklad příkazové řádky je tokenizér, ne shell.** Rozdělení na `&&`, `||`, `;`, `|`
   respektuje uvozovky a escape znak podle shellu, ale neprovádí expanzi.
   🔴 **Věta „chyba směřuje k falešnému `ask`, ne k falešnému `allow`" tu stála a byla
   nepravdivá.** Vyvrátily ji nálezy G1–G3 review Amber (kolo 4): jakmile skener
   špatně určí, kde končí řetězec, spolkne zbytek řádku *do řetězce* — a to je
   falešné **allow**, ne `ask`. Platí tedy slabší a pravdivé tvrzení: chyba
   v **jednotlivém pravidle** směřuje k `ask`; chyba ve **skeneru** může propustit.
   Proto je skener jediný (`Split-Unquoted`) a proto má regresní invariant.
   Council nad ním **proběhl jen zčásti**: otázka na obaly se vrátila a všech sedm
   nálezů je opravených, otázka na **escapování uvozovek a zkratky parametrů**
   se nevrátila vůbec (poskytovatelé selhali — kvóta a chyby CLI, ne otázka).
   Ta část tedy councilem prověřená **není**.
5. **`git clean -X` bez `-x`** (tedy jen ignorované soubory) je `ask`, ne `deny` —
   `-fdX` je legitimní úklid buildu.
6. **Hook čte text příkazu, ne to, co z něj shell vyrobí.** `psql -c ('TRUN' + 'CATE TABLE x')`
   se skládá až za běhu; statický rozbor takový tvar nemá jak vidět. Totéž platí pro
   jakoukoli expanzi proměnných. Je to **hranice metody, ne nedodělek**.
   🔴 Do 0.1.9 tu stálo *„proto tvary s proměnnou končí `ask`, a ne `allow`"* — to už
   neplatí. Od 0.1.10 končí **auditem**, tedy plugin je nezastaví a rozhoduje o nich
   vrstva nad ním. Rozsah brány je rozhodnutí zadavatele (`T36-O5 A`), ne odhad
   pluginu — a nemá smysl ptát se 45× na to, kde jsou dva zásahy.
   🔴 **Věta *„cena za to je pojmenovaná: `Where-Object { … -or (git reset --hard) }`
   ho plugin propustí"* platila jen pro 0.1.10 a od 0.1.11 je ZRUŠENÁ** (nález Ada
   N35). Cituje se, ne maže: byla to skutečná cena a je poctivé, že šla vidět.
   Neplatí proto, že se ukázalo, že nutná nebyla — hlavu rozebrat pořád neumíme, ale
   destruktivní **literál** v ní vidět je, takže ho chytí token-test nad `Leaf.Raw`
   (viz omezení 21). Nezměnila se metoda, změnilo se pořadí: klasifikace už
   nerozhoduje dřív, než se kdokoli podívá na text.
7. **Timeout hooku propouští.** Když handler nestihne `timeout` z `hooks/hooks.json`,
   Claude Code ho na `PreToolUse` **neblokuje** — příkaz projde. Timeouty jsou proto
   nastavené vysoko nad naměřený studený start a hook nedělá nic, co by mohlo čekat
   na síť nebo na člověka.
8. **Proměnná v pozici příkazu končí auditem, i když jde o výraz.** `[Math]::Truncate($x)`
   se nerozebere. Do 0.1.9 z toho byl `ask`; od 0.1.10 je to příčina `variable`, tedy
   audit. Přiřazení `$x = <příkaz>` je výjimka: rozebere se jeho pravá strana, takže
   `$x = git branch -D y` je pořád `deny`. Druhá výjimka (nález L1, **jen PowerShell**):
   čtení hodnoty — `$_`, `$var.Prop`, `$var[…]`, `$i++`, porovnání operátorem — nic
   nespouští a projde bez záznamu. Jakákoli **závorka** výjimku ruší. V Bashi výjimka
   neplatí: `$cmd -rf src` je tam příkaz.
   🔴 **Výjimka z výjimky je spuštění obsahu proměnné.** Operátory `&` a `.` a obaly
   `eval`, `bash|sh|cmd|pwsh -c`, `Start-Process $x` a `iex $cmd` obsah proměnné
   **spustí** — všechny nesou příčinu `invoked` a zůstávají `ask` (detail v omezení 2).
   Do 0.1.10 to platilo **jen pro `&`**; ostatní tvary končily auditem, přestože dělají
   totéž. Příznak se proto nese až do listu; bez něj by `bash -c "$x"` a `"EXIT=$code"`
   měly tutéž politiku.
   ➕ **Druhá výjimka je destruktivní literál pod nerozebratelnou hlavou** —
   viz omezení 21.
9. **`*.json` se ptá.** Zástupný znak, který může padnout na chráněné jméno (`secrets.json`,
   `settings.local.json`), končí `ask`. `*.md`, `config*` ani `src/*.cs` se neptají.
   Od 0.1.8 (nález N26) se glob vyhodnocuje **jen tam, kde ho shell rozvine**: nad
   **neuvozeným** tokenem v **pozici cesty** u příkazu ze seznamu `secrets.pathCommands`
   (čtení a kopírování souborů). `git commit -m "**2**"`, `echo **2**` ani
   `Write-Host "**2**"` tedy nejsou cesty a neptají se — dřív ano, protože glob `**2**`
   sedne na `server.p12`.
10. **SQL, které v příkazu není vidět, se ZAPÍŠE DO AUDITU a pustí dál.**
    `psql -f migrace.sql`, `sqlcmd -i migrace.sql`, `psql -h prod < drop.sql`,
    `psql -h prod <<< $SQL` i `cat migrace.sql | psql` — obsah souboru ani roury hook
    nečte, takže rozsah nezná; od 0.1.9 z toho **není dotaz**, ale řádek v auditu
    (rozhodnutí `T-10 A`). **V téhle třídě nezůstal ani jeden dotaz** — změřeno nad
    0.1.11:

    | tvar | rozhodnutí | tvar v auditu |
    |---|---|---|
    | `psql -f m.sql`, `psql -h prod < drop.sql`, `psql <<< $SQL` | ticho | `sqlFromFile` |
    | `cat drop.sql \| psql -h prod` | ticho | `sqlFromPipe` |
    | `$sql \| psql -h prod` | ticho | `opaque:variable` *(hlava je proměnná)* |
    | `echo "DROP TABLE x" \| psql -h prod` | **deny** | — *(literál je vidět)* |

    Literál z `echo "…" | psql` i z `psql <<< "DROP TABLE x"` se rozebere.
    🔴 **Do 0.1.10 tu stálo *„končí `ask`"* a bylo to nepravdivé** — a o pár obrazovek
    výš to táž README říkala správně (nález Ada N30).
    🔴 **A od 0.1.11 platí navíc druhá věta, která tu chyběla úplně** (nález Ada N28):
    **viditelné destruktivní SQL vedle `-f`, `<` nebo `<<<` je `deny`.**
    `psql -h prod -c "DROP TABLE x" < /dev/null` i `psql -h prod -f m.sql -c "DROP TABLE x"`
    končí `deny`, ne auditem. Do 0.1.10 stačilo k libovolnému destruktivnímu `-c`
    přilepit `< /dev/null` a brána se neprovedla vůbec — příznak „ze souboru" se
    vyhodnocoval **dřív** než pravidlo. Audit se od 0.1.11 uplatní až tehdy, když
    nic viditelného nestřílí.
    ➕ **Platí to i pro `dropdb`** (nález Amber A-1, opraveno v témž vydání):
    `dropdb -h prod mydb < /dev/null` i `dropdb -h prod mydb -f x.sql` končí `deny`.
    Byla to táž třída o řádek níž — destruktivnost totiž nenese jen **text SQL**, ale
    i **jméno programu** (`dropdb`) a `dotnet ef database drop`, a první oprava
    podmínila audit jen tím textem. *„Vyhodnotit výjimku až po pravidle" nestačí —
    musí se vyhodnotit po **celém** pravidle.*
11. **Příkaz uvnitř kontejneru se nerozebírá.** `docker exec` a `docker run` se odloupnou
    jen kvůli jménu klienta (`docker exec -i db psql …` je pořád `psql`), ale to, co se
    spustí *uvnitř* kontejneru, se pravidly nad cestami neposuzuje. Důvod je věcný:
    `/tmp` v obrazu není pracovní strom Toma, takže by pravidlo „mazání mimo povolené
    složky" blokovalo běžnou práci — a brána, která blokuje běžnou práci, se do týdne
    vypne. Vědomé rozhodnutí kola 4, ne opomenutí.
    ⚠️ **Co ale kryté JE:** destrukce databáze se pozná podle `-h <host>` v příkazu,
    takže `docker exec -i db psql -h prod -c "DROP TABLE x"` končí `deny` jako každý
    jiný `psql`. Nekryté jsou **jen cesty uvnitř obrazu**.
12. **Krátká absolutní cesta `/xxx` končí `ask`.** `rm -rf /srv` je od `/s` `/q` `/f`
    (přepínače `cmd`) k nerozeznání, takže se rozsah nezná. `rm -rf /srv/data` je `deny`.
    Důvod v hlášce mluví o rouře, ne o téhle nejednoznačnosti — vlastní tvar zprávy
    je v backlogu **v0.2**. (Kosmetika hlášky, ne průchod: rozhodnutí `ask` je správné.)
13. **Seznam interpretů je na dvou místech.** `gate.codeInterpreters` v konfiguraci čte
    větev heredocu; větev pro `-c` / `-e` v `Get-CommandLeaf` má týž seznam natvrdo.
    Dnes jsou shodné. Přidat do konfigurace `lua` znamená, že `lua <<EOF` se chytne
    a `lua -c` ne. `Get-CommandLeaf` konfiguraci nedostává; protažení je refaktor
    podpisů → **v0.2**.
14. 🔴 **Escapování uvozovek a zkratky parametrů PowerShellu nebyly prověřeny councilem
    — je to VERIFIKAČNÍ DLUH, ne odložená funkce.** Otázka na ně se z poskytovatelů
    nevrátila (kvóta, chyby CLI). Opravy v těch dvou oblastech stojí jen na review
    a na vlastních testech, ne na nezávislém protihráči. **Spustit hned, jak kvóta
    naběhne** — ne až u v0.2.
15. 🔴 **`cmd /c` se rozebírá s escapem hostitelského shellu — je to OBCHÁZENÍ
    `deny` → `allow`, ne kosmetika.** Skutečný escape `cmd.exe` je `^` a ten skener
    nezná, takže příkaz escapovaný po způsobu `cmd` může projít. `bash -c` a `pwsh -c`
    se přepínají správně (nález I2) a od 0.1.6 i tělo heredocu (`bash <<'EOF'`,
    nález K3), `cmd` ne → **v0.2**.
16. **Toast zatím nikdo neviděl.** Kanál `toast` je vybraný měřením prostředí, ale živá
    zkouška (skutečné okno na obrazovce) proběhne až při zapojení. Když se toast neukáže,
    správná odpověď je přepnout `notify.channel` na `none` s uvedeným důvodem, ne tvrdit,
    že upozornění fungují.
17. 🔴 **Blok s ocasem se nerozebírá — OBCHÁZENÍ `deny` → `allow`.** Tělo `{ … }` se
    hledá jen tehdy, když jím statement **končí**, takže
    `if ($x) { rm -rf src } else { git status }`, `try { … } catch { … }`
    i `{ … } # poznámka` projdou **nerozebrané, tedy `allow`**. Stará díra (nález K2),
    ne regrese; zavřít ji znamená rozebírat **všechny** bloky ve statementu → **v0.2**.
18. **Příkaz jako argument vzdáleného shellu končí `ask`, ne `deny`.** `ssh host "rm -rf /"`
    se spustí na cizím stroji, kde pravidla nad cestami neplatí — rozhoduje proto člověk
    (nález Ada N21, opraveno v 0.1.7). `ssh host` a `ssh -T git@github.com` zůstávají
    `allow`, aby běžná práce přes ssh nekončila dotazem. Totéž platí pro `ssh prod <<EOF`:
    do 0.1.9 sdílel jednu podmínku s `python <<EOF`, od 0.1.10 jsou to dvě různé věci —
    kód interpretu jde politikou `opaque.interpreter`, cizí stroj zůstává dotazem.
19. 🔴 **Co audit NEVIDÍ.** Od 0.1.10 propadá nerozebratelný tvar do normálního toku
    oprávnění Claude Code — a to znamená, že o něm **rozhoduje vrstva nad pluginem**
    (klasifikátor auto režimu, `permissions.allow` / `permissions.deny` projektu).
    `$TOOL git push` tedy neběží „bez brány", ale běží **pod jinou** — a plugin o ní
    nic netvrdí. Řádek v `gate-audit.jsonl` říká, že se tvar objevil; **neříká, jestli
    se provedl**. Kdo chce vědět to druhé, musí se zeptat Claude Code, ne pluginu.
    🔴 **A v `bypassPermissions` žádná taková vrstva není** (přiznáno v 0.1.11,
    rozhodl Tom `2026-09-08/T36-Q7 = A`). Audit tam znamená „prošlo bez druhé
    kontroly", ne „rozhodne o tom Claude Code". Řádek to proto říká sám: nese
    `"decision":"allow-bypass"` místo `"allow"`. **Nic se kvůli tomu neblokuje** —
    kdo si zapne bypass, ten si ho zapnul; evidence jen přestává tvrdit něco, co
    v tom režimu neplatí.
20. **Destruktivní volání v kódu interpretu se hledá TOKENEM, ne parserem.**
    `gate.interpreterDestructiveTokens` je seznam řetězců a porovnává se
    **case-sensitivně** prostým výskytem v těle. Z toho plyne obojí: `python -c
    "shutil.rmtree('x')"` se ptá, a `python -c "getattr(shutil, 'rm' + 'tree')(x)"` ne.
    Rozbor kódu Pythonu ani JavaScriptu tenhle plugin nedělá a dělat nebude — proto je
    seznam **konfigurace**, ne pravidlo v kódu.
    🔴 **`DELETE FROM` v tomhle seznamu schválně NENÍ** (0.1.11, nález Ada N50), zatímco
    v `gate.rawDestructiveTokens` je. Není to nedůslednost, je to asymetrie s důvodem:
    tělo interpretu běžně nese SQL řetězce **s `WHERE`**, které token-test ověřit
    neumí, takže by `DELETE FROM` vyrobil dotaz nad běžnou prací. U nerozebratelného
    tvaru (omezení 21) o obsahu nevíme nic jiného, takže je `ask` levný.
21. **Destruktivní literál pod nerozebratelnou hlavou končí `ask` — token, ne parser.**
    (0.1.11, nález Ada N35.) Je-li příčina `variable`, `heredocUnterminated` nebo
    `depth` a v `Leaf.Raw` se vyskytne řetězec z `gate.rawDestructiveTokens`, hook se
    zeptá. `ask`, ne `deny`: hlavu rozebrat neumíme, takže kontext neznáme —
    `$SUDO git reset --hard` může být cokoli. Porovnání je stejné jako u omezení 20:
    `IndexOf`, ordinálně, case-sensitivně, žádný parser. Cena nad výpisem 46 skutečných
    dotazů ze 7. 9.: **0** — žádný z nich token nenese.
    ⚠️ **Co to nechytí:** literál složený až za běhu (`$a = 'git reset'; "$a --hard"`),
    protože platí omezení 6. Je to zúžení díry, ne její uzavření.

---

## Konvence zdrojů (proč to tak je)

🔴 **`hooks/scripts/*.ps1` jsou čistě ASCII a bez BOM.** Windows PowerShell 5.1 čte
`.ps1` bez BOM jako ANSI, takže jakýkoli český znak ve zdroji by se rozsypal. Všechny
lidské texty proto žijí v `hooks/config/defaults.json`, který se čte **explicitně jako
UTF-8**. Vedlejší přínos: texty jsou konfigurace, ne kód.

Testy v `tests/*.ps1` naopak **BOM mají** — nesou české řetězce a bez BOM by pod 5.1
měřily vlastní zkomolení místo produktu.

Stdin, stdout i stderr hooků jdou přes vlastní UTF-8 stream (bez BOM); `-NoProfile`
je povinné, protože cokoli, co profil vypíše, rozbije JSON na stdout.

**Fail-closed u brány, fail-open u evidence.** `gate.ps1` a `secrets.ps1` končí při
jakékoli výjimce, prázdném nebo nevalidním vstupu **exit 2** — tedy blokují.
`resume-cost.ps1` a `notify.ps1` naopak končí **exit 0** a mlčí: chyba v evidenci
nesmí zastavit session.

### Proměnné prostředí

| Proměnná | Kde platí | Co dělá |
|---|---|---|
| `SINOGARD_HOOKS_DEBUG=1` | `gate.ps1`, `secrets.ps1` | K hlášce o interní chybě přidá výjimku a místo. Fail-closed to **neoslabuje** — pořád se blokuje, jen se navíc řekne proč. Bez ní zůstane v logu jen „internal error" a příčina nikde. Zapnutá na CI, v produkci vypnutá (mohla by nést cizí text). |
| `SINOGARD_HOOKS_DRYRUN=1` | `notify.ps1`, hlásí `resume-cost.ps1` | Kanály `toast` a `messagebox` **nic nepošlou** a místo toho napíšou na stderr, co by poslaly. Používá to sada — jinak by testy střílely skutečná okna, která po sobě nechávají viset procesy. `stdout` zůstává prázdný, takže tvrzení „kanál nic nevypíše" platí dál. **Je to globální proměnná**, takže kdyby prosákla do produkce, upozornění by tiše přestala chodit — proto ji kanárek při startu session **přizná**. |

`resume-cost.ps1` a `notify.ps1` `SINOGARD_HOOKS_DEBUG` nečtou — jsou fail-open, takže
selhání nikdy nedrží session a nemá co skrývat.

---

## Testy

Bez Pesteru — čistý PowerShell s asserty a nenulovým návratovým kódem.

```powershell
pwsh -NoProfile -File tests/gate.tests.ps1
pwsh -NoProfile -File tests/secrets.tests.ps1
pwsh -NoProfile -File tests/resume-cost.tests.ps1
pwsh -NoProfile -File tests/notify.tests.ps1

# plný výpis místo tichého defaultu
pwsh -NoProfile -File tests/gate.tests.ps1 -Full

# druhý interpret (výchozí je powershell.exe, tedy produkční cesta)
pwsh -NoProfile -File tests/gate.tests.ps1 -Interpreter pwsh
```

Šev je **skript hooku jako celek**: vstupní JSON na stdin → skript → návratový kód
a stdout JSON. Testy spouštějí skutečný proces, ne dot-source — dot-source by ztratil
návratový kód i kódování, tedy přesně to, o čem sada tvrdí.

Verdikt dává **souhrnný řádek** `N passed / N failed / N skipped`, ne návratový kód:
pád uprostřed sady vypadá zvenčí jako červená, a přitom je to „neměřeno".

### Konvence: kontrolní skupina je fixtura, ne věta

🔴 **Každý řádek kontrolní skupiny, na který se odvolává review nebo hlášení, musí
existovat jako případ v sadě.** Věta „`ssh host` zůstává `allow`" napsaná jen do
hlášení je **tvrzení**; případ v `gate.tests.ps1` je doklad, který se přehraje při
každém běhu — a hlavně **při příštím kole**, kde se přesně takové věty rozbíjejí.

Důvod je konkrétní: dvě kola po sobě zavedla oprava regresi (G4 → I1, I1 → K1 + L1)
a v obou případech chyběl v sadě právě ten tvar, o kterém se předtím psalo, že drží.
(Doporučila Ada, přijato 2026-09-07.)

Z toho plyne i tvar sady: u každého nálezu stojí **opravený tvar i jeho protipól** —
tvar, který se změnit **nesmí**. Bez protipólu měří test jen to, že se něco změnilo,
ne že se změnilo to správné.

### Regresní invariant

`tests/fixtures/invariants.json` je **append-only** seznam tvarů s očekáváním; přehrává
ho každá sada, které se týká (`Invoke-InvariantRows`). Roste **generátorem**
(`tests/_generate-invariants.ps1 -WhatIf` pro náhled), ne ruční editací — a generátor
při **sporu** (týž tvar, jiné očekávání) nezapíše nic a skončí nenulově. Řádek odsud
odchází jen s citovaným rozhodnutím.

**`allow` v invariantu znamená, že hook MLČÍ** — prázdný stdout a `exit 0`, tedy platí
normální tok oprávnění Claude Code. Není to `permissionDecision: allow`; ten by tu
vrstvu přeskočil. Plugin žádný allow writer nemá (`_common.ps1` umí jen
`Write-DenyDecision` a `Write-AskDecision`), takže **každý řádek `allow` je tvrzení
o tichu**. Rozdíl drží `Get-Decision` v `tests/_harness.ps1`: uvidí-li
`permissionDecision: allow`, vrátí `DECISION-ALLOW` — a to se nerovná žádnému očekávání
v žádné fixtuře, takže takový hook zčervená na **každém** řádku. (0.1.11, nález Ada N46.
Druhé jméno pro tichu se schválně nezavádí: jeden slovník, rozdíl se čte tady.)

#### Změna očekávání jde jen nástrojem

🔴 **Ruční editace `expect` v `invariants.json` je zakázaná.** Očekávání se mění
výhradně přepínačem `-Prijmout`, který k zápisu vyžaduje **citaci rozhodnutí**:

```powershell
# náhled: co by se změnilo a proč
pwsh -NoProfile -File tests/_generate-invariants.ps1 -Prijmout "T36-N34 (i)" -WhatIf

# zápis: změní expect u sporných řádků a doplní hlavičku `_zmeneno`
pwsh -NoProfile -File tests/_generate-invariants.ps1 -Prijmout "T36-N34 (i)"
```

Bez citace nástroj nezapíše nic a skončí nenulově. Zapisuje **jen ty řádky, na kterých
generátor hlásil spor** (týž tvar, jiné očekávání v sadě), a do hlavičky `_zmeneno`
připojí datum, citaci, směr změny a výčet tvarů. Append-only pravidlo tím zůstává:
řádek nikdy neodchází, jen mění očekávání — a vždy s tím, kdo o tom rozhodl.

---

## Licence

MIT — viz [LICENSE](LICENSE).
