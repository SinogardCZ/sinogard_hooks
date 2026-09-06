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
| `gate.ps1` | `PreToolUse` nad `Bash`/`PowerShell` | Destruktivní git (force push na chráněnou větev, `reset --hard`, mazání větví, `clean -f`, přepis historie), rekurzivní mazání mimo povolené složky a destruktivní DB operace → **deny**. Šedá zóna → **ask**. |
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
  "gate": {
    "allowedRemoveRoots": ["bin", "obj", "node_modules", "tmp", "dist", "TestResults"],
    "localDbHosts": ["localhost", "127.0.0.1", "::1"],
    "protectedBranches": ["main"]
  },
  "notify": { "channel": "osc9" }
}
```

**Slučování je mělké:** klíč v override nahradí celý klíč z defaults. Je to záměr —
při hlubokém slučování by z override šlo položku seznamu jen přidat, nikdy odebrat.

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
2. **Obal s proměnnou končí `ask`, ne `deny`.** `bash -c "$CMD"` nejde rozebrat, takže
   rozhoduje člověk. V `bypassPermissions` se z toho stane `deny`.
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
   jakoukoli expanzi proměnných. Poctivá odpověď je, že tohle je hranice metody, ne
   nedodělek — proto tvary s proměnnou končí `ask`, a ne `allow`.
7. **Timeout hooku propouští.** Když handler nestihne `timeout` z `hooks/hooks.json`,
   Claude Code ho na `PreToolUse` **neblokuje** — příkaz projde. Timeouty jsou proto
   nastavené vysoko nad naměřený studený start a hook nedělá nic, co by mohlo čekat
   na síť nebo na člověka.
8. **Proměnná v pozici příkazu končí `ask`, i když jde o výraz.** `[Math]::Truncate($x)`
   se nerozebere, takže rozhoduje člověk. Přiřazení `$x = <příkaz>` je výjimka: rozebere
   se jeho pravá strana, protože jinak by `ask` končila každá druhá řádka běžné práce.
   Druhá výjimka (nález L1, **jen PowerShell**): čtení hodnoty — `$_`, `$var.Prop`,
   `$var[…]`, `$i++`, porovnání operátorem — nic nespouští a projde. Jakákoli **závorka**
   výjimku ruší, protože `$_.Delete()` maže. V Bashi výjimka neplatí: `$cmd -rf src`
   je tam příkaz.
9. **`*.json` se ptá.** Zástupný znak, který může padnout na chráněné jméno (`secrets.json`,
   `settings.local.json`), končí `ask`. `*.md`, `config*` ani `src/*.cs` se neptají.
10. **SQL, které v příkazu není vidět, končí `ask`.** `cat migrace.sql | psql`,
    `psql -f migrace.sql`, `sqlcmd -i migrace.sql` i `$sql | psql` — obsah souboru ani
    roury hook nečte, takže rozsah nezná. Od 0.1.7 sem patří i **přesměrování stdin** —
    `psql -h prod < drop.sql` a `psql -h prod <<< $SQL` (nález Ada N20). Literál
    z `echo "…" | psql` i z `psql <<< "DROP TABLE x"` se rozebere.
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
    `allow`, aby běžná práce přes ssh nekončila dotazem.

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

---

## Licence

MIT — viz [LICENSE](LICENSE).
