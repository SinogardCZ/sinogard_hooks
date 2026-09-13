# Changelog

Formát vychází z [Keep a Changelog](https://keepachangelog.com/cs/1.1.0/);
verzování je [semver](https://semver.org/lang/cs/).

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
(README 9): `cat *` a `.en?`.
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
