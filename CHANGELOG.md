# Changelog

Formát vychází z [Keep a Changelog](https://keepachangelog.com/cs/1.1.0/);
verzování je [semver](https://semver.org/lang/cs/).

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

[0.1.0]: https://github.com/SinogardCZ/sinogard_hooks/releases/tag/v0.1.0
