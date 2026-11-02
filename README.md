# paths-ppl

toolkit for process memory analysis and path-based detection on windows.

two modules:

## exploit (pplscan / ppldump)

dumps protected process memory via PPL bypass (WerFaultSecure technique). targets csrss for artifact extraction.

- `pplscan.exe` — main scanner. launches WerFaultSecure as WinTcb-Light, inherits handles from csrss, dumps memory regions and runs pattern matching.
- **build note:** embed the legacy `WerFaultSecure.exe` **6.3.x** (Win8.1, e.g. `6.3.9600.17415`). Modern `10.x` only fills `/encfile` and leaves the plaintext `/file` empty → `dump invalid or encrypted`.
- `ppldump.exe` — standalone PPL dumper.
- `regctl.exe` / `elevate.exe` — privilege escalation helpers (TrustedInstaller token, COM elevation).

builds with MSVC (`cl`). see `src/exploit/build_*.bat`.

## paths-parser (paths)

parses filesystem paths and matches against embedded YARA rules for known cheat signatures, bypass frameworks, and suspicious tooling.

- pattern matching across process paths, loaded modules, file artifacts.
- configurable replace rules via `Replaceparser.h`.

builds with MSVC. entry point in `src/paths-parser/main.cpp`.

## structure

```
tools/          prebuilt binaries
src/
  exploit/      PPL bypass scanner + helpers
  paths-parser/ YARA-based path analyzer
ref/            third-party references (system-informer, pplfault)
```

## requirements

- windows 10/11
- MSVC (Visual Studio Build Tools)
- admin / elevated prompt for PPL operations

## pplscan

Fluxo único em C++ (`pplscan.exe`): dump → paths → analyzer `paths` → consulta USN Journal dos arquivos deletados. Sem Python.

## path extraction (csrss)

`pplscan` varre as regioes `MINIDUMP_MEMORY64` em **UTF-16LE** e **ASCII/ANSI (cp1252)**.

Regex-equivalente (case-insensitive):

```
(?<![A-Za-z0-9])
(?:
    (?:\\\\\?\\|\\\\\.\\|\\\?\?\\)?[A-Za-z]:[\\/]
  | \\Device\\HarddiskVolume\d+\\
  | \\SystemRoot\\ | %SystemRoot%\\ | %windir%\\
  | \\\\[^\\/:*?\"<>|]{1,63}\\[^\\/:*?\"<>|]+\\
)
(?:[^\x00-\x1F\\/:*?\"<>|]{1,255}[\\/]){0,63}
[^\x00-\x1F\\/:*?\"<>|]{1,250}\.[A-Za-z0-9]{2,8}
```

Extras: extensao com >=1 letra e 2-8 chars (rejeita `.79` / `.e`); rejeita `*.exe.Local`;
segmentos <=255 / <=64 niveis; trim de espacos/pontos finais; UTF-16 so BMP latino.

Normalizacao: `\Device\HarddiskVolumeN\` -> letra via `QueryDosDeviceW`;
`\SystemRoot\` / `%windir%` -> `GetWindowsDirectoryW`; `\\?\C:\` / `\??\C:\` -> `C:\`.
Dedup case-insensitive (hash). Extensoes hot (`.dll` `.exe` `.sys` `.scr` `.cpl` `.ocx` `.tmp` `.dat` `.bin` ...) saem primeiro.

Teste: `pplscan.exe --paths-only [saida.txt]` (tambem grava `saida.txt.old` com o extrator legado).

