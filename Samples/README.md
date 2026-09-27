# Native PE teaching samples

The source, scripts, documentation and four teaching executables are covered by the repository's [MIT License](../LICENSE). See [third-party licensing notes](../THIRD_PARTY_NOTICES.md) for external build tools and operating-system dependencies.

Four small x64 Windows executables for PE Workshop comparisons. They use native Win32 imports and do not need the .NET or Visual C++ runtime. The programs only write console text or display a message box. They do not use networking, persistence, process injection, or destructive operations.

| File | Behavior | PE subsystem |
| --- | --- | --- |
| `ConsoleDemo.exe` | Prints `PE Workshop console demo: native Win32.` | Windows CUI, 3 |
| `GuiDemo.exe` | Displays a message box; `--self-test` exits silently | Windows GUI, 2 |
| `OriginalConsole.exe` | Prints `PE Workshop training marker: ORIGINAL.` | Windows CUI, 3 |
| `ModifiedConsole.exe` | Prints `PE Workshop training marker: MODIFIED.` | Windows CUI, 3 |

All successful runs exit with code 0. Console output ends with CRLF. `ModifiedConsole.exe` is produced by byte-patching `OriginalConsole.exe`; it is not compiled from a separate program. The full before/after patch data and file SHA256s are in `manifest.json`.

## Run and rebuild

From this directory in PowerShell:

```powershell
.\ConsoleDemo.exe
.\OriginalConsole.exe
.\ModifiedConsole.exe
.\GuiDemo.exe --self-test
.\build.ps1
```

Run `GuiDemo.exe` without arguments to display its dialog. The build runs `verify.ps1` by default. Run that script independently to validate existing artifacts without rebuilding them.

The supplied build defaults to LLVM clang-cl/lld-link 18.1.8 under `C:\Program Files\LLVM\bin` and Windows SDK 10.0.26100.0 x64 import libraries. Override `-ClangCl`, `-Linker`, or `-SdkLib` for another installation. No SDK headers are needed: `source/win32_min.h` declares the few imported Win32 functions. Object files live in `build/`.

`source/console.c` builds the console demonstration and the original training file. `source/gui.c` builds the dialog demonstration. A volatile absolute pointer in each program ensures the linker emits a real base relocation. The build enables `DYNAMIC_BASE`, `HIGH_ENTROPY_VA`, and `NX_COMPAT`, fixes the original COFF timestamp to 2024-01-01 UTC, reserves header space with a 1024-byte file alignment, and writes a valid PE checksum. `source/pe-tools.ps1` provides an independent parser for build verification and manifest generation.

Two complete builds on the recorded toolchain produced identical bytes for all four executables and `manifest.json`. Different compiler/linker versions may change code layout and hashes; the script derives its patch offsets from the freshly built original instead of relying on the example offsets below.

## Comparison walkthrough

First compare `ConsoleDemo.exe` with `GuiDemo.exe`. Their subsystem, program code, message strings, and imports differ for ordinary application reasons. Console code imports `GetStdHandle`, `WriteFile`, and `ExitProcess` from `KERNEL32.dll`. GUI code imports `GetCommandLineA` and `ExitProcess` from `KERNEL32.dll`, plus `MessageBoxA` from `USER32.dll`. Both declare the same three mitigations and contain valid checksums and relocation tables. A GUI subsystem or a `USER32.dll` import is not itself suspicious.

Next compare `OriginalConsole.exe` with `ModifiedConsole.exe`. Select the changed fields and sections, inspect their exact bytes, and follow the redirected entry RVA. These deliberately recognizable alterations demonstrate several findings commonly worth investigating:

| File offset | Change | Expected interpretation |
| --- | --- | --- |
| `0x0000081D` | `ORIGINAL` → `MODIFIED`, eight bytes | Changed printed data; no length shift |
| `0x00000080` | COFF timestamp: 2024-01-01 → 2025-01-01 UTC | Metadata changed; timestamps can be edited |
| `0x000000D6` | DLL characteristics: `0x8160` → `0x8000` | ASLR, high-entropy VA, and NX declarations removed |
| `0x000001A4` | `.text` flags: `0x60000020` → `0xE0000020` | Existing executable code section becomes writable |
| `0x00000248` | New 40-byte `.demo` section header | Added section with read/write/execute code flags |
| `0x0000007E` | Section count: 5 → 6 | Header accounts for the new section |
| `0x00000094` | SizeOfCode: `0x400` → `0x800` | Raw code size includes the added section |
| `0x000000C8` | SizeOfImage: `0x6000` → `0x7000` | Image size correctly covers the added section |
| `0x000000A0` | Entry RVA: `0x1000` → `0x6000` | Entry now starts in `.demo` |
| `0x00001800` | New 1024-byte raw section | Five-byte jump followed by zero alignment padding |
| `0x00001C00` | New 75-byte labeled training overlay | Appended bytes outside mapped sections |
| `0x000000D0` | Stored checksum stays `64113`; computed value becomes `27871` | Original valid checksum is intentionally stale |

The added `.demo` section has RVA `0x6000`, raw file offset `0x1800`, virtual size 5, raw size 1024, and flags `0xE0000020`. Its only instruction is:

```text
E9 FB AF FF FF    JMP rel32 -20485
target RVA = 0x6000 + 5 - 20485 = 0x1000
```

It immediately transfers control to the original entry point. The original `.text` code bytes and imports remain identical. The added section's zero padding is file-alignment padding; the program does not execute it. The overlay is explicitly labeled `PE WORKSHOP TRAINING OVERLAY - harmless appended bytes; never executed.` and has surrounding CRLFs. It is outside the section mappings.

Removing header mitigation flags changes the image's declarations; actual runtime enforcement also depends on Windows policy and architecture. Writable executable sections, redirected entry points, overlays, timestamps, and checksum mismatches are clues to examine in context. Static differences alone do not establish execution, intent, or malware. PE checksums are not digital signatures or proof of authenticity. These samples intentionally remain unsigned.

## Verification and manifest

`verify.ps1` checks AMD64/PE32+, native imports, a zero CLR directory, section bounds/alignment, relocation presence, subsystem, mitigation flags, the exact `.demo` jump target, preserved imports, overlay contents, recorded SHA256s, and console output/exit codes. It checks checksum calculations independently against Windows `imagehlp.dll!MapFileAndCheckSumW`. The GUI self-test exits without displaying a dialog; interactive dialog appearance was not part of the automated check.

The verifier also reconstructs `ModifiedConsole.exe` from the original bytes plus `manifest.json` changes and demands exact equality. Each change records a numeric file offset, hexadecimal offset, length, description, and Base64 before/after bytes. The manifest records the retained checksum separately because that field is deliberately not patched. See `build-report.md` for the measured build results.
