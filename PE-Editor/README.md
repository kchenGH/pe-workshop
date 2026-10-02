# PE Workshop

A native Windows editor for Portable Executable files: `.exe`, `.dll`, `.sys`, `.ocx`, `.efi`, and other PE32 / PE32+ images. Built with C# and WPF on .NET 10. No third-party runtime packages.

New to executable formats? Start with the [beginner guide](docs/USER-GUIDE.md). It explains what the editor reveals and walks through inspecting the editor itself.

Choose **Compare files** to compare any two supported PE files. **Console vs GUI** and **Original vs modified** load the teaching pairs from the adjacent [Samples folder](../Samples/README.md). The comparison lists structural changes and exact byte differences, explains possible causes, and highlights investigation priorities. Select a row for paired evidence bytes; **A in editor** or **B in editor** opens its snapshot with pink evidence outlines in the normal hex editor. Comparison is static and does not execute either file. Suspicious indicators are reasons to investigate, not malware verdicts.

Small circular **i** buttons appear beside technical labels, fields, table headings, and actions. Hover for a detailed explanation, or click / press Enter or Space to keep it open. Press Escape or click outside to dismiss it. Help includes practical examples and editing implications; reading it never invokes the adjacent action or edits the file.

Choose **Explore debug symbols** on the welcome screen, or open a GCC/MinGW EXE with embedded DWARF symbols and choose **Variables**. The view reads compiler-recorded globals, locals and parameters, including names, types, scopes, source declarations and storage descriptions. Filter the table and select a row for its complete description. **View symbol in hex** highlights its debug record, not a live value. The reader runs in the background; changing files, views or document bytes cancels obsolete work.

## Run

Double-click **`PE Workshop.cmd`**, or launch **`artifacts/PEWorkshop/PEWorkshop.exe`** after building. Framework-dependent builds require the .NET 10 Windows Desktop Runtime. Keep the files in the published folder together.

You can also pass a file on the command line:

```powershell
.\artifacts\PEWorkshop\PEWorkshop.exe C:\Windows\System32\notepad.exe
```

Drop a file into the window, select **Open file**, or use **Explore PE Workshop itself** on the welcome screen. Inspected binaries are read as data; the editor never loads or executes them.

## Editing

- **Overview** shows format, architecture, section layout, metadata, and parsing diagnostics. Select a segment in the section map to open its bytes.
- **Headers** exposes DOS, COFF, and optional-header numeric fields. Select a row and choose **Edit value**, or double-click it. Values accept decimal or `0x` hexadecimal, with field-width validation.
- **Sections** shows virtual and raw layout, flags, and read/write/execute permissions. Double-click a section to edit its numeric fields; **Rename selected section** changes its name.
- **Data directories** lists addresses, sizes, and mapped offsets. Address and size fields are editable. The certificate entry uses a file offset.
- **Imports / Exports** inspect named and ordinal symbols, import modules, hints, IAT addresses, and export forwarders. Filter any table with the search box.
- **Variables** decodes common embedded DWARF 2–5 records, including GNU long section names, DWARF32/64 lengths and 32/64-bit addresses. It describes simple locations and identifies location lists without evaluating them. Missing, partial, unsupported and damaged information have explicit status messages and diagnostics.
- **Hex editor** displays paged hex and ASCII. Click a byte and type two hex digits to replace it. **Go to** accepts a file offset or RVA; **Find next** searches hex bytes or ASCII text and wraps at EOF. **Replace at cursor** applies a sequence such as `90 90 00` without changing file length.
- **Changes** lists applied edits. Undo and redo span both structured and hex changes. Amber hex bytes differ from the last saved copy.
- **Update checksum** calculates and writes the PE checksum as an undoable edit. Saving does not change the checksum automatically.

Changes are staged in memory. Invalid essential-header or out-of-bounds changes are rejected without changing the document. **Save copy** writes a temporary file and atomically moves or replaces it at the destination. The original source is protected, including common Windows path aliases. After a successful save, the current bytes become the clean baseline; undo history remains available.

## Shortcuts

| Action | Shortcut |
| --- | --- |
| Open | Ctrl+O |
| Save copy | Ctrl+S or Ctrl+Shift+S |
| Undo / redo document changes | Ctrl+Z / Ctrl+Y outside text inputs |
| Filter table / find bytes | Ctrl+F |
| Go to offset or RVA | Ctrl+G |
| Move hex cursor | Arrow keys, Home, End, Page Up, Page Down |
| First / last byte | Ctrl+Home / Ctrl+End in the hex view |
| Cancel a half-entered byte | Esc |

## Build and verify

Requires Windows and the .NET 10 SDK. From this directory:

```powershell
.\build.ps1
```

This builds/verifies the four comparison samples in `../Samples`, uses the included `DebugSymbolsDemo.exe`, runs the core test suite, publishes the app to `artifacts/PEWorkshop`, and runs the WPF integration test including comparison, DWARF variables and evidence highlights. Building the comparison samples uses LLVM clang-cl/lld-link and Windows SDK import libraries; [their README](../Samples/README.md) lists defaults and path overrides. Run `../Samples/build-debug-symbols.ps1` with MinGW GCC to rebuild the debug demo and create optional DWARF 5 and stripped fixtures; GNU objdump verifies their names independently. Use `./build.ps1 -SelfContained` to bundle the Windows x64 runtime for a machine without .NET (the first build may download runtime packs).

Individual commands:

```powershell
dotnet build PEWorkshop.sln -c Release
dotnet run --project tests/PeWorkshop.Tests -c Release
dotnet run --project src/PeWorkshop.App -c Release
dotnet run --project src/PeWorkshop.App -c Release -- --smoke-test artifacts/smoke
```

The test project is a console test runner, so run it with `dotnet run`, not `dotnet test`. It checks synthetic 32/64-bit fixtures, imports/exports, comparison explanations and evidence, exact-byte edits, history, original-file protection, saved baselines, malformed files, and checksum parity with Windows ImageHlp. The WPF smoke test exercises views, filtering, the edit dialog, toolbar actions, hex editing and searching, comparison, copy saving, and an independent `PEReader` check. It creates screenshots and test output under `artifacts/smoke` and reads its PE inputs as data. The separate sample verifier runs only the four supplied harmless programs to check their expected outputs and exit codes.

## Scope

This version performs **fixed-size edits** and accepts files up to **128 MiB**. It does not add or resize sections, rebuild imports, disassemble code, edit resource trees, or re-sign files. Imports/Exports inspect standard tables; delay-import directories are listed but not decoded. Structural validation does not guarantee that an edited file will execute correctly.

Variable inspection requires retained debug records; `gcc -O0 -g3 -gdwarf-4 program.c -o program.exe` is a useful starting point. DWARF 5 is also supported for common forms. Full debug output does not guarantee every optimized variable has a location. PDB, external/split/compressed debug data, indexed forms and unsupported unit kinds are diagnosed rather than loaded. The app never follows recorded source paths or invokes GDB, executes debug expressions or reads another process. Runtime values require a debugger. Basic type summaries do not reconstruct all C++ declarations or expand every structure member. This is read-only symbol inspection; it is not a symbol editor.

The DWARF reader caps compilation units at 4,096, debug entries at 200,000, variables at 50,000, nesting/reference depth at 64, abbreviations at 65,536, attributes at 1,000,000, individual strings at 16 KiB and decoded string bytes at 32 MiB. Line tables have bounded file/directory counts and format columns. Type/scope display text is limited to 4,096 characters and diagnostics to 256 plus a truncation notice. Reaching a limit produces an explicit diagnostic; partial results must not be treated as a complete list of source variables.

Embedded certificate data is preserved. Editing signed content can invalidate its signature; certificate trust and catalog signatures are not verified. Auxiliary-table damage is shown as diagnostics, and any successfully parsed entries remain visible.

## Project layout

- `src/PeWorkshop.Core` — bounds-checked parser, field metadata, edit history, checksum, and save logic.
- `src/PeWorkshop.App` — WPF workspace, inspection views, field dialogs, and hex editor.
- `tests/PeWorkshop.Tests` — deterministic console tests and Windows reference checks.
- `docs` — beginner guide and comparison walkthrough.

Format references: [Microsoft PE / COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), [DWARF 4](https://dwarfstd.org/doc/DWARF4.pdf), [DWARF 5](https://dwarfstd.org/doc/DWARF5.pdf).

## License

PE Workshop is licensed under the [MIT License](../LICENSE). See [third-party licensing notes](../THIRD_PARTY_NOTICES.md) for external runtimes and build tools.
