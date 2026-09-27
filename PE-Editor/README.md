# PE Workshop

A native Windows editor for Portable Executable files: `.exe`, `.dll`, `.sys`, `.ocx`, `.efi`, and other PE32 / PE32+ images. Built with C# and WPF on .NET 10. No third-party runtime packages.

New to executable formats? Start with the [beginner guide](docs/USER-GUIDE.md). It explains what the editor reveals and walks through inspecting the editor itself.

Choose **Compare files** to compare any two supported PE files. **Console vs GUI** and **Original vs modified** load the teaching pairs from the adjacent [Samples folder](../Samples/README.md). The comparison lists structural changes and exact byte differences, explains possible causes, and highlights investigation priorities. Select a row for paired evidence bytes; **A in editor** or **B in editor** opens its snapshot with pink evidence outlines in the normal hex editor. Comparison is static and does not execute either file. Suspicious indicators are reasons to investigate, not malware verdicts.

Small circular **i** buttons appear beside technical labels, fields, table headings, and actions. Hover for a detailed explanation, or click / press Enter or Space to keep it open. Press Escape or click outside to dismiss it. Help includes practical examples and editing implications; reading it never invokes the adjacent action or edits the file.

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

This builds/verifies the four native samples in `../Samples`, runs the core test suite, publishes the app to `artifacts/PEWorkshop`, and runs the WPF integration test including comparison and evidence highlights. Building the samples uses LLVM clang-cl/lld-link and Windows SDK import libraries; [their README](../Samples/README.md) lists defaults and path overrides. Use `./build.ps1 -SelfContained` to bundle the Windows x64 runtime for a machine without .NET (the first build may download runtime packs).

Individual commands:

```powershell
dotnet build PEWorkshop.sln -c Release
dotnet run --project tests/PeWorkshop.Tests -c Release
dotnet run --project src/PeWorkshop.App -c Release
dotnet run --project src/PeWorkshop.App -c Release -- --smoke-test artifacts/smoke
```

The test project is a console test runner, so run it with `dotnet run`, not `dotnet test`. It checks synthetic 32/64-bit fixtures, imports/exports, comparison explanations and evidence, exact-byte edits, history, original-file protection, saved baselines, malformed files, and checksum parity with Windows ImageHlp. The WPF smoke test exercises views, filtering, the edit dialog, toolbar actions, hex editing and searching, comparison, copy saving, and an independent `PEReader` check. It creates screenshots and test output under `artifacts/smoke` and reads its PE inputs as data. The separate sample verifier runs only the four supplied harmless programs to check their expected outputs and exit codes.

## Scope

This version performs **fixed-size edits** and accepts files up to **128 MiB**. It does not add or resize sections, rebuild imports, disassemble code, edit resource trees, or re-sign files. The symbol views inspect the standard import/export tables; delay-import directories are listed but not decoded. Structural validation does not guarantee that an edited file will execute correctly.

Embedded certificate data is preserved. Editing signed content can invalidate its signature; certificate trust and catalog signatures are not verified. Auxiliary-table damage is shown as diagnostics, and any successfully parsed entries remain visible.

## Project layout

- `src/PeWorkshop.Core` — bounds-checked parser, field metadata, edit history, checksum, and save logic.
- `src/PeWorkshop.App` — WPF workspace, inspection views, field dialogs, and hex editor.
- `tests/PeWorkshop.Tests` — deterministic console tests and Windows reference checks.
- `docs` — beginner guide and comparison walkthrough.

Format reference: [Microsoft PE / COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

## License

PE Workshop is licensed under the [MIT License](../LICENSE). See [third-party licensing notes](../THIRD_PARTY_NOTICES.md) for external runtimes and build tools.
