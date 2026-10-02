# PE Workshop

A Windows desktop inspector, fixed-size editor and comparison tool for Portable Executable (PE) files. Built with C# and WPF on .NET 10.

- Inspect PE32/PE32+ headers, sections, data directories, ordinary imports and exports.
- Edit existing bytes and numeric fields with undo/redo, checksum updates and protected copy saving.
- Compare two executables with structural explanations, investigation priorities and highlighted byte evidence.
- Inspect compiler-recorded variable names, types, scopes, source declarations and storage descriptions in embedded DWARF debug information.
- Learn the format through contextual help and five small native teaching programs.

Comparisons read files as data. Explanations describe possible causes; suspicious indicators do not establish malicious intent or runtime behavior.

## Run

On Windows with the .NET 10 SDK, clone this repository and run:

```powershell
git clone https://github.com/kchenGH/pe-workshop.git
cd pe-workshop
dotnet run --project PE-Editor/src/PeWorkshop.App -c Release
```

The five native x64 sample EXEs are included. Choose **Compare files**, then **Console vs GUI** or **Original vs modified**, or choose your own supported PE files. Choose **Explore debug symbols** on the welcome screen to inspect the DWARF sample. For your own GCC/MinGW program, retain the symbols (for example, compile with `gcc -O0 -g3 -gdwarf-4 program.c -o program.exe`), open the EXE and choose **Variables**. No GDB installation is required to inspect it.

The Variables view supports common embedded DWARF 2–5 records. It does not recover stripped names or provide live variable values, PDB parsing, or external/split/compressed debug-file loading. Diagnostics identify partial or unsupported results. [The guide](PE-Editor/docs/USER-GUIDE.md#inspect-variable-names-and-debug-symbols) explains the distinctions.

To rebuild the samples, run all checks and publish the editor:

```powershell
cd PE-Editor
.\build.ps1
```

The complete build additionally needs LLVM clang-cl/lld-link and Windows SDK import libraries. Rebuilding the optional DWARF fixtures uses MinGW GCC through `Samples/build-debug-symbols.ps1`; the normal editor build uses the included debug sample. See the [sample build instructions](Samples/README.md) for default paths and overrides. After publishing, open `PE-Editor/PE Workshop.cmd` or `PE-Editor/artifacts/PEWorkshop/PEWorkshop.exe`. Framework-dependent builds require the .NET 10 Windows Desktop Runtime; `build.ps1 -SelfContained` bundles the runtime.

## Explore

| Location | Contents |
| --- | --- |
| [PE-Editor](PE-Editor/README.md) | Application source, solution, launcher, tests and build instructions |
| [User guide](PE-Editor/docs/USER-GUIDE.md) | PE concepts, editing walkthrough and comparison workflow |
| [Samples](Samples/README.md) | Console, GUI, original/modified console and DWARF debug EXEs, plus sources |
| [Patch manifest](Samples/manifest.json) | Exact teaching modifications, before/after bytes and hashes |

The modified sample is byte-patched from the original. Its added entry stub only jumps back to the original code; the programs print text or display a message box. The sample walkthrough documents every intentional alteration.

## Verification

Core scenarios cover PE parsing/editing/comparison and DWARF records, malformed data, limits and real compiler output. The WPF integration test covers the Variables view, filtering, help, symbol highlights and stale-result cancellation alongside the existing editor checks. The test project uses a console runner:

```powershell
dotnet run --project PE-Editor/tests/PeWorkshop.Tests -c Release
```

Editor build outputs, local task notes and unrelated workspace files are excluded from Git.

## License

Project-owned code, documentation, scripts and teaching samples are licensed under the [MIT License](LICENSE), copyright 2026 kchenGH. External runtimes and build tools retain their own terms; see [third-party licensing notes](THIRD_PARTY_NOTICES.md).
