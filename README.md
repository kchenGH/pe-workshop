# PE Workshop

A Windows desktop inspector, fixed-size editor and comparison tool for Portable Executable (PE) files. Built with C# and WPF on .NET 10.

- Inspect PE32/PE32+ headers, sections, data directories, ordinary imports and exports.
- Edit existing bytes and numeric fields with undo/redo, checksum updates and protected copy saving.
- Compare two executables with structural explanations, investigation priorities and highlighted byte evidence.
- Learn the format through contextual help and four small native teaching programs.

Comparisons read files as data. Explanations describe possible causes; suspicious indicators do not establish malicious intent or runtime behavior.

## Run

On Windows with the .NET 10 SDK, clone this repository and run:

```powershell
git clone https://github.com/kchenGH/pe-workshop.git
cd pe-workshop
dotnet run --project PE-Editor/src/PeWorkshop.App -c Release
```

The four native x64 sample EXEs are included, so the comparison shortcuts work without rebuilding them. Choose **Compare files**, then **Console vs GUI** or **Original vs modified**, or choose your own supported PE files.

To rebuild the samples, run all checks and publish the editor:

```powershell
cd PE-Editor
.\build.ps1
```

The complete build additionally needs LLVM clang-cl/lld-link and Windows SDK import libraries. See the [sample build instructions](Samples/README.md) for default paths and overrides. After publishing, open `PE-Editor/PE Workshop.cmd` or `PE-Editor/artifacts/PEWorkshop/PEWorkshop.exe`. Framework-dependent builds require the .NET 10 Windows Desktop Runtime; `build.ps1 -SelfContained` bundles the runtime.

## Explore

| Location | Contents |
| --- | --- |
| [PE-Editor](PE-Editor/README.md) | Application source, solution, launcher, tests and build instructions |
| [User guide](PE-Editor/docs/USER-GUIDE.md) | PE concepts, editing walkthrough and comparison workflow |
| [Samples](Samples/README.md) | Console, GUI, original console and harmless modified-console EXEs, plus sources |
| [Patch manifest](Samples/manifest.json) | Exact teaching modifications, before/after bytes and hashes |

The modified sample is byte-patched from the original. Its added entry stub only jumps back to the original code; the programs print text or display a message box. The sample walkthrough documents every intentional alteration.

## Verification

The version 1.2 release was verified with 45 passing core scenarios, native sample output/structure/checksum checks and a passing WPF integration test. The test project uses a console runner:

```powershell
dotnet run --project PE-Editor/tests/PeWorkshop.Tests -c Release
```

Editor build outputs, local task notes and unrelated workspace files are excluded from Git.

## License

Project-owned code, documentation, scripts and teaching samples are licensed under the [MIT License](LICENSE), copyright 2026 kchenGH. External runtimes and build tools retain their own terms; see [third-party licensing notes](THIRD_PARTY_NOTICES.md).
