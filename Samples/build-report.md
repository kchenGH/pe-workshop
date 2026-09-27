# Native sample build report

Completed 2026-09-27 with LLVM clang-cl/lld-link 18.1.8 and Windows SDK 10.0.26100.0 x64 import libraries.

## Artifacts

| File | Bytes | SHA256 |
| --- | ---: | --- |
| `ConsoleDemo.exe` | 6144 | `486e3c43ec864b7526cbf21bc64a591523c2a0e3ec175e271cce01a20b10540d` |
| `GuiDemo.exe` | 6144 | `945c00b666bfb31f8987e73e6a46a45a41832a7b57404b4500d8a88b883c38ab` |
| `OriginalConsole.exe` | 6144 | `eb8b6e22a0253a3f87546bf36886d457b666af7cb4f2a1b139f345911e0c739b` |
| `ModifiedConsole.exe` | 7243 | `c5df92ac46f4b8ac9bf4d24de3c98671775273a8b032e2c9d5399c4cf77ed29c` |

Source, `build.ps1`, `verify.ps1`, and `manifest.json` are retained. Only `OS/Samples` was edited for this task. The editor and `fibonacci.c` were untouched.

## Verification evidence

1. Before implementation, `verify.ps1` failed with the expected missing-artifact assertion: `ConsoleDemo.exe must exist`.
2. `build.ps1` compiled all native sources and linked with no compiler/linker errors or warnings; its complete verification run passed.
3. A second `build.ps1` run passed all checks and reproduced all four executables and `manifest.json` byte-for-byte. Manifest SHA256: `a65ef0fde62da3651887dc2e7446d3bc618e51b3c28590302d164355d58bcf02`.
4. All console samples produced the exact expected messages with CRLF, no stderr, and exit code 0. `GuiDemo.exe --self-test` produced no output and exited 0 without a dialog.
5. Independent parsing confirmed AMD64 PE32+, correct console/GUI subsystems, expected Win32 imports, nonzero base-relocation directories, zero CLR directories, and valid file/section alignments and bounds.
6. Windows ImageHlp agreed with the independent checksum algorithm: ConsoleDemo `56370`, GuiDemo `39013`, and OriginalConsole `64113` are valid. ModifiedConsole retains `64113` while its computed checksum is `27871`.
7. The modified file adds exactly one RWX `.demo` section. Its entry RVA `0x6000` points at `E9 FB AF FF FF`, a relative jump directly to original entry RVA `0x1000`. All original imports remain identical. The original `.text` code is unchanged; its section permissions are changed.
8. All 11 patch records reconstruct the modified bytes exactly from OriginalConsole; the unchanged checksum is separately recorded. The 75-byte overlay is explicitly labeled and lies outside mapped sections.

## Scope and limits

All planned transformations were implemented; no substitute transformations were needed. Reproducibility was established on the installed, recorded toolchain. Different toolchain versions can produce different layouts and hashes. Automated GUI validation covers its noninteractive path and GUI subsystem/imports; an interactive dialog screenshot was not requested or taken. PE Workshop comparison-engine and UI integration checks are performed by the parent task.

The reduced mitigation declarations and writable executable sections are deliberate teaching fixtures. They are facts about PE metadata, not a claim that an operating system will disable every corresponding runtime protection, or that similar findings establish malware intent.
