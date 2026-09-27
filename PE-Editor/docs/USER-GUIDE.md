# Learning with PE Workshop

PE Workshop lets you inspect how a Windows executable or library is organized and make small, reversible edits to its existing bytes. It answers practical questions such as “Is this x86 or ARM64?”, “Which DLLs and symbols does it declare as dependencies?”, “Where is the entry point?”, and “Which bytes did my patch change?” Opening a file reads it as data; the workshop does not execute the opened program.

It is useful for learning the PE format, comparing header metadata between builds, investigating structural warnings or declared dependency mismatches, and reviewing precise binary patches. It does not recover source code, judge whether a file is malware, or provide an arbitrary feature editor. Changing a number that describes a program does not automatically change the program to match that description.

## Read the help beside a label

The small circular **i** beside a technical term or action explains its meaning, a practical use and any editing implications. Hover over it for a tooltip. Click it to keep the explanation open; click it again or press **Escape** to dismiss it. Keyboard users can focus the help button and activate it with **Enter** or **Space**. Activating help is independent of the nearby action: it does not apply an edit, sort a table or navigate to another view.

Read a field's own help before editing. Names can be misleading: the COFF header's **Characteristics** flags describe the overall image, while a section's **Characteristics** flags describe that section. **DllCharacteristics** also applies to EXE files. A directory's address usually means RVA, but the **Certificate** directory stores a disk file offset.

## A first walkthrough: inspect the workshop itself

1. On the welcome screen, choose **Explore PE Workshop itself →**. This opens the workshop's executable as a static sample. You do not need to download or launch another program.
2. In **Overview**, read **Architecture** and **Format**. Architecture comes from the COFF Machine value. PE32 and PE32+ describe header layouts; PE32+ by itself does not mean x64. Compare **File size** with **Image size**: stored disk bytes and the loaded image's memory span are different measures. Read any **Diagnostics**.
3. Open **Headers**. Filter for `Machine`, then select the row and read its help. Next find `e_lfanew`: its stored value is the file offset of the PE signature. **View in hex** shows where a selected field's bytes are stored; it does not interpret that field's value as a destination. Open **Hex editor**, select **File offset**, enter the `e_lfanew` value and choose **Go** to inspect the signature at that destination. It begins with bytes `50 45 00 00`.
4. Open **Sections**. Find a familiar name such as `.text` if present. Compare its **RVA**, **Virtual size**, **Raw offset**, **Raw size** and **Permissions**. Conventionally `.text` holds code, but section names are labels chosen by the producer. R/W/X summarize requested readable, writable and executable memory. Select a section and choose **View in hex** to inspect its stored bytes; the app does not disassemble instructions.
5. Open **Data directories**. These entries point to structures such as imports, resources and relocations. Read the help for **Import**, **Resource** and **Certificate**. A zero address and size generally indicate an absent entry. Resource bytes are available through **View in hex**, but the workshop does not decode icons, dialogs or version-resource trees.
6. Open **Imports**. Filter for a module name visible in your sample. Each row is an ordinary declared import, with a name or ordinal, a hint when applicable and an IAT slot RVA. These are requested dependencies, not proof that execution calls every listed function. The app does not locate DLL files or simulate Windows DLL search; dynamically obtained and delay-loaded symbols may not appear here.
7. Open **Exports**. A program may have no exported symbols; a DLL commonly has some. An ordinal is a module-specific numeric identifier. A forwarder names another module's symbol rather than this image's implementation. The app displays these declarations without loading the destination module.
8. Return to **Hex editor**. In **File offset** mode, go to `0x0`; the file starts with `4D 5A`, the MZ signature. Select **Hex bytes** search, enter `4D 5A` and choose **Find next**. It searches onward and wraps to the start. Alternatively, select **ASCII text** to search for a short name you saw in Imports. Matches establish equal bytes, not their meaning. Avoid typing into byte cells during this read-only walkthrough: typing two hex digits applies an edit.

The exact sections, imports and metadata depend on how this executable was built and packaged. An absent entry is an observation about this sample, not an error in the walkthrough.

## Compare two programs

Choose **Compare files** in the top toolbar. You can compare files even when the main editor is empty. If a file is already open, its current bytes become baseline A, including unsaved edits. Choose **A** as the reference and **B** as the candidate, then choose **Compare**. Each comparison uses snapshots; choose the files again to pick up later changes on disk.

The window compares PE structure, declared dependencies and exact bytes. Each row includes values from both files and an explanation of the field or feature, with plausible reasons for the difference. Static inspection cannot determine the author's exact reason for a change, prove that imported code executes, or establish malware intent.

1. Choose **Console vs GUI** to load the first supplied pair. Find the **Subsystem** difference: the console sample declares a console program, while the GUI sample declares a windowed program. Inspect imports: console output uses `GetStdHandle` and `WriteFile`; the GUI sample declares `USER32.dll!MessageBoxA`. These are ordinary differences between programs with different features.
2. Choose **Original vs modified**, then choose **Suspicious only**. This harmless training pair demonstrates removed mitigation declarations, writable executable memory and an entry point moved into an added executable section. Other findings explain the changed timestamp, marker text, appended bytes and stale checksum.
3. Select a finding. Read the full before/after values and explanation below the table. The paired byte preview shows each side at that finding's own evidence offset. Pink marks unequal preview bytes; amber marks other bytes within the evidence range. **Previous** and **Next** page through long ranges. An absent side explicitly says that no stored evidence is available.
4. Choose **A in editor** or **B in editor** to reveal that snapshot and highlight its evidence in the main Hex editor. The comparison window hides so the bytes are visible. Choose **Compare files** again to return to the same report. The usual unsaved-change prompt applies if this replaces edited work. Merely selecting a finding or inspecting its bytes does not patch a file.
5. Choose **Raw bytes** to see literal changed ranges, or enter words in **Filter** to narrow findings. Raw differences compare the same file positions; inserting bytes can therefore produce many positional changes. Structural findings match relevant PE records separately.

**Information**, **Review** and **Suspicious** describe investigation priority. A new section, API import or checksum mismatch can have legitimate causes. The engine does not run either input, disassemble instructions, verify publisher trust, or compare every possible PE substructure. Read its displayed limitations and parser warnings. Large results are capped for display while the differing-byte count still covers the complete files.

The four runnable samples and their source are in the sibling `Samples` folder. See [the sample walkthrough](../../Samples/README.md) for each deliberate alteration and [manifest.json](../../Samples/manifest.json) for exact before/after bytes. These are native x64 Windows programs. `ModifiedConsole.exe` is patched directly from `OriginalConsole.exe`; its added entry stub immediately jumps back to the original code, which prints a changed teaching marker.

## Which view answers which question?

| Your question | View | What the result means |
| --- | --- | --- |
| Which CPU and header layout does it declare? | Overview, Headers | Machine identifies architecture; Magic selects PE32 or PE32+. Neither verifies that code matches a changed declaration. |
| How are disk bytes mapped into image memory? | Sections | Raw ranges locate disk bytes; RVA and virtual sizes describe the loaded layout. Some memory is zero-filled and has no stored bytes. |
| Where are imports, resources or runtime tables located? | Data directories | Address/size pairs locate structures. Per-directory help identifies what this app decodes. |
| Which ordinary dependencies does it declare? | Imports | Module and symbol records reveal the ordinary import interface, not every runtime dependency or function call. |
| What interface does it publish? | Exports | Names, ordinals, RVAs and forwarders describe the exported binary interface, not source signatures. |
| What bytes occupy this location or match this pattern? | Hex editor | Literal file bytes and an ASCII reading aid, without instruction or resource decoding. |
| What did I edit in this session? | Changes | Patch offsets and before/after bytes for applied edits in the current undo history. |
| How do two programs differ, and what might explain that? | Compare files | PE structure and exact byte differences, possible causes, and prioritized evidence to investigate. |
| Does the parser see structural inconsistencies? | Overview diagnostics | Bounds, alignment and mapping warnings, not a complete loader validation or safety verdict. |

## Understand the three kinds of address

A **file offset** counts bytes from the beginning of the disk file. An **RVA**, or relative virtual address, counts from the base of the image when it is loaded. A **virtual address** is the actual loaded base plus the RVA. The preferred Image base can differ from the actual load base because of relocation and address randomization.

For a file-backed position inside a section, the file offset is its Raw offset plus the distance of the RVA from the section's starting RVA. The workshop can perform this mapping when you select **RVA** in the **Hex editor** Go to control. A zero-filled memory tail may have an RVA with no disk bytes, so it cannot be revealed. Certificate directory addresses are the important exception: use **File offset** for them.

## Optional metadata exercise on a separate copy

This exercise makes a narrow metadata change without attempting to change the program's features. It is reversible in the editor, but changing signed content can invalidate an Authenticode signature. Keep the resulting copy as a learning artifact; you do not need to run it.

1. While inspecting the workshop itself, use **Save copy** to write a distinct filename such as `PEWorkshop-learning-copy.exe` in a directory you control. Keep it separate from the installed/running executable. **Open** that copy for the exercise.
2. In **Headers**, filter for `TimeDateStamp` in the **COFF header**. Record the displayed value. Read its help: this is producer metadata, may reflect a reproducible build, and is not proof of creation time.
3. Select the field and choose **Edit value**. Enter a slightly different value that still fits four bytes: add one unless the value is `0xFFFFFFFF`, in which case subtract one. Choose **Apply**. In **Changes**, inspect its offset and Before/After bytes.
4. Choose **Undo** and confirm that the original field value returns. Choose **Redo** to restore the experimental edit. The unsaved state tells you whether edits still need writing to disk; Undo does not rewrite files you already saved.
5. Optionally choose **Update checksum** and inspect its additional change record. A PE checksum is not cryptographic signing; recalculating it cannot repair an invalidated signature.
6. Use **Save copy** to write another distinct filename, for example `PEWorkshop-timestamp-experiment.exe`. Saving marks the current buffer clean. Reopen the original sample to inspect its original bytes. Undo after saving affects only the in-memory buffer and can mark it unsaved again. Keep the original workshop executable unchanged.

You can also inspect **Rename section**, then Cancel, to see its eight-ASCII-byte constraint. A name change is only a label change. Do not assume that renaming `.data` to `.text` transforms data into instructions.

## Editing boundaries and interpretation

Edits preserve the existing file length. Numeric fields retain their original widths and little-endian byte order. Hex replacement overwrites existing bytes; it does not insert or delete data. The application does not rebuild sections, directories, resources, imports, relocations or debug information automatically. Changing a pointer or size can make a table refer to unrelated bytes, even if the file still parses.

Changing **Machine** does not convert CPU instructions. Changing **Magic** does not convert PE32 to PE32+. Changing **ImageBase** is not complete rebasing. An **Entry point** often starts runtime initialization rather than the source function `main`; redirecting it can skip required setup. Increasing **NumberOfRvaAndSizes** does not create more directory storage. Version fields are metadata or loader declarations, not proof of requirements or tested OS support.

Embedded certificate presence is not signature verification. The app does not establish publisher trust, catalog signing or whether a signature remains valid. A file without an embedded certificate is not automatically unsafe. Diagnostics likewise describe parsing concerns, not malware detection. No warnings is not proof of runtime correctness.

The app supports PE32/PE32+ images up to 128 MiB, at most 96 sections and the first sixteen standard directories. Ordinary imports and exports are decoded with bounded table sizes; warnings can indicate incomplete information. It does not decode resources, managed .NET metadata/IL, exception records, TLS callbacks or all loader/security configuration structures. Raw bytes remain useful for learning, but interpreting these structures may require additional specialized tools.

## Reference

The field meanings and coordinate conventions follow Microsoft's [PE format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format). This guide distinguishes that format's declarations from the workshop's implemented inspection and editing capabilities. Consult the specification when investigating unusual producers, reserved values or architecture-specific records.
