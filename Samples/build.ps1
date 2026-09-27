[CmdletBinding()]
param(
    [string]$ClangCl = 'C:\Program Files\LLVM\bin\clang-cl.exe',
    [string]$Linker = 'C:\Program Files\LLVM\bin\lld-link.exe',
    [string]$SdkLib = 'C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64',
    [switch]$SkipVerification
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'source\pe-tools.ps1')
foreach ($required in @($ClangCl, $Linker, (Join-Path $SdkLib 'kernel32.lib'), (Join-Path $SdkLib 'user32.lib'))) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Build input not found: $required" }
}
[void](New-Item -ItemType Directory -Force -Path (Join-Path $PSScriptRoot 'build'))
function Invoke-SampleTool([string]$Tool, [string[]]$ToolArguments) {
    & $Tool @ToolArguments
    if ($LASTEXITCODE -ne 0) { throw "$Tool failed with exit code $LASTEXITCODE" }
}

Push-Location $PSScriptRoot
try {
    $compilerFlags = @('/nologo', '/c', '/TC', '/O1', '/Oi', '/GS-', '/Zl', '/W4', '/WX', '/clang:--target=x86_64-pc-windows-msvc')
    Invoke-SampleTool $ClangCl ($compilerFlags + @('source\console.c', '/Fobuild\ConsoleDemo.obj'))
    Invoke-SampleTool $ClangCl ($compilerFlags + @('/DORIGINAL_SAMPLE', 'source\console.c', '/Fobuild\OriginalConsole.obj'))
    Invoke-SampleTool $ClangCl ($compilerFlags + @('source\gui.c', '/Fobuild\GuiDemo.obj'))
    # Fixed COFF timestamp and no debug paths make same-toolchain rebuilds reproducible.
    # A 1024-byte file alignment leaves enough section-table room for .demo.
    $linkFlags = @('/nologo', '/machine:x64', '/nodefaultlib', '/entry:sample_main',
        '/dynamicbase', '/highentropyva', '/nxcompat', '/fixed:no', '/filealign:1024',
        '/base:0x140000000', '/opt:ref', '/opt:icf', '/incremental:no',
        '/timestamp:1704067200', "/libpath:$SdkLib", 'kernel32.lib')
    foreach ($name in @('ConsoleDemo', 'OriginalConsole')) {
        Invoke-SampleTool $Linker ($linkFlags + @('/subsystem:console', "/out:$name.exe", "build\$name.obj"))
    }
    Invoke-SampleTool $Linker ($linkFlags + @('/subsystem:windows', '/out:GuiDemo.exe', 'build\GuiDemo.obj', 'user32.lib'))
} finally { Pop-Location }

# The three linked originals get genuine PE checksums before any teaching patch.
foreach ($name in @('ConsoleDemo.exe', 'GuiDemo.exe', 'OriginalConsole.exe')) {
    $path = Join-Path $PSScriptRoot $name
    $bytes = [IO.File]::ReadAllBytes($path)
    $pe = Read-SamplePe $bytes
    Write-U32 $bytes $pe.ChecksumOffset (Get-SampleChecksum $bytes $pe.ChecksumOffset)
    [IO.File]::WriteAllBytes($path, $bytes)
}

# ModifiedConsole is produced solely by cloning and editing OriginalConsole bytes.
$originalBytes = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'OriginalConsole.exe'))
$originalPe = Read-SamplePe $originalBytes
$originalLength = $originalBytes.Length
$sectionHeaderOffset = $originalPe.SectionTableOffset + 40 * $originalPe.SectionCount
$firstRaw = ($originalPe.Sections | Measure-Object RawPointer -Minimum).Minimum
if ($sectionHeaderOffset + 40 -gt $firstRaw -or $sectionHeaderOffset + 40 -gt $originalPe.SizeOfHeaders) {
    throw 'Insufficient reserved header space for the .demo section'
}
if ($originalPe.OverlayLength -ne 0) { throw 'Original unexpectedly contains an overlay' }
if (($originalPe.DllCharacteristics -band 0x160) -ne 0x160 -or $originalPe.RelocationRva -eq 0) {
    throw 'Original must declare all three mitigations and retain base relocations'
}
$newRaw = [int](Align-SampleValue $originalLength $originalPe.FileAlignment)
$newRva = [int](Align-SampleValue $originalPe.SizeOfImage $originalPe.SectionAlignment)
$newRawSize = [int]$originalPe.FileAlignment
$overlay = [Text.Encoding]::ASCII.GetBytes("`r`nPE WORKSHOP TRAINING OVERLAY - harmless appended bytes; never executed.`r`n")
$modifiedBytes = [byte[]]::new($newRaw + $newRawSize + $overlay.Length)
[Array]::Copy($originalBytes, $modifiedBytes, $originalLength)
$changes = [Collections.Generic.List[object]]::new()
function Set-SamplePatch([int]$Offset, [byte[]]$Replacement, [string]$Description) {
    $before = [byte[]]::new([Math]::Min($Replacement.Length, [Math]::Max(0, $originalLength - $Offset)))
    if ($before.Length) { [Array]::Copy($modifiedBytes, $Offset, $before, 0, $before.Length) }
    [Array]::Copy($Replacement, 0, $modifiedBytes, $Offset, $Replacement.Length)
    $changes.Add([ordered]@{
        description = $Description
        offset = $Offset
        offsetHex = '0x{0:X8}' -f $Offset
        length = $Replacement.Length
        beforeBase64 = [Convert]::ToBase64String($before)
        afterBase64 = [Convert]::ToBase64String($Replacement)
    })
}
$asciiOriginal = [Text.Encoding]::ASCII.GetString($originalBytes)
$markerOffset = $asciiOriginal.IndexOf('ORIGINAL', [StringComparison]::Ordinal)
if ($markerOffset -lt 0 -or $asciiOriginal.IndexOf('ORIGINAL', $markerOffset + 1, [StringComparison]::Ordinal) -ge 0) {
    throw 'Expected exactly one ORIGINAL marker'
}
Set-SamplePatch $markerOffset ([Text.Encoding]::ASCII.GetBytes('MODIFIED')) 'Replace the same-length printed marker ORIGINAL with MODIFIED'
Set-SamplePatch ($originalPe.CoffOffset + 4) ([BitConverter]::GetBytes([uint32]1735689600)) 'Change COFF timestamp from 2024-01-01 to 2025-01-01 UTC'
Set-SamplePatch ($originalPe.OptionalOffset + 70) ([BitConverter]::GetBytes([uint16]($originalPe.DllCharacteristics -band 0xfe9f))) 'Remove HIGH_ENTROPY_VA, DYNAMIC_BASE, and NX_COMPAT declarations'
$textSection = $originalPe.Sections | Where-Object Name -eq '.text'
if (-not $textSection) { throw 'Expected an original .text section' }
Set-SamplePatch ($textSection.HeaderOffset + 36) ([BitConverter]::GetBytes([uint32]($textSection.Characteristics -bor [uint32]2147483648))) 'Add WRITE permission to the original executable .text section'

$newSectionHeader = [byte[]]::new(40)
[Array]::Copy([Text.Encoding]::ASCII.GetBytes('.demo'), $newSectionHeader, 5)
Write-U32 $newSectionHeader 8 5
Write-U32 $newSectionHeader 12 $newRva
Write-U32 $newSectionHeader 16 $newRawSize
Write-U32 $newSectionHeader 20 $newRaw
Write-U32 $newSectionHeader 36 ([uint32]3758096416)
Set-SamplePatch $sectionHeaderOffset $newSectionHeader 'Add a .demo section header: five-byte code, read/write/execute permissions'
Set-SamplePatch ($originalPe.CoffOffset + 2) ([BitConverter]::GetBytes([uint16]($originalPe.SectionCount + 1))) 'Increase NumberOfSections by one'
Set-SamplePatch ($originalPe.OptionalOffset + 4) ([BitConverter]::GetBytes([uint32]($originalPe.SizeOfCode + $newRawSize))) 'Increase SizeOfCode to include the new raw code section'
Set-SamplePatch ($originalPe.OptionalOffset + 56) ([BitConverter]::GetBytes([uint32](Align-SampleValue ($newRva + 5) $originalPe.SectionAlignment))) 'Increase SizeOfImage with the required section alignment'
Set-SamplePatch ($originalPe.OptionalOffset + 16) ([BitConverter]::GetBytes([uint32]$newRva)) 'Redirect AddressOfEntryPoint to the .demo section'
$sectionBytes = [byte[]]::new($newRawSize)
$sectionBytes[0] = 0xe9
[int32]$relativeJump = $originalPe.EntryRva - ($newRva + 5)
[Array]::Copy([BitConverter]::GetBytes($relativeJump), 0, $sectionBytes, 1, 4)
Set-SamplePatch $newRaw $sectionBytes 'Append a relative JMP to the original entry RVA, followed by zero file-alignment padding'
Set-SamplePatch ($newRaw + $newRawSize) $overlay 'Append an explicitly labeled, non-executed training overlay'
# Intentionally do not update CheckSum: this is one of the comparison findings.
$modifiedPath = Join-Path $PSScriptRoot 'ModifiedConsole.exe'
[IO.File]::WriteAllBytes($modifiedPath, $modifiedBytes)

$manifest = [ordered]@{
    schemaVersion = 1
    purpose = 'Harmless native PE comparison training. Static findings describe changes, not malware intent.'
    provenance = 'ModifiedConsole.exe is a byte-patched copy of OriginalConsole.exe. The patch manifest reconstructs it exactly.'
    toolchain = [ordered]@{
        compiler = (@(& $ClangCl '--version') -join "`n")
        linker = (@(& $Linker '--version') -join "`n")
        windowsSdk = [IO.Path]::GetFileName((Split-Path (Split-Path $SdkLib -Parent) -Parent))
        linkTimestampUtc = '2024-01-01T00:00:00Z'
        fileAlignment = 1024
        sectionAlignment = 4096
    }
    files = @('ConsoleDemo.exe', 'GuiDemo.exe', 'OriginalConsole.exe', 'ModifiedConsole.exe') | ForEach-Object {
        Get-SampleFileRecord (Join-Path $PSScriptRoot $_)
    }
    changes = $changes.ToArray()
    retainedChecksum = [ordered]@{
        offset = $originalPe.ChecksumOffset
        originalValue = $originalPe.Checksum
        modifiedStoredValue = (Read-SamplePe $modifiedBytes).Checksum
        modifiedComputedValue = Get-SampleChecksum $modifiedBytes $originalPe.ChecksumOffset
        explanation = 'The valid original checksum is intentionally left stale after patching.'
    }
    entryStub = [ordered]@{
        offset = $newRaw
        rva = $newRva
        bytesHex = ($sectionBytes[0..4] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
        instruction = 'JMP rel32'
        displacement = $relativeJump
        targetRva = $originalPe.EntryRva
        behavior = 'Immediately transfer control to the original console entry point; no other new code.'
    }
}
$manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'manifest.json') -Encoding utf8
Write-Host 'Built all four native PE teaching samples and manifest.json.'
if (-not $SkipVerification) { & (Join-Path $PSScriptRoot 'verify.ps1') }
