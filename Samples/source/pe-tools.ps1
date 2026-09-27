# Minimal PE32+ reader used only by the reproducible teaching-sample build.
# This is deliberately independent of the PE Workshop application parser.
Set-StrictMode -Version Latest
function Read-U16([byte[]]$Data, [int]$Offset) { [BitConverter]::ToUInt16($Data, $Offset) }
function Read-U32([byte[]]$Data, [int]$Offset) { [BitConverter]::ToUInt32($Data, $Offset) }
function Write-U16([byte[]]$Data, [int]$Offset, [uint16]$Value) {
    [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Data, $Offset, 2)
}
function Write-U32([byte[]]$Data, [int]$Offset, [uint32]$Value) {
    [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Data, $Offset, 4)
}
function Align-SampleValue([long]$Value, [long]$Alignment) {
    [int64]([Math]::Ceiling($Value / [double]$Alignment) * $Alignment)
}
function Read-AsciiZ([byte[]]$Data, [int]$Offset) {
    $end = $Offset
    while ($end -lt $Data.Length -and $Data[$end] -ne 0) { $end++ }
    if ($end -eq $Data.Length) { throw 'Unterminated PE string' }
    [Text.Encoding]::ASCII.GetString($Data, $Offset, $end - $Offset)
}
function Resolve-SampleRva($Image, [uint32]$Rva) {
    if ($Rva -lt $Image.SizeOfHeaders) { return [int]$Rva }
    foreach ($section in $Image.Sections) {
        if ($Rva -ge $section.Rva -and $Rva -lt ($section.Rva + $section.RawSize)) {
            return [int]($section.RawPointer + $Rva - $section.Rva)
        }
    }
    throw ('Unmapped RVA 0x{0:X8}' -f $Rva)
}
function Read-SamplePe([byte[]]$Data) {
    if ($Data.Length -lt 64 -or (Read-U16 $Data 0) -ne 0x5a4d) { throw 'Missing MZ header' }
    $peOffset = [int](Read-U32 $Data 0x3c)
    if ((Read-U32 $Data $peOffset) -ne 0x4550) { throw 'Missing PE signature' }
    $coff = $peOffset + 4; $optional = $coff + 20
    if ((Read-U16 $Data $optional) -ne 0x20b) { throw 'Samples require PE32+' }
    $sectionCount = Read-U16 $Data ($coff + 2)
    $sectionTable = $optional + (Read-U16 $Data ($coff + 16))
    $sections = @()
    $rawEnd = [int](Read-U32 $Data ($optional + 60))
    for ($i = 0; $i -lt $sectionCount; $i++) {
        $header = $sectionTable + 40 * $i
        $section = [pscustomobject][ordered]@{
            Name = [Text.Encoding]::ASCII.GetString($Data, $header, 8).TrimEnd([char]0)
            HeaderOffset = $header
            VirtualSize = Read-U32 $Data ($header + 8)
            Rva = Read-U32 $Data ($header + 12)
            RawSize = Read-U32 $Data ($header + 16)
            RawPointer = Read-U32 $Data ($header + 20)
            Characteristics = Read-U32 $Data ($header + 36)
        }
        $sections += $section
        $rawEnd = [Math]::Max($rawEnd, $section.RawPointer + $section.RawSize)
    }
    $image = [pscustomobject][ordered]@{
        Machine = Read-U16 $Data $coff
        Magic = Read-U16 $Data $optional
        CoffOffset = $coff
        OptionalOffset = $optional
        SectionTableOffset = $sectionTable
        SectionCount = $sectionCount
        Timestamp = Read-U32 $Data ($coff + 4)
        EntryRva = Read-U32 $Data ($optional + 16)
        SizeOfCode = Read-U32 $Data ($optional + 4)
        SectionAlignment = Read-U32 $Data ($optional + 32)
        FileAlignment = Read-U32 $Data ($optional + 36)
        SizeOfImage = Read-U32 $Data ($optional + 56)
        SizeOfHeaders = Read-U32 $Data ($optional + 60)
        ChecksumOffset = $optional + 64
        Checksum = Read-U32 $Data ($optional + 64)
        Subsystem = Read-U16 $Data ($optional + 68)
        DllCharacteristics = Read-U16 $Data ($optional + 70)
        ImportRva = Read-U32 $Data ($optional + 112 + 8)
        RelocationRva = Read-U32 $Data ($optional + 112 + 5 * 8)
        ClrRva = Read-U32 $Data ($optional + 112 + 14 * 8)
        Sections = $sections
        OverlayOffset = $rawEnd
        OverlayLength = $Data.Length - $rawEnd
        Imports = @()
    }
    if ($image.ImportRva) {
        $descriptor = Resolve-SampleRva $image $image.ImportRva
        while ((Read-U32 $Data ($descriptor + 12)) -ne 0) {
            $dll = Read-AsciiZ $Data (Resolve-SampleRva $image (Read-U32 $Data ($descriptor + 12)))
            $thunkRva = Read-U32 $Data $descriptor
            if (-not $thunkRva) { $thunkRva = Read-U32 $Data ($descriptor + 16) }
            $thunk = Resolve-SampleRva $image $thunkRva
            $functions = @()
            while ([BitConverter]::ToUInt64($Data, $thunk) -ne 0) {
                $value = [BitConverter]::ToUInt64($Data, $thunk)
                if ($value -ge [uint64]9223372036854775808) {
                    $functions += '#' + ($value -band 0xffff)
                } else {
                    $functions += Read-AsciiZ $Data ((Resolve-SampleRva $image ([uint32]$value)) + 2)
                }
                $thunk += 8
            }
            $image.Imports += [pscustomobject][ordered]@{ dll = $dll; functions = $functions }
            $descriptor += 20
        }
    }
    return $image
}
function Get-SampleChecksum([byte[]]$Data, [int]$ChecksumOffset) {
    [uint64]$sum = 0
    for ($i = 0; $i -lt $Data.Length - 1; $i += 2) {
        if ($i -eq $ChecksumOffset -or $i -eq $ChecksumOffset + 2) { continue }
        $sum += Read-U16 $Data $i
        $sum = ($sum -band 0xffff) + ($sum -shr 16)
    }
    if (($Data.Length % 2) -ne 0) { $sum += $Data[$Data.Length - 1] }
    $sum = ($sum -band 0xffff) + ($sum -shr 16)
    return [uint32]($sum + $Data.Length)
}
function Get-SampleFileRecord([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $pe = Read-SamplePe $bytes
    [ordered]@{
        name = [IO.Path]::GetFileName($Path)
        sizeBytes = $bytes.Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
        machine = 'AMD64 (0x8664)'
        format = 'PE32+'
        managedRuntime = $false
        subsystem = $pe.Subsystem
        timestamp = $pe.Timestamp
        timestampUtc = [DateTimeOffset]::FromUnixTimeSeconds($pe.Timestamp).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
        entryRva = $pe.EntryRva
        entryRvaHex = '0x{0:X8}' -f $pe.EntryRva
        dllCharacteristics = $pe.DllCharacteristics
        dllCharacteristicsHex = '0x{0:X4}' -f $pe.DllCharacteristics
        checksumOffset = $pe.ChecksumOffset
        storedChecksum = $pe.Checksum
        computedChecksum = Get-SampleChecksum $bytes $pe.ChecksumOffset
        checksumValid = $pe.Checksum -eq (Get-SampleChecksum $bytes $pe.ChecksumOffset)
        fileAlignment = $pe.FileAlignment
        sectionAlignment = $pe.SectionAlignment
        sizeOfImage = $pe.SizeOfImage
        sections = $pe.Sections
        imports = $pe.Imports
        overlayOffset = $pe.OverlayOffset
        overlayLength = $pe.OverlayLength
    }
}
