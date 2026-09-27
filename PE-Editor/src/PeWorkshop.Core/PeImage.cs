using System.Buffers.Binary;
using System.Text;

namespace PeWorkshop.Core;

public sealed record PeField(string Group, string Name, int Offset, int Size, ulong Value, string Description)
{
    public string HexValue => $"0x{Value.ToString($"X{Size * 2}")}";
    public string OffsetHex => $"0x{Offset:X8}";
}
public sealed record PeSection(string Name, int HeaderOffset, uint VirtualAddress, uint VirtualSize, uint RawOffset, uint RawSize, uint Characteristics)
{
    public string Permissions => string.Concat((Characteristics & 0x40000000) != 0 ? "R" : "-", (Characteristics & 0x80000000) != 0 ? "W" : "-", (Characteristics & 0x20000000) != 0 ? "X" : "-");
}
public sealed record PeDirectory(int Index, string Name, uint Address, uint Size, int EntryOffset, int? FileOffset);
public sealed record PeImport(string Module, string Name, uint? Ordinal, uint Hint, uint IatRva);
public sealed record PeExport(string Name, uint Ordinal, uint Rva, string? Forwarder);
public sealed class PeFormatException(string message) : Exception(message);
public sealed class PeImage
{
    public const int MaxFileSize = 128 * 1024 * 1024;
    private readonly byte[] bytes;
    private readonly List<PeField> fields = [];
    private readonly List<PeSection> sections = [];
    private readonly List<PeDirectory> directories = [];
    private readonly List<PeImport> imports = [];
    private readonly List<PeExport> exports = [];
    private readonly List<string> warnings = [];
    private PeImage(byte[] bytes) { this.bytes = bytes; ReadHeaders(); ReadAuxiliary(); }
    public static PeImage Parse(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length > MaxFileSize) throw new PeFormatException("Files larger than 128 MiB are not supported.");
        return new PeImage((byte[])bytes.Clone());
    }
    public bool Is64Bit { get; private set; }
    public string Architecture => Machine switch { 0x14c => "x86", 0x8664 => "x64", 0xaa64 => "ARM64", 0x1c0 or 0x1c4 => "ARM", 0xa641 => "ARM64EC", 0xa64e => "ARM64X", _ => $"Unknown (0x{Machine:X4})" };
    public ushort Machine { get; private set; }
    public ulong ImageBase { get; private set; }
    public uint EntryPoint { get; private set; }
    public uint SizeOfImage { get; private set; }
    public uint SizeOfHeaders { get; private set; }
    public ushort Subsystem { get; private set; }
    public uint TimeDateStamp { get; private set; }
    public int PeOffset { get; private set; }
    public int ChecksumOffset { get; private set; }
    public uint StoredChecksum { get; private set; }
    public bool HasCertificate => directories.Any(d => d.Index == 4 && (d.Address != 0 || d.Size != 0));
    public IReadOnlyList<PeField> Fields => fields.AsReadOnly();
    public IReadOnlyList<PeSection> Sections => sections.AsReadOnly();
    public IReadOnlyList<PeDirectory> Directories => directories.AsReadOnly();
    public IReadOnlyList<PeImport> Imports => imports.AsReadOnly();
    public IReadOnlyList<PeExport> Exports => exports.AsReadOnly();
    public IReadOnlyList<string> Warnings => warnings.AsReadOnly();

    private void Require(long offset, long length, string what)
    {
        if (offset < 0 || length < 0 || offset > bytes.Length || length > bytes.Length - offset)
            throw new PeFormatException($"{what} lies outside the file.");
    }
    private ushort U16(int offset) { Require(offset, 2, "16-bit value"); return BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset)); }
    private uint U32(int offset) { Require(offset, 4, "32-bit value"); return BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset)); }
    private ulong U64(int offset) { Require(offset, 8, "64-bit value"); return BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset)); }
    private ulong Field(string group, string name, int offset, int size, string? description = null)
    {
        Require(offset, size, name);
        ulong value = size switch { 1 => bytes[offset], 2 => U16(offset), 4 => U32(offset), 8 => U64(offset), _ => throw new PeFormatException("Unsupported field width.") };
        fields.Add(new(group, name, offset, size, value, description ?? name)); return value;
    }
    private void ReadHeaders()
    {
        Require(0, 64, "DOS header");
        if (U16(0) != 0x5a4d) throw new PeFormatException("Missing DOS MZ signature.");
        uint pe = (uint)Field("DOS header", "e_lfanew", 0x3c, 4, "File offset of the PE signature.");
        Require(pe, 24, "PE and COFF headers");
        if (pe < 64) throw new PeFormatException("PE header overlaps the DOS header.");
        PeOffset = (int)pe;
        if (U32(PeOffset) != 0x4550) throw new PeFormatException("Missing PE signature.");
        int c = PeOffset + 4;
        Machine = (ushort)Field("COFF header", "Machine", c, 2);
        uint count = (uint)Field("COFF header", "NumberOfSections", c + 2, 2);
        if (count > 96) throw new PeFormatException("More than 96 sections are not supported.");
        TimeDateStamp = (uint)Field("COFF header", "TimeDateStamp", c + 4, 4);
        Field("COFF header", "PointerToSymbolTable", c + 8, 4); Field("COFF header", "NumberOfSymbols", c + 12, 4);
        int optionalSize = (int)Field("COFF header", "SizeOfOptionalHeader", c + 16, 2);
        Field("COFF header", "Characteristics", c + 18, 2);
        int o = c + 20; Require(o, optionalSize, "Optional header");
        if (optionalSize < 2) throw new PeFormatException("Optional header is missing.");
        ushort magic = U16(o);
        if (magic != 0x10b && magic != 0x20b) throw new PeFormatException("Only PE32 and PE32+ images are supported.");
        Is64Bit = magic == 0x20b;
        int directoryStart = Is64Bit ? 112 : 96;
        if (optionalSize < directoryStart) throw new PeFormatException("Optional header is truncated.");
        string group = "Optional header";
        Field(group, "Magic", o, 2); Field(group, "MajorLinkerVersion", o + 2, 1); Field(group, "MinorLinkerVersion", o + 3, 1);
        Field(group, "SizeOfCode", o + 4, 4); Field(group, "SizeOfInitializedData", o + 8, 4); Field(group, "SizeOfUninitializedData", o + 12, 4);
        EntryPoint = (uint)Field(group, "AddressOfEntryPoint", o + 16, 4);
        Field(group, "BaseOfCode", o + 20, 4);
        if (!Is64Bit) Field(group, "BaseOfData", o + 24, 4);
        ImageBase = Field(group, "ImageBase", o + (Is64Bit ? 24 : 28), Is64Bit ? 8 : 4);
        uint sectionAlignment = (uint)Field(group, "SectionAlignment", o + 32, 4);
        uint fileAlignment = (uint)Field(group, "FileAlignment", o + 36, 4);
        string[] versions = ["MajorOperatingSystemVersion", "MinorOperatingSystemVersion", "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion", "MinorSubsystemVersion"];
        for (int i = 0; i < versions.Length; i++) Field(group, versions[i], o + 40 + i * 2, 2);
        Field(group, "Win32VersionValue", o + 52, 4);
        SizeOfImage = (uint)Field(group, "SizeOfImage", o + 56, 4); SizeOfHeaders = (uint)Field(group, "SizeOfHeaders", o + 60, 4);
        ChecksumOffset = o + 64; StoredChecksum = (uint)Field(group, "CheckSum", ChecksumOffset, 4);
        Subsystem = (ushort)Field(group, "Subsystem", o + 68, 2); Field(group, "DllCharacteristics", o + 70, 2);
        string[] stack = ["SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit"];
        int width = Is64Bit ? 8 : 4;
        for (int i = 0; i < stack.Length; i++) Field(group, stack[i], o + 72 + i * width, width);
        Field(group, "LoaderFlags", o + directoryStart - 8, 4);
        uint directoryCount = (uint)Field(group, "NumberOfRvaAndSizes", o + directoryStart - 4, 4);
        if ((ulong)directoryCount * 8 > (uint)(optionalSize - directoryStart)) throw new PeFormatException("Advertised data directories do not fit the optional header.");
        if (directoryCount > 16) warnings.Add("Only the first 16 data directories are displayed.");
        long table = (long)o + optionalSize; Require(table, count * 40, "Section table");
        for (int i = 0; i < count; i++)
        {
            int s = (int)table + i * 40; string name = Encoding.ASCII.GetString(bytes, s, 8).TrimEnd('\0'); string sg = "Section: " + name;
            uint vs = (uint)Field(sg, "VirtualSize", s + 8, 4), va = (uint)Field(sg, "VirtualAddress", s + 12, 4);
            uint rs = (uint)Field(sg, "SizeOfRawData", s + 16, 4), ro = (uint)Field(sg, "PointerToRawData", s + 20, 4);
            Field(sg, "PointerToRelocations", s + 24, 4); Field(sg, "PointerToLinenumbers", s + 28, 4);
            Field(sg, "NumberOfRelocations", s + 32, 2); Field(sg, "NumberOfLinenumbers", s + 34, 2);
            uint flags = (uint)Field(sg, "Characteristics", s + 36, 4);
            if (rs > 0) Require(ro, rs, $"Raw data for section '{name}'");
            sections.Add(new(name, s, va, vs, ro, rs, flags));
            if ((ulong)va + Math.Max(vs, rs) > uint.MaxValue) warnings.Add($"Section '{name}' virtual range exceeds the RVA address space.");
            if ((ulong)va + Math.Max(vs, rs) > SizeOfImage) warnings.Add($"Section '{name}' extends beyond SizeOfImage.");
            if (rs > 0 && ro < SizeOfHeaders) warnings.Add($"Section '{name}' raw data overlaps the headers.");
            if ((sectionAlignment != 0 && va % sectionAlignment != 0) || (fileAlignment != 0 && rs > 0 && (ro % fileAlignment != 0 || rs % fileAlignment != 0))) warnings.Add($"Section '{name}' has misaligned data.");
        }
        for (int i = 0; i < sections.Count; i++) for (int j = i + 1; j < sections.Count; j++)
        {
            var a = sections[i]; var b = sections[j];
            if (Overlap(a.RawOffset, a.RawSize, b.RawOffset, b.RawSize) || Overlap(a.VirtualAddress, Math.Max(a.VirtualSize, a.RawSize), b.VirtualAddress, Math.Max(b.VirtualSize, b.RawSize))) warnings.Add($"Sections '{a.Name}' and '{b.Name}' overlap.");
        }
        if (!PowerOfTwo(fileAlignment) || !PowerOfTwo(sectionAlignment) || sectionAlignment < fileAlignment || (sectionAlignment < 4096 ? fileAlignment != sectionAlignment : fileAlignment < 512 || fileAlignment > 65536)) warnings.Add("FileAlignment or SectionAlignment is invalid.");
        if (SizeOfHeaders < table + count * 40 || SizeOfHeaders > bytes.Length || (fileAlignment != 0 && SizeOfHeaders % fileAlignment != 0)) warnings.Add("SizeOfHeaders does not describe a valid aligned header range.");
        if (SizeOfImage == 0 || SizeOfImage < SizeOfHeaders || (sectionAlignment != 0 && SizeOfImage % sectionAlignment != 0)) warnings.Add("SizeOfImage is invalid or misaligned.");
        if (EntryPoint != 0 && RvaToOffset(EntryPoint) is null) warnings.Add("Entry point does not map to file-backed data.");
        string[] names = ["Export", "Import", "Resource", "Exception", "Certificate", "Base relocation", "Debug", "Architecture", "Global pointer", "TLS", "Load configuration", "Bound import", "Import address table", "Delay import", "CLR runtime", "Reserved"];
        for (int i = 0; i < Math.Min(directoryCount, 16); i++)
        {
            int d = o + directoryStart + i * 8; string dg = "Directory: " + names[i];
            uint address = (uint)Field(dg, "VirtualAddress", d, 4), size = (uint)Field(dg, "Size", d + 4, 4);
            int? offset = null;
            if (address != 0) offset = i == 4 ? ((ulong)address + size <= (ulong)bytes.Length ? (int)address : null) : MapRange(address, Math.Max(1u, size));
            directories.Add(new(i, names[i], address, size, d, offset));
            if ((address != 0 || size != 0) && offset is null) warnings.Add($"{names[i]} directory does not map to a valid file range.");
        }
        if (HasCertificate) warnings.Add("This image contains an embedded certificate. Editing signed content can invalidate its Authenticode signature; the certificate is preserved.");
    }
    private static bool PowerOfTwo(uint n) => n != 0 && (n & (n - 1)) == 0;
    private static bool Overlap(uint a, uint al, uint b, uint bl) => al != 0 && bl != 0 && (ulong)a < (ulong)b + bl && (ulong)b < (ulong)a + al;
    public int? RvaToOffset(uint rva) => MapRange(rva, 1);
    private int? MapRange(uint rva, ulong length)
    {
        if ((ulong)rva + length > (ulong)uint.MaxValue + 1) return null;
        if (rva < SizeOfHeaders && (ulong)rva + length <= Math.Min((ulong)SizeOfHeaders, (ulong)bytes.Length)) return (int)rva;
        foreach (var s in sections)
        {
            if (rva < s.VirtualAddress) continue;
            ulong delta = (ulong)rva - s.VirtualAddress;
            if (delta + length > s.RawSize) continue;
            ulong offset = s.RawOffset + delta;
            if (offset + length <= (ulong)bytes.Length) return (int)offset;
        }
        return null;
    }
    private int Mapped(uint rva, ulong length, string label) => MapRange(rva, length) ?? throw new PeFormatException($"{label} does not map to file-backed data.");
    private static uint AddRva(uint rva, ulong delta)
    {
        ulong value = rva + delta;
        if (value > uint.MaxValue) throw new PeFormatException("RVA arithmetic overflow.");
        return (uint)value;
    }
    private string CString(uint rva)
    {
        var result = new List<byte>();
        for (int i = 0; i < 4096; i++) { int p = Mapped(AddRva(rva, (uint)i), 1, "String"); if (bytes[p] == 0) return Encoding.ASCII.GetString(result.ToArray()); result.Add(bytes[p]); }
        throw new PeFormatException("String is not terminated within 4096 bytes.");
    }
    private void ReadAuxiliary()
    {
        try { ReadImports(); } catch (PeFormatException e) { warnings.Add("Import table: " + e.Message); }
        try { ReadExports(); } catch (PeFormatException e) { warnings.Add("Export table: " + e.Message); }
    }
    private void ReadImports()
    {
        var dir = directories.FirstOrDefault(d => d.Index == 1);
        if (dir is null || dir.Address == 0 || dir.Size == 0) return;
        int maxDescriptors = (int)Math.Min(4096u, dir.Size / 20);
        for (int i = 0; i < maxDescriptors; i++)
        {
            int d = Mapped(AddRva(dir.Address, (uint)i * 20), 20, "Import descriptor");
            uint lookup = U32(d), stamp = U32(d + 4), chain = U32(d + 8), name = U32(d + 12), iat = U32(d + 16);
            if ((lookup | stamp | chain | name | iat) == 0) return;
            string module = CString(name);
            if (lookup == 0) lookup = iat;
            if (lookup == 0) throw new PeFormatException("Import descriptor has no thunk table.");
            int width = Is64Bit ? 8 : 4;
            for (uint j = 0; ; j++)
            {
                if (imports.Count >= 65536) { warnings.Add("Import symbols truncated at 65536 entries."); return; }
                int t = Mapped(AddRva(lookup, (ulong)j * (uint)width), (uint)width, "Import thunk");
                ulong value = Is64Bit ? U64(t) : U32(t); if (value == 0) break;
                ulong mask = Is64Bit ? 0x8000000000000000ul : 0x80000000ul;
                uint iatRva = AddRva(iat, (ulong)j * (uint)width);
                if ((value & mask) != 0) { uint ordinal = (uint)(value & 0xffff); imports.Add(new(module, $"#{ordinal}", ordinal, 0, iatRva)); }
                else
                {
                    if (value > uint.MaxValue) throw new PeFormatException("Import name RVA exceeds 32 bits.");
                    uint nr = (uint)value; uint hint = U16(Mapped(nr, 2, "Import hint"));
                    imports.Add(new(module, CString(AddRva(nr, 2)), null, hint, iatRva));
                }
            }
        }
        warnings.Add(maxDescriptors == 4096 ? "Import descriptors truncated at 4096 entries." : "Import descriptor table has no terminator within its declared size.");
    }
    private void ReadExports()
    {
        var dir = directories.FirstOrDefault(d => d.Index == 0);
        if (dir is null || dir.Address == 0 || dir.Size == 0) return;
        if (dir.Size < 40) throw new PeFormatException("Export directory is too small.");
        int e = Mapped(dir.Address, 40, "Export directory");
        uint ordinalBase = U32(e + 16), functionCount = U32(e + 20), nameCount = U32(e + 24);
        uint functionsRva = U32(e + 28), namesRva = U32(e + 32), ordinalsRva = U32(e + 36);
        if (functionCount == 0)
        {
            if (nameCount != 0) throw new PeFormatException("Export names exist without an address table.");
            return;
        }
        int functions = Mapped(functionsRva, (ulong)functionCount * 4, "Export address table");
        int names = nameCount == 0 ? 0 : Mapped(namesRva, (ulong)nameCount * 4, "Export name table");
        int ordinals = nameCount == 0 ? 0 : Mapped(ordinalsRva, (ulong)nameCount * 2, "Export ordinal table");
        int cap = (int)Math.Min(functionCount, 65536u);
        if (functionCount > 65536 || nameCount > 65536) warnings.Add("Exports truncated at 65536 entries.");
        var namesByIndex = new Dictionary<uint, List<string>>();
        for (int i = 0; i < Math.Min(nameCount, 65536u); i++)
        {
            uint index = U16(ordinals + i * 2);
            if (index >= functionCount) throw new PeFormatException("Export ordinal index exceeds the function count.");
            if (!namesByIndex.TryGetValue(index, out var list)) namesByIndex[index] = list = [];
            list.Add(CString(U32(names + i * 4)));
        }
        for (uint i = 0; i < cap; i++)
        {
            uint rva = U32(functions + (int)i * 4); if (rva == 0) continue;
            uint ordinal = AddRva(ordinalBase, i);
            string? forwarder = rva >= dir.Address && (ulong)rva < (ulong)dir.Address + dir.Size ? CString(rva) : null;
            var namesForFunction = namesByIndex.GetValueOrDefault(i) ?? [ $"#{ordinal}" ];
            foreach (string name in namesForFunction)
            {
                if (exports.Count == 65536) { warnings.Add("Exports truncated at 65536 entries."); return; }
                exports.Add(new(name, ordinal, rva, forwarder));
            }
        }
    }
}
