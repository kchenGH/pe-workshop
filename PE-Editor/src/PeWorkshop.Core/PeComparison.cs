using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace PeWorkshop.Core;

public enum DifferenceSeverity { Information, Review, Suspicious }
public sealed record PeDifference(string Category, string Title, string LeftValue, string RightValue,
    string Explanation, DifferenceSeverity Severity, int? LeftOffset, int? RightOffset,
    int LeftLength = 0, int RightLength = 0);
public sealed record PeByteRange(int Offset, int Length);
public sealed record PeComparisonResult(IReadOnlyList<PeDifference> Differences,
    IReadOnlyList<PeByteRange> ByteRanges, long DifferentByteCount, bool ByteRangesTruncated,
    string LeftSha256, string RightSha256, IReadOnlyList<string> Limitations)
{ public bool Identical => DifferentByteCount == 0; }
public static class PeComparison
{
    private const int FindingLimit = 10_000, RangeLimit = 2_000;
    private const uint Execute = 0x20000000, Write = 0x80000000;

    public static PeComparisonResult Compare(byte[] left, byte[] right)
    {
        ArgumentNullException.ThrowIfNull(left); ArgumentNullException.ThrowIfNull(right);
        // Check both limits before either parser allocates its defensive copy.
        if (left.Length > PeImage.MaxFileSize || right.Length > PeImage.MaxFileSize)
            throw new PeFormatException("Files larger than 128 MiB are not supported.");
        return new Comparison(left, right, PeImage.Parse(left), PeImage.Parse(right)).Run();
    }

    private readonly record struct Evidence(int? Offset, int Length)
    {
        public static Evidence At(int offset, int length) => length > 0 ? new(offset, length) : default;
    }
    private readonly record struct ImportLocation(Evidence Symbol, Evidence Hint, Evidence IatBase);
    private sealed record ExportEntry(PeExport Export, bool IsNamed, Evidence Name, Evidence Forwarder, Evidence Target);

    private sealed class Comparison(byte[] left, byte[] right, PeImage a, PeImage b)
    {
        private readonly List<PeDifference> differences = [];
        private readonly List<PeByteRange> ranges = [];
        private readonly List<string> limitations = [
            "Byte ranges are positional file offsets, not an insertion-alignment algorithm; missing tail bytes count as differences even when zero. A range may extend past the shorter file.",
            "Severity is an investigation priority, not a malware verdict. Static declarations do not establish execution, intent, runtime behavior, or the effectiveness of a mitigation.",
            "Ordinary import/export comparison uses the bounded PE parser (at most 4,096 import descriptors and 65,536 symbols per table). DLL declarations, including empty thunk lists, are also decoded independently within the declared directory size, with a 4,096-descriptor and 4,096-byte name limit. Delay imports, runtime resolution, disassembly, resources, relocations, debug data, TLS and load-configuration contents are not semantically decoded; their directory fields and raw bytes are compared.",
            "Capability labels use a conservative allowlist of case-insensitive full DLL names and exact symbol names. Unlisted DLL/API-set combinations receive a generic explanation. A declaration does not authenticate the DLL that will actually be loaded.",
            "Certificate reporting describes the declared embedded certificate table and its bounded file range; certificate records, Authenticode trust, catalog signatures, and signature validity are not verified.",
            "Sections match by case-sensitive name and occurrence; renamed sections appear removed and added. Import DLL identities ignore case, while symbol names, export names and forwarders preserve case. A name-only section match does not prove code lineage."
        ];
        private long findingCount;

        public PeComparisonResult Run()
        {
            string leftHash = Convert.ToHexString(SHA256.HashData(left)), rightHash = Convert.ToHexString(SHA256.HashData(right));
            var (byteCount, truncated) = CompareBytes();
            limitations.AddRange(a.Warnings.Select(w => "Left parser warning: " + w));
            limitations.AddRange(b.Warnings.Select(w => "Right parser warning: " + w));
            if (byteCount != 0)
            {
                Add("File", "SHA-256", leftHash, rightHash, "Different hashes identify different file bytes; rebuilds, metadata, resources or edits can all change a hash.");
                if (left.Length != right.Length) Add("File", "File length", $"{left.Length} bytes", $"{right.Length} bytes", "File length changed. Added sections, resources, certificates, alignment padding or trailing data are possible causes.");
                CompareMitigations();
                CompareSections();
                CompareChecksum();
                CompareCertificateAndOverlay();
                CompareHeaders();
                CompareDirectories();
                CompareImports();
                CompareExports();
            }
            if (findingCount > FindingLimit) limitations.Add($"Semantic findings truncated at 10,000 of {findingCount.ToString(CultureInfo.InvariantCulture)} detected findings. The byte count still covers both complete files; omitted findings may warrant review.");
            if (truncated) limitations.Add("Raw byte ranges truncated at 2,000 ranges. DifferentByteCount still counts every differing byte in both complete files.");
            return new(differences.AsReadOnly(), ranges.AsReadOnly(), byteCount, truncated, leftHash, rightHash, limitations.AsReadOnly());
        }

        private (long Count, bool Truncated) CompareBytes()
        {
            int length = Math.Max(left.Length, right.Length), start = -1;
            long count = 0; bool truncated = false;
            for (int i = 0; i < length; i++)
            {
                bool differs = i >= left.Length || i >= right.Length || left[i] != right[i];
                if (differs) { count++; if (start < 0) start = i; }
                if (start >= 0 && (!differs || i == length - 1))
                {
                    int end = differs ? i + 1 : i;
                    if (ranges.Count < RangeLimit) ranges.Add(new(start, end - start)); else truncated = true;
                    start = -1;
                }
            }
            return (count, truncated);
        }

        private void Add(string category, string title, string l, string r, string explanation,
            DifferenceSeverity severity = DifferenceSeverity.Information, Evidence le = default, Evidence re = default)
        {
            findingCount++;
            if (differences.Count == FindingLimit) return;
            le = Bounded(le, left.Length); re = Bounded(re, right.Length);
            differences.Add(new(category, title, l, r, explanation, severity, le.Offset, re.Offset, le.Length, re.Length));
        }
        private static Evidence Bounded(Evidence e, int length) => e.Offset is int o && o >= 0 && e.Length > 0 && (long)o + e.Length <= length ? e : default;
        private static Evidence At(PeField? f) => f is null ? default : Evidence.At(f.Offset, f.Size);
        private static string Value(PeField? f) => f is null ? "Absent" : $"{f.HexValue} ({f.Value})";
        private static string Hex(uint value) => $"0x{value:X8}";

        private void CompareHeaders()
        {
            string[] dosNames = ["e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc", "e_ss", "e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc", "e_ovno", "e_res[0]", "e_res[1]", "e_res[2]", "e_res[3]", "e_oemid", "e_oeminfo", "e_res2[0]", "e_res2[1]", "e_res2[2]", "e_res2[3]", "e_res2[4]", "e_res2[5]", "e_res2[6]", "e_res2[7]", "e_res2[8]", "e_res2[9]"];
            for (int i = 0; i < dosNames.Length; i++)
            {
                ushort l = U16(left, i * 2), r = U16(right, i * 2);
                if (l != r) Add("DOS header", dosNames[i], $"0x{l:X4}", $"0x{r:X4}", "A numeric DOS-header field changed. Legacy stub layout, producer defaults, reserved data or editing may explain this; it does not establish the behavior of the Windows entry point.", le: Evidence.At(i * 2, 2), re: Evidence.At(i * 2, 2));
            }
            var lf = a.Fields.Where(HeaderField).ToDictionary(f => (f.Group, f.Name));
            var rf = b.Fields.Where(HeaderField).ToDictionary(f => (f.Group, f.Name));
            foreach (var key in lf.Keys.Union(rf.Keys))
            {
                var l = lf.GetValueOrDefault(key); var r = rf.GetValueOrDefault(key);
                if (l?.Value == r?.Value && l?.Size == r?.Size) continue;
                Add(key.Group, key.Name, Value(l), Value(r), HeaderMeaning(key.Name), le: At(l), re: At(r));
            }
        }
        private static bool HeaderField(PeField f) => f.Group is "DOS header" or "COFF header" or "Optional header";
        private static string HeaderMeaning(string name) => name switch
        {
            "Subsystem" => "Subsystem 3 (Windows CUI) requests console behavior, including console allocation or attachment; subsystem 2 (Windows GUI) uses the windowed application convention without automatic console allocation. Linker startup/entry conventions may differ. This does not prove that a GUI exists: either kind can create windows or explicitly manage a console.",
            "TimeDateStamp" => "This stored timestamp changed. Rebuilds, reproducible-build identifiers, tooling or manual edits can explain it; timestamp values alone establish neither chronology nor risk.",
            "DllCharacteristics" => "Loader/security declarations changed. Compiler/linker settings and compatibility requirements are legitimate causes. Individual removed mitigation declarations are reported separately; actual enforcement also depends on the image and platform.",
            "AddressOfEntryPoint" => "The RVA of the declared entry point changed. Recompilation, startup libraries, instrumentation, packing or manual redirection can move it; the destination bytes need review to establish behavior.",
            "CheckSum" => "The stored PE checksum changed. It is a loader integrity checksum, not a cryptographic authenticity check; builds and explicit checksum updates can change it.",
            "Machine" or "Magic" => "The target architecture or PE32/PE32+ format changed. A different build target can change pointer widths, ABI and available header fields; static comparison does not establish platform compatibility.",
            "Characteristics" => "COFF image characteristics changed. These flags describe image/linker properties; build options and manual changes are possible explanations.",
            "e_lfanew" => "The file offset of the PE signature changed. DOS stub size, layout or producer changes can relocate all following headers.",
            _ => "This numeric header field changed. It describes image layout, version, sizes, addresses or loader settings; recompilation, linker settings, alignment and manual editing are possible causes. Raw field values are shown without inferring runtime behavior."
        };

        private void CompareMitigations()
        {
            var l = a.Fields.Single(f => f.Name == "DllCharacteristics"); var r = b.Fields.Single(f => f.Name == "DllCharacteristics");
            foreach (var (mask, name, detail) in new (uint, string, string)[] {
                (0x40, "ASLR", "DYNAMIC_BASE permits image relocation for address randomization"),
                (0x100, "NX compatibility", "NX_COMPAT declares compatibility with non-executable data protection"),
                (0x20, "high-entropy VA", "HIGH_ENTROPY_VA declares support for a larger randomized virtual-address space on supported 64-bit platforms"),
                (0x4000, "CFG", "GUARD_CF declares Control Flow Guard support; instrumentation and load-configuration metadata also matter") })
                if ((l.Value & mask) != 0 && (r.Value & mask) == 0)
                    Add("Mitigations", name + " declaration removed", $"Set (0x{mask:X4})", "Clear", $"DllCharacteristics bit 0x{mask:X4} was cleared: {detail}. Review the reduced declaration; compatibility settings, a different toolchain or a deliberate rebuild can explain it, and the flag alone does not prove enforcement.", DifferenceSeverity.Suspicious, At(l), At(r));
        }

        private static Dictionary<(string Name, int Occurrence), PeSection> SectionMap(PeImage image)
        {
            var counts = new Dictionary<string, int>(StringComparer.Ordinal);
            var result = new Dictionary<(string, int), PeSection>();
            foreach (var s in image.Sections) { int n = counts.GetValueOrDefault(s.Name) + 1; counts[s.Name] = n; result[(s.Name, n)] = s; }
            return result;
        }
        private void CompareSections()
        {
            var ls = SectionMap(a); var rs = SectionMap(b);
            foreach (var key in ls.Keys.Union(rs.Keys))
            {
                var l = ls.GetValueOrDefault(key); var r = rs.GetValueOrDefault(key);
                string label = $"{key.Name} (occurrence {key.Occurrence})";
                if (l is null || r is null)
                {
                    bool executable = r is not null && (r.Characteristics & Execute) != 0;
                    Add("Sections", label + (r is null ? " removed" : " added"), SectionValue(l), SectionValue(r),
                        "Section identity is name plus occurrence. A new or removed section can reflect a renamed section, different linker layout, extra code/resources, instrumentation or packing." + (executable ? " The added section declares executable memory; inspect its bytes and references. This is a review cue, not proof of malicious code." : " Section permissions are declarations and do not establish runtime use."),
                        executable ? DifferenceSeverity.Suspicious : DifferenceSeverity.Information,
                        l is null ? default : Evidence.At(l.HeaderOffset, 40), r is null ? default : Evidence.At(r.HeaderOffset, 40));
                    if (executable && a.EntryPoint != b.EntryPoint && ContainsRva(r!, b.EntryPoint))
                        Add("Entry point", "Entry point moved to a newly added executable section", Hex(a.EntryPoint), $"{Hex(b.EntryPoint)} in {label}",
                            "AddressOfEntryPoint now falls within this added executable section's declared virtual span (max of virtual/raw size). This can redirect startup code. Instrumentation, a wrapper, packing, changed startup libraries or section renaming can also explain it; inspect mapped bytes before drawing conclusions.", DifferenceSeverity.Suspicious,
                            At(a.Fields.Single(f => f.Name == "AddressOfEntryPoint")), At(b.Fields.Single(f => f.Name == "AddressOfEntryPoint")));
                    continue;
                }
                bool wasWx = (l.Characteristics & (Execute | Write)) == (Execute | Write);
                bool nowWx = (r.Characteristics & (Execute | Write)) == (Execute | Write);
                if (!wasWx && nowWx)
                    Add("Sections", label + " is newly writable and executable", SectionValue(l), SectionValue(r), "Characteristics now combine IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE. Writable executable memory deserves review; JIT/runtime code generation, unpacking, instrumentation or linker settings are possible legitimate causes, and flags do not prove actual execution.", DifferenceSeverity.Suspicious, Evidence.At(l.HeaderOffset + 36, 4), Evidence.At(r.HeaderOffset + 36, 4));
                if ((l.Characteristics & Execute) == 0 && (r.Characteristics & Execute) != 0)
                    Add("Sections", label + " became executable", l.Permissions, r.Permissions, "The section gained IMAGE_SCN_MEM_EXECUTE. New code, merged sections or linker settings may explain this; inspect the section's contents and references.", DifferenceSeverity.Suspicious, Evidence.At(l.HeaderOffset + 36, 4), Evidence.At(r.HeaderOffset + 36, 4));
                var lFields = a.Fields.Where(f => f.Offset >= l.HeaderOffset + 8 && f.Offset < l.HeaderOffset + 40).ToDictionary(f => f.Name);
                foreach (var rf in b.Fields.Where(f => f.Offset >= r.HeaderOffset + 8 && f.Offset < r.HeaderOffset + 40))
                {
                    var lf = lFields[rf.Name];
                    if (lf.Value != rf.Value) Add("Sections", label + ": " + rf.Name, Value(lf), Value(rf), "The section's stored layout or characteristics field changed. Recompilation, alignment, section merging, relocation or manual edits can cause this. Raw file offsets and RVAs address different spaces.", le: At(lf), re: At(rf));
                }
                ReadOnlySpan<byte> lb = SectionBytes(left, l), rb = SectionBytes(right, r);
                if (!lb.SequenceEqual(rb))
                {
                    Add("Section content", label + " content changed", $"{lb.Length} bytes; SHA-256 {Convert.ToHexString(SHA256.HashData(lb))}", $"{rb.Length} bytes; SHA-256 {Convert.ToHexString(SHA256.HashData(rb))}", "The matched section's file-backed bytes differ. Code, constants, resources, table addresses or padding may have changed. This compares raw section data including padding; it is not disassembly or proof of behavior.", le: Evidence.At((int)l.RawOffset, lb.Length), re: Evidence.At((int)r.RawOffset, rb.Length));
                    double le = Entropy(lb), re = Entropy(rb);
                    if (lb.Length >= 512 && rb.Length >= 512 && re >= 6.5 && re - le >= 1.0)
                        Add("Entropy", label + " entropy increased", le.ToString("F3", CultureInfo.InvariantCulture) + " bits/byte", re.ToString("F3", CultureInfo.InvariantCulture) + " bits/byte", "Shannon byte entropy increased by at least 1.0 to at least 6.5 bits/byte in sections of at least 512 bytes. Compression, encryption, packed code, media or fewer zero-padding bytes can explain this statistical signal. It does not identify intent or prove packing.", DifferenceSeverity.Review, Evidence.At((int)l.RawOffset, lb.Length), Evidence.At((int)r.RawOffset, rb.Length));
                }
            }
        }
        private static string SectionValue(PeSection? s) => s is null ? "Absent" : $"{s.Name}: {s.Permissions}, RVA {Hex(s.VirtualAddress)}, virtual {s.VirtualSize}, raw {Hex(s.RawOffset)} + {s.RawSize}, flags {Hex(s.Characteristics)}";
        private static bool ContainsRva(PeSection s, uint rva) => rva >= s.VirtualAddress && (ulong)rva < (ulong)s.VirtualAddress + Math.Max(s.VirtualSize, s.RawSize);
        private static ReadOnlySpan<byte> SectionBytes(byte[] bytes, PeSection s) => s.RawSize == 0 ? [] : bytes.AsSpan((int)s.RawOffset, (int)s.RawSize);
        private static double Entropy(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty) return 0;
            Span<int> counts = stackalloc int[256]; counts.Clear(); foreach (byte value in data) counts[value]++;
            double entropy = 0; foreach (int n in counts) if (n != 0) { double p = (double)n / data.Length; entropy -= p * Math.Log2(p); }
            return entropy;
        }

        private void CompareDirectories()
        {
            foreach (int index in a.Directories.Select(d => d.Index).Union(b.Directories.Select(d => d.Index)))
            {
                var l = a.Directories.FirstOrDefault(d => d.Index == index); var r = b.Directories.FirstOrDefault(d => d.Index == index);
                if (l?.Address == r?.Address && l?.Size == r?.Size) continue;
                Add("Directories", (r ?? l)!.Name + " directory", DirectoryValue(l), DirectoryValue(r),
                    (index == 4 ? "The certificate directory uses a file offset, unlike the RVAs in other directories. " : "Directory address/size declares where this table is stored in the image. ") + "Relayout, feature changes, link settings or edits can change it; presence alone does not prove valid contents or runtime use.",
                    le: l is null ? default : Evidence.At(l.EntryOffset, 8), re: r is null ? default : Evidence.At(r.EntryOffset, 8));
            }
        }
        private static string DirectoryValue(PeDirectory? d) => d is null ? "Absent" : $"{Hex(d.Address)} + {d.Size} bytes; file {(d.FileOffset is int o ? $"0x{o:X8}" : "unmapped")}";
        private void CompareChecksum()
        {
            uint lc = PeChecksum.Calculate(left, a.ChecksumOffset), rc = PeChecksum.Calculate(right, b.ChecksumOffset);
            string ls = ChecksumStatus(a.StoredChecksum, lc), rs = ChecksumStatus(b.StoredChecksum, rc);
            bool wasValid = a.StoredChecksum != 0 && a.StoredChecksum == lc;
            bool stale = b.StoredChecksum != 0 && b.StoredChecksum != rc;
            if (ls != rs || wasValid && stale)
                Add("Checksum", wasValid && stale ? "Checksum became stale" : "Checksum status changed", $"{ls}; stored {Hex(a.StoredChecksum)}, calculated {Hex(lc)}", $"{rs}; stored {Hex(b.StoredChecksum)}, calculated {Hex(rc)}", "A nonzero stored checksum is compared with the PE checksum calculation. A mismatch can result from ordinary editing or a build that did not update it. Zero commonly means unset. This checksum is not a signature or malware test; loader requirements vary by image type.", wasValid && stale ? DifferenceSeverity.Review : DifferenceSeverity.Information, Evidence.At(a.ChecksumOffset, 4), Evidence.At(b.ChecksumOffset, 4));
        }
        private static string ChecksumStatus(uint stored, uint calculated) => stored == 0 ? "Unset" : stored == calculated ? "Matches" : "Stale/mismatch";
        private void CompareCertificateAndOverlay()
        {
            var l = a.Directories.FirstOrDefault(d => d.Index == 4); var r = b.Directories.FirstOrDefault(d => d.Index == 4);
            if (a.HasCertificate != b.HasCertificate)
                Add("Certificate", b.HasCertificate ? "Embedded certificate declaration added" : "Embedded certificate declaration removed", CertificateStatus(l), CertificateStatus(r), "The embedded certificate-table declaration changed. Removal may result from editing/re-signing or a different build. A declaration is not a verified signature, and absence does not establish that a file is unsigned because catalog signatures may exist. Trust and signature validity have not been checked.", a.HasCertificate ? DifferenceSeverity.Review : DifferenceSeverity.Information, l is null ? default : Evidence.At(l.EntryOffset, 8), r is null ? default : Evidence.At(r.EntryOffset, 8));
            var lo = Overlay(a, left.Length); var ro = Overlay(b, right.Length);
            if (lo.Size != ro.Size)
                Add("Overlay", ro.Size > lo.Size ? "Trailing overlay grew" : "Trailing overlay shrank", $"{lo.Size} bytes", $"{ro.Size} bytes", "Overlay counts bytes after the bounded header/section raw-data extent, excluding a bounded, nonempty certificate-table range. It may include installer payloads, metadata, padding or appended content. Growth deserves inspection but is not evidence of execution. Highlighting identifies the first uncovered contiguous span; a certificate can split the overlay.", ro.Size > lo.Size ? DifferenceSeverity.Review : DifferenceSeverity.Information, lo.First, ro.First);
        }
        private static string CertificateStatus(PeDirectory? d) => d is null || d.Address == 0 && d.Size == 0 ? "Absent" : d.Address != 0 && d.Size > 0 && d.FileOffset is not null ? $"Declared, bounded ({d.Size} bytes)" : "Declared, invalid or empty range";
        private static (long Size, Evidence First) Overlay(PeImage p, int fileLength)
        {
            ulong end = Math.Min(p.SizeOfHeaders, (uint)fileLength);
            // Include the actual parsed section table even if SizeOfHeaders is underdeclared.
            end = Math.Max(end, (ulong)(p.PeOffset + 24) + p.Fields.Single(f => f.Name == "SizeOfOptionalHeader").Value + (ulong)p.Sections.Count * 40);
            foreach (var s in p.Sections) if (s.RawSize != 0) end = Math.Max(end, (ulong)s.RawOffset + s.RawSize);
            int start = (int)Math.Min(end, (ulong)fileLength);
            var c = p.Directories.FirstOrDefault(d => d.Index == 4);
            if (c is { Address: > 0, Size: > 0, FileOffset: not null })
            {
                int cs = (int)Math.Max((ulong)start, c.Address), ce = (int)((ulong)c.Address + c.Size);
                if (ce > cs) { int prefix = cs - start, suffix = fileLength - ce; return ((long)prefix + suffix, prefix > 0 ? Evidence.At(start, prefix) : Evidence.At(ce, suffix)); }
            }
            return (fileLength - start, Evidence.At(start, fileLength - start));
        }

        private void CompareImports()
        {
            CompareImportModules();
            var lm = ImportMap(a, left); var rm = ImportMap(b, right);
            // Added sensitive declarations precede ordinary entries so a long import list cannot hide these behind the cap.
            var keys = lm.Keys.Union(rm.Keys).OrderByDescending(k => !lm.ContainsKey(k) && rm.TryGetValue(k, out var x) && Sensitive(x.Import));
            foreach (var key in keys)
            {
                bool hasLeft = lm.TryGetValue(key, out var l), hasRight = rm.TryGetValue(key, out var r);
                if (!hasLeft || !hasRight)
                {
                    var symbol = hasRight ? r.Import : l.Import; bool sensitive = hasRight && Sensitive(symbol);
                    Add("Imports", (hasRight ? "Import added: " : "Import removed: ") + symbol.Module + "!" + symbol.Name,
                        hasLeft ? ImportValue(l.Import) : "Absent", hasRight ? ImportValue(r.Import) : "Absent",
                        ImportMeaning(symbol, hasRight), sensitive ? DifferenceSeverity.Suspicious : DifferenceSeverity.Information,
                        hasLeft ? l.Location.Symbol : default, hasRight ? r.Location.Symbol : default);
                    continue;
                }
                if (l.Import.Hint != r.Import.Hint)
                    Add("Imports", key.Module + "!" + key.Symbol + " hint", l.Import.Hint.ToString(CultureInfo.InvariantCulture), r.Import.Hint.ToString(CultureInfo.InvariantCulture), "The lookup hint changed while the imported name stayed the same. Hints help export lookup and can change with SDK/library versions or relinking; they do not change the requested symbol name.", le: l.Location.Hint, re: r.Location.Hint);
                if (l.Import.IatRva != r.Import.IatRva)
                    Add("Imports", key.Module + "!" + key.Symbol + " IAT RVA", Hex(l.Import.IatRva), Hex(r.Import.IatRva), "The symbol's import-address-table slot RVA changed. Relinking, architecture or layout changes can move it. Highlighted evidence is the descriptor's stored FirstThunk base; the reported slot RVA also includes its table index and pointer width.", le: l.Location.IatBase, re: r.Location.IatBase);
            }
        }
        private void CompareImportModules()
        {
            var lm = ImportModuleMap(a, left, "Left"); var rm = ImportModuleMap(b, right, "Right");
            foreach (var key in lm.Keys.Union(rm.Keys))
            {
                bool hasLeft = lm.TryGetValue(key, out var l), hasRight = rm.TryGetValue(key, out var r);
                if (hasLeft && hasRight) continue;
                Add("Imports", (hasRight ? "DLL declaration added: " : "DLL declaration removed: ") + (hasRight ? r.Name : l.Name) + $" (occurrence {key.Occurrence})",
                    hasLeft ? l.Name : "Absent", hasRight ? r.Name : "Absent",
                    "This ordinary import descriptor declares a DLL, including when its thunk list has no symbols. DLL identity is case-insensitive and duplicate occurrences are retained. A build/linker change, different features or runtime loading can add or remove declarations; an absent declaration does not prove a DLL is never loaded. Findings describe the decoded descriptor prefix; any incomplete decoding is disclosed in Limitations.",
                    le: hasLeft ? l.Evidence : default, re: hasRight ? r.Evidence : default);
            }
        }
        private Dictionary<(string Module, int Occurrence), (string Name, Evidence Evidence)> ImportModuleMap(PeImage p, byte[] bytes, string side)
        {
            var result = new Dictionary<(string, int), (string, Evidence)>();
            var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var dir = p.Directories.FirstOrDefault(d => d.Index == 1);
            if (dir is null || dir.Address == 0 && dir.Size == 0) return result;
            void Incomplete(string reason) => limitations.Add($"{side} DLL descriptor comparison incomplete: {reason}");
            if (dir.Address == 0 || dir.Size == 0) { Incomplete("the import directory has an empty address or size."); return result; }
            uint count = Math.Min(4096u, dir.Size / 20);
            for (uint i = 0; i < count; i++)
            {
                int? at = Map(p, bytes.Length, (ulong)dir.Address + (ulong)i * 20, 20);
                if (at is not int d) { Incomplete("a descriptor does not map to a complete file-backed range."); return result; }
                uint name = U32(bytes, d + 12);
                if ((U32(bytes, d) | U32(bytes, d + 4) | U32(bytes, d + 8) | name | U32(bytes, d + 16)) == 0) return result;
                var decoded = MappedString(p, bytes, name);
                if (decoded is not { } text) { Incomplete("a DLL name is unmapped or has no terminator within 4,096 bytes."); return result; }
                int occurrence = counts.GetValueOrDefault(text.Value) + 1; counts[text.Value] = occurrence;
                result[(text.Value.ToUpperInvariant(), occurrence)] = (text.Value, text.Evidence.Offset is not null ? text.Evidence : Evidence.At(d + 12, 4));
            }
            Incomplete(count == 4096 ? "no null terminator was reached within the 4,096-descriptor cap." : "no null terminator was reached within the declared directory size.");
            return result;
        }
        private static string ImportValue(PeImport i) => $"{i.Module}!{i.Name}; hint {i.Hint}, IAT RVA {Hex(i.IatRva)}";
        private static bool ModuleIs(PeImport import, string module) => import.Module.Equals(module, StringComparison.OrdinalIgnoreCase);
        private static bool KernelModule(PeImport import) => ModuleIs(import, "KERNEL32.dll") || ModuleIs(import, "KERNELBASE.dll");
        private static bool Sensitive(PeImport import) => import.Ordinal is null && (
            KernelModule(import) && import.Name is ("VirtualAlloc" or "VirtualAllocEx" or "VirtualProtect" or "VirtualProtectEx" or "WriteProcessMemory" or "ReadProcessMemory" or "OpenProcess" or "CreateRemoteThread" or "CreateRemoteThreadEx" or "QueueUserAPC" or "SetThreadContext" or "ResumeThread" or "CreateProcessA" or "CreateProcessW" or "WinExec") ||
            ModuleIs(import, "NTDLL.dll") && import.Name is ("NtCreateThreadEx" or "NtAllocateVirtualMemory" or "NtProtectVirtualMemory" or "NtWriteVirtualMemory") ||
            ModuleIs(import, "SHELL32.dll") && import.Name is ("ShellExecuteA" or "ShellExecuteW"));
        private static bool OutputImport(PeImport import) => import.Ordinal is null && (
            KernelModule(import) && import.Name is ("WriteConsoleA" or "WriteConsoleW" or "AllocConsole" or "AttachConsole" or "GetStdHandle" or "WriteFile") ||
            (ModuleIs(import, "MSVCRT.dll") || ModuleIs(import, "UCRTBASE.dll") || ModuleIs(import, "api-ms-win-crt-stdio-l1-1-0.dll")) && import.Name is ("printf" or "puts" or "fwrite"));
        private static string ImportMeaning(PeImport import, bool added)
        {
            string capability = Sensitive(import) ? "This module and exact symbol identify an expected Windows memory-management or process-control API. Debuggers, JITs, launchers and instrumentation also use these APIs; an import does not prove a call occurs or authenticate the DLL actually loaded. " :
                ModuleIs(import, "USER32.dll") && import.Ordinal is null && import.Name is ("MessageBoxA" or "MessageBoxW") ? "This USER32 and exact MessageBox symbol combination declares an expected message-dialog capability. It does not prove the dialog executes, establish the application's subsystem or authenticate the DLL actually loaded. " :
                OutputImport(import) ? "This module and exact symbol identify an expected API for console, standard-stream or file output. WriteFile/fwrite and standard handles can also refer to files or pipes; presence does not prove console output or authenticate the DLL actually loaded. " :
                "This is a declared ordinary loader import. Its capability is not established by this comparison's module-and-symbol allowlist; a familiar symbol name in an arbitrary DLL need not have Windows API semantics. ";
            return capability + (added ? "A feature change, new runtime library, linking choice or manual edit may add this declaration. " : "A removed declaration can reflect static linking, different features, runtime loading, or producer choices; it does not prove the capability is absent at runtime. ") + "DLL identity ignores case; symbol names are case-sensitive and ordinal imports are distinct from named imports.";
        }
        private static Dictionary<(string Module, string Symbol, bool Ordinal, int Occurrence), (PeImport Import, ImportLocation Location)> ImportMap(PeImage p, byte[] bytes)
        {
            var locations = ImportLocations(p, bytes);
            var counts = new Dictionary<(string, string, bool), int>();
            var result = new Dictionary<(string, string, bool, int), (PeImport, ImportLocation)>();
            for (int i = 0; i < p.Imports.Count; i++)
            {
                var import = p.Imports[i]; var key = (import.Module.ToUpperInvariant(), import.Name, import.Ordinal is not null);
                int n = counts.GetValueOrDefault(key) + 1; counts[key] = n;
                result[(key.Item1, key.Name, key.Item3, n)] = (import, locations[i]);
            }
            return result;
        }
        private static ImportLocation[] ImportLocations(PeImage p, byte[] bytes)
        {
            // The parser preserves descriptor/thunk order. Resolve only the entries it actually parsed.
            var result = new ImportLocation[p.Imports.Count]; int index = 0, width = p.Is64Bit ? 8 : 4;
            var dir = p.Directories.FirstOrDefault(d => d.Index == 1); if (dir is null) return result;
            for (uint i = 0; i < Math.Min(4096u, dir.Size / 20) && index < result.Length; i++)
            {
                int? descriptor = Map(p, bytes.Length, (ulong)dir.Address + i * 20, 20); if (descriptor is not int d) break;
                uint lookup = U32(bytes, d); if (lookup == 0) lookup = U32(bytes, d + 16); if (lookup == 0) break;
                for (uint j = 0; index < result.Length; j++)
                {
                    int? thunk = Map(p, bytes.Length, (ulong)lookup + (ulong)j * (uint)width, width); if (thunk is not int t) return result;
                    ulong value = width == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(t)) : U32(bytes, t); if (value == 0) break;
                    var import = p.Imports[index]; Evidence symbol = Evidence.At(t, width), hint = default;
                    if (import.Ordinal is null)
                    {
                        int? h = Map(p, bytes.Length, value, 2); int? n = Map(p, bytes.Length, value + 2, import.Name.Length + 1);
                        hint = h is int ho ? Evidence.At(ho, 2) : default;
                        symbol = n is int no ? Evidence.At(no, import.Name.Length + 1) : default;
                    }
                    result[index++] = new(symbol, hint, Evidence.At(d + 16, 4));
                }
            }
            return result;
        }

        private void CompareExports()
        {
            var lm = ExportMap(a, left); var rm = ExportMap(b, right);
            foreach (var key in lm.Keys.Union(rm.Keys))
            {
                var l = lm.GetValueOrDefault(key); var r = rm.GetValueOrDefault(key);
                if (l?.Export == r?.Export) continue;
                bool identityChange = l is null || r is null;
                bool forwarderOnly = !identityChange && l!.Export.Rva == r!.Export.Rva && l.Export.Forwarder != r.Export.Forwarder;
                Evidence Highlight(ExportEntry? entry) => entry is null ? default :
                    identityChange && entry.IsNamed ? entry.Name :
                    forwarderOnly && entry.Export.Forwarder is not null ? entry.Forwarder : entry.Target;
                Add("Exports", key.Name + $" (ordinal {key.Ordinal}, occurrence {key.Occurrence})", ExportValue(l?.Export), ExportValue(r?.Export), "The declared exported symbol, ordinal, target RVA or forwarder changed. Export names and forwarders are case-sensitive. Relinking, ABI changes, forwarding or instrumentation can explain this; an export does not prove it is called. Highlighting identifies stored name strings for named additions/removals, forwarder strings for forwarding-text changes at the same RVA, and export-address-table entries for changed targets or ordinal-only exports. Unmapped string evidence is omitted.", le: Highlight(l), re: Highlight(r));
            }
        }
        private static Dictionary<(string Name, uint Ordinal, int Occurrence), ExportEntry> ExportMap(PeImage p, byte[] bytes)
        {
            var counts = new Dictionary<(string, uint), int>();
            var result = new Dictionary<(string, uint, int), ExportEntry>();
            var names = ExportNames(p, bytes);
            foreach (var export in p.Exports)
            {
                var key = (export.Name, export.Ordinal); int n = counts.GetValueOrDefault(key) + 1; counts[key] = n;
                bool isNamed = names.TryGetValue((key.Name, key.Ordinal, n), out var name);
                int? forwarder = export.Forwarder is null ? null : Map(p, bytes.Length, export.Rva, export.Forwarder.Length + 1);
                result[(key.Name, key.Ordinal, n)] = new(export, isNamed, name,
                    forwarder is int f ? Evidence.At(f, export.Forwarder!.Length + 1) : default, ExportEvidence(p, bytes, export));
            }
            return result;
        }
        private static Dictionary<(string Name, uint Ordinal, int Occurrence), Evidence> ExportNames(PeImage p, byte[] bytes)
        {
            var result = new Dictionary<(string, uint, int), Evidence>();
            if (p.Exports.Count == 0) return result;
            var dir = p.Directories.FirstOrDefault(d => d.Index == 0); if (dir is null) return result;
            int? at = Map(p, bytes.Length, dir.Address, 40); if (at is not int d) return result;
            uint ordinalBase = U32(bytes, d + 16), functionCount = U32(bytes, d + 20), nameCount = Math.Min(U32(bytes, d + 24), 65536u);
            uint namesRva = U32(bytes, d + 32), ordinalsRva = U32(bytes, d + 36);
            var counts = new Dictionary<(string, uint), int>();
            for (uint i = 0; i < nameCount; i++)
            {
                int? nameAt = Map(p, bytes.Length, (ulong)namesRva + (ulong)i * 4, 4);
                int? ordinalAt = Map(p, bytes.Length, (ulong)ordinalsRva + (ulong)i * 2, 2);
                if (nameAt is not int nameOffset || ordinalAt is not int ordinalOffset) break;
                uint index = U16(bytes, ordinalOffset);
                if (index >= functionCount || (ulong)ordinalBase + index > uint.MaxValue) break;
                var decoded = MappedString(p, bytes, U32(bytes, nameOffset)); if (decoded is not { } name) break;
                uint ordinal = ordinalBase + index; var key = (name.Value, ordinal);
                int n = counts.GetValueOrDefault(key) + 1; counts[key] = n;
                result[(name.Value, ordinal, n)] = name.Evidence;
            }
            return result;
        }
        private static string ExportValue(PeExport? e) => e is null ? "Absent" : $"{e.Name}; ordinal {e.Ordinal}, RVA {Hex(e.Rva)}" + (e.Forwarder is null ? "" : ", forwarder " + e.Forwarder);
        private static Evidence ExportEvidence(PeImage p, byte[] bytes, PeExport? e)
        {
            if (e is null) return default;
            var dir = p.Directories.FirstOrDefault(d => d.Index == 0); if (dir is null) return default;
            int? at = Map(p, bytes.Length, dir.Address, 40); if (at is not int d) return default;
            uint ordinalBase = U32(bytes, d + 16); if (e.Ordinal < ordinalBase) return default;
            int? slot = Map(p, bytes.Length, (ulong)U32(bytes, d + 28) + ((ulong)e.Ordinal - ordinalBase) * 4, 4);
            return slot is int s ? Evidence.At(s, 4) : default;
        }
        private static int? Map(PeImage p, int fileLength, ulong rva, int length)
        {
            if (rva > uint.MaxValue || length <= 0 || rva + (ulong)length > (ulong)uint.MaxValue + 1) return null;
            if (rva < p.SizeOfHeaders && rva + (ulong)length <= Math.Min((ulong)p.SizeOfHeaders, (ulong)fileLength)) return (int)rva;
            foreach (var s in p.Sections)
            {
                if (rva < s.VirtualAddress) continue;
                ulong delta = rva - s.VirtualAddress, offset = (ulong)s.RawOffset + delta;
                if (delta + (ulong)length <= s.RawSize && offset + (ulong)length <= (ulong)fileLength) return (int)offset;
            }
            return null;
        }
        private static (string Value, Evidence Evidence)? MappedString(PeImage p, byte[] bytes, ulong rva)
        {
            Span<byte> content = stackalloc byte[4096];
            for (int i = 0; i < content.Length; i++)
            {
                int? at = Map(p, bytes.Length, rva + (ulong)i, 1); if (at is not int offset) return null;
                if (bytes[offset] == 0)
                {
                    int? whole = Map(p, bytes.Length, rva, i + 1);
                    return (Encoding.ASCII.GetString(content[..i]), whole is int start ? Evidence.At(start, i + 1) : default);
                }
                content[i] = bytes[offset];
            }
            return null;
        }
        private static ushort U16(byte[] bytes, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset));
        private static uint U32(byte[] bytes, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset));
    }
}
