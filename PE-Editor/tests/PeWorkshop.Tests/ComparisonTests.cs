using System.Buffers.Binary;
using System.Security.Cryptography;
using PeWorkshop.Core;

internal static partial class Program
{
    private static void ComparisonTests()
    {
        Test("comparison-identical-pe32-and-pe32plus", () => {
            foreach (bool x64 in new[] { false, true }) {
                var b = Fixture(x64); var result = PeComparison.Compare(b, (byte[])b.Clone());
                True(result.Identical); Equal(0L, result.DifferentByteCount); Equal(0, result.Differences.Count);
                Equal(0, result.ByteRanges.Count); True(!result.ByteRangesTruncated);
                Equal(Convert.ToHexString(SHA256.HashData(b)), result.LeftSha256); Equal(result.LeftSha256, result.RightSha256);
                True(result.Limitations.Any(s => s.Contains("positional", StringComparison.OrdinalIgnoreCase)));
            }
        });
        Test("comparison-sized-tails-count-every-byte", () => {
            var a = Fixture(false); var b = a.Concat(new byte[] { 0, 7, 0 }).ToArray();
            var result = PeComparison.Compare(a, b);
            Equal(3L, result.DifferentByteCount); Equal(new PeByteRange(a.Length, 3), result.ByteRanges.Single());
            True(result.Differences.Any(d => d.Category == "Overlay")); CheckEvidence(result, a, b);
            var reversed = PeComparison.Compare(b, a); Equal(3L, reversed.DifferentByteCount); CheckEvidence(reversed, b, a);
        });
        Test("comparison-byte-header-dos-and-offsets", () => {
            var a = Fixture(false); var b = (byte[])a.Clone(); b[0x9c] ^= 1; b[2] = 9;
            var result = PeComparison.Compare(a, b); Equal(2L, result.DifferentByteCount);
            True(result.Differences.Any(d => d.Title.Contains("SizeOfCode") && d.LeftOffset == 0x9c && d.RightLength == 4));
            True(result.Differences.Any(d => d.Category.Contains("DOS") && d.RightOffset == 2)); CheckEvidence(result, a, b);
        });
        Test("comparison-console-windowed-explanation", () => {
            var a = Fixture(false); var b = (byte[])a.Clone(); W16(b, 0x98 + 68, 2);
            var diff = PeComparison.Compare(a, b).Differences.Single(d => d.Title == "Subsystem");
            Equal(DifferenceSeverity.Information, diff.Severity);
            True(diff.Explanation.Contains("console", StringComparison.OrdinalIgnoreCase));
            True(diff.Explanation.Contains("does not prove", StringComparison.OrdinalIgnoreCase));
        });
        Test("comparison-reduced-mitigations", () => {
            var a = Fixture(true); var b = (byte[])a.Clone(); W16(a, 0x98 + 70, 0x4160);
            var diffs = PeComparison.Compare(a, b).Differences;
            foreach (string name in new[] { "ASLR", "NX", "high-entropy", "CFG" })
                True(diffs.Any(d => d.Title.Contains(name, StringComparison.OrdinalIgnoreCase) && d.Severity == DifferenceSeverity.Suspicious && d.LeftOffset == 0x98 + 70));
        });
        Test("comparison-newly-writable-executable-section", () => {
            var a = Fixture(false); W32(a, 0x178 + 36, 0x60000020); var b = (byte[])a.Clone(); W32(b, 0x178 + 36, 0xe0000020);
            var result = PeComparison.Compare(a, b);
            True(result.Differences.Any(d => d.Severity == DifferenceSeverity.Suspicious && d.Title.Contains("writable", StringComparison.OrdinalIgnoreCase) && d.RightOffset == 0x178 + 36));
            CheckEvidence(result, a, b);
        });
        Test("comparison-added-entry-section", () => {
            var a = Fixture(false); var b = AddedSection(a, ".extra"); W32(b, 0x98 + 16, 0x2000);
            var result = PeComparison.Compare(a, b);
            True(result.Differences.Any(d => d.Title.Contains("Entry point", StringComparison.OrdinalIgnoreCase) && d.Severity == DifferenceSeverity.Suspicious && d.RightOffset == 0x98 + 16));
            True(result.Differences.Any(d => d.Title.Contains(".extra") && d.Severity == DifferenceSeverity.Suspicious));
            CheckEvidence(result, a, b);
        });
        Test("comparison-section-duplicate-names-keep-occurrence", () => {
            var a = AddedSection(Fixture(false), ".text"); var b = (byte[])a.Clone(); b[0xa00] ^= 1;
            var result = PeComparison.Compare(a, b);
            var content = result.Differences.Where(d => d.Category == "Section content").ToArray();
            Equal(1, content.Length); Equal(0xa00, content[0].RightOffset); CheckEvidence(result, a, b);
        });
        Test("comparison-import-dll-case-insensitive-symbol-case-sensitive", () => {
            var a = Fixture(false); var b = (byte[])a.Clone(); Text(b, 0x340, "kernel32.DLL");
            True(!PeComparison.Compare(a, b).Differences.Any(d => d.Category == "Imports"));
            Text(b, 0x382, "exitProcess"); var result = PeComparison.Compare(a, b);
            var imports = result.Differences.Where(d => d.Category == "Imports").ToArray(); Equal(2, imports.Length);
            True(imports.Any(d => d.LeftValue.Contains("ExitProcess"))); True(imports.Any(d => d.RightValue.Contains("exitProcess")));
            CheckEvidence(result, a, b);
        });
        Test("comparison-sensitive-import-and-gui-capability", () => {
            var a = Fixture(false); var b = (byte[])a.Clone(); Array.Clear(b, 0x382, 40); Text(b, 0x382, "VirtualProtect");
            var result = PeComparison.Compare(a, b);
            True(result.Differences.Any(d => d.Category == "Imports" && d.RightValue.Contains("VirtualProtect") && d.Severity == DifferenceSeverity.Suspicious && d.RightOffset == 0x382));
            Array.Clear(b, 0x340, 24); Text(b, 0x340, "USER32.dll"); Array.Clear(b, 0x382, 40); Text(b, 0x382, "MessageBoxW");
            result = PeComparison.Compare(a, b);
            True(result.Differences.Any(d => d.Category == "Imports" && d.RightValue.Contains("MessageBoxW") && d.Explanation.Contains("dialog", StringComparison.OrdinalIgnoreCase)));
            True(result.Differences.Any(d => d.Category == "Imports" && d.RightValue == "Absent" && d.Explanation.Contains("runtime", StringComparison.OrdinalIgnoreCase)));
            CheckEvidence(result, a, b);
        });
        Test("comparison-capability-requires-known-module-and-exact-symbol", () => {
            foreach (string symbol in new[] { "VirtualProtect", "MessageBoxW", "WriteFile" }) {
                var a = Fixture(false); var b = ImportNamed(a, "CUSTOM.dll", symbol);
                var result = PeComparison.Compare(a, b);
                var d = result.Differences.Single(d => d.Category == "Imports" && d.Title.StartsWith("Import added:") && d.RightValue.Contains("!" + symbol + ";"));
                Equal(DifferenceSeverity.Information, d.Severity);
                True(!d.Explanation.Contains("memory-management")); True(!d.Explanation.Contains("message-dialog")); True(!d.Explanation.Contains("console, standard-stream"));
                CheckEvidence(result, a, b);
            }
            foreach (var (module, symbol, severity, meaning) in new[] {
                ("kErNeL32.DlL", "VirtualProtect", DifferenceSeverity.Suspicious, "memory-management"),
                ("KERNELBASE.dll", "WriteFile", DifferenceSeverity.Information, "console, standard-stream"),
                ("uSeR32.dLl", "MessageBoxW", DifferenceSeverity.Information, "message-dialog"),
                ("NTDLL.dll", "NtProtectVirtualMemory", DifferenceSeverity.Suspicious, "memory-management") }) {
                var a = Fixture(false); var b = ImportNamed(a, module, symbol);
                var d = PeComparison.Compare(a, b).Differences.Single(d => d.Category == "Imports" && d.Title.StartsWith("Import added:") && d.RightValue.Contains("!" + symbol + ";"));
                Equal(severity, d.Severity); True(d.Explanation.Contains(meaning));
            }
            foreach (var (module, symbol) in new[] { ("KERNEL32.dll", "virtualProtect"), ("USER32.dll", "messageBoxW"), ("USER32.dll", "VirtualProtect"), ("SHELL32.dll", "VirtualProtect"), ("CUSTOM.dll", "NtProtectVirtualMemory") }) {
                var a = Fixture(false); var b = ImportNamed(a, module, symbol);
                var d = PeComparison.Compare(a, b).Differences.Single(d => d.Category == "Imports" && d.Title.StartsWith("Import added:") && d.RightValue.Contains("!" + symbol + ";"));
                Equal(DifferenceSeverity.Information, d.Severity); True(!d.Explanation.Contains("message-dialog")); True(!d.Explanation.Contains("memory-management"));
            }
        });
        Test("comparison-empty-import-descriptors-added-removed-renamed", () => {
            foreach (bool x64 in new[] { false, true }) {
                var b = Fixture(x64); Array.Clear(b, 0x360, 24); Equal(0, PeImage.Parse(b).Imports.Count);
                var a = (byte[])b.Clone(); Array.Clear(a, 0x300, 20);
                var added = PeComparison.Compare(a, b); var removed = PeComparison.Compare(b, a);
                var d = added.Differences.Single(d => d.Category == "Imports" && d.Title.StartsWith("DLL declaration added:"));
                Equal("KERNEL32.dll", d.RightValue); Equal(0x340, d.RightOffset); Equal(13, d.RightLength);
                True(removed.Differences.Any(d => d.Category == "Imports" && d.Title.StartsWith("DLL declaration removed:") && d.LeftOffset == 0x340));
                var renamed = (byte[])b.Clone(); Array.Clear(renamed, 0x340, 20); Text(renamed, 0x340, "CUSTOM.dll");
                Equal(2, PeComparison.Compare(b, renamed).Differences.Count(d => d.Category == "Imports"));
                Text(renamed, 0x340, "kernel32.DLL");
                True(!PeComparison.Compare(b, renamed).Differences.Any(d => d.Category == "Imports"));
                CheckEvidence(added, a, b); CheckEvidence(removed, b, a);
            }
        });
        Test("comparison-import-descriptor-duplicate-occurrence-and-null-stop", () => {
            var a = Fixture(false); Array.Clear(a, 0x360, 24); var b = (byte[])a.Clone();
            Array.Copy(b, 0x300, b, 0x314, 20); W32(b, 0x98 + 96 + 12, 60);
            var result = PeComparison.Compare(a, b);
            Equal(1, result.Differences.Count(d => d.Category == "Imports" && d.Title.StartsWith("DLL declaration added:")));
            Array.Clear(b, 0x314, 20); Array.Copy(b, 0x300, b, 0x328, 20);
            W32(a, 0x98 + 96 + 12, 60);
            True(!PeComparison.Compare(a, b).Differences.Any(d => d.Category == "Imports"));
        });
        Test("comparison-import-descriptor-incomplete-disclosed", () => {
            var a = Fixture(false); var b = (byte[])a.Clone(); W32(b, 0x30c, uint.MaxValue);
            var result = PeComparison.Compare(a, b);
            True(result.Limitations.Any(s => s.Contains("Right") && s.Contains("DLL descriptor comparison") && s.Contains("incomplete")));
            b = (byte[])a.Clone(); W32(b, 0x98 + 96 + 12, 20);
            result = PeComparison.Compare(a, b);
            True(result.Limitations.Any(s => s.Contains("Right") && s.Contains("DLL descriptor comparison") && s.Contains("terminator")));
            CheckEvidence(result, a, b);
        });
        Test("comparison-import-descriptor-and-name-caps", () => {
            var b = Fixture(false); Array.Resize(ref b, 0x15400); Array.Clear(b, 0x200, b.Length - 0x200);
            Array.Clear(b, 0x98 + 96, 8); W32(b, 0x178 + 16, (uint)b.Length - 0x200); W32(b, 0x178 + 8, 0x20000);
            W32(b, 0x98 + 56, 0x22000); Text(b, 0x500, "EMPTY.dll"); Text(b, 0x540, "BEYOND.dll");
            for (int i = 0; i < 4097; i++) {
                int d = 0x1000 + i * 20; W32(b, d, 0x1200); W32(b, d + 12, i < 4096 ? 0x1300u : 0x1340u); W32(b, d + 16, 0x1200);
            }
            W32(b, 0x98 + 96 + 8, 0x1e00); W32(b, 0x98 + 96 + 12, 4098 * 20);
            var a = (byte[])b.Clone(); Array.Clear(a, 0x98 + 96 + 8, 8);
            var result = PeComparison.Compare(a, b);
            Equal(4096, result.Differences.Count(d => d.Category == "Imports" && d.Title.StartsWith("DLL declaration added:")));
            True(!result.Differences.Any(d => d.Category == "Imports" && d.RightValue.Contains("BEYOND")));
            True(result.Limitations.Any(s => s.Contains("Right DLL descriptor comparison incomplete") && s.Contains("4,096-descriptor")));
            CheckEvidence(result, a, b);
            a = Fixture(false); b = (byte[])a.Clone(); Array.Resize(ref b, 0x2000); W32(b, 0x178 + 16, 0x1e00); W32(b, 0x30c, 0x1300);
            Array.Fill(b, (byte)'A', 0x500, 4096);
            result = PeComparison.Compare(a, b);
            True(result.Limitations.Any(s => s.Contains("Right DLL descriptor comparison incomplete") && s.Contains("4,096 bytes")));
            CheckEvidence(result, a, b);
        });
        Test("comparison-import-hint-iat-and-ordinal", () => {
            var a = Fixture(false); var b = (byte[])a.Clone(); W16(b, 0x380, 44); W32(b, 0x310, 0x1190); W32(b, 0x364, 0x8000000d);
            var result = PeComparison.Compare(a, b);
            True(result.Differences.Any(d => d.Category == "Imports" && d.Title.Contains("hint", StringComparison.OrdinalIgnoreCase)));
            True(result.Differences.Any(d => d.Category == "Imports" && d.Title.Contains("IAT", StringComparison.Ordinal)));
            True(result.Differences.Any(d => d.Category == "Imports" && d.RightValue.Contains("#13"))); CheckEvidence(result, a, b);
        });
        Test("comparison-exports-case-target-forwarder", () => {
            var a = Fixture(false); var b = (byte[])a.Clone(); Text(b, 0x470, "named"); W32(b, 0x444, 0x1030); Text(b, 0x480, "OTHER.Target2");
            var result = PeComparison.Compare(a, b); var diffs = result.Differences.Where(d => d.Category == "Exports").ToArray();
            True(diffs.Any(d => d.LeftValue.Contains("Named"))); True(diffs.Any(d => d.RightValue.Contains("named")));
            True(diffs.Any(d => d.LeftValue.Contains("1010") && d.RightValue.Contains("1030")));
            True(diffs.Any(d => d.RightValue.Contains("OTHER.Target2"))); CheckEvidence(result, a, b);
        });
        Test("comparison-export-string-evidence-points-to-changed-bytes", () => {
            var a = Fixture(false); var b = (byte[])a.Clone(); Text(b, 0x470, "named"); Text(b, 0x480, "OTHER.Target2");
            var result = PeComparison.Compare(a, b);
            var removed = result.Differences.Single(d => d.Category == "Exports" && d.LeftValue.StartsWith("Named;"));
            var added = result.Differences.Single(d => d.Category == "Exports" && d.RightValue.StartsWith("named;"));
            var forwarder = result.Differences.Single(d => d.Category == "Exports" && d.RightValue.Contains("OTHER.Target2"));
            Equal(0x470, removed.LeftOffset); Equal(6, removed.LeftLength);
            Equal(0x470, added.RightOffset); Equal(6, added.RightLength);
            Equal(0x480, forwarder.LeftOffset); Equal(13, forwarder.LeftLength);
            Equal(0x480, forwarder.RightOffset); Equal(14, forwarder.RightLength);
            True(a[forwarder.LeftOffset!.Value + 12] != b[forwarder.RightOffset!.Value + 12]); CheckEvidence(result, a, b);
            b = (byte[])a.Clone(); W32(b, 0x440, 0x1030);
            var target = PeComparison.Compare(a, b).Differences.Single(d => d.Category == "Exports");
            Equal(0x440, target.LeftOffset); Equal(0x440, target.RightOffset); Equal(4, target.RightLength);
        });
        Test("comparison-checksum-becomes-stale", () => {
            var a = Fixture(false); W32(a, 0x98 + 64, PeChecksum.Calculate(a, 0x98 + 64)); var b = (byte[])a.Clone(); b[0x700] ^= 1;
            var result = PeComparison.Compare(a, b);
            True(result.Differences.Any(d => d.Category == "Checksum" && d.Severity == DifferenceSeverity.Review && d.RightOffset == 0x98 + 64));
        });
        Test("comparison-certificate-removal-and-overlay", () => {
            var a = Fixture(false); W32(a, 0x98 + 96 + 32, 0xa00); W32(a, 0x98 + 96 + 36, 32);
            W32(a, 0xa00, 32); W16(a, 0xa04, 0x200); W16(a, 0xa06, 2);
            var b = (byte[])a.Clone(); Array.Clear(b, 0x98 + 96 + 32, 8);
            var result = PeComparison.Compare(a, b);
            True(result.Differences.Any(d => d.Category == "Certificate" && d.Severity == DifferenceSeverity.Review));
            True(result.Differences.Any(d => d.Category == "Overlay" && d.LeftValue.Contains("1 byte") && d.RightValue.Contains("33 byte")));
            CheckEvidence(result, a, b);
        });
        Test("comparison-section-entropy-increase", () => {
            var a = Fixture(false); Array.Clear(a, 0x98 + 96, 16); Array.Clear(a, 0x200, 0x800); var b = (byte[])a.Clone();
            for (int i = 0x200; i < 0xa00; i++) b[i] = (byte)i;
            var result = PeComparison.Compare(a, b);
            True(result.Differences.Any(d => d.Category == "Entropy" && d.Severity == DifferenceSeverity.Review)); CheckEvidence(result, a, b);
        });
        Test("comparison-bounds-warnings-cross-architecture", () => {
            var a = Fixture(false); var b = Fixture(true); W32(b, 0x98 + 112 + 13 * 8, uint.MaxValue); W32(b, 0x98 + 112 + 13 * 8 + 4, 50);
            var result = PeComparison.Compare(a, b); CheckEvidence(result, a, b);
            True(result.Limitations.Any(s => s.Contains("Right", StringComparison.Ordinal) && s.Contains("Delay import")));
            Throws<PeFormatException>(() => PeComparison.Compare(a, new byte[63]));
            Throws<PeFormatException>(() => PeComparison.Compare(a, new byte[PeImage.MaxFileSize + 1]));
            Throws<ArgumentNullException>(() => PeComparison.Compare(null!, a));
        });
        Test("comparison-range-cap-counts-all", () => {
            var a = Fixture(false); Array.Resize(ref a, 16000); var b = (byte[])a.Clone();
            for (int i = 3000; i < 15000; i += 2) b[i] = 1;
            var result = PeComparison.Compare(a, b); Equal(6000L, result.DifferentByteCount); Equal(2000, result.ByteRanges.Count); True(result.ByteRangesTruncated);
            True(result.Limitations.Any(s => s.Contains("2,000") || s.Contains("2000"))); CheckEvidence(result, a, b);
        });
        Test("comparison-finding-cap-disclosed", () => {
            var b = ManyImports(12000); var a = (byte[])b.Clone(); Array.Clear(a, 0x98 + 96 + 8, 8);
            var result = PeComparison.Compare(a, b); Equal(10000, result.Differences.Count);
            True(result.Limitations.Any(s => (s.Contains("10,000") || s.Contains("10000")) && s.Contains("truncat", StringComparison.OrdinalIgnoreCase)));
            Equal(Enumerable.Range(0, a.Length).LongCount(i => a[i] != b[i]), result.DifferentByteCount); CheckEvidence(result, a, b);
        });
        Test("comparison-timestamp-alone-is-information", () => {
            var a = Fixture(false); var b = (byte[])a.Clone(); W32(b, 0x88, 0xffffffff);
            True(PeComparison.Compare(a, b).Differences.All(d => d.Severity == DifferenceSeverity.Information));
        });
    }

    private static void CheckEvidence(PeComparisonResult result, byte[] left, byte[] right)
    {
        foreach (var d in result.Differences) {
            True(!string.IsNullOrWhiteSpace(d.Explanation));
            True(d.LeftOffset is int l ? l >= 0 && d.LeftLength > 0 && (long)l + d.LeftLength <= left.Length : d.LeftLength == 0);
            True(d.RightOffset is int r ? r >= 0 && d.RightLength > 0 && (long)r + d.RightLength <= right.Length : d.RightLength == 0);
        }
        foreach (var range in result.ByteRanges) True(range.Offset >= 0 && range.Length > 0 && (long)range.Offset + range.Length <= Math.Max(left.Length, right.Length));
    }
    private static byte[] AddedSection(byte[] source, string name)
    {
        var b = (byte[])source.Clone(); Array.Resize(ref b, 0xc00); Array.Clear(b, 0xa00, 0x200);
        W16(b, 0x86, 2); int s = 0x1a0; Text(b, s, name); W32(b, s + 8, 0x200); W32(b, s + 12, 0x2000);
        W32(b, s + 16, 0x200); W32(b, s + 20, 0xa00); W32(b, s + 36, 0x60000020); W32(b, 0x98 + 56, 0x3000); return b;
    }
    private static byte[] ImportNamed(byte[] source, string module, string symbol)
    {
        var b = (byte[])source.Clone(); Array.Clear(b, 0x500, 128); Text(b, 0x500, module); W32(b, 0x30c, 0x1300);
        Array.Clear(b, 0x382, 80); Text(b, 0x382, symbol); return b;
    }
    private static byte[] ManyImports(int count)
    {
        var b = Fixture(false); Array.Resize(ref b, ((0x600 + (count + 1) * 4 + 511) / 512) * 512);
        Array.Clear(b, 0x98 + 96, 8); W32(b, 0x178 + 16, (uint)b.Length - 0x200); W32(b, 0x178 + 8, (uint)b.Length);
        W32(b, 0x300, 0x1400); W32(b, 0x310, 0x1400);
        for (int i = 0; i < count; i++) W32(b, 0x600 + i * 4, 0x80000000 | (uint)(i + 1));
        return b;
    }
}
