using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using PeWorkshop.Core;

internal static partial class Program
{
    private static int failures;
    private static int count;
    private static void Main()
    {
        ComparisonTests();
        foreach (bool x64 in new[] { false, true })
        {
            Test($"headers/{x64}", () => {
                var p = PeImage.Parse(Fixture(x64));
                Equal(x64, p.Is64Bit); Equal(x64 ? 0x140000000ul : 0x400000ul, p.ImageBase);
                Equal(0x1000u, p.EntryPoint); Equal(1, p.Sections.Count);
                Equal(0x200, p.RvaToOffset(0x1000)); Equal(null, p.RvaToOffset(0x1900));
                Equal("RWX", p.Sections[0].Permissions.Replace(" ", "").Replace("/", ""));
                True(p.Fields.Any(f => f.Name == "CheckSum")); True(p.Fields.Any(f => f.Name == "Characteristics"));
            });
            Test($"imports/{x64}", () => {
                var p = PeImage.Parse(Fixture(x64)); Equal(2, p.Imports.Count);
                Equal("KERNEL32.dll", p.Imports[0].Module); Equal("ExitProcess", p.Imports[0].Name);
                Equal(7u, p.Imports[0].Hint); Equal(12u, p.Imports[1].Ordinal);
                var b = Fixture(x64); W32(b, 0x300, 0); p = PeImage.Parse(b); Equal(2, p.Imports.Count);
            });
            Test($"exports/{x64}", () => {
                var p = PeImage.Parse(Fixture(x64)); Equal(3, p.Exports.Count);
                Equal("Named", p.Exports[0].Name); Equal(5u, p.Exports[0].Ordinal);
                Equal(6u, p.Exports[1].Ordinal); Equal("OTHER.Target", p.Exports[2].Forwarder);
            });
        }
        Test("malformed-essential", () => {
            foreach (int size in new[] { 0, 2, 63, 100, 0x90, 0x180 }) Throws<PeFormatException>(() => PeImage.Parse(Fixture(false)[..size]));
            var b = Fixture(false); b[0] = 0; Throws<PeFormatException>(() => PeImage.Parse(b));
            b = Fixture(false); W32(b, 0x3c, uint.MaxValue); Throws<PeFormatException>(() => PeImage.Parse(b));
            b = Fixture(false); W32(b, 0x98 + 92, 17); Throws<PeFormatException>(() => PeImage.Parse(b));
            b = Fixture(false); W32(b, 0x178 + 20, uint.MaxValue); Throws<PeFormatException>(() => PeImage.Parse(b));
        });
        Test("broken-auxiliary-warning", () => {
            var b = Fixture(false); W32(b, 0x98 + 104, 0xfffffff0); var p = PeImage.Parse(b);
            True(p.Warnings.Count > 0); Equal(1, p.Sections.Count);
            b = Fixture(false); W32(b, 0x400 + 20, uint.MaxValue); p = PeImage.Parse(b); True(p.Warnings.Count > 0);
            b = Fixture(false); W32(b, 0x178 + 12, 0xffffff00); p = PeImage.Parse(b); Equal(null, p.RvaToOffset(0x1000));
        });
        Test("export-aliases", () => {
            var b = Fixture(false); W32(b, 0x418, 4);
            for (int i = 0; i < 4; i++) { W32(b, 0x450 + i * 4, (uint)(0x1290 + i * 8)); W16(b, 0x460 + i * 2, 0); Text(b, 0x490 + i * 8, "Alias" + i); }
            var p = PeImage.Parse(b); Equal(6, p.Exports.Count); Equal(4, p.Exports.Count(e => e.Ordinal == 5));
        });
        Test("auxiliary-caps-and-string-bounds", () => {
            var b = Fixture(false); Array.Resize(ref b, 0x1200 + 65537 * 4); W32(b, 0x178 + 16, (uint)b.Length - 0x200);
            W32(b, 0x300, 0x2000); for (int i = 0; i < 65537; i++) W32(b, 0x1200 + i * 4, 0x8000000c);
            var p = PeImage.Parse(b); Equal(65536, p.Imports.Count); True(p.Warnings.Any(w => w.Contains("truncated")));
            b = Fixture(false); Array.Resize(ref b, 0x1200 + 4097 * 20); W32(b, 0x178 + 16, (uint)b.Length - 0x200);
            W32(b, 0x98 + 104, 0x2000); W32(b, 0x98 + 108, 4097 * 20);
            for (int i = 0; i < 4097; i++) { W32(b, 0x1200 + i * 20, 0x1160); W32(b, 0x120c + i * 20, 0x1140); W32(b, 0x1210 + i * 20, 0x1160); }
            p = PeImage.Parse(b); Equal(8192, p.Imports.Count); True(p.Warnings.Any(w => w.Contains("4096")));
            b = Fixture(false); Array.Resize(ref b, 0x1200 + 65537 * 4); W32(b, 0x178 + 16, (uint)b.Length - 0x200);
            W32(b, 0x414, 65537); W32(b, 0x418, 0); W32(b, 0x41c, 0x2000);
            for (int i = 0; i < 65537; i++) W32(b, 0x1200 + i * 4, 0x1000);
            p = PeImage.Parse(b); Equal(65536, p.Exports.Count); True(p.Warnings.Any(w => w.Contains("truncated")));
            b = Fixture(false); Array.Resize(ref b, 0x2201); W32(b, 0x178 + 16, (uint)b.Length - 0x200); W32(b, 0x30c, 0x2000);
            Array.Fill(b, (byte)'A', 0x1200, 4096); p = PeImage.Parse(b); True(p.Warnings.Any(w => w.Contains("terminated")));
        });
        Test("warnings-and-certificate-offset", () => {
            var b = Fixture(false); W32(b, 0x98 + 96 + 4 * 8, 0xa00); W32(b, 0x98 + 96 + 4 * 8 + 4, 16);
            var p = PeImage.Parse(b); True(p.HasCertificate); Equal(0xa00, p.Directories[4].FileOffset); True(p.Warnings.Any(w => w.Contains("certificate")));
            W32(b, 0x98 + 32, 3); W32(b, 0x98 + 56, 1); W32(b, 0x98 + 60, 0xfffffff0);
            p = PeImage.Parse(b); True(p.Warnings.Any(w => w.Contains("Alignment"))); True(p.Warnings.Any(w => w.Contains("SizeOfImage"))); True(p.Warnings.Any(w => w.Contains("SizeOfHeaders")));
        });
        Test("transaction-and-exact-bytes", () => {
            var original = Fixture(false); var d = new PeDocument(original); original[0] = 0;
            var before = d.Data.ToArray(); var field = d.Image.Fields.Single(f => f.Name == "AddressOfEntryPoint");
            d.SetField(field, "0x1010"); True(d.IsDirty); Equal(1, d.Changes.Count); True(d.IsByteChanged(field.Offset));
            for (int i = 0; i < before.Length; i++) if (i < field.Offset || i >= field.Offset + field.Size) Equal(before[i], d.Data.Span[i]);
            var applied = d.Data.ToArray(); Throws<PeFormatException>(() => d.ApplyPatch(0, [0], "bad"));
            True(applied.SequenceEqual(d.Data.ToArray())); Equal(1, d.Changes.Count);
            Throws<ArgumentOutOfRangeException>(() => d.ApplyPatch(int.MaxValue, [1], "bad"));
            Throws<ArgumentException>(() => d.SetField(field, "20"));
            var machine = d.Image.Fields.Single(f => f.Name == "Machine");
            Throws<ArgumentException>(() => d.SetField(machine, "65536"));
            d.Undo(); True(!d.IsDirty); True(d.CanRedo); Equal(0, d.Changes.Count);
            d.Redo(); Equal(0x1010u, d.Image.EntryPoint); d.Undo();
            d.SetField(d.Image.Fields.Single(f => f.Name == "AddressOfEntryPoint"), "4112"); True(!d.CanRedo);
        });
        Test("rename-and-noop", () => {
            var d = new PeDocument(Fixture(true)); d.ApplyPatch(0, [0x4d], "noop"); True(!d.IsDirty); Equal(0, d.Changes.Count);
            var oldSection = d.Image.Sections[0];
            d.RenameSection(d.Image.Sections[0], ".new"); Equal(".new", d.Image.Sections[0].Name);
            Throws<ArgumentException>(() => d.RenameSection(oldSection, "stale"));
            var exposedHistory = d.Changes[0]; exposedHistory.Before[0] = 0; d.Undo(); Equal(".text", d.Image.Sections[0].Name); d.Redo();
            Equal((byte)0, d.Data.Span[d.Image.Sections[0].HeaderOffset + 4]);
            Throws<ArgumentException>(() => d.RenameSection(d.Image.Sections[0], "123456789"));
            Throws<ArgumentException>(() => d.RenameSection(d.Image.Sections[0], "å"));
        });
        Test("save-baseline-overlay-and-protection", () => {
            string dir = Path.Combine(Path.GetTempPath(), "PeWorkshopTests-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
            try {
                string src = Path.Combine(dir, "source.exe"), dst = Path.Combine(dir, "copy.exe"); File.WriteAllBytes(src, Fixture(false));
                var d = PeDocument.Open(src); d.RenameSection(d.Image.Sections[0], "changed");
                Throws<IOException>(() => d.SaveCopy(Path.Combine(dir, "missing", "x.exe"))); True(d.IsDirty);
                Throws<ArgumentException>(() => d.SaveCopy(Path.Combine(dir, ".", "SOURCE.EXE")));
                Throws<ArgumentException>(() => d.SaveCopy(src + "."));
                d.SaveCopy(dst); True(!d.IsDirty); True(!d.IsByteChanged(d.Image.Sections[0].HeaderOffset)); Equal(src, d.SourcePath);
                True(File.ReadAllBytes(dst).AsSpan(0xa00).SequenceEqual(Fixture(false).AsSpan(0xa00)));
                d.Undo(); True(d.IsDirty); d.Redo(); True(!d.IsDirty); d.UpdateChecksum(); d.SaveCopy(dst);
                Equal(PeChecksum.Calculate(d.Data.Span, d.Image.ChecksumOffset), d.Image.StoredChecksum);
            } finally { Directory.Delete(dir, true); }
        });
        Test("save-source-junction-and-hardlink-aliases", () => {
            if (!OperatingSystem.IsWindows()) return;
            string dir = Path.Combine(Path.GetTempPath(), "PeWorkshopAliases-" + Guid.NewGuid().ToString("N"));
            string originalDir = Path.Combine(dir, "original"), junction = Path.Combine(dir, "junction");
            Directory.CreateDirectory(originalDir);
            try {
                string source = Path.Combine(originalDir, "source.exe"); var original = Fixture(false); File.WriteAllBytes(source, original);
                var start = new System.Diagnostics.ProcessStartInfo("cmd.exe") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                foreach (string argument in new[] { "/c", "mklink", "/J", junction, originalDir }) start.ArgumentList.Add(argument);
                using (var process = System.Diagnostics.Process.Start(start)!) { process.WaitForExit(); if (process.ExitCode != 0) throw new Exception("Cannot create test junction: " + process.StandardError.ReadToEnd()); }
                string hardlink = Path.Combine(dir, "hardlink.exe"); True(CreateHardLink(hardlink, source, 0));
                var d = PeDocument.Open(source); d.RenameSection(d.Image.Sections[0], "changed");
                foreach (string alias in new[] { Path.Combine(junction, "source.exe"), hardlink }) {
                    Throws<ArgumentException>(() => d.SaveCopy(alias));
                    True(File.ReadAllBytes(source).SequenceEqual(original)); True(File.ReadAllBytes(alias).SequenceEqual(original));
                    True(d.IsDirty); Equal(1, d.Changes.Count); True(d.IsByteChanged(d.Image.Sections[0].HeaderOffset));
                }
            } finally {
                if (Directory.Exists(junction)) Directory.Delete(junction);
                Directory.Delete(dir, true);
            }
        });
        Test("checksum-imagehlp", () => {
            foreach (bool x64 in new[] {false, true}) foreach (int pad in new[] {0, 1}) foreach (int shift in new[] {0, 1, 2, 3}) {
                var b = Fixture(x64); if (pad == 1) Array.Resize(ref b, b.Length + 1);
                if (shift != 0) { Array.Copy(b, 0x80, b, 0x80 + shift, 0x200 - 0x80); W32(b, 0x3c, (uint)(0x80 + shift)); }
                W32(b, 0x98 + shift + 64, 0x12345678);
                nint p = CheckSumMappedFile(b, (uint)b.Length, out _, out uint expected); True(p != 0);
                uint actual = PeChecksum.Calculate(b, 0x98 + shift + 64);
                Equal(expected, actual);
            }
        });
        Test("checksum-imagehlp-boundary-bytes", () => {
            var random = new Random(123);
            for (int n = 0; n < 100; n++) {
                var b = Fixture(n % 2 == 0); int shift = n % 4;
                Array.Copy(b, 0x80, b, 0x80 + shift, 0x200 - 0x80); W32(b, 0x3c, (uint)(0x80 + shift));
                int offset = 0x98 + shift + 64; W32(b, offset, (uint)random.NextInt64(0, (long)uint.MaxValue + 1));
                b[offset - 1] = (byte)random.Next(256); b[offset + 4] = (byte)random.Next(256);
                if (n % 3 == 0) Array.Resize(ref b, b.Length + 1); b[^1] = (byte)random.Next(256);
                True(CheckSumMappedFile(b, (uint)b.Length, out _, out uint expected) != 0);
                Equal(expected, PeChecksum.Calculate(b, offset));
            }
        });
        Test("open-size-guard", () => {
            string path = Path.Combine(Path.GetTempPath(), "PeWorkshopLarge-" + Guid.NewGuid().ToString("N"));
            try { using (var file = File.Create(path)) file.SetLength((long)PeImage.MaxFileSize + 1); Throws<PeFormatException>(() => PeDocument.Open(path)); }
            finally { File.Delete(path); }
        });
        Test("fuzz-bounded", () => {
            var random = new Random(42);
            for (int n = 0; n < 1500; n++) {
                var b = Fixture(n % 2 == 0); for (int j = 0; j < 1 + n % 16; j++) b[random.Next(b.Length)] = (byte)random.Next(256);
                if (n % 5 == 0) Array.Resize(ref b, random.Next(b.Length));
                try { var p = PeImage.Parse(b); _ = p.RvaToOffset(uint.MaxValue); } catch (PeFormatException) { }
            }
        });
        Test("real-windows-images", () => {
            foreach (string name in new[] { "kernel32.dll", "user32.dll", "notepad.exe" }) {
                var p = PeDocument.Open(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), name));
                True(p.Image.Sections.Count > 0); True(p.Image.Fields.Count > 30);
                nint ptr = CheckSumMappedFile(p.Data.ToArray(), (uint)p.Data.Length, out _, out uint expected); True(ptr != 0);
                Equal(expected, PeChecksum.Calculate(p.Data.Span, p.Image.ChecksumOffset));
            }
        });
        Console.WriteLine($"{count - failures}/{count} tests passed"); Environment.ExitCode = failures == 0 ? 0 : 1;
    }
    private static void Test(string name, Action action) { count++; try { action(); Console.WriteLine("PASS " + name); } catch (Exception e) { failures++; Console.WriteLine("FAIL " + name + ": " + e); } }
    private static void True(bool value) { if (!value) throw new Exception("Expected true"); }
    private static void Equal<T>(T expected, T actual) { if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new Exception($"Expected {expected}, actual {actual}"); }
    private static void Throws<T>(Action a) where T : Exception { try { a(); } catch (T) { return; } throw new Exception("Expected " + typeof(T).Name); }
    internal static void W16(byte[] b, int o, ushort v) => BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(o), v);
    internal static void W32(byte[] b, int o, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(o), v);
    private static void Text(byte[] b, int o, string s) => Encoding.ASCII.GetBytes(s).CopyTo(b, o);
    internal static byte[] Fixture(bool x64)
    {
        var b = new byte[0xa21]; W16(b, 0, 0x5a4d); W32(b, 0x3c, 0x80); W32(b, 0x80, 0x4550);
        W16(b, 0x84, (ushort)(x64 ? 0x8664 : 0x14c)); W16(b, 0x86, 1); W16(b, 0x94, (ushort)(x64 ? 240 : 224)); W16(b, 0x96, 0x22);
        const int opt = 0x98; W16(b, opt, (ushort)(x64 ? 0x20b : 0x10b)); W32(b, opt + 16, 0x1000);
        if (x64) BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(opt + 24), 0x140000000); else W32(b, opt + 28, 0x400000);
        W32(b, opt + 32, 0x1000); W32(b, opt + 36, 0x200); W32(b, opt + 56, 0x2000); W32(b, opt + 60, 0x200); W16(b, opt + 68, 3);
        int dirs = opt + (x64 ? 112 : 96); W32(b, dirs - 4, 16); W32(b, dirs, 0x1200); W32(b, dirs + 4, 0x100); W32(b, dirs + 8, 0x1100); W32(b, dirs + 12, 40);
        int s = opt + (x64 ? 240 : 224); Text(b, s, ".text"); W32(b, s + 8, 0x1000); W32(b, s + 12, 0x1000); W32(b, s + 16, 0x800); W32(b, s + 20, 0x200); W32(b, s + 36, 0xe0000020);
        W32(b, 0x300, 0x1160); W32(b, 0x30c, 0x1140); W32(b, 0x310, 0x1160); Text(b, 0x340, "KERNEL32.dll");
        if (x64) { BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(0x360), 0x1180); BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(0x368), 0x800000000000000cul); }
        else { W32(b, 0x360, 0x1180); W32(b, 0x364, 0x8000000c); }
        W16(b, 0x380, 7); Text(b, 0x382, "ExitProcess");
        W32(b, 0x410, 5); W32(b, 0x414, 3); W32(b, 0x418, 1); W32(b, 0x41c, 0x1240); W32(b, 0x420, 0x1250); W32(b, 0x424, 0x1260);
        W32(b, 0x440, 0x1000); W32(b, 0x444, 0x1010); W32(b, 0x448, 0x1280); W32(b, 0x450, 0x1270); W16(b, 0x460, 0); Text(b, 0x470, "Named"); Text(b, 0x480, "OTHER.Target");
        for (int i = 0xa00; i < b.Length; i++) b[i] = (byte)(i ^ 0xab);
        return b;
    }
    [DllImport("imagehlp.dll", SetLastError = true)]
    private static extern nint CheckSumMappedFile(byte[] baseAddress, uint fileLength, out uint headerSum, out uint checkSum);
    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string newFileName, string existingFileName, nint securityAttributes);
}
