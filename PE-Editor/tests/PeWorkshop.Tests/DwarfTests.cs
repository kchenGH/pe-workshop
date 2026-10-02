using System.Buffers.Binary;
using System.Text;
using PeWorkshop.Core;

internal static partial class Program
{
    private static void DwarfTests()
    {
        Test("dwarf-coff-long-section-names", () => {
            var b = DwarfPe(false, (".debug_info", new byte[] { 1, 2 }), (".debug_abbrev", new byte[] { 0 }));
            var p = PeImage.Parse(b); Equal(".debug_info", p.Sections[0].Name); Equal("/4", p.Sections[0].RawName);
            Equal(0x178, p.Sections[0].HeaderOffset);
            var d = new PeDocument(b); d.RenameSection(d.Image.Sections[0], ".renamed");
            Equal(".renamed", d.Image.Sections[0].Name); d.Undo(); Equal(".debug_info", d.Image.Sections[0].Name);
            True(PeComparison.Compare(b, b).Identical);
        });
        Test("dwarf-coff-malformed-long-names", () => {
            var original = DwarfPe(false, (".debug_info", new byte[] { 0 }));
            foreach (string invalid in new[] { "/0", "/3", "/99999", "/oops" }) {
                var b = (byte[])original.Clone(); Array.Clear(b, 0x178, 8); Text(b, 0x178, invalid);
                var p = PeImage.Parse(b); Equal(invalid, p.Sections[0].Name); True(p.Warnings.Any(w => w.Contains("name", StringComparison.OrdinalIgnoreCase)));
            }
            foreach (int corrupt in new[] { 0, 1, 2, 3 }) {
                var b = (byte[])original.Clone(); int table = (int)BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(0x8c));
                if (corrupt == 0) W32(b, table, uint.MaxValue);
                if (corrupt == 1) b[^1] = 65;
                if (corrupt == 2) b[table + 4] = 0xff;
                if (corrupt == 3) { W32(b, 0x8c, uint.MaxValue); W32(b, 0x90, uint.MaxValue); }
                var p = PeImage.Parse(b); Equal("/4", p.Sections[0].Name); True(p.Warnings.Any(w => w.Contains("name", StringComparison.OrdinalIgnoreCase)));
            }
        });
        foreach (int version in new[] { 2, 3, 4, 5 }) foreach (bool x64 in new[] { false, true }) {
            Test($"dwarf-variables-v{version}-pe{(x64 ? "32plus" : "32")}", () => {
                var f = StandardDwarf(version, x64, version == 5); var b = f.Image(); var original = (byte[])b.Clone();
                var result = PeDwarfReader.Read(b); Equal(DebugSymbolStatus.Available, result.Status); Equal("DWARF", result.Format);
                var global = result.Variables.Single(v => v.Name == "global"); Equal("Global", global.Kind); Equal("int", global.Type);
                Equal("C:/src/inc/other.h", global.SourceFile); Equal(130, global.Line); True(global.Location.Contains("0x401020"));
                var local = result.Variables.First(v => v.Name == "local"); Equal("Local", local.Kind); Equal("const Count*", local.Type);
                True(local.Scope.Contains("sample::work")); True(local.Location.Contains("-129"));
                var parameter = result.Variables.Single(v => v.Name == "input"); Equal("Parameter", parameter.Kind); True(parameter.Location.Contains("register 129"));
                var shadow = result.Variables.Last(v => v.Name == "local"); True(shadow.Scope.Contains("lexical")); True(shadow.Scope != local.Scope);
                var info = PeImage.Parse(b).Sections.Single(s => s.Name == ".debug_info");
                foreach (var variable in result.Variables) { True(variable.DebugOffset >= info.RawOffset); True(variable.DebugLength > 0); True((long)variable.DebugOffset + variable.DebugLength <= info.RawOffset + info.RawSize); }
                Equal((int)info.RawOffset + f.Offsets["global"], global.DebugOffset); Equal(f.Lengths["global"], global.DebugLength);
                True(original.SequenceEqual(b));
            });
        }
        Test("dwarf-derived-types-references-and-declarations", () => {
            var f = StandardDwarf();
            f.Abbrev(11, 0x34, false, (3, 8), (0x47, 0x13), (0x3c, 0x19));
            f.Die(11, "definition", "", new DRef("global"));
            f.Abbrev(12, 0x34, false, (0x31, 0x13)); f.Die(12, "origin", new DRef("local"));
            f.Abbrev(13, 0x01, true, (0x49, 0x13)); f.Die(13, "array", new DRef("int"));
            f.Abbrev(14, 0x21, false, (0x2f, 0x0f)); f.Die(14, "bound", 3ul); f.End();
            f.Abbrev(15, 0x13, false, (3, 8)); f.Die(15, "aggregate", "Widget");
            f.Abbrev(16, 0x10, false, (0x49, 0x13)); f.Die(16, "reference", new DRef("aggregate"));
            f.Die(5, "arrayvar", "arrayvar", new DRef("array"), 2ul, 9ul, new byte[] { 0x50 });
            f.Die(5, "refvar", "refvar", new DRef("reference"), 2ul, 9ul, new byte[] { 0x70, 0x7e });
            var result = PeDwarfReader.Read(f.Image()); Equal(DebugSymbolStatus.Available, result.Status);
            var definition = result.Variables.Single(v => v.IsDeclaration); Equal("global", definition.Name); Equal("int", definition.Type);
            Equal("const Count*", result.Variables.Single(v => v.DebugOffset == (int)PeImage.Parse(f.Image()).Sections[0].RawOffset + f.Offsets["origin"]).Type);
            Equal("int[4]", result.Variables.Single(v => v.Name == "arrayvar").Type);
            Equal("Widget&", result.Variables.Single(v => v.Name == "refvar").Type);
        });
        Test("dwarf-strp-line-strp-indirect-and-implicit-const", () => {
            var f = new DwarfFixture(5, true, true);
            f.Strings = Encoding.UTF8.GetBytes("signed long\0value\0"); f.LineStrings = Encoding.UTF8.GetBytes("source.cpp\0C:/src\0");
            f.Abbrev(1, 0x11, true, (3, 0x1f), (0x1b, 0x1f)); f.Die(1, "cu", 0ul, 11ul);
            f.Abbrev(2, 0x24, false, (3, 0x0e)); f.Die(2, "type", 0ul);
            f.Abbrev(3, 0x34, false, (3, 0x16, 0), (0x49, 0x13, 0), (0x3b, 0x21, 42), (0x1c, 0x0d, 0));
            f.Die(3, "var", new DIndirect(0x0e, 12ul), new DRef("type"), -129L);
            var result = PeDwarfReader.Read(f.Image()); Equal(DebugSymbolStatus.Available, result.Status);
            var v = result.Variables.Single(); Equal("value", v.Name); Equal("signed long", v.Type); Equal(42, v.Line); True(v.Location.Contains("compile-time constant -129"));
        });
        Test("dwarf-unknown-source-index-is-not-cu-filename", () => {
            var f = StandardDwarf(); f.Die(5, "unknownfile", "unknownfile", new DRef("int"), 99ul, 0ul, new byte[] { 0x50 });
            var result = PeDwarfReader.Read(f.Image()); Equal(DebugSymbolStatus.Partial, result.Status); Equal("", result.Variables.Single(v => v.Name == "unknownfile").SourceFile);
            True(result.Diagnostics.Any(d => d.Contains("file index")));
        });
        Test("dwarf-unsupported-and-missing-diagnostics", () => {
            Equal(DebugSymbolStatus.NotFound, PeDwarfReader.Read(Fixture(false)).Status);
            var f = StandardDwarf(); var bytes = f.Info(); W16(bytes, 4, 9);
            Equal(DebugSymbolStatus.Unsupported, PeDwarfReader.Read(DwarfPe(false, (".debug_info", bytes), (".debug_abbrev", f.Abbreviations()))).Status);
            f = StandardDwarf(5); bytes = f.Info(); bytes[6] = 2;
            Equal(DebugSymbolStatus.Unsupported, PeDwarfReader.Read(DwarfPe(false, (".debug_info", bytes), (".debug_abbrev", f.Abbreviations()))).Status);
            Equal(DebugSymbolStatus.Unsupported, PeDwarfReader.Read(DwarfPe(false, (".zdebug_info", new byte[16]))).Status);
            Equal(DebugSymbolStatus.Unsupported, PeDwarfReader.Read(DwarfPe(false, (".debug_info.dwo", new byte[16]))).Status);
            Equal(DebugSymbolStatus.Unsupported, PeDwarfReader.Read(DwarfPe(false, (".debug_sup", new byte[16]))).Status);
            f = new DwarfFixture(); f.Abbrev(1, 0x11, false, (0x2130, 8)); f.Die(1, "cu", "external.dwo");
            var split = PeDwarfReader.Read(f.Image()); Equal(DebugSymbolStatus.Unsupported, split.Status); True(split.Diagnostics.Any(d => d.Contains("Split")));
            f = new DwarfFixture(); f.Abbrev(1, 0x11, false, (3, 0x1a)); f.Die(1, "cu", 0ul);
            Equal(DebugSymbolStatus.Unsupported, PeDwarfReader.Read(f.Image()).Status);
            f = new DwarfFixture(); f.Abbrev(1, 0x11, false, (3, 0xffff)); f.Body.Add(1);
            Equal(DebugSymbolStatus.Unsupported, PeDwarfReader.Read(f.Image()).Status);
            f = StandardDwarf(); bytes = f.Info(); W16(bytes, 4, 9); var good = StandardDwarf().Info();
            var result = PeDwarfReader.Read(DwarfPe(false, (".debug_info", bytes.Concat(good).ToArray()), (".debug_abbrev", f.Abbreviations()), (".debug_line", f.Line)));
            Equal(DebugSymbolStatus.Partial, result.Status); True(result.Variables.Count > 0);
            var pdb = Fixture(false); W32(pdb, 0x98 + 96 + 6 * 8, 0x1500); W32(pdb, 0x98 + 96 + 6 * 8 + 4, 28); W32(pdb, 0x700 + 12, 2);
            var p = PeDwarfReader.Read(pdb); Equal(DebugSymbolStatus.Unsupported, p.Status); True(p.Diagnostics.Any(d => d.Contains("PDB")));
        });
        Test("dwarf-malformed-bounds-and-leb", () => {
            foreach (int mutation in new[] { 0, 1, 2, 3, 4 }) {
                var f = StandardDwarf(); var info = f.Info(); var abbrev = f.Abbreviations();
                if (mutation == 0) W32(info, 0, uint.MaxValue - 1);
                if (mutation == 1) { info = info[..^3]; W32(info, 0, (uint)info.Length - 4); }
                if (mutation == 2) abbrev = new byte[] { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 1 };
                if (mutation == 3) info[f.Offsets["global"]] = 127;
                if (mutation == 4) { int reference = f.Offsets["global"] + 8; W32(info, reference, 0xffffffff); }
                var r = PeDwarfReader.Read(DwarfPe(false, (".debug_info", info), (".debug_abbrev", abbrev), (".debug_line", f.Line)));
                True(r.Status is DebugSymbolStatus.Malformed or DebugSymbolStatus.Partial);
                True(r.Diagnostics.Count > 0);
            }
            var badString = new DwarfFixture(); badString.Abbrev(1, 0x11, false, (3, 8)); badString.Body.Add(1); badString.Body.AddRange(Enumerable.Repeat((byte)65, 16385));
            Equal(DebugSymbolStatus.Malformed, PeDwarfReader.Read(badString.Image()).Status);
        });
        Test("dwarf-cycle-and-location-expressions", () => {
            var f = StandardDwarf(); f.Abbrev(11, 0x0f, false, (0x49, 0x13)); f.Die(11, "cycle", new DRef("cycle"));
            f.Die(5, "cyclic", "cyclic", new DRef("cycle"), 2ul, 1ul, new byte[] { 0x03 });
            f.Die(5, "unsupportedop", "unsupportedop", new DRef("int"), 2ul, 1ul, new byte[] { 0x99, 1 });
            f.Die(5, "bregx", "bregx", new DRef("int"), 2ul, 1ul, new byte[] { 0x92, 0x81, 1, 0x7f });
            f.Abbrev(12, 0x34, false, (3, 8), (0x49, 0x13), (2, 0x17)); f.Die(12, "list", "listed", new DRef("int"), 12ul);
            var result = PeDwarfReader.Read(f.Image()); Equal(DebugSymbolStatus.Partial, result.Status);
            True(result.Variables.Single(v => v.Name == "cyclic").Type.Contains("cycle"));
            True(result.Variables.Single(v => v.Name == "cyclic").Location.Contains("malformed"));
            True(result.Variables.Single(v => v.Name == "unsupportedop").Location.Contains("99"));
            True(result.Variables.Single(v => v.Name == "bregx").Location.Contains("register 129"));
            True(result.Variables.Single(v => v.Name == "listed").Location.Contains(".debug_loc"));
        });
        Test("dwarf-cancellation-depth-and-result-caps", () => {
            using var cancellation = new CancellationTokenSource(); cancellation.Cancel(); Throws<OperationCanceledException>(() => PeDwarfReader.Read(StandardDwarf().Image(), cancellation.Token));
            var f = new DwarfFixture(); f.Abbrev(1, 0x11, true); f.Abbrev(2, 0x0b, true); f.Die(1, "cu");
            for (int i = 0; i < 65; i++) f.Die(2, "scope" + i);
            Equal(DebugSymbolStatus.Malformed, PeDwarfReader.Read(f.Image()).Status);
            f = new DwarfFixture(); f.Abbrev(1, 0x11, true); f.Abbrev(2, 0x34, false, (3, 8)); f.Die(1, "cu");
            for (int i = 0; i < 50001; i++) f.Die(2, "var" + i, "v");
            var r = PeDwarfReader.Read(f.Image()); Equal(DebugSymbolStatus.Partial, r.Status); Equal(50000, r.Variables.Count); True(r.Diagnostics.Any(d => d.Contains("50000")));
            f = new DwarfFixture(); f.Abbrev(1, 0x11, false); f.Die(1, "cu");
            var many = Enumerable.Range(0, 4097).SelectMany(_ => f.Info()).ToArray(); r = PeDwarfReader.Read(DwarfPe(false, (".debug_info", many), (".debug_abbrev", f.Abbreviations())));
            Equal(DebugSymbolStatus.Partial, r.Status); if (!r.Diagnostics.Any(d => d.Contains("4096"))) throw new Exception(string.Join("; ", r.Diagnostics));
        });
        Test("dwarf-mutation-loop-is-bounded-and-read-only", () => {
            var original = StandardDwarf(5, true, true).Image(); var random = new Random(744);
            for (int n = 0; n < 250; n++) {
                var b = (byte[])original.Clone(); for (int j = 0; j < 1 + n % 5; j++) b[random.Next(b.Length)] = (byte)random.Next(256);
                var before = (byte[])b.Clone(); try { var r = PeDwarfReader.Read(b); True(r.Variables.Count <= 50000); True(r.Diagnostics.Count <= 257); } catch (PeFormatException) { }
                True(before.SequenceEqual(b));
            }
        });
        Test("dwarf-pe-debug-padding-obeys-virtual-size", () => {
            var f = StandardDwarf(); var b = f.Image();
            int header = PeImage.Parse(b).Sections[0].HeaderOffset;
            W32(b, header + 16, (uint)((f.Info().Length + 511) & ~511));
            Equal(DebugSymbolStatus.Available, PeDwarfReader.Read(b).Status);
        });
        Test("dwarf-specification-scope-and-declaration-semantics", () => {
            var f = new DwarfFixture(); f.Abbrev(1, 0x11, true); f.Die(1, "cu");
            f.Abbrev(2, 0x24, false, (3, 8)); f.Die(2, "int", "int");
            f.Abbrev(3, 0x39, true, (3, 8)); f.Die(3, "namespace", "declared");
            f.Abbrev(4, 0x34, false, (3, 8), (0x49, 0x13), (0x3c, 0x19)); f.Die(4, "declaration", "counter", new DRef("int")); f.End();
            f.Abbrev(5, 0x34, false, (0x47, 0x13)); f.Die(5, "definition", new DRef("declaration"));
            var r = PeDwarfReader.Read(f.Image()); Equal(DebugSymbolStatus.Available, r.Status);
            Equal(2, r.Variables.Count); var definition = r.Variables.Last(); Equal("counter", definition.Name); Equal("declared", definition.Scope); Equal("int", definition.Type); True(!definition.IsDeclaration);
            True(r.Variables.First().IsDeclaration);
        });
        Test("dwarf-pointer-const-and-reference-depth", () => {
            var f = StandardDwarf(); f.Abbrev(11, 0x26, false, (0x49, 0x13)); f.Die(11, "constpointer", new DRef("pointer"));
            f.Die(5, "constvar", "constvar", new DRef("constpointer"), 2ul, 1ul, new byte[] { 0x50 });
            var r = PeDwarfReader.Read(f.Image()); Equal("const Count* const", r.Variables.Single(v => v.Name == "constvar").Type);
            f = StandardDwarf(); f.Abbrev(11, 0x0f, false, (0x49, 0x13));
            for (int i = 0; i < 70; i++) f.Die(11, "t" + i, new DRef(i == 69 ? "int" : "t" + (i + 1)));
            f.Die(5, "deep", "deep", new DRef("t0"), 2ul, 1ul, new byte[] { 0x50 });
            r = PeDwarfReader.Read(f.Image()); Equal(DebugSymbolStatus.Partial, r.Status); True(r.Variables.Single(v => v.Name == "deep").Type.Contains("depth limit"));
        });
        Test("dwarf-attribute-and-die-caps", () => {
            var f = new DwarfFixture(); f.Abbrev(1, 0x11, true); f.Abbrev(2, 0x24, false); f.Die(1, "cu"); f.Body.AddRange(Enumerable.Repeat((byte)2, 200001));
            var r = PeDwarfReader.Read(f.Image()); Equal(DebugSymbolStatus.Partial, r.Status); True(r.Diagnostics.Any(d => d.Contains("200000")));
            f = new DwarfFixture(); f.Abbrev(1, 0x11, false, Enumerable.Range(1, 257).Select(i => (i, 0x0b)).ToArray()); f.Body.Add(1);
            r = PeDwarfReader.Read(f.Image()); Equal(DebugSymbolStatus.Malformed, r.Status); True(r.Diagnostics.Any(d => d.Contains("256")));
        });
        Test("dwarf-string-sections-and-leb-overflow", () => {
            foreach (bool signed in new[] { false, true }) {
                var f = new DwarfFixture(); f.Abbrev(1, 0x11, true); f.Abbrev(2, 0x34, false, (3, 8), (0x1c, signed ? 0x0d : 0x0f)); f.Die(1, "cu");
                f.Die(2, "value", "value", signed ? (object)long.MinValue : ulong.MaxValue);
                var r = PeDwarfReader.Read(f.Image()); Equal(DebugSymbolStatus.Available, r.Status); True(r.Variables.Single().Location.Contains(signed ? long.MinValue.ToString() : ulong.MaxValue.ToString()));
                f.Body.RemoveAt(f.Body.Count - 1); f.Body.Add(0x7e);
                Equal(DebugSymbolStatus.Malformed, PeDwarfReader.Read(f.Image()).Status);
            }
            foreach (bool outside in new[] { false, true }) {
                var f = new DwarfFixture(); f.Abbrev(1, 0x11, false, (3, 0x0e)); f.Strings = Enumerable.Repeat((byte)65, 16385).ToArray(); f.Die(1, "cu", outside ? 16385ul : 0ul);
                Equal(DebugSymbolStatus.Malformed, PeDwarfReader.Read(f.Image()).Status);
            }
        });
        Test("dwarf-cross-unit-ref-addr-and-reference-cycle", () => {
            var first = new DwarfFixture(); first.Abbrev(1, 0x11, true); first.Abbrev(2, 0x24, false, (3, 8)); first.Abbrev(3, 0x34, false, (3, 8), (0x49, 0x10));
            first.Die(1, "cu"); first.Die(2, "type", "cross-unit");
            var second = new DwarfFixture(); second.Abbrev(1, 0x11, true); second.Abbrev(2, 0x24, false, (3, 8)); second.Abbrev(3, 0x34, false, (3, 8), (0x49, 0x10));
            second.Die(1, "cu"); second.Die(3, "variable", "other", (ulong)first.Offsets["type"]);
            var r = PeDwarfReader.Read(DwarfPe(false, (".debug_info", first.Info().Concat(second.Info()).ToArray()), (".debug_abbrev", first.Abbreviations())));
            Equal(DebugSymbolStatus.Available, r.Status); Equal("cross-unit", r.Variables.Single().Type);
            var f = new DwarfFixture(); f.Abbrev(1, 0x11, true); f.Abbrev(2, 0x34, false, (0x47, 0x13)); f.Die(1, "cu"); f.Die(2, "a", new DRef("b")); f.Die(2, "b", new DRef("a"));
            r = PeDwarfReader.Read(f.Image()); Equal(DebugSymbolStatus.Partial, r.Status); True(r.Diagnostics.Any(d => d.Contains("cycle")));
        });
        Test("dwarf-array-const-is-not-duplicated", () => {
            var f = StandardDwarf(); f.Abbrev(11, 0x01, false, (0x49, 0x13)); f.Die(11, "array", new DRef("const"));
            f.Die(4, "constarray", new DRef("array")); f.Die(5, "v", "qualified_array", new DRef("constarray"), 2ul, 1ul, new byte[] { 0x50 });
            Equal("const Count[]", PeDwarfReader.Read(f.Image()).Variables.Single(v => v.Name == "qualified_array").Type);
        });
        Test("dwarf-specification-graph-traversal-is-bounded", () => {
            var f = new DwarfFixture(); f.Abbrev(1, 0x11, true); f.Die(1, "cu");
            f.Abbrev(2, 0x2e, false, (0x31, 0x13), (0x47, 0x13)); f.Abbrev(3, 0x2e, false); f.Abbrev(4, 0x34, false, (0x31, 0x13));
            for (int i = 0; i < 511; i++) {
                if (i < 255) f.Die(2, "n" + i, new DRef("n" + (i * 2 + 1)), new DRef("n" + (i * 2 + 2)));
                else f.Die(3, "n" + i);
            }
            f.Die(4, "var", new DRef("n0")); var r = PeDwarfReader.Read(f.Image());
            Equal(DebugSymbolStatus.Partial, r.Status); True(r.Diagnostics.Any(d => d.Contains("traversal")));
        });
        Test("dwarf-real-gcc-fixtures", () => {
            var root = new DirectoryInfo(AppContext.BaseDirectory);
            while (root is not null && !File.Exists(Path.Combine(root.FullName, "Samples", "source", "debug_symbols.c"))) root = root.Parent;
            True(root is not null);
            var files = new[] { Path.Combine(root!.FullName, "Samples", "DebugSymbolsDemo.exe"), Path.Combine(root.FullName, "Samples", "build", "DebugSymbolsDwarf5.exe") };
            foreach (string file in files) {
                if (file.Contains("build") && !File.Exists(file)) continue;
                var b = File.ReadAllBytes(file); var result = PeDwarfReader.Read(b);
                if (result.Status != DebugSymbolStatus.Available) throw new Exception(file + ": " + result.Status + ": " + string.Join("; ", result.Diagnostics));
                foreach (var expected in new[] { ("global_counter", "volatile int", "Global", 4), ("seed", "int", "Parameter", 10), ("alias", "Counter", "Local", 11), ("local_total", "int", "Local", 12), ("scale", "double", "Local", 13), ("pair", "Pair", "Local", 14), ("values", "int[3]", "Local", 15), ("pointer", "int*", "Local", 16), ("local_mode", "Mode", "Local", 17), ("block_value", "int", "Local", 19), ("result", "int", "Local", 26) }) {
                    var v = result.Variables.Single(v => v.Name == expected.Item1); Equal(expected.Item2, v.Type); Equal(expected.Item3, v.Kind); Equal(expected.Item4, v.Line);
                    True(v.SourceFile.Replace('\\', '/').EndsWith("source/debug_symbols.c"));
                    if (v.Kind != "Global") True(v.Scope.Contains(v.Name == "result" ? "sample_main" : "compute_score"));
                    True(v.DebugOffset >= 0 && v.DebugLength > 0 && (long)v.DebugOffset + v.DebugLength <= b.Length);
                    True(v.Location.Contains(v.Kind == "Global" ? "declared address" : "frame base"));
                }
                True(result.Variables.Single(v => v.Name == "block_value").Scope.Contains("lexical"));
                Equal("const char[37]", result.Variables.Single(v => v.Name == "banner").Type);
            }
            string stripped = Path.Combine(root.FullName, "Samples", "build", "DebugSymbolsStripped.exe");
            if (File.Exists(stripped)) Equal(DebugSymbolStatus.NotFound, PeDwarfReader.Read(File.ReadAllBytes(stripped)).Status);
        });
    }

    private sealed record DRef(string Label);
    private sealed record DIndirect(int Form, object Value);
    private sealed class DwarfFixture(int version = 4, bool x64 = false, bool dwarf64 = false)
    {
        public readonly List<byte> Body = [];
        private readonly List<byte> abbreviation = [];
        private readonly Dictionary<int, (int Attr, int Form, long Implicit)[]> definitions = [];
        private readonly HashSet<int> childCodes = [];
        private bool rootChildren;
        private readonly List<(int At, string Label)> references = [];
        public readonly Dictionary<string, int> Offsets = [];
        public readonly Dictionary<string, int> Lengths = [];
        public byte[] Line = [], Strings = [], LineStrings = [];
        private int HeaderSize => (dwarf64 ? 12 : 4) + (version == 5 ? 4 : 3) + (dwarf64 ? 8 : 4);
        public void Abbrev(int code, int tag, bool children, params (int Attr, int Form, long Implicit)[] attrs) {
            definitions[code] = attrs; if (children) childCodes.Add(code); DUleb(abbreviation, (ulong)code); DUleb(abbreviation, (ulong)tag); abbreviation.Add(children ? (byte)1 : (byte)0);
            foreach (var a in attrs) { DUleb(abbreviation, (ulong)a.Attr); DUleb(abbreviation, (ulong)a.Form); if (a.Form == 0x21) DSleb(abbreviation, a.Implicit); }
            abbreviation.AddRange(new byte[] { 0, 0 });
        }
        public void Abbrev(int code, int tag, bool children, params (int Attr, int Form)[] attrs) => Abbrev(code, tag, children, attrs.Select(a => (a.Attr, a.Form, 0L)).ToArray());
        public void Abbrev(int code, int tag, bool children) => Abbrev(code, tag, children, Array.Empty<(int, int, long)>());
        public void Die(int code, string label, params object[] values) {
            int start = Body.Count; if (start == 0) rootChildren = childCodes.Contains(code); Offsets[label] = HeaderSize + start; DUleb(Body, (ulong)code); int i = 0;
            foreach (var a in definitions[code]) { if (a.Form is 0x19 or 0x21) continue; Value(a.Form, values[i++]); }
            Lengths[label] = Body.Count - start;
        }
        private void Value(int form, object value) {
            if (value is DRef reference) { references.Add((Body.Count, reference.Label)); DFixed(Body, 0, 4); return; }
            if (value is DIndirect indirect) { DUleb(Body, (ulong)indirect.Form); Value(indirect.Form, indirect.Value); return; }
            if (form == 8) { Body.AddRange(Encoding.UTF8.GetBytes((string)value)); Body.Add(0); return; }
            if (form is 0x09 or 0x18 or 0x0a) { var block = (byte[])value; if (form == 0x0a) Body.Add((byte)block.Length); else DUleb(Body, (ulong)block.Length); Body.AddRange(block); return; }
            if (form == 0x0d) { DSleb(Body, (long)value); return; }
            ulong v = Convert.ToUInt64(value);
            if (form is 0x0f or 0x1a) DUleb(Body, v);
            else DFixed(Body, v, form switch { 1 => x64 ? 8 : 4, 5 or 0x12 => 2, 7 or 0x14 => 8, 0x0b or 0x0c or 0x11 => 1, 0x0e or 0x17 or 0x1f => dwarf64 ? 8 : 4, _ => 4 });
        }
        public void End() => Body.Add(0);
        public byte[] Abbreviations() => abbreviation.Concat(new byte[] { 0 }).ToArray();
        public byte[] Info() {
            var body = Body.ToArray(); foreach (var r in references) W32(body, r.At, (uint)Offsets[r.Label]);
            var result = new List<byte>(); int terminator = rootChildren ? 1 : 0; if (dwarf64) { DFixed(result, uint.MaxValue, 4); DFixed(result, (ulong)(HeaderSize - 12 + body.Length + terminator), 8); } else DFixed(result, (ulong)(HeaderSize - 4 + body.Length + terminator), 4);
            DFixed(result, (ulong)version, 2); if (version == 5) { result.Add(1); result.Add(x64 ? (byte)8 : (byte)4); }
            DFixed(result, 0, dwarf64 ? 8 : 4); if (version != 5) result.Add(x64 ? (byte)8 : (byte)4);
            result.AddRange(body); if (rootChildren) result.Add(0); return result.ToArray();
        }
        public byte[] Image() => DwarfPe(x64, (".debug_info", Info()), (".debug_abbrev", Abbreviations()), (".debug_line", Line), (".debug_str", Strings), (".debug_line_str", LineStrings));
    }

    private static DwarfFixture StandardDwarf(int version = 4, bool x64 = false, bool dwarf64 = false) {
        var f = new DwarfFixture(version, x64, dwarf64) { Line = DwarfLine(version) };
        f.Abbrev(1, 0x11, true, (3, 8), (0x1b, 8), (0x10, version < 4 ? 0x06 : 0x17)); f.Die(1, "cu", "demo.cpp", "C:/src", 0ul);
        f.Abbrev(2, 0x24, false, (3, 8)); f.Die(2, "int", "int");
        f.Abbrev(3, 0x16, false, (3, 8), (0x49, 0x13)); f.Die(3, "alias", "Count", new DRef("int"));
        f.Abbrev(4, 0x26, false, (0x49, 0x13)); f.Die(4, "const", new DRef("alias"));
        f.Abbrev(10, 0x0f, false, (0x49, 0x13)); f.Die(10, "pointer", new DRef("const"));
        f.Abbrev(5, 0x34, false, (3, 8), (0x49, 0x13), (0x3a, 0x0f), (0x3b, 0x0f), (2, version < 4 ? 0x0a : 0x18));
        var address = new List<byte> { 3 }; DFixed(address, 0x401020, x64 ? 8 : 4);
        f.Die(5, "global", "global", new DRef("int"), version == 5 ? 1ul : 2ul, 130ul, address.ToArray());
        f.Abbrev(6, 0x39, true, (3, 8)); f.Die(6, "namespace", "sample");
        f.Abbrev(7, 0x2e, true, (3, 8)); f.Die(7, "function", "work");
        f.Abbrev(8, 0x05, false, (3, 8), (0x49, 0x13), (2, version < 4 ? 0x0a : 0x18)); f.Die(8, "parameter", "input", new DRef("int"), new byte[] { 0x90, 0x81, 1 });
        f.Die(5, "local", "local", new DRef("pointer"), version == 5 ? 1ul : 2ul, 7ul, new byte[] { 0x91, 0xff, 0x7e });
        f.Abbrev(9, 0x0b, true); f.Die(9, "lexical"); f.Die(5, "shadow", "local", new DRef("int"), version == 5 ? 1ul : 2ul, 8ul, new byte[] { 0x51 });
        f.End(); f.End(); f.End(); return f;
    }

    private static byte[] DwarfLine(int version) {
        var header = new List<byte> { 1 }; if (version >= 4) header.Add(1); header.AddRange(new byte[] { 1, 0xfb, 14, 13 }); header.AddRange(new byte[12]);
        if (version == 5) {
            header.Add(1); DUleb(header, 1); DUleb(header, 8); DUleb(header, 2); header.AddRange(Encoding.UTF8.GetBytes("C:/src\0inc\0"));
            header.Add(2); DUleb(header, 1); DUleb(header, 8); DUleb(header, 2); DUleb(header, 0x0f); DUleb(header, 2);
            header.AddRange(Encoding.UTF8.GetBytes("demo.cpp\0")); DUleb(header, 0); header.AddRange(Encoding.UTF8.GetBytes("other.h\0")); DUleb(header, 1);
        } else {
            header.AddRange(Encoding.UTF8.GetBytes("inc\0\0demo.cpp\0")); header.AddRange(new byte[] { 0, 0, 0 });
            header.AddRange(Encoding.UTF8.GetBytes("other.h\0")); header.AddRange(new byte[] { 1, 0, 0, 0 });
        }
        var result = new List<byte>(); DFixed(result, (ulong)(2 + (version == 5 ? 2 : 0) + 4 + header.Count), 4); DFixed(result, (ulong)version, 2);
        if (version == 5) result.AddRange(new byte[] { 8, 0 }); DFixed(result, (ulong)header.Count, 4); result.AddRange(header); return result.ToArray();
    }
    private static byte[] DwarfPe(bool x64, params (string Name, byte[] Bytes)[] data) {
        int sectionStart = 0x98 + (x64 ? 240 : 224), rawStart = (sectionStart + data.Length * 40 + 511) & ~511;
        int table = rawStart + data.Sum(s => (s.Bytes.Length + 511) & ~511); var names = new List<byte>(new byte[4]);
        var b = new byte[table + 4 + data.Sum(s => Encoding.UTF8.GetByteCount(s.Name) + 1)];
        var baseline = Fixture(x64); baseline.AsSpan(0, sectionStart).CopyTo(b); W16(b, 0x86, (ushort)data.Length); W32(b, 0x8c, (uint)table); W32(b, 0x90, 0);
        W32(b, 0x98 + (x64 ? 108 : 92), 0); W32(b, 0x98 + 60, (uint)rawStart); W32(b, 0x98 + 56, (uint)((data.Length + 1) * 4096));
        int raw = rawStart;
        for (int i = 0; i < data.Length; i++) {
            int section = sectionStart + i * 40; Text(b, section, "/" + names.Count); names.AddRange(Encoding.UTF8.GetBytes(data[i].Name)); names.Add(0);
            W32(b, section + 8, (uint)data[i].Bytes.Length); W32(b, section + 12, (uint)((i + 1) * 4096)); W32(b, section + 16, (uint)data[i].Bytes.Length); W32(b, section + 20, (uint)raw);
            data[i].Bytes.CopyTo(b, raw); raw += (data[i].Bytes.Length + 511) & ~511;
        }
        names.CopyTo(b, table); W32(b, table, (uint)names.Count); return b;
    }
    private static void DUleb(List<byte> target, ulong value) { do { byte b = (byte)(value & 127); value >>= 7; target.Add(value == 0 ? b : (byte)(b | 128)); } while (value != 0); }
    private static void DSleb(List<byte> target, long value) { bool more; do { byte b = (byte)(value & 127); value >>= 7; more = !((value == 0 && (b & 64) == 0) || (value == -1 && (b & 64) != 0)); target.Add(more ? (byte)(b | 128) : b); } while (more); }
    private static void DFixed(List<byte> target, ulong value, int width) { for (int i = 0; i < width; i++) target.Add((byte)(value >> (i * 8))); }
}
