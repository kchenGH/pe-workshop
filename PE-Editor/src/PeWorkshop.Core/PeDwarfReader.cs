using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace PeWorkshop.Core;

public enum DebugSymbolStatus { Available, Partial, NotFound, Unsupported, Malformed }
public sealed record PeVariable(string Name, string Kind, string Type, string Scope,
    string SourceFile, int? Line, string Location, int DebugOffset, int DebugLength,
    bool IsDeclaration = false);
public sealed record PeDebugSymbols(DebugSymbolStatus Status, string Format,
    IReadOnlyList<PeVariable> Variables, IReadOnlyList<string> Diagnostics);
public static class PeDwarfReader
{
    public static PeDebugSymbols Read(byte[] imageBytes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(imageBytes);
        cancellationToken.ThrowIfCancellationRequested();
        // PeImage validates essential PE structure and the 128 MiB input limit.
        return new Reader(imageBytes, PeImage.Parse(imageBytes), cancellationToken).Read();
    }

    private const int MaxDies = 200000, MaxVariables = 50000, MaxUnits = 4096, MaxDepth = 64;
    private const int MaxAttributes = 1000000, MaxAbbreviations = 65536, MaxStringBytes = 16384;
    private const int MaxStringStorageBytes = 32 * 1024 * 1024, MaxRenderedCharacters = 4096;
    private sealed class DwarfException(string message, bool unsupported = false, bool limit = false) : Exception(message)
    {
        public bool Unsupported { get; } = unsupported;
        public bool Limit { get; } = limit;
    }
    private readonly record struct Section(int Start, int End);
    private readonly record struct Block(int Start, int Length);
    private sealed record Value(uint Form, ulong Number = 0, long Signed = 0, bool IsSigned = false,
        string? Text = null, Block? Bytes = null, bool IsReference = false);
    private sealed record Attribute(uint Name, uint Form, long Implicit);
    private sealed record Abbreviation(uint Tag, bool Children, Attribute[] Attributes);
    private sealed class Unit(int start, int end, int offsetSize)
    {
        public int Start { get; } = start;
        public int End { get; } = end;
        public int OffsetSize { get; } = offsetSize;
        public int Version, AddressSize;
        public Die? Root;
        public Dictionary<ulong, string>? Files;
    }
    private sealed class Die(int offset, int length, uint tag, Unit unit, Die? parent, Dictionary<uint, Value> attrs)
    {
        public int Offset { get; } = offset;
        public int Length { get; } = length;
        public uint Tag { get; } = tag;
        public Unit Unit { get; } = unit;
        public Die? Parent { get; } = parent;
        public Dictionary<uint, Value> Attributes { get; } = attrs;
        public List<Die>? Children;
    }

    // All cursors carry an explicit section/unit/header/expression bound. No read is allowed
    // to borrow bytes from an adjacent DWARF contribution or from PE padding.
    private sealed class Cursor(byte[] bytes, int start, int end)
    {
        public int Position = start;
        public int End { get; } = end;
        public void Require(int count)
        {
            if (count < 0 || Position < 0 || Position > End || count > End - Position)
                throw new DwarfException("Truncated DWARF data.");
        }
        public byte Byte() { Require(1); return bytes[Position++]; }
        public ulong Fixed(int count)
        {
            Require(count);
            ulong value = count switch {
                1 => bytes[Position], 2 => BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(Position)),
                4 => BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(Position)),
                8 => BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(Position)),
                _ => throw new DwarfException("Unsupported numeric width.", true)
            };
            Position += count; return value;
        }
        public ulong Uleb()
        {
            ulong value = 0;
            for (int shift = 0; shift <= 63; shift += 7) {
                byte b = Byte();
                if (shift == 63 && (b & 0x7e) != 0) throw new DwarfException("ULEB128 overflow.");
                value |= (ulong)(b & 127) << shift;
                if ((b & 128) == 0) return value;
            }
            throw new DwarfException("Unterminated or overflowing ULEB128.");
        }
        public long Sleb()
        {
            ulong value = 0;
            for (int shift = 0; shift <= 63; shift += 7) {
                byte b = Byte();
                if (shift == 63 && b is not 0 and not 0x7f) throw new DwarfException("SLEB128 overflow.");
                value |= (ulong)(b & 127) << shift;
                if ((b & 128) == 0) {
                    int bits = shift + 7;
                    if (bits < 64 && (b & 64) != 0) value |= ulong.MaxValue << bits;
                    return unchecked((long)value);
                }
            }
            throw new DwarfException("Unterminated or overflowing SLEB128.");
        }
        public Block Block(ulong length)
        {
            if (length > int.MaxValue) throw new DwarfException("DWARF block exceeds bounded input.");
            Require((int)length); var result = new Block(Position, (int)length); Position += (int)length; return result;
        }
    }

    private sealed class Reader(byte[] bytes, PeImage image, CancellationToken cancellation)
    {
        private readonly Dictionary<string, Section> sections = new(StringComparer.Ordinal);
        private readonly Dictionary<int, Die> dies = [];
        private readonly List<Die> variables = [];
        private readonly List<Unit> units = [];
        private readonly List<string> diagnostics = [];
        private readonly HashSet<string> diagnosticSet = new(StringComparer.Ordinal);
        private readonly Dictionary<int, string> strings = [];
        private readonly Dictionary<int, Dictionary<ulong, Abbreviation>> abbreviations = [];
        private int dieCount, attributeCount, abbreviationCount, stringStorageBytes;
        private bool malformed, unsupported, incomplete;

        private void Diagnostic(string message, bool isMalformed = false, bool isUnsupported = false)
        {
            malformed |= isMalformed; unsupported |= isUnsupported;
            if (diagnostics.Count < 256 && diagnosticSet.Add(message)) diagnostics.Add(message);
            else if (diagnostics.Count == 256) diagnostics.Add("Additional DWARF diagnostics were truncated.");
        }
        public PeDebugSymbols Read()
        {
            foreach (var section in image.Sections) {
                cancellation.ThrowIfCancellationRequested();
                if (section.Name.StartsWith(".zdebug", StringComparison.Ordinal))
                    Diagnostic("Compressed DWARF sections are unsupported; no decompression was attempted.", isUnsupported: true);
                if (section.Name.EndsWith(".dwo", StringComparison.Ordinal) || section.Name is ".gnu_debuglink" or ".gnu_debugaltlink" or ".debug_sup")
                    Diagnostic("Split or external DWARF is unsupported; referenced files are not opened.", isUnsupported: true);
                if (!section.Name.StartsWith(".debug", StringComparison.Ordinal)) continue;
                // PE SizeOfRawData includes file-alignment padding; VirtualSize describes
                // the actual debug payload. Both are bounded by PeImage before this point.
                uint payloadSize = section.VirtualSize == 0 ? section.RawSize : Math.Min(section.RawSize, section.VirtualSize);
                if (!sections.TryAdd(section.Name, new((int)section.RawOffset, (int)((long)section.RawOffset + payloadSize))))
                    Diagnostic($"Duplicate {section.Name} sections; only the first is decoded.", true);
            }
            bool pdb = HasCodeView();
            if (pdb) Diagnostic("PDB/CodeView symbols are unsupported; external PDB paths are not followed.", isUnsupported: true);
            foreach (var warning in image.Warnings.Where(w => w.StartsWith("Section name", StringComparison.Ordinal))) Diagnostic(warning, true);
            if (!sections.TryGetValue(".debug_info", out var info)) {
                if (sections.ContainsKey(".debug_abbrev")) Diagnostic(".debug_abbrev exists without .debug_info.", true);
                if (!malformed && !unsupported) Diagnostic("No embedded DWARF debug information was found.");
                return Result([], pdb ? "PDB/CodeView" : sections.Count != 0 || unsupported ? "DWARF" : "", false);
            }
            if (info.End - info.Start >= 4 && bytes.AsSpan(info.Start, 4).SequenceEqual("ZLIB"u8)) {
                Diagnostic("Compressed DWARF .debug_info is unsupported.", isUnsupported: true); return Result([], "DWARF", false);
            }
            if (!sections.ContainsKey(".debug_abbrev")) {
                Diagnostic("Embedded .debug_info is missing its .debug_abbrev section.", true); return Result([], "DWARF", false);
            }
            ReadUnits(info);
            var result = new List<PeVariable>(variables.Count);
            foreach (var variable in variables) {
                cancellation.ThrowIfCancellationRequested();
                try { result.Add(Variable(variable, info)); }
                catch (DwarfException e) {
                    incomplete = true; Diagnostic($"Variable output at DIE 0x{variable.Offset:X}: {e.Message}"); break;
                }
            }
            if (units.Count == 0 && !malformed && !unsupported) Diagnostic(".debug_info contains no compilation units.", true);
            return Result(result.AsReadOnly(), "DWARF", units.Count != 0);
        }
        private PeDebugSymbols Result(IReadOnlyList<PeVariable> result, string format, bool decoded)
        {
            DebugSymbolStatus status = incomplete || ((malformed || unsupported) && (decoded || result.Count != 0)) ? DebugSymbolStatus.Partial
                : malformed ? DebugSymbolStatus.Malformed : unsupported ? DebugSymbolStatus.Unsupported
                : decoded ? DebugSymbolStatus.Available : DebugSymbolStatus.NotFound;
            return new(status, format, result, diagnostics.AsReadOnly());
        }
        private bool HasCodeView()
        {
            var directory = image.Directories.FirstOrDefault(d => d.Index == 6);
            if (directory?.FileOffset is not int start || directory.Size < 28) return false;
            for (int i = 0; i < Math.Min(directory.Size / 28, 4096u); i++) {
                cancellation.ThrowIfCancellationRequested();
                int offset = start + i * 28;
                if ((long)offset + 28 > bytes.Length) break;
                if (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 12)) == 2) return true;
            }
            return false;
        }
        private static (int End, int OffsetSize) InitialLength(Cursor cursor)
        {
            ulong length = cursor.Fixed(4); int width = 4;
            if (length == uint.MaxValue) { length = cursor.Fixed(8); width = 8; }
            else if (length >= 0xfffffff0) throw new DwarfException("Reserved DWARF initial length.");
            if (length > (ulong)(cursor.End - cursor.Position)) throw new DwarfException("DWARF contribution length extends beyond its section.");
            return (cursor.Position + (int)length, width);
        }
        private void ReadUnits(Section info)
        {
            var cursor = new Cursor(bytes, info.Start, info.End); int count = 0;
            while (cursor.Position < cursor.End) {
                cancellation.ThrowIfCancellationRequested();
                if (++count > MaxUnits) { incomplete = true; Diagnostic("DWARF compilation units truncated at 4096 entries."); break; }
                int start = cursor.Position, end;
                Unit unit;
                try {
                    var length = InitialLength(cursor); end = length.End; unit = new(start - info.Start, end - info.Start, length.OffsetSize);
                } catch (DwarfException e) { Diagnostic($".debug_info at 0x{start - info.Start:X}: {e.Message}", true); break; }
                // The next unit offset is established before decoding the current unit.
                var body = new Cursor(bytes, cursor.Position, end); cursor.Position = end;
                var decoded = new List<Die>();
                try {
                    unit.Version = (int)body.Fixed(2);
                    if (unit.Version is < 2 or > 5) throw new DwarfException($"DWARF version {unit.Version} is unsupported.", true);
                    ulong abbreviationOffset;
                    if (unit.Version == 5) {
                        byte kind = body.Byte(); unit.AddressSize = body.Byte(); abbreviationOffset = body.Fixed(unit.OffsetSize);
                        if (kind != 1) throw new DwarfException($"DWARF5 unit kind 0x{kind:X2} is unsupported (only ordinary compilation units are decoded).", true);
                    } else { abbreviationOffset = body.Fixed(unit.OffsetSize); unit.AddressSize = body.Byte(); }
                    if (unit.AddressSize is not 4 and not 8) throw new DwarfException($"DWARF address size {unit.AddressSize} is unsupported.", true);
                    var abbrev = ReadAbbreviations(abbreviationOffset);
                    var parents = new Stack<Die>(); bool closedRoot = false;
                    while (body.Position < body.End) {
                        cancellation.ThrowIfCancellationRequested(); int recordStart = body.Position; ulong code = body.Uleb();
                        if (code == 0) {
                            if (parents.Count == 0) throw new DwarfException("Unexpected null DIE at the compilation unit root.");
                            parents.Pop(); if (parents.Count == 0) closedRoot = true;
                            continue;
                        }
                        if (closedRoot || (unit.Root is not null && parents.Count == 0)) throw new DwarfException("Multiple root DIEs in one compilation unit.");
                        if (!abbrev.TryGetValue(code, out var definition)) throw new DwarfException($"Unknown abbreviation code {code}.");
                        if (++dieCount > MaxDies) { incomplete = true; throw new DwarfException("Decoded DIEs truncated at 200000 entries."); }
                        var values = new Dictionary<uint, Value>();
                        foreach (var attribute in definition.Attributes) {
                            if (++attributeCount > MaxAttributes) { incomplete = true; throw new DwarfException("Decoded attributes truncated at 1000000 entries."); }
                            Value value = ReadValue(body, attribute.Form, attribute.Implicit, unit, 0);
                            if (!values.TryAdd(attribute.Name, value)) throw new DwarfException("Duplicate attribute in a DIE abbreviation.");
                        }
                        var die = new Die(recordStart - info.Start, body.Position - recordStart, definition.Tag, unit, parents.Count == 0 ? null : parents.Peek(), values);
                        if (unit.Root is null) {
                            if (die.Tag != 0x11) throw new DwarfException("Compilation unit root is not DW_TAG_compile_unit.");
                            unit.Root = die;
                            if (values.ContainsKey(0x76) || values.ContainsKey(0x2130) || values.ContainsKey(0x2131))
                                throw new DwarfException("Split/external DWARF compilation unit is unsupported; its DWO file is not opened.", true);
                        }
                        if (die.Parent is not null) (die.Parent.Children ??= []).Add(die);
                        decoded.Add(die); dies.Add(die.Offset, die);
                        if (die.Tag is 0x34 or 0x05) {
                            if (variables.Count >= MaxVariables) { incomplete = true; throw new DwarfException("Variables truncated at 50000 entries."); }
                            variables.Add(die);
                        }
                        if (definition.Children) {
                            if (parents.Count >= MaxDepth) throw new DwarfException("DWARF nesting depth exceeds 64.");
                            parents.Push(die);
                        }
                    }
                    if (unit.Root is null || parents.Count != 0) throw new DwarfException("Unterminated compilation unit DIE tree.");
                    units.Add(unit);
                } catch (DwarfException e) {
                    Diagnostic($"Compilation unit at 0x{unit.Start:X}: {e.Message}", !e.Unsupported && !e.Limit, e.Unsupported);
                    if (e.Unsupported) {
                        // Unsupported forms invalidate this unit. Do not expose a prefix as if the
                        // remaining attributes or references had been decoded successfully.
                        foreach (var die in decoded) dies.Remove(die.Offset);
                        variables.RemoveAll(d => ReferenceEquals(d.Unit, unit));
                    }
                    if (incomplete) break;
                }
            }
        }
        private Dictionary<ulong, Abbreviation> ReadAbbreviations(ulong offset)
        {
            Section section = sections[".debug_abbrev"];
            if (offset >= (ulong)(section.End - section.Start)) throw new DwarfException("Abbreviation offset is outside .debug_abbrev.");
            int start = section.Start + (int)offset;
            if (abbreviations.TryGetValue(start, out var cached)) return cached;
            var cursor = new Cursor(bytes, start, section.End); var result = new Dictionary<ulong, Abbreviation>();
            while (cursor.Position < cursor.End) {
                cancellation.ThrowIfCancellationRequested(); ulong code = cursor.Uleb();
                if (code == 0) { abbreviations.Add(start, result); return result; }
                if (++abbreviationCount > MaxAbbreviations) throw new DwarfException("Abbreviation definitions exceed 65536 entries.");
                ulong tag = cursor.Uleb(); if (tag > uint.MaxValue) throw new DwarfException("DWARF tag overflow.");
                byte children = cursor.Byte(); if (children > 1) throw new DwarfException("Invalid abbreviation children flag.");
                var attrs = new List<Attribute>();
                while (true) {
                    cancellation.ThrowIfCancellationRequested(); ulong name = cursor.Uleb(), form = cursor.Uleb();
                    if (name == 0 && form == 0) break;
                    if (name == 0 || form == 0 || name > uint.MaxValue || form > uint.MaxValue) throw new DwarfException("Invalid abbreviation attribute or form.");
                    if (attrs.Count >= 256) throw new DwarfException("Attributes per abbreviation exceed 256 entries.");
                    if (++attributeCount > MaxAttributes) throw new DwarfException("Abbreviation attributes exceed bounded budget.");
                    long implicitValue = form == 0x21 ? cursor.Sleb() : 0;
                    attrs.Add(new((uint)name, (uint)form, implicitValue));
                }
                if (!result.TryAdd(code, new((uint)tag, children == 1, attrs.ToArray()))) throw new DwarfException("Duplicate abbreviation code.");
            }
            throw new DwarfException("Abbreviation table is missing its terminator.");
        }
        private Value ReadValue(Cursor cursor, uint form, long implicitValue, Unit unit, int depth)
        {
            if (depth >= MaxDepth) throw new DwarfException("DW_FORM_indirect nesting exceeds 64.");
            switch (form) {
                case 0x01: return new(form, cursor.Fixed(unit.AddressSize));
                case 0x03: return new(form, Bytes: cursor.Block(cursor.Fixed(2)));
                case 0x04: return new(form, Bytes: cursor.Block(cursor.Fixed(4)));
                case 0x05: return new(form, cursor.Fixed(2));
                case 0x06: return new(form, cursor.Fixed(4));
                case 0x07: return new(form, cursor.Fixed(8));
                case 0x08: return new(form, Text: String(cursor));
                case 0x09: case 0x18: return new(form, Bytes: cursor.Block(cursor.Uleb()));
                case 0x0a: return new(form, Bytes: cursor.Block(cursor.Byte()));
                case 0x0b: case 0x0c: return new(form, cursor.Byte());
                case 0x0d: return new(form, Signed: cursor.Sleb(), IsSigned: true);
                case 0x0e: return new(form, Text: SectionString(".debug_str", cursor.Fixed(unit.OffsetSize)));
                case 0x0f: return new(form, cursor.Uleb());
                case 0x10: return new(form, cursor.Fixed(unit.Version == 2 ? unit.AddressSize : unit.OffsetSize), IsReference: true);
                case 0x11: return Reference(form, cursor.Byte(), unit);
                case 0x12: return Reference(form, cursor.Fixed(2), unit);
                case 0x13: return Reference(form, cursor.Fixed(4), unit);
                case 0x14: return Reference(form, cursor.Fixed(8), unit);
                case 0x15: return Reference(form, cursor.Uleb(), unit);
                case 0x16:
                    ulong indirectForm = cursor.Uleb();
                    if (indirectForm > uint.MaxValue || indirectForm == 0x21) throw new DwarfException("Invalid indirect DWARF form.");
                    return ReadValue(cursor, (uint)indirectForm, 0, unit, depth + 1);
                case 0x17: return new(form, cursor.Fixed(unit.OffsetSize));
                case 0x19: return new(form, 1);
                case 0x1e: return new(form, Bytes: cursor.Block(16));
                case 0x1f: return new(form, Text: SectionString(".debug_line_str", cursor.Fixed(unit.OffsetSize)));
                case 0x21: return new(form, Signed: implicitValue, IsSigned: true);
                case 0x1a: case 0x1b: case 0x22: case 0x23:
                case >= 0x25 and <= 0x2c:
                    throw new DwarfException($"Indexed DWARF form 0x{form:X} is unsupported; the compilation unit is skipped.", true);
                case 0x1c: case 0x1d: case 0x20: case 0x24:
                    throw new DwarfException($"Split, supplementary or signature reference form 0x{form:X} is unsupported.", true);
                default: throw new DwarfException($"DWARF form 0x{form:X} is unsupported; the compilation unit is skipped.", true);
            }
        }
        private static Value Reference(uint form, ulong offset, Unit unit)
        {
            // CU-relative references must stay in the same contribution. Global ref_addr
            // is resolved after every supported unit has been read.
            if (offset >= (ulong)(unit.End - unit.Start)) throw new DwarfException("CU-relative DIE reference extends beyond its compilation unit.");
            return new(form, (ulong)unit.Start + offset, IsReference: true);
        }
        private string String(Cursor cursor)
        {
            int start = cursor.Position, limit = Math.Min(cursor.End, start + MaxStringBytes + 1);
            while (cursor.Position < limit && bytes[cursor.Position] != 0) cursor.Position++;
            if (cursor.Position == limit) throw new DwarfException("DWARF string is unterminated or exceeds 16 KiB.");
            int length = cursor.Position - start; cursor.Position++;
            if (strings.TryGetValue(start, out var cached)) return cached;
            try {
                var encoding = new UTF8Encoding(false, true);
                ChargeString(encoding.GetCharCount(bytes, start, length));
                string value = encoding.GetString(bytes, start, length); strings[start] = value; return value;
            }
            catch (DecoderFallbackException) { throw new DwarfException("DWARF string contains invalid UTF-8."); }
        }
        // Count UTF-16 payload for every decoded/generated string allocation, including
        // temporary type joins and repeated line tables in separate compilation units.
        // The separately capped diagnostic pool remains usable after this budget runs out.
        private void ChargeString(int characters)
        {
            cancellation.ThrowIfCancellationRequested();
            if (characters > (MaxStringStorageBytes - stringStorageBytes) / sizeof(char)) {
                incomplete = true;
                throw new DwarfException("Decoded and derived DWARF string storage exceeds the 32 MiB UTF-16 budget; output was truncated.", limit: true);
            }
            stringStorageBytes += characters * sizeof(char);
        }
        private string Text(string? kind, params string[] parts) => JoinText(kind, parts, "");
        private string JoinText(string? kind, IReadOnlyList<string> parts, string separator)
        {
            long length = (long)Math.Max(0, parts.Count - 1) * separator.Length;
            foreach (string part in parts) length += part.Length;
            bool truncated = kind is not null && length > MaxRenderedCharacters;
            if (truncated) Diagnostic($"Rendered DWARF {kind} was truncated at 4096 characters.", true);
            if (!truncated && parts.Count == 1) return parts[0];
            int contentLength = (int)(truncated ? MaxRenderedCharacters : length), outputLength = contentLength + (truncated ? 1 : 0);
            if (outputLength == 0) return "";
            ChargeString(outputLength);
            return string.Create(outputLength, (parts, separator, contentLength, truncated), static (output, state) => {
                int at = 0;
                for (int i = 0; i < state.parts.Count && at < state.contentLength; i++) {
                    if (i != 0) {
                        int count = Math.Min(state.separator.Length, state.contentLength - at);
                        state.separator.AsSpan(0, count).CopyTo(output[at..]); at += count;
                    }
                    int take = Math.Min(state.parts[i].Length, state.contentLength - at);
                    state.parts[i].AsSpan(0, take).CopyTo(output[at..]); at += take;
                }
                if (state.truncated) output[^1] = '…';
            });
        }
        private string Number(ulong value, string? format = null)
        {
            ChargeString(20); return value.ToString(format, CultureInfo.InvariantCulture);
        }
        private string Number(long value)
        {
            ChargeString(20); return value.ToString(CultureInfo.InvariantCulture);
        }
        private string SectionString(string name, ulong offset)
        {
            if (!sections.TryGetValue(name, out var section) || offset >= (ulong)(section.End - section.Start)) throw new DwarfException($"String offset is outside {name}.");
            return String(new Cursor(bytes, section.Start + (int)offset, section.End));
        }
        private (Value Value, Die Owner)? AttributeOf(Die die, uint name)
            => FindAttribute(die, name, [], [], 0);
        private (Value Value, Die Owner)? FindAttribute(Die die, uint name, HashSet<int> path, HashSet<int> visited, int depth)
        {
            cancellation.ThrowIfCancellationRequested();
            if (depth >= MaxDepth || path.Contains(die.Offset)) {
                Diagnostic($"Specification/abstract origin cycle or depth limit at DIE 0x{die.Offset:X}.", true); return null;
            }
            if (visited.Contains(die.Offset)) return null;
            if (visited.Count >= 256) {
                incomplete = true; Diagnostic("Specification/abstract origin traversal exceeds 256 DIEs; unresolved attributes remain explicit."); return null;
            }
            visited.Add(die.Offset); path.Add(die.Offset);
            if (die.Attributes.TryGetValue(name, out var value) && value.Text != "") { path.Remove(die.Offset); return (value, die); }
            foreach (uint attribute in new uint[] { 0x31, 0x47 }) {
                if (!die.Attributes.TryGetValue(attribute, out var reference)) continue;
                Die? target = Referenced(reference, die.Offset);
                if (target is not null) {
                    var result = FindAttribute(target, name, path, visited, depth + 1);
                    if (result is not null) { path.Remove(die.Offset); return result; }
                }
            }
            path.Remove(die.Offset); return null;
        }
        private Die? Referenced(Value reference, int ownerOffset)
        {
            if (!reference.IsReference || reference.Number > int.MaxValue || !dies.TryGetValue((int)reference.Number, out var target)) {
                Diagnostic($"Missing or invalid DIE reference 0x{reference.Number:X} from DIE 0x{ownerOffset:X}.", true); return null;
            }
            return target;
        }
        private string Name(Die die) => AttributeOf(die, 3)?.Value.Text ?? "";
        private static bool Numeric(Value value, out ulong number)
        {
            number = value.Number;
            if (value.IsSigned) { if (value.Signed < 0) return false; number = (ulong)value.Signed; }
            return value.Text is null && value.Bytes is null && !value.IsReference;
        }
        private string VariableType(Die die)
        {
            var value = AttributeOf(die, 0x49);
            if (value is null) return "<unresolved type>";
            Die? type = Referenced(value.Value.Value, die.Offset);
            return type is null ? "<unresolved type reference>" : Type(type, [], 0);
        }
        private static string Qualifiers(int value) => value switch {
            0 => "", 1 => "const", 2 => "volatile", 3 => "const volatile",
            4 => "restrict", 5 => "const restrict", 6 => "volatile restrict", 7 => "const volatile restrict",
            8 => "atomic", 9 => "const atomic", 10 => "volatile atomic", 11 => "const volatile atomic",
            12 => "restrict atomic", 13 => "const restrict atomic", 14 => "volatile restrict atomic", _ => "const volatile restrict atomic"
        };
        private string Type(Die die, HashSet<int> seen, int depth, int qualifiers = 0)
        {
            cancellation.ThrowIfCancellationRequested();
            if (depth >= MaxDepth || !seen.Add(die.Offset)) {
                Diagnostic($"Type cycle or reference depth limit at DIE 0x{die.Offset:X}.", true); return "<type cycle/depth limit>";
            }
            string name = Name(die), type;
            string Qualified(string value) => qualifiers == 0 ? Text("type", value) : Text("type", Qualifiers(qualifiers), " ", value);
            string Underlying(bool voidAllowed = false, int inheritedQualifiers = 0) {
                var attr = AttributeOf(die, 0x49);
                if (attr is null) return voidAllowed ? "void" : "<unresolved type>";
                Die? target = Referenced(attr.Value.Value, die.Offset);
                return target is null ? "<unresolved type reference>" : Type(target, seen, depth + 1, inheritedQualifiers);
            }
            switch (die.Tag) {
                case 0x24: type = Qualified(name.Length != 0 ? name : "<unnamed base type>"); break;
                case 0x16: type = name.Length != 0 ? Qualified(name) : Underlying(inheritedQualifiers: qualifiers); break;
                case 0x02: case 0x04: case 0x13: case 0x17:
                    type = Qualified(name.Length != 0 ? name : die.Tag switch { 0x02 => "<anonymous class>", 0x04 => "<anonymous enum>", 0x13 => "<anonymous struct>", _ => "<anonymous union>" }); break;
                case 0x0f: type = Text("type", Underlying(true), "*", qualifiers == 0 ? "" : " ", Qualifiers(qualifiers)); break;
                case 0x10: type = Text("type", Underlying(inheritedQualifiers: qualifiers), "&"); break;
                case 0x42: type = Text("type", Underlying(inheritedQualifiers: qualifiers), "&&"); break;
                // Qualifiers follow the recorded type level. Arrays pass them to their
                // elements; pointers consume them after '*', leaving pointees separate.
                case 0x26: type = Underlying(inheritedQualifiers: qualifiers | 1); break;
                case 0x35: type = Underlying(inheritedQualifiers: qualifiers | 2); break;
                case 0x37: type = Underlying(inheritedQualifiers: qualifiers | 4); break;
                case 0x47: type = Underlying(inheritedQualifiers: qualifiers | 8); break;
                case 0x01:
                    type = Underlying(inheritedQualifiers: qualifiers);
                    var dimensions = die.Children?.Where(c => c.Tag == 0x21).Take(65).ToArray() ?? [];
                    if (dimensions.Length == 0) type = Text("type", type, "[]");
                    foreach (var range in dimensions.Take(64)) type = Text("type", type, "[", ArrayCount(range), "]");
                    if (dimensions.Length > 64) {
                        incomplete = true; Diagnostic("DWARF array dimensions were truncated at 64 entries.");
                        type = Text("type", type, "[<dimensions truncated>]");
                    }
                    break;
                case 0x15: type = Qualified(Text("type", Underlying(true), " (function)")); break;
                case 0x3b: type = Qualified(name.Length == 0 ? "<unspecified type>" : name); break;
                default: type = Qualified(name.Length == 0 ? Text("type", "<unsupported type tag 0x", Number(die.Tag, "X"), ">") : name); break;
            }
            seen.Remove(die.Offset);
            return type;
        }
        private string ArrayCount(Die range)
        {
            var count = AttributeOf(range, 0x37);
            if (count is not null && Numeric(count.Value.Value, out ulong size)) return Number(size);
            var upper = AttributeOf(range, 0x2f); if (upper is null) return "";
            var lower = AttributeOf(range, 0x22);
            if (Numeric(upper.Value.Value, out ulong hi)) {
                ulong lo = 0;
                if (lower is not null && !Numeric(lower.Value.Value, out lo)) return "?";
                return hi >= lo && hi - lo != ulong.MaxValue ? Number(hi - lo + 1) : "?";
            }
            return "?";
        }
        private PeVariable Variable(Die die, Section info)
        {
            string name = Name(die); if (name.Length == 0) name = "<unnamed>";
            string scope = Scope(die), kind = die.Tag == 0x05 ? "Parameter" : InFunction(die) ? "Local" : "Global";
            int? line = null;
            var recordedLine = AttributeOf(die, 0x3b);
            if (recordedLine is not null) {
                if (Numeric(recordedLine.Value.Value, out ulong n) && n <= int.MaxValue) line = (int)n;
                else Diagnostic($"Invalid declaration line at DIE 0x{die.Offset:X}.", true);
            }
            // DW_AT_specification commonly points from a definition to a declaration;
            // that declaration's flag must not turn the defining DIE into a declaration.
            bool declaration = die.Attributes.TryGetValue(0x3c, out var decl) && Numeric(decl, out ulong flag) && flag != 0;
            return new(name, kind, VariableType(die), scope, SourceFile(die), line, Location(die), info.Start + die.Offset, die.Length, declaration);
        }
        private bool InFunction(Die die)
        {
            die = ScopeContext(die);
            for (Die? p = die.Parent; p is not null; p = p.Parent) if (p.Tag is 0x2e or 0x1d) return true;
            return false;
        }
        private Die ScopeContext(Die die)
        {
            Die original = die; var seen = new HashSet<int>();
            // Out-of-line definitions can be direct CU children while their declaration
            // carries the namespace/class/function context in a specification DIE.
            for (int depth = 0; depth < MaxDepth && seen.Add(die.Offset); depth++) {
                if (die.Parent is not null && die.Parent.Tag != 0x11) return die;
                Value? reference = die.Attributes.GetValueOrDefault(0x47u) ?? die.Attributes.GetValueOrDefault(0x31u);
                if (reference is null) break;
                Die? target = Referenced(reference, die.Offset); if (target is null) break;
                die = target;
            }
            return original;
        }
        private string Scope(Die die)
        {
            die = ScopeContext(die);
            var parts = new List<string>();
            for (Die? p = die.Parent; p is not null; p = p.Parent) {
                if (p.Tag is 0x39 or 0x2e or 0x1d or 0x02 or 0x13 or 0x17) {
                    string name = Name(p); parts.Add(name.Length == 0 ? Text(null, "<scope at 0x", Number((ulong)p.Offset, "X"), ">") : name);
                } else if (p.Tag == 0x0b) parts.Add(Text(null, "<lexical at 0x", Number((ulong)p.Offset, "X"), ">"));
            }
            parts.Reverse(); string value = JoinText("scope", parts, "::");
            return value.Length == 0 ? "Compilation unit" : value;
        }
        private string SourceFile(Die die)
        {
            var attribute = AttributeOf(die, 0x3a);
            if (attribute is null) return "";
            if (!Numeric(attribute.Value.Value, out ulong index)) { Diagnostic($"Invalid declaration file index at DIE 0x{die.Offset:X}.", true); return ""; }
            Unit unit = attribute.Value.Owner.Unit;
            if (unit.Files is null) unit.Files = ReadFiles(unit);
            if (unit.Files.TryGetValue(index, out var path)) return path;
            Diagnostic($"Declaration file index {index} could not be resolved for compilation unit 0x{unit.Start:X}.", true); return "";
        }
        private Dictionary<ulong, string> ReadFiles(Unit unit)
        {
            var result = new Dictionary<ulong, string>();
            if (unit.Root is null || !unit.Root.Attributes.TryGetValue(0x10, out var statement)) return result;
            try {
                if (!Numeric(statement, out ulong offset) || !sections.TryGetValue(".debug_line", out var section) || offset >= (ulong)(section.End - section.Start)) throw new DwarfException("Line table offset is outside .debug_line.");
                var cursor = new Cursor(bytes, section.Start + (int)offset, section.End); var length = InitialLength(cursor);
                cursor = new Cursor(bytes, cursor.Position, length.End); int version = (int)cursor.Fixed(2);
                if (version is < 2 or > 5) throw new DwarfException($"DWARF line table version {version} is unsupported.", true);
                if (version == 5) {
                    int addressSize = cursor.Byte(), segmentSize = cursor.Byte();
                    if (addressSize is not 4 and not 8 || segmentSize != 0) throw new DwarfException("Segmented or unusual-address line tables are unsupported.", true);
                }
                ulong headerLength = cursor.Fixed(length.OffsetSize);
                if (headerLength > (ulong)(cursor.End - cursor.Position)) throw new DwarfException("Line header length exceeds its contribution.");
                cursor = new Cursor(bytes, cursor.Position, cursor.Position + (int)headerLength);
                cursor.Byte(); if (version >= 4) cursor.Byte(); cursor.Byte(); cursor.Byte(); cursor.Byte();
                int opcodeBase = cursor.Byte(); if (opcodeBase == 0) throw new DwarfException("Line table opcode base is zero.");
                cursor.Block((ulong)opcodeBase - 1);
                string compDir = unit.Root.Attributes.GetValueOrDefault(0x1bu)?.Text ?? "";
                var dirs = new Dictionary<ulong, string>();
                if (version < 5) {
                    dirs[0] = compDir;
                    for (ulong i = 1; ; i++) {
                        cancellation.ThrowIfCancellationRequested(); string directory = String(cursor); if (directory.Length == 0) break;
                        if (i > 65536) throw new DwarfException("Line table directories exceed 65536 entries."); dirs[i] = JoinPath(compDir, directory);
                    }
                    for (ulong i = 1; ; i++) {
                        cancellation.ThrowIfCancellationRequested(); string file = String(cursor); if (file.Length == 0) break;
                        if (i > 65536) throw new DwarfException("Line table files exceed 65536 entries.");
                        ulong directory = cursor.Uleb(); cursor.Uleb(); cursor.Uleb();
                        if (IsAbsolute(file)) result[i] = Normalize(file);
                        else if (dirs.TryGetValue(directory, out string? parent)) result[i] = JoinPath(parent, file);
                        else Diagnostic($"Unknown line table directory index {directory}.", true);
                    }
                } else {
                    var lineUnit = new Unit(0, length.End - section.Start, length.OffsetSize) { Version = 5, AddressSize = unit.AddressSize };
                    var directoryFormats = LineFormats(cursor); ulong directoryCount = cursor.Uleb();
                    if (directoryCount > 65536) throw new DwarfException("Line table directories exceed 65536 entries.");
                    for (ulong i = 0; i < directoryCount; i++) {
                        cancellation.ThrowIfCancellationRequested(); var entry = LineEntry(cursor, directoryFormats, lineUnit);
                        if (entry.TryGetValue(1, out var path) && path.Text is not null) dirs[i] = JoinPath(compDir, path.Text);
                        else throw new DwarfException("Line directory path is missing or has an unsupported form.", true);
                    }
                    var fileFormats = LineFormats(cursor); ulong fileCount = cursor.Uleb();
                    if (fileCount > 65536) throw new DwarfException("Line table files exceed 65536 entries.");
                    for (ulong i = 0; i < fileCount; i++) {
                        cancellation.ThrowIfCancellationRequested(); var entry = LineEntry(cursor, fileFormats, lineUnit);
                        if (!entry.TryGetValue(1, out var path) || path.Text is null) throw new DwarfException("Line file path is missing or has an unsupported form.", true);
                        ulong directory = 0;
                        if (entry.TryGetValue(2, out var dir) && !Numeric(dir, out directory)) throw new DwarfException("Invalid line directory index.");
                        if (IsAbsolute(path.Text)) result[i] = Normalize(path.Text);
                        else if (dirs.TryGetValue(directory, out string? parent)) result[i] = JoinPath(parent, path.Text);
                        else if (!entry.ContainsKey(2)) result[i] = JoinPath(compDir, path.Text);
                        else Diagnostic($"Unknown line table directory index {directory}.", true);
                    }
                }
            } catch (DwarfException e) { Diagnostic($"Line table for compilation unit 0x{unit.Start:X}: {e.Message}", !e.Unsupported && !e.Limit, e.Unsupported); }
            return result;
        }
        private static (ulong Content, uint Form)[] LineFormats(Cursor cursor)
        {
            int count = cursor.Byte(); if (count > 64) throw new DwarfException("Line table format columns exceed 64 entries.");
            var result = new (ulong, uint)[count];
            for (int i = 0; i < count; i++) {
                ulong content = cursor.Uleb(), form = cursor.Uleb();
                if (form > uint.MaxValue) throw new DwarfException("Line table form overflow.");
                result[i] = (content, (uint)form);
            }
            return result;
        }
        private Dictionary<ulong, Value> LineEntry(Cursor cursor, (ulong Content, uint Form)[] formats, Unit unit)
        {
            var result = new Dictionary<ulong, Value>();
            foreach (var format in formats) {
                if (++attributeCount > MaxAttributes) throw new DwarfException("Line table attributes exceed bounded budget.");
                if (!result.TryAdd(format.Content, ReadValue(cursor, format.Form, 0, unit, 0))) throw new DwarfException("Duplicate line table content column.");
            }
            return result;
        }
        // Paths are textual metadata. They are never opened or resolved against the host's
        // filesystem, and Windows drive paths also work when decoding on another OS.
        private string Normalize(string value)
        {
            if (!value.Contains('\\')) return value;
            ChargeString(value.Length); return value.Replace('\\', '/');
        }
        private static bool IsAbsolute(string value) => value.StartsWith('/') || value.StartsWith('\\') || value.Length >= 3 && char.IsAsciiLetter(value[0]) && value[1] == ':' && value[2] is '/' or '\\';
        private string JoinPath(string directory, string file)
        {
            if (IsAbsolute(file) || directory.Length == 0 || directory == ".") return Normalize(file);
            int directoryLength = directory.Length;
            while (directoryLength > 0 && directory[directoryLength - 1] is '/' or '\\') directoryLength--;
            int length = directoryLength + 1 + file.Length;
            ChargeString(length);
            return string.Create(length, (directory, file, directoryLength), static (output, state) => {
                for (int i = 0; i < state.directoryLength; i++) output[i] = state.directory[i] == '\\' ? '/' : state.directory[i];
                output[state.directoryLength] = '/';
                for (int i = 0; i < state.file.Length; i++) output[state.directoryLength + 1 + i] = state.file[i] == '\\' ? '/' : state.file[i];
            });
        }
        private string Location(Die die)
        {
            var constant = AttributeOf(die, 0x1c);
            if (constant is not null) {
                Value value = constant.Value.Value;
                if (value.Text is not null) return Text(null, "Recorded compile-time constant \"", value.Text, "\"");
                if (value.Bytes is { } block) return Text(null, "Recorded compile-time constant bytes ", Preview(block));
                return Text(null, "Recorded compile-time constant ", value.IsSigned ? Number(value.Signed) : Number(value.Number));
            }
            var attribute = AttributeOf(die, 2);
            if (attribute is null) return "Location unavailable (no recorded location)";
            Value location = attribute.Value.Value;
            if (location.Bytes is { } expression) return Expression(expression, die.Unit.AddressSize, die.Offset);
            if (location.Form is 0x17 or 0x06 or 0x07) return Text(null, "Location list ", die.Unit.Version >= 5 ? ".debug_loclists" : ".debug_loc", " + 0x", Number(location.Number, "X"), " (not evaluated)");
            Diagnostic($"Unsupported location attribute form 0x{location.Form:X} at DIE 0x{die.Offset:X}.", isUnsupported: true);
            return Text(null, "Location unavailable (unsupported form 0x", Number(location.Form, "X"), ")");
        }
        private string Expression(Block block, int addressSize, int dieOffset)
        {
            if (block.Length == 0) return "Location unavailable (empty expression)";
            var cursor = new Cursor(bytes, block.Start, block.Start + block.Length);
            try {
                byte opcode = cursor.Byte(); string? value = opcode switch {
                    0x03 => Text(null, "Recorded declared address 0x", Number(cursor.Fixed(addressSize), "X"), " (DW_OP_addr)"),
                    >= 0x50 and <= 0x6f => Text(null, "DWARF register ", Number((ulong)(opcode - 0x50))),
                    >= 0x70 and <= 0x8f => Text(null, "DWARF register ", Number((ulong)(opcode - 0x70)), " base offset ", Number(cursor.Sleb())),
                    0x90 => Text(null, "DWARF register ", Number(cursor.Uleb())),
                    0x91 => Text(null, "Recorded frame base offset ", Number(cursor.Sleb()), " (DW_OP_fbreg)"),
                    0x92 => Text(null, "DWARF register ", Number(cursor.Uleb()), " base offset ", Number(cursor.Sleb())),
                    _ => null
                };
                if (value is not null && cursor.Position == cursor.End) return value;
                Diagnostic($"Unsupported location expression at DIE 0x{dieOffset:X}; bounded bytes are displayed.", isUnsupported: true);
                return Text(null, "Unsupported location expression bytes ", Preview(block));
            } catch (DwarfException e) {
                if (e.Limit) throw;
                Diagnostic($"Malformed location expression at DIE 0x{dieOffset:X}: {e.Message}", true);
                return Text(null, "Location unavailable (malformed expression bytes ", Preview(block), ")");
            }
        }
        private string Preview(Block block)
        {
            int length = Math.Min(block.Length, 64); ChargeString(length * 2);
            string hex = Convert.ToHexString(bytes.AsSpan(block.Start, length));
            return block.Length > 64 ? Text(null, hex, "… (", Number((ulong)block.Length), " bytes)") : hex;
        }
    }
}
