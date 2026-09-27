using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PeWorkshop.Core;
public sealed record EditRecord(int Offset, byte[] Before, byte[] After, string Description) { public string OffsetHex => $"0x{Offset:X8}"; }
public sealed class PeDocument
{
    private byte[] bytes;
    private byte[] baseline;
    private readonly List<EditRecord> history = [];
    private int position;
    public PeDocument(byte[] bytes, string? sourcePath = null)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        Image = PeImage.Parse(bytes);
        this.bytes = (byte[])bytes.Clone(); baseline = (byte[])bytes.Clone();
        SourcePath = sourcePath is null ? null : Path.GetFullPath(sourcePath);
    }
    public static PeDocument Open(string path)
    {
        string fullPath = Path.GetFullPath(path);
        using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > PeImage.MaxFileSize) throw new PeFormatException("Files larger than 128 MiB are not supported.");
        var data = new byte[(int)stream.Length]; stream.ReadExactly(data); return new(data, fullPath);
    }
    public ReadOnlyMemory<byte> Data => bytes;
    public PeImage Image { get; private set; }
    public string? SourcePath { get; }
    public bool IsDirty => !bytes.AsSpan().SequenceEqual(baseline);
    public bool CanUndo => position > 0;
    public bool CanRedo => position < history.Count;
    // Return snapshots because EditRecord deliberately exposes byte arrays in its public contract.
    public IReadOnlyList<EditRecord> Changes => history.Take(position).Select(e => new EditRecord(e.Offset, (byte[])e.Before.Clone(), (byte[])e.After.Clone(), e.Description)).ToList().AsReadOnly();
    public bool IsByteChanged(int offset)
    {
        if ((uint)offset >= bytes.Length) throw new ArgumentOutOfRangeException(nameof(offset));
        return bytes[offset] != baseline[offset];
    }
    public void ApplyPatch(int offset, byte[] replacement, string description)
    {
        ArgumentNullException.ThrowIfNull(replacement);
        if (offset < 0 || offset > bytes.Length || replacement.Length > bytes.Length - offset) throw new ArgumentOutOfRangeException(nameof(offset), "Patch must stay within the file.");
        if (bytes.AsSpan(offset, replacement.Length).SequenceEqual(replacement)) return;
        var candidate = (byte[])bytes.Clone(); replacement.CopyTo(candidate, offset);
        PeImage image = PeImage.Parse(candidate);
        var edit = new EditRecord(offset, bytes.AsSpan(offset, replacement.Length).ToArray(), (byte[])replacement.Clone(), description);
        if (position < history.Count) history.RemoveRange(position, history.Count - position);
        history.Add(edit); position++; bytes = candidate; Image = image;
    }
    public void SetField(PeField field, string value)
    {
        ArgumentNullException.ThrowIfNull(field); ArgumentNullException.ThrowIfNull(value);
        if (!Image.Fields.Any(f => ReferenceEquals(f, field))) throw new ArgumentException("The selected field is stale. Select it again from the current image.", nameof(field));
        string text = value.Trim(); bool hex = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
        if (hex) text = text[2..];
        if (!ulong.TryParse(text, hex ? NumberStyles.AllowHexSpecifier : NumberStyles.None, CultureInfo.InvariantCulture, out ulong parsed) || (field.Size < 8 && parsed >= (1ul << (field.Size * 8)))) throw new ArgumentException($"Value must fit an unsigned {field.Size * 8}-bit field.", nameof(value));
        var replacement = new byte[field.Size];
        for (int i = 0; i < replacement.Length; i++) replacement[i] = (byte)(parsed >> (i * 8));
        ApplyPatch(field.Offset, replacement, $"Set {field.Name} to {value}");
    }
    public void RenameSection(PeSection section, string name)
    {
        ArgumentNullException.ThrowIfNull(section); ArgumentNullException.ThrowIfNull(name);
        if (!Image.Sections.Any(s => ReferenceEquals(s, section))) throw new ArgumentException("The selected section is stale. Select it again from the current image.", nameof(section));
        if (name.Length is < 1 or > 8 || name.Any(c => c < 32 || c > 126)) throw new ArgumentException("Section names must contain 1 to 8 printable ASCII characters.", nameof(name));
        var replacement = new byte[8]; Encoding.ASCII.GetBytes(name).CopyTo(replacement, 0);
        ApplyPatch(section.HeaderOffset, replacement, $"Rename section {section.Name} to {name}");
    }
    public void UpdateChecksum()
    {
        var replacement = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(replacement, PeChecksum.Calculate(bytes, Image.ChecksumOffset));
        ApplyPatch(Image.ChecksumOffset, replacement, "Update PE checksum");
    }
    private void Restore(EditRecord edit, bool forward)
    {
        var candidate = (byte[])bytes.Clone(); (forward ? edit.After : edit.Before).CopyTo(candidate, edit.Offset);
        PeImage image = PeImage.Parse(candidate); bytes = candidate; Image = image;
    }
    public void Undo() { if (!CanUndo) return; Restore(history[position - 1], false); position--; }
    public void Redo() { if (!CanRedo) return; Restore(history[position], true); position++; }
    public void SaveCopy(string destination)
    {
        string target = Path.GetFullPath(destination);
        if (SourcePath is not null && (string.Equals(target, SourcePath, StringComparison.OrdinalIgnoreCase) || IsSameWindowsFile(SourcePath, target))) throw new ArgumentException("Save Copy cannot overwrite the original source file, including through a link or path alias.", nameof(destination));
        string directory = Path.GetDirectoryName(target) ?? throw new ArgumentException("Destination has no directory.", nameof(destination));
        string temp = Path.Combine(directory, ".peworkshop-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough)) { file.Write(bytes); file.Flush(true); }
            if (File.Exists(target)) File.Replace(temp, target, null); else File.Move(temp, target);
            baseline = (byte[])bytes.Clone();
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    private static bool IsSameWindowsFile(string source, string destination)
    {
        if (!OperatingSystem.IsWindows() || !File.Exists(destination) || !File.Exists(source)) return false;
        // Opening normally follows junctions and symbolic links. File identity also
        // catches hard links and aliases such as short (8.3) names.
        using var sourceHandle = File.OpenHandle(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var destinationHandle = File.OpenHandle(destination, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (!GetFileInformationByHandle(sourceHandle, out var sourceInfo)) throw IdentityError();
        if (!GetFileInformationByHandle(destinationHandle, out var destinationInfo)) throw IdentityError();
        return sourceInfo.VolumeSerialNumber == destinationInfo.VolumeSerialNumber
            && sourceInfo.FileIndexHigh == destinationInfo.FileIndexHigh
            && sourceInfo.FileIndexLow == destinationInfo.FileIndexLow;
    }
    private static IOException IdentityError() => new("Could not verify that the destination is distinct from the original source file.", new Win32Exception(Marshal.GetLastWin32Error()));
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
}
public static class PeChecksum
{
    public static uint Calculate(ReadOnlySpan<byte> bytes, int checksumOffset)
    {
        if (checksumOffset < 0 || checksumOffset > bytes.Length - 4) throw new ArgumentOutOfRangeException(nameof(checksumOffset));
        ulong sum = 0;
        // ImageHlp sums whole WORDs on each side of CheckSum separately. Retaining
        // this behavior matters for deliberately unaligned PE headers.
        for (int i = 0; i + 1 < checksumOffset; i += 2)
        { sum += BinaryPrimitives.ReadUInt16LittleEndian(bytes[i..]); sum = (sum & 0xffff) + (sum >> 16); }
        for (int i = checksumOffset + 4; i + 1 < bytes.Length; i += 2)
        { sum += BinaryPrimitives.ReadUInt16LittleEndian(bytes[i..]); sum = (sum & 0xffff) + (sum >> 16); }
        if ((bytes.Length & 1) != 0) sum += bytes[^1];
        sum = (sum & 0xffff) + (sum >> 16);
        return (uint)sum + (uint)bytes.Length;
    }
}
