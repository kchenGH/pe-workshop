using System.Globalization;

namespace PeWorkshop.App;

internal static class UiInput
{
    public static ulong Number(string text)
    {
        text = text.Trim().Replace("_", "", StringComparison.Ordinal);
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return ulong.Parse(text.AsSpan(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
        return ulong.Parse(text, NumberStyles.None, CultureInfo.InvariantCulture);
    }

    public static byte[] HexBytes(string text)
    {
        var compact = string.Concat(text.Where(c => !char.IsWhiteSpace(c)));
        if (compact.Length == 0 || compact.Length % 2 != 0)
            throw new FormatException("Enter complete byte pairs, for example: 4D 5A 90 00.");
        if (compact.Length > 131072)
            throw new FormatException("A single patch or search can contain at most 65,536 bytes.");
        return Convert.FromHexString(compact);
    }

    public static string Bytes(long count) => count >= 1024 * 1024
        ? $"{count / (1024d * 1024):0.##} MiB"
        : count >= 1024 ? $"{count / 1024d:0.##} KiB" : $"{count:N0} bytes";
}
