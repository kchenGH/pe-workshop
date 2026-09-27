using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace PeWorkshop.App;

public partial class MainWindow
{
    private UIElement BuildHexWorkspace()
    {
        var document = Document!;
        // Snapshot every old control before assigning any of the rebuilt controls.
        var jumpText = _jumpInput?.Text ?? "0x00000000";
        var jumpType = _jumpType?.SelectedIndex ?? 0;
        var findText = _findInput?.Text ?? "";
        var findTypeIndex = _findType?.SelectedIndex ?? 0;
        var patchText = _patchInput?.Text ?? "";
        var root = new Grid();
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition());
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var jumpBar = new WrapPanel { Margin = new Thickness(0, 0, 0, 10) };
        jumpBar.Children.Add(HelpUi.Label("Go to", "GoTo"));
        var addressType = _jumpType = new ComboBox { ItemsSource = new[] { "File offset", "RVA" }, SelectedIndex = jumpType, Width = 108, Margin = new Thickness(0, 0, 8, 0) };
        _jumpInput = InputBox(jumpText, 160, "Decimal or 0x-prefixed hexadecimal address");
        var go = new Button { Content = "Go", Margin = new Thickness(8, 0, 0, 0) };
        void Jump()
        {
            try
            {
                var value = UiInput.Number(_jumpInput.Text);
                int offset;
                if (addressType.SelectedIndex == 1)
                {
                    if (value > uint.MaxValue) throw new FormatException("An RVA must fit in 32 bits.");
                    offset = document.Image.RvaToOffset((uint)value) ?? throw new FormatException("This RVA has no bytes in the file (it may be zero-filled memory).");
                }
                else offset = value < (ulong)document.Data.Length ? (int)value : throw new FormatException("Offset is beyond the end of the file.");
                _hex?.GoTo(offset); _hex?.Focus();
            }
            catch (Exception ex) when (IsExpected(ex)) { SetStatus(ex.Message); }
        }
        go.Click += (_, _) => Jump();
        _jumpInput.KeyDown += (_, e) => { if (e.Key == Key.Enter) { Jump(); e.Handled = true; } };
        var addressHelp = new HelpBadge(addressType.SelectedIndex == 1 ? "RVA" : "Offset");
        addressType.SelectionChanged += (_, _) => addressHelp.TopicKey = addressType.SelectedIndex == 1 ? "RVA" : "Offset";
        jumpBar.Children.Add(addressType); jumpBar.Children.Add(addressHelp);
        jumpBar.Children.Add(HelpUi.Beside(_jumpInput, "NumericInput")); jumpBar.Children.Add(HelpUi.Beside(go, "Go"));
        jumpBar.Children.Add(new TextBlock { Text = "  Ctrl+G", FontSize = 11, Foreground = Brush("#6F8AAC"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) });
        root.Children.Add(jumpBar);

        var findBar = new WrapPanel { Margin = new Thickness(0, 0, 0, 14) };
        findBar.Children.Add(HelpUi.Label("Find", "Search"));
        var findType = _findType = new ComboBox { ItemsSource = new[] { "Hex bytes", "ASCII text" }, SelectedIndex = findTypeIndex, Width = 108, Margin = new Thickness(0, 0, 8, 0) };
        _findInput = InputBox(findText, 260, "Hex bytes such as 4D 5A, or select ASCII text");
        var find = new Button { Content = "Find next", Margin = new Thickness(8, 0, 0, 0) };
        void FindNext()
        {
            try
            {
                var text = _findInput.Text;
                if (text.Length == 0) throw new FormatException("Enter bytes or text to find.");
                if (findType.SelectedIndex == 1 && text.Any(c => c > 127)) throw new FormatException("ASCII search supports characters in the range 0–127.");
                var pattern = findType.SelectedIndex == 0 ? UiInput.HexBytes(text) : Encoding.ASCII.GetBytes(text);
                var start = Math.Min((_hex?.SelectedOffset ?? 0) + 1, document.Data.Length);
                var bytes = document.Data.Span;
                var relative = bytes[start..].IndexOf(pattern);
                var found = relative >= 0 ? start + relative : bytes[..Math.Min(bytes.Length, start + pattern.Length - 1)].IndexOf(pattern);
                if (found < 0) { SetStatus("Pattern not found."); return; }
                _hex?.GoTo(found); _hex?.Focus();
                SetStatus($"Found {pattern.Length} bytes at 0x{found:X8}{(relative < 0 ? " · Wrapped to start" : "")}");
            }
            catch (Exception ex) when (IsExpected(ex)) { SetStatus(ex.Message); }
        }
        find.Click += (_, _) => FindNext();
        _findInput.KeyDown += (_, e) => { if (e.Key == Key.Enter) { FindNext(); e.Handled = true; } };
        var modeHelp = new HelpBadge(findType.SelectedIndex == 1 ? "ASCII" : "HexBytes");
        findType.SelectionChanged += (_, _) => modeHelp.TopicKey = findType.SelectedIndex == 1 ? "ASCII" : "HexBytes";
        findBar.Children.Add(findType); findBar.Children.Add(modeHelp);
        findBar.Children.Add(HelpUi.Beside(_findInput, "Search")); findBar.Children.Add(HelpUi.Beside(find, "FindNext"));
        Grid.SetRow(findBar, 1); root.Children.Add(findBar);

        // A new host is built on each refresh, so detach the persistent hex surface first.
        if (_hex?.Parent is Panel oldPanel) oldPanel.Children.Remove(_hex);
        if (_hex is null)
        {
            _hex = new HexView();
            _hex.SelectionChanged += UpdateHexPosition;
            _hex.PatchRequested += (offset, replacement) => ApplyHexPatch(offset, replacement);
        }
        _hex.SetDocument(document);
        var surface = new Grid();
        surface.Children.Add(_hex);
        // Header badges share the drawn column coordinates without covering any byte cells.
        foreach (var (key, x) in new[] { ("Offset", 76d), ("HexColumns", 549d), ("DecodedText", 668d) })
            surface.Children.Add(new HelpBadge(key) { HorizontalAlignment = HorizontalAlignment.Left, VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(x, 6, 0, 0) });
        var hexBorder = new Border { BorderBrush = Brush("#2E3F55"), BorderThickness = new Thickness(1), Child = surface };
        Grid.SetRow(hexBorder, 2); root.Children.Add(hexBorder);

        var footer = new DockPanel { Margin = new Thickness(0, 9, 0, 10) };
        var pages = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var previous = new Button { Content = "← Previous", Padding = new Thickness(10, 5, 10, 5), Margin = new Thickness(0, 0, 6, 0) };
        var next = new Button { Content = "Next →", Padding = new Thickness(10, 5, 10, 5) };
        previous.Click += (_, _) => _hex.Page(-1); next.Click += (_, _) => _hex.Page(1);
        pages.Children.Add(HelpUi.Beside(previous, "Previous")); pages.Children.Add(HelpUi.Beside(next, "Next")); DockPanel.SetDock(pages, Dock.Right); footer.Children.Add(pages);
        _hexPosition = new TextBlock { FontFamily = new FontFamily("Consolas"), FontSize = 11, Foreground = Brush("#89A5C8"), VerticalAlignment = VerticalAlignment.Center };
        _hexByteValue = new TextBlock { FontFamily = new FontFamily("Consolas"), FontSize = 11, Foreground = Brush("#89A5C8"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };
        _hexPage = new TextBlock { FontFamily = new FontFamily("Consolas"), FontSize = 11, Foreground = Brush("#89A5C8"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };
        var positionDetails = new WrapPanel { VerticalAlignment = VerticalAlignment.Center };
        positionDetails.Children.Add(HelpUi.Beside(_hexPosition, "Cursor"));
        positionDetails.Children.Add(HelpUi.Beside(_hexByteValue, "HexBytes"));
        positionDetails.Children.Add(HelpUi.Beside(_hexPage, "Page"));
        footer.Children.Add(positionDetails); Grid.SetRow(footer, 3); root.Children.Add(footer);

        var patchBar = new DockPanel { LastChildFill = true };
        var apply = new Button { Content = "Replace at cursor", Margin = new Thickness(8, 0, 0, 0) };
        var applyWithHelp = HelpUi.Beside(apply, "Replace");
        DockPanel.SetDock(applyWithHelp, Dock.Right); patchBar.Children.Add(applyWithHelp);
        var patch = _patchInput = InputBox(patchText, double.NaN, "Replacement bytes, for example: 90 90. File size stays unchanged.");
        patchBar.Children.Add(HelpUi.Beside(patch, "ReplacementBytes"));
        apply.Click += (_, _) =>
        {
            try { ApplyHexPatch(_hex.SelectedOffset, UiInput.HexBytes(patch.Text)); }
            catch (Exception ex) when (IsExpected(ex)) { SetStatus(ex.Message); }
        };
        Grid.SetRow(patchBar, 4); root.Children.Add(patchBar);
        UpdateHexPosition(_hex.SelectedOffset);
        return root;
    }

    private void ApplyHexPatch(int offset, byte[] replacement)
    {
        Mutate(() => Document?.ApplyPatch(offset, replacement, $"Hex patch at 0x{offset:X8}"), $"Replaced {replacement.Length} bytes at 0x{offset:X8}");
        _hex?.Focus();
    }

    private void UpdateHexPosition(int offset)
    {
        if (_hexPosition is null || Document is null || _hex is null) return;
        _hexPosition.Text = $"Cursor 0x{offset:X8}";
        if (_hexByteValue is not null) _hexByteValue.Text = $"Value 0x{Document.Data.Span[offset]:X2}";
        if (_hexPage is not null) _hexPage.Text = $"Page 0x{_hex.PageOffset:X8}";
    }

    private static TextBlock ToolbarLabel(string label) => new() { Text = label, Width = 47, Foreground = Brush("#90A7C4"), VerticalAlignment = VerticalAlignment.Center };
    private static TextBox InputBox(string text, double width, string hint) => new() { Text = text, Width = width, FontFamily = new FontFamily("Consolas"), ToolTip = hint };
}
