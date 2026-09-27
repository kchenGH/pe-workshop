using System.IO;
using System.Reflection.PortableExecutable;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using PeWorkshop.Core;

namespace PeWorkshop.App;

/// <summary>An opt-in, in-process integration test; no automation of other applications.</summary>
internal static class UiSmokeTest
{
    public static void Run(string output)
    {
        var source = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        var sourceBytes = File.ReadAllBytes(source);
        var window = new MainWindow();
        var root = (FrameworkElement)window.Content;
        try
        {
        Layout(root);
        Render(root, Path.Combine(output, "welcome.png"));
        AssertDarkNavigation(window, root);
        var document = PeDocument.Open(source);
        CheckHexResizeAndWheel(document);
        window.LoadDocument(document);
        Layout(root);
        AssertDarkNavigation(window, root);
        Assert(Descendants<Button>(root).Any(b => b.GetType().Name == "HelpBadge"),
            "Technical terms and actions should have visible help icons.");
        Assert(window.SaveButton.IsEnabled, "Save should be enabled after opening.");
        Assert(window.SidebarFile.Text == "notepad.exe", "Sidebar should identify loaded file.");
        Render(root, Path.Combine(output, "overview.png"));
        HelpSmokeTest.Run(window, document, output);
        Layout(root);

        foreach (var page in new[] { "Headers", "Sections", "Directories", "Imports", "Exports", "Hex", "Changes", "Overview" })
        {
            window.Navigate(page); Layout(root);
            Assert(window.ViewHost.Content is not null, $"View missing: {page}");
        }
        window.Navigate("Headers"); Layout(root);
        window.FilterBox.Text = "AddressOfEntryPoint";
        var table = Descendants<DataGrid>(root).Single();
        Assert(table.Items.Count == 1, "Header filtering should find the entry point.");
        table.SelectedIndex = 0;
        Assert(window.InspectorPanel.Visibility == Visibility.Visible, "Selecting a field should show its inspector.");
        window.FilterBox.Text = "";

        var field = document.Image.Fields.Single(f => f.Name == "TimeDateStamp" && f.Group == "COFF header");
        var previous = field.Value;
        var dialog = new EditFieldDialog(document, [field], field)
        {
            ShowInTaskbar = false, WindowStartupLocation = WindowStartupLocation.Manual, Left = -20000, Top = -20000
        };
        dialog.Loaded += (_, _) =>
        {
            Descendants<TextBox>(dialog).Single().Text = $"0x{(previous ^ 1):X8}";
            Descendants<Button>(dialog).Single(b => b.IsDefault).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        };
        Assert(dialog.ShowDialog() == true, "Edit dialog should accept a valid field change.");
        window.RefreshWorkspace();
        Assert(document.IsDirty && window.UndoButton.IsEnabled, "Editing should mark dirty and enable Undo.");
        window.UndoButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Assert(!document.IsDirty && window.RedoButton.IsEnabled, "Undo button should restore clean bytes.");
        window.RedoButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Assert(document.IsDirty, "Redo button should restore the edit.");
        window.Navigate("Hex"); Layout(root);
        var hex = Descendants<HexView>(root).Single();
        hex.GoTo(field.Offset);
        Assert(hex.SelectedOffset == field.Offset, "Hex navigation should select requested offset.");
        hex.GoTo(37);
        var relativeCursor = hex.SelectedOffset - hex.PageOffset;
        hex.Page(1);
        Assert(HexSelectionVisible(hex), "Next page should keep the hex cursor visible.");
        Assert(hex.SelectedOffset - hex.PageOffset == relativeCursor, "Paging should preserve the cursor's row and column.");
        hex.Page(-1);
        Assert(hex.SelectedOffset == 37, "Previous page should restore the relative cursor position.");
        hex.RaiseEvent(new MouseWheelEventArgs(Mouse.PrimaryDevice, 0, -120) { RoutedEvent = Mouse.MouseWheelEvent });
        Assert(HexSelectionVisible(hex) && hex.SelectedOffset - hex.PageOffset == relativeCursor,
            "Mouse wheel should keep the cursor visible at its relative row and column.");
        hex.GoTo(document.Data.Length - 1);
        hex.Page(1);
        Assert(HexSelectionVisible(hex) && hex.SelectedOffset == document.Data.Length - 1,
            "Paging at the file end should leave a valid visible cursor.");
        var stubOffset = 0x50;
        var originalByte = document.Data.Span[stubOffset];
        var editedByte = (byte)(originalByte ^ 1);
        var asciiMode = Descendants<ComboBox>(root).Single(c => c.Items.Contains("ASCII text"));
        asciiMode.SelectedIndex = 1;
        var asciiSearch = Descendants<TextBox>(root).Single(t => t.ToolTip?.ToString() == "Hex bytes such as 4D 5A, or select ASCII text");
        asciiSearch.Text = "MZ";
        var jumpMode = Descendants<ComboBox>(root).Single(c => c.Items.Contains("RVA"));
        jumpMode.SelectedIndex = 1;
        Descendants<TextBox>(root).Single(t => t.ToolTip?.ToString() == "Decimal or 0x-prefixed hexadecimal address").Text = "0x1234";
        Descendants<TextBox>(root).Single(t => t.ToolTip?.ToString()?.StartsWith("Replacement bytes", StringComparison.Ordinal) == true).Text = "90 90";
        hex.GoTo(stubOffset);
        foreach (var digit in editedByte.ToString("X2"))
        {
            var composition = new TextComposition(InputManager.Current, hex, digit.ToString());
            hex.RaiseEvent(new TextCompositionEventArgs(Keyboard.PrimaryDevice, composition)
            { RoutedEvent = TextCompositionManager.TextInputEvent });
        }
        Assert(document.Data.Span[stubOffset] == editedByte, "Typing two hex digits should replace the selected byte.");
        Assert(hex.SelectedOffset == stubOffset + 1, "Hex input should advance the cursor.");
        Layout(root);
        AssertHexToolbarState(root);
        window.UndoButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Assert(document.Data.Span[stubOffset] == originalByte, "Undo should revert typed hex bytes.");
        Layout(root);
        AssertHexToolbarState(root);
        window.RedoButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Layout(root);
        AssertHexToolbarState(root);
        window.UndoButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        window.Navigate("Overview"); window.Navigate("Hex"); Layout(root);
        AssertHexToolbarState(root);
        hex.GoTo(document.Data.Length - 1);
        Descendants<Button>(root).Single(b => b.Content?.ToString() == "Find next").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Assert(hex.SelectedOffset == 0, "Preserved ASCII search should remain usable after edits and undo.");
        Descendants<ComboBox>(root).Single(c => c.Items.Contains("ASCII text")).SelectedIndex = 0;
        hex.GoTo(document.Data.Length - 1);
        var search = Descendants<TextBox>(root).Single(t => t.ToolTip?.ToString() == "Hex bytes such as 4D 5A, or select ASCII text");
        search.Text = "4D 5A";
        Descendants<Button>(root).Single(b => b.Content?.ToString() == "Find next").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Assert(hex.SelectedOffset == 0, "Find next should wrap to the MZ signature.");
        hex.GoTo(stubOffset);
        var patchBox = Descendants<TextBox>(root).Single(t => t.ToolTip?.ToString()?.StartsWith("Replacement bytes", StringComparison.Ordinal) == true);
        patchBox.Text = editedByte.ToString("X2");
        Descendants<Button>(root).Single(b => b.Content?.ToString() == "Replace at cursor").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Assert(document.Data.Span[stubOffset] == editedByte, "Replace at cursor should apply a hex patch.");
        window.UndoButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        hex.GoTo(field.Offset);
        Render(root, Path.Combine(output, "hex.png"));

        var destination = Path.Combine(output, "notepad.edited.exe");
        document.SaveCopy(destination);
        Assert(!document.IsDirty, "Saved document should be clean.");
        Assert(File.ReadAllBytes(source).SequenceEqual(sourceBytes), "Saving must preserve source bytes.");
        var saved = File.ReadAllBytes(destination);
        Assert(saved.SequenceEqual(document.Data.ToArray()), "Saved bytes should match the editor buffer.");
        using (var pe = new PEReader(new MemoryStream(saved)))
            Assert((uint)pe.PEHeaders.CoffHeader.TimeDateStamp == (uint)(previous ^ 1), "Independent PE reader should see the timestamp change.");
        Assert(UiInput.Number("0xFF") == 255 && UiInput.Number("255") == 255, "Numeric inputs should parse.");
        Assert(UiInput.HexBytes("90 00\nFF").SequenceEqual(new byte[] { 0x90, 0, 0xFF }), "Hex input should parse whitespace.");
        window.RefreshWorkspace();
        window.LoadDocument(new PeDocument(sourceBytes, source));
        window.Navigate("Hex"); Layout(root);
        Assert(Descendants<ComboBox>(root).Single(c => c.Items.Contains("ASCII text")).SelectedIndex == 0
            && Descendants<TextBox>(root).Single(t => t.ToolTip?.ToString() == "Hex bytes such as 4D 5A, or select ASCII text").Text == ""
            && Descendants<ComboBox>(root).Single(c => c.Items.Contains("RVA")).SelectedIndex == 0
            && Descendants<TextBox>(root).Single(t => t.ToolTip?.ToString() == "Decimal or 0x-prefixed hexadecimal address").Text == "0x00000000"
            && Descendants<TextBox>(root).Single(t => t.ToolTip?.ToString()?.StartsWith("Replacement bytes", StringComparison.Ordinal) == true).Text == "",
            "Loading a new document should reset the hex toolbar.");
        ComparisonSmokeTest.Run(window, output);
        }
        finally
        {
            // A failed assertion must not leave an unsaved-changes prompt blocking test shutdown.
            window.LoadDocument(new PeDocument(sourceBytes, source));
            window.Close();
        }
    }

    private static void Layout(FrameworkElement element)
    {
        element.Measure(new Size(1380, 820));
        element.Arrange(new Rect(0, 0, 1380, 820));
        element.UpdateLayout();
    }

    private static void AssertDarkNavigation(MainWindow window, FrameworkElement root)
    {
        // Check the rendered background, not Navigation.Background: the platform's
        // disabled ListBox template can paint over a transparent control background.
        var bitmap = new RenderTargetBitmap(1380, 820, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(root);
        var origin = window.Navigation.TranslatePoint(new Point(3, 3), root);
        var pixel = new byte[4];
        bitmap.CopyPixels(new Int32Rect((int)origin.X, (int)origin.Y, 1, 1), pixel, 4, 0);
        Assert(pixel[0] < 70 && pixel[1] < 70 && pixel[2] < 70 && pixel[3] == 255,
            $"Navigation must retain a dark background with IsEnabled={window.Navigation.IsEnabled}; rendered RGB={pixel[2]},{pixel[1]},{pixel[0]}.");
    }

    private static bool HexSelectionVisible(HexView hex) =>
        hex.SelectedOffset >= hex.PageOffset && hex.SelectedOffset < hex.PageOffset + hex.VisibleRows * 16;

    private static void CheckHexResizeAndWheel(PeDocument document)
    {
        var hex = new HexView();
        hex.SetDocument(document);
        hex.Measure(new Size(760, 500)); hex.Arrange(new Rect(0, 0, 760, 500)); hex.UpdateLayout();
        hex.GoTo(165);
        hex.Measure(new Size(760, 180)); hex.Arrange(new Rect(0, 0, 760, 180)); hex.UpdateLayout();
        Assert(HexSelectionVisible(hex), "Shrinking the hex viewport should keep the cursor visible.");
        var patchedOffset = -1;
        byte? patchedValue = null;
        hex.PatchRequested += (offset, bytes) => { patchedOffset = offset; patchedValue = bytes[0]; };
        TypeHex(hex, "A");
        hex.RaiseEvent(new MouseWheelEventArgs(Mouse.PrimaryDevice, 0, -120) { RoutedEvent = Mouse.MouseWheelEvent });
        var visibleOffset = hex.SelectedOffset;
        TypeHex(hex, "1");
        Assert(patchedOffset == -1, "Scrolling should discard a pending half-byte before typing at the new cursor.");
        TypeHex(hex, "2");
        Assert(patchedOffset == visibleOffset && patchedValue == 0x12 && HexSelectionVisible(hex),
            "Typing after resize and scrolling should edit the visible cursor byte.");
    }

    private static void TypeHex(HexView hex, string text)
    {
        foreach (var digit in text)
        {
            var composition = new TextComposition(InputManager.Current, hex, digit.ToString());
            hex.RaiseEvent(new TextCompositionEventArgs(Keyboard.PrimaryDevice, composition)
                { RoutedEvent = TextCompositionManager.TextInputEvent });
        }
    }

    private static void AssertHexToolbarState(DependencyObject root)
    {
        Assert(Descendants<ComboBox>(root).Single(c => c.Items.Contains("ASCII text")).SelectedIndex == 1
            && Descendants<TextBox>(root).Single(t => t.ToolTip?.ToString() == "Hex bytes such as 4D 5A, or select ASCII text").Text == "MZ",
            "Editing and undo should preserve ASCII search mode and query.");
        Assert(Descendants<ComboBox>(root).Single(c => c.Items.Contains("RVA")).SelectedIndex == 1
            && Descendants<TextBox>(root).Single(t => t.ToolTip?.ToString() == "Decimal or 0x-prefixed hexadecimal address").Text == "0x1234"
            && Descendants<TextBox>(root).Single(t => t.ToolTip?.ToString()?.StartsWith("Replacement bytes", StringComparison.Ordinal) == true).Text == "90 90",
            "Editing and undo should preserve jump mode, address and replacement bytes.");
    }

    private static void Render(FrameworkElement element, string path)
    {
        Layout(element);
        var image = new RenderTargetBitmap(1380, 820, 96, 96, PixelFormats.Pbgra32);
        image.Render(element);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(image));
        using var stream = File.Create(path); encoder.Save(stream);
    }

    private static IEnumerable<T> Descendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T match) yield return match;
            foreach (var descendant in Descendants<T>(child)) yield return descendant;
        }
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
