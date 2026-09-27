using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using Microsoft.Win32;
using PeWorkshop.Core;

namespace PeWorkshop.App;

public partial class MainWindow : Window
{
    internal PeDocument? Document { get; private set; }
    private DataGrid? _activeTable;
    private object? _selected;
    private HexView? _hex;
    private TextBox? _jumpInput;
    private TextBox? _findInput;
    private ComboBox? _jumpType;
    private ComboBox? _findType;
    private TextBox? _patchInput;
    private TextBlock? _hexPosition;
    private TextBlock? _hexByteValue;
    private TextBlock? _hexPage;
    private ComparisonWindow? _comparisonWindow;
    private bool _refreshing;
    private string CurrentPage => (Navigation.SelectedItem as ListBoxItem)?.Tag as string ?? "Overview";

    public MainWindow()
    {
        InitializeComponent();
        PreviewKeyDown += Window_PreviewKeyDown;
        Closing += Window_Closing;
        SourceInitialized += (_, _) =>
        {
            var enabled = 1;
            _ = DwmSetWindowAttribute(new WindowInteropHelper(this).Handle, 20, ref enabled, sizeof(int));
        };
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(nint window, int attribute, ref int value, int size);

    internal bool OpenPath(string path)
    {
        try
        {
            Mouse.OverrideCursor = Cursors.Wait;
            var document = PeDocument.Open(path);
            Mouse.OverrideCursor = null;
            if (!ResolveUnsaved()) return false;
            LoadDocument(document);
            return true;
        }
        catch (Exception ex) when (IsExpected(ex))
        {
            ShowError("Could not open file", ex.Message);
            return false;
        }
        finally { Mouse.OverrideCursor = null; }
    }

    internal void LoadDocument(PeDocument document)
    {
        Document = document;
        _hex = null;
        _jumpInput = _findInput = _patchInput = null;
        _jumpType = _findType = null;
        Navigation.SelectedIndex = 0;
        FilterBox.Text = "";
        RefreshWorkspace();
        SetStatus($"Opened {Path.GetFileName(document.SourcePath) ?? "binary"} · {document.Image.Sections.Count} sections");
    }

    internal void Navigate(string page)
    {
        foreach (ListBoxItem item in Navigation.Items)
            if ((string)item.Tag == page) { Navigation.SelectedItem = item; break; }
    }

    internal void RefreshWorkspace()
    {
        if (Document is null) return;
        _refreshing = true;
        try
        {
            var image = Document.Image;
            WelcomePanel.Visibility = Visibility.Collapsed;
            DocumentPanel.Visibility = Visibility.Visible;
            Navigation.IsEnabled = true;
            SaveButton.IsEnabled = ChecksumButton.IsEnabled = true;
            UndoButton.IsEnabled = Document.CanUndo;
            RedoButton.IsEnabled = Document.CanRedo;
            var filename = Path.GetFileName(Document.SourcePath) ?? "Untitled binary";
            Title = $"{filename}{(Document.IsDirty ? " •" : "")} — PE Workshop";
            SidebarFile.Text = filename;
            SidebarFile.ToolTip = Document.SourcePath;
            SidebarFormat.Text = $"{(image.Is64Bit ? "PE32+" : "PE32")}  ·  {image.Architecture}  ·  {UiInput.Bytes(Document.Data.Length)}";
            DirtyLabel.Text = Document.IsDirty ? "● Unsaved changes" : "● No unsaved changes";
            DirtyLabel.Foreground = Brush(Document.IsDirty ? "#E9B974" : "#8BC9B3");
            StatusRight.Text = $"{image.Architecture}  |  {Document.Data.Length:N0} bytes";
            RenderPage();
        }
        finally { _refreshing = false; }
    }

    private void RenderPage()
    {
        if (Document is null || ViewHost is null) return;
        _activeTable = null;
        _selected = null;
        InspectorPanel.Visibility = Visibility.Collapsed;
        PageHelp.TopicKey = CurrentPage;
        FilterBox.Visibility = CurrentPage is "Overview" or "Hex" ? Visibility.Collapsed : Visibility.Visible;
        FilterHelp.Visibility = FilterBox.Visibility;
        switch (CurrentPage)
        {
            case "Overview":
                SetPage("Binary overview", "File structure, image metadata, and validation at a glance.");
                ViewHost.Content = BuildOverview(); break;
            case "Headers":
                SetPage("Headers", "Select a field to inspect its location, then edit its value.");
                ShowFields(Document.Image.Fields.Where(f => f.Group is "DOS header" or "COFF header" or "Optional header")); break;
            case "Sections":
                SetPage("Sections", $"{Document.Image.Sections.Count} sections · Double-click to edit section fields. Use Rename for the section name.");
                ShowSections(); break;
            case "Directories":
                SetPage("Data directories", "RVA and size pairs locate image tables. The certificate table uses a file offset.");
                ShowDirectories(); break;
            case "Imports":
                SetPage("Imports", $"{Document.Image.Imports.Count:N0} imported symbols · {Document.Image.Imports.Select(i => i.Module).Distinct().Count()} modules");
                ShowImports(); break;
            case "Exports":
                SetPage("Exports", $"{Document.Image.Exports.Count:N0} exported symbols · Includes ordinal-only and forwarded exports.");
                ShowExports(); break;
            case "Hex":
                SetPage("Hex editor", "Select a byte and type two hex digits. Changed bytes appear in amber.");
                ViewHost.Content = BuildHexWorkspace(); break;
            case "Changes":
                SetPage("Changes", "Applied edits in undo history. Save copy preserves the original file.");
                ShowChanges(); break;
        }
        ApplyFilter();
    }

    private void Open_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open a Portable Executable",
            Filter = "Portable Executables|*.exe;*.dll;*.sys;*.ocx;*.efi;*.scr;*.cpl|All files|*.*",
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) == true) OpenPath(dialog.FileName);
    }

    private void OpenSelf_Click(object sender, RoutedEventArgs e) => OpenPath(Environment.ProcessPath ?? typeof(App).Assembly.Location);
    private void Compare_Click(object sender, RoutedEventArgs e)
    {
        if (_comparisonWindow is null)
        {
            _comparisonWindow = new ComparisonWindow(this) { Owner = this };
            _comparisonWindow.Closed += (_, _) => _comparisonWindow = null;
        }
        _comparisonWindow.Show(); _comparisonWindow.WindowState = WindowState.Normal; _comparisonWindow.Activate();
    }

    internal bool ShowComparisonEvidence(ComparisonInput input, int offset, int length, string title)
    {
        if (offset < 0 || offset >= input.Bytes.Length) return false;
        if (Document is null || !string.Equals(Document.SourcePath, input.Path, StringComparison.OrdinalIgnoreCase) || !Document.Data.Span.SequenceEqual(input.Bytes))
        {
            if (!ResolveUnsaved()) return false;
            LoadDocument(new PeDocument(input.Bytes, input.Path));
        }
        Navigate("Hex");
        _hex?.HighlightEvidence(offset, length, title);
        SetStatus($"Comparison evidence: {title} · highlighted in pink · snapshot bytes");
        return true;
    }
    private void Save_Click(object sender, RoutedEventArgs e) => SaveCopy();

    private bool SaveCopy()
    {
        if (Document is null) return false;
        var source = Document.SourcePath ?? "binary.exe";
        var dialog = new SaveFileDialog
        {
            Title = "Save edited copy",
            FileName = $"{Path.GetFileNameWithoutExtension(source)}.edited{Path.GetExtension(source)}",
            Filter = "All files|*.*", AddExtension = false, OverwritePrompt = true
        };
        if (dialog.ShowDialog(this) != true) return false;
        try
        {
            Document.SaveCopy(dialog.FileName);
            RefreshWorkspace();
            SetStatus($"Saved copy: {dialog.FileName}");
            return true;
        }
        catch (Exception ex) when (IsExpected(ex)) { ShowError("Could not save copy", ex.Message); return false; }
    }

    private void Undo_Click(object sender, RoutedEventArgs e) => Mutate(() => Document?.Undo(), "Undid last change");
    private void Redo_Click(object sender, RoutedEventArgs e) => Mutate(() => Document?.Redo(), "Redid change");
    private void Checksum_Click(object sender, RoutedEventArgs e) => Mutate(() => Document?.UpdateChecksum(), "PE checksum updated");

    private void Mutate(Action action, string status)
    {
        try { action(); _hex?.ClearEvidence(); RefreshWorkspace(); SetStatus(status); }
        catch (Exception ex) when (IsExpected(ex)) { ShowError("Change rejected", ex.Message); }
    }

    private void Navigation_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ViewHost is null || Document is null) return;
        FilterBox.Text = "";
        RenderPage();
    }

    private void Filter_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!_refreshing) ApplyFilter();
    }

    private void Edit_Click(object sender, RoutedEventArgs e) => EditSelected();

    private void EditSelected()
    {
        if (Document is null) return;
        IEnumerable<PeField> fields;
        PeField? selected = null;
        switch (_selected)
        {
            case PeField field: fields = Document.Image.Fields.Where(f => f.Group == field.Group); selected = field; break;
            case SectionRow section:
                fields = Document.Image.Fields.Where(f => f.Offset >= section.Value.HeaderOffset && f.Offset < section.Value.HeaderOffset + 40);
                selected = fields.FirstOrDefault(f => f.Name == "Characteristics"); break;
            case DirectoryRow directory:
                fields = Document.Image.Fields.Where(f => f.Offset >= directory.Value.EntryOffset && f.Offset < directory.Value.EntryOffset + 8); break;
            default: return;
        }
        var dialog = new EditFieldDialog(Document, fields, selected) { Owner = this };
        if (dialog.ShowDialog() == true) { RefreshWorkspace(); SetStatus("Field updated · Ctrl+Z to undo"); }
    }

    private void Reveal_Click(object sender, RoutedEventArgs e)
    {
        if (Document is null) return;
        int? offset = _selected switch
        {
            PeField field => field.Offset,
            SectionRow section => section.Value.RawSize > 0 ? checked((int)section.Value.RawOffset) : section.Value.HeaderOffset,
            DirectoryRow directory => directory.Value.FileOffset,
            ImportRow import => Document.Image.RvaToOffset(import.Value.IatRva),
            ExportRow export => Document.Image.RvaToOffset(export.Value.Rva),
            ChangeRow change => change.Value.Offset,
            _ => null
        };
        if (offset is null) { SetStatus("This address is not backed by bytes in the file."); return; }
        Navigate("Hex");
        _hex?.GoTo(offset.Value);
        _hex?.Focus();
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (!Keyboard.Modifiers.HasFlag(ModifierKeys.Control)) return;
        switch (e.Key)
        {
            case Key.O: Open_Click(this, new RoutedEventArgs()); break;
            case Key.S: SaveCopy(); break;
            case Key.Z when e.OriginalSource is not TextBox: Undo_Click(this, new RoutedEventArgs()); break;
            case Key.Y when e.OriginalSource is not TextBox: Redo_Click(this, new RoutedEventArgs()); break;
            case Key.F:
                if (CurrentPage == "Hex") _findInput?.Focus();
                else if (FilterBox.Visibility == Visibility.Visible) FilterBox.Focus();
                else { Navigate("Hex"); _findInput?.Focus(); }
                break;
            case Key.G when Document is not null: Navigate("Hex"); _jumpInput?.Focus(); break;
            default: return;
        }
        e.Handled = true;
    }

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } paths) OpenPath(paths[0]);
    }

    private bool ResolveUnsaved()
    {
        if (Document?.IsDirty != true) return true;
        var result = MessageBox.Show(this, "Save a copy of your changes before continuing?", "Unsaved changes", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
        return result == MessageBoxResult.No || (result == MessageBoxResult.Yes && SaveCopy());
    }

    private void Window_Closing(object? sender, CancelEventArgs e) => e.Cancel = !ResolveUnsaved();
    private void SetPage(string title, string subtitle) { PageTitle.Text = title; PageSubtitle.Text = subtitle; }
    private void SetStatus(string text) => StatusText.Text = text;
    private void ShowError(string title, string message) { SetStatus($"{title}: {message}"); MessageBox.Show(this, message, title, MessageBoxButton.OK, MessageBoxImage.Warning); }
    private static bool IsExpected(Exception ex) => ex is PeFormatException or IOException or UnauthorizedAccessException or ArgumentException or FormatException or OverflowException or InvalidOperationException or NotSupportedException or System.Security.SecurityException;
}
