using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using Microsoft.Win32;
using PeWorkshop.Core;

namespace PeWorkshop.App;

internal sealed record ComparisonInput(string Label, string? Path, byte[] Bytes);

public sealed class ComparisonWindow : Window
{
    private readonly MainWindow _editor;
    private ComparisonInput? _left, _right;
    private readonly TextBlock _leftPath = PathLabel(), _rightPath = PathLabel();
    private readonly TextBlock _summary = new() { Text = "Choose a baseline and a candidate, or try one of the sample pairs.", TextWrapping = TextWrapping.Wrap, FontSize = 12, Foreground = HelpUi.Brush("#B8CBE3") };
    private readonly TextBox _filter = new() { Width = 240, ToolTip = "Filter findings by title, value, category or explanation" };
    private readonly ComboBox _severity = new() { Width = 180, ItemsSource = new[] { "All findings", "Review & suspicious", "Suspicious only", "Raw bytes" }, SelectedIndex = 0 };
    private readonly List<Button> _loadActions = [];
    private readonly Button _compare = new() { Content = "Compare", Style = (Style)Application.Current.FindResource("PrimaryButton") };
    private readonly Button _openLeft = new() { Content = "A in editor", IsEnabled = false };
    private readonly Button _openRight = new() { Content = "B in editor", IsEnabled = false };
    private readonly TextBlock _title = new() { FontSize = 16, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock _detail = new() { TextWrapping = TextWrapping.Wrap, LineHeight = 20, FontSize = 12, Foreground = HelpUi.Brush("#C1D0E4") };
    private bool _busy, _closed;
    internal PeComparisonResult? Result { get; private set; }
    internal DataGrid FindingsGrid { get; } = new() { RowHeight = 36 };
    internal ComparisonBytePreview Preview { get; } = new();
    internal string Explanation => _detail.Text;

    public ComparisonWindow(MainWindow editor)
    {
        _editor = editor;
        Style = (Style)Application.Current.FindResource(typeof(Window));
        Title = "Compare executables — PE Workshop";
        Width = 1320; Height = 940; MinWidth = 1120; MinHeight = 800;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        if (editor.Document is { } document)
            _left = new(Path.GetFileName(document.SourcePath) + (document.IsDirty ? " (unsaved snapshot)" : ""), document.SourcePath, document.Data.ToArray());
        var root = new Grid();
        foreach (var size in new[] { GridLength.Auto, GridLength.Auto, GridLength.Auto, GridLength.Auto, GridLength.Auto, new GridLength(1, GridUnitType.Star), new GridLength(275), GridLength.Auto })
            root.RowDefinitions.Add(new() { Height = size });
        var heading = HelpUi.Beside(new TextBlock { Text = "Compare executables", FontSize = 26, FontWeight = FontWeights.SemiBold }, "Compare");
        heading.HorizontalAlignment = HorizontalAlignment.Left; Add(root, heading, 0);
        Add(root, new TextBlock { Text = "Choose A as your reference. B is examined relative to A. Files are read as data; comparison does not run them.", Foreground = HelpUi.Brush("#96ACC9"), Margin = new Thickness(0, 7, 0, 12), TextWrapping = TextWrapping.Wrap }, 1);
        var paths = new StackPanel(); paths.Children.Add(PathRow("A · BASELINE", _leftPath, true)); paths.Children.Add(PathRow("B · CANDIDATE", _rightPath, false)); Add(root, paths, 2);
        var actions = new WrapPanel { Margin = new Thickness(0, 10, 0, 10) };
        _compare.Click += async (_, _) => await CompareCurrentAsync(); _loadActions.Add(_compare);
        actions.Children.Add(HelpUi.Beside(_compare, "Compare"));
        AddPairButton(actions, "Console vs GUI", "ConsoleDemo.exe", "GuiDemo.exe");
        AddPairButton(actions, "Original vs modified", "OriginalConsole.exe", "ModifiedConsole.exe");
        actions.Children.Add(HelpUi.Beside(_severity, "CompareSeverity"));
        var filterRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(10, 0, 0, 0) };
        filterRow.Children.Add(new TextBlock { Text = "Filter", Margin = new Thickness(0, 0, 7, 0), VerticalAlignment = VerticalAlignment.Center });
        filterRow.Children.Add(HelpUi.Beside(_filter, "Filter")); actions.Children.Add(filterRow);
        System.Windows.Automation.AutomationProperties.SetName(_filter, "Filter comparison findings");
        System.Windows.Automation.AutomationProperties.SetName(_severity, "Comparison priority filter");
        Add(root, actions, 3);
        var summaryScroll = new ScrollViewer { Content = _summary, MaxHeight = 88, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(0, 0, 0, 10) }; Add(root, HelpUi.Beside(summaryScroll, "CompareHash"), 4);
        AddColumn("PRIORITY", nameof(PeDifference.Severity), 110, "CompareSeverity");
        AddColumn("CATEGORY", nameof(PeDifference.Category), 125, "Compare");
        AddColumn("DIFFERENCE", nameof(PeDifference.Title), 0, "Compare");
        AddColumn("A · BEFORE", nameof(PeDifference.LeftValue), 165, "Before");
        AddColumn("B · AFTER", nameof(PeDifference.RightValue), 165, "After");
        var rowStyle = new Style(typeof(DataGridRow));
        foreach (var (severity, color) in new[] { (DifferenceSeverity.Suspicious, "#63343F"), (DifferenceSeverity.Review, "#473C29") })
        {
            var trigger = new DataTrigger { Binding = new Binding(nameof(PeDifference.Severity)), Value = severity };
            trigger.Setters.Add(new Setter(Control.BackgroundProperty, HelpUi.Brush(color))); rowStyle.Triggers.Add(trigger);
        }
        FindingsGrid.RowStyle = rowStyle; FindingsGrid.SelectionChanged += (_, _) => ShowSelection();
        Add(root, FindingsGrid, 5);
        var evidence = new Grid { Margin = new Thickness(0, 13, 0, 8) };
        evidence.ColumnDefinitions.Add(new() { Width = new GridLength(0.9, GridUnitType.Star) });
        evidence.ColumnDefinitions.Add(new() { Width = new GridLength(2, GridUnitType.Star) });
        var explanation = new DockPanel { Margin = new Thickness(0, 0, 20, 0) };
        var inspect = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) };
        inspect.Children.Add(HelpUi.Beside(_openLeft, "CompareInspect")); inspect.Children.Add(HelpUi.Beside(_openRight, "CompareInspect"));
        DockPanel.SetDock(inspect, Dock.Bottom); explanation.Children.Add(inspect);
        var prose = new StackPanel(); prose.Children.Add(_title); _detail.Margin = new Thickness(0, 8, 0, 0); prose.Children.Add(_detail);
        explanation.Children.Add(new ScrollViewer { Content = prose, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        evidence.Children.Add(explanation); Grid.SetColumn(Preview, 1); evidence.Children.Add(Preview); Add(root, evidence, 6);
        Add(root, new TextBlock { Text = "Suspicious means investigate, not proven malware. Static differences cannot establish the author's intent or what executes at runtime.", TextWrapping = TextWrapping.Wrap, Foreground = HelpUi.Brush("#A6B9D1"), FontSize = 11 }, 7);
        _openLeft.Click += (_, _) => Inspect(true); _openRight.Click += (_, _) => Inspect(false);
        _filter.TextChanged += (_, _) => ApplyFilter(); _severity.SelectionChanged += (_, _) => ApplyFilter();
        Closed += (_, _) => _closed = true;
        Content = new Border { Background = HelpUi.Brush("#10141B"), Padding = new Thickness(22), Child = root };
        UpdatePaths(); SetBusy(false);
    }

    private FrameworkElement PathRow(string label, TextBlock value, bool left)
    {
        var row = new DockPanel { Margin = new Thickness(0, 3, 0, 3) };
        var pick = new Button { Content = left ? "Choose A…" : "Choose B…" };
        pick.Click += async (_, _) =>
        {
            var dialog = new OpenFileDialog { Title = left ? "Choose baseline (A)" : "Choose candidate (B)", Filter = "PE files|*.exe;*.dll;*.sys;*.efi;*.ocx|All files|*.*" };
            if (dialog.ShowDialog(this) == true) await PickAsync(dialog.FileName, left);
        };
        _loadActions.Add(pick); var pickHelp = HelpUi.Beside(pick, left ? "CompareBaseline" : "CompareCandidate"); DockPanel.SetDock(pickHelp, Dock.Right); row.Children.Add(pickHelp);
        var caption = new TextBlock { Text = label, Width = 118, Foreground = HelpUi.Brush("#84AADB"), FontSize = 11, VerticalAlignment = VerticalAlignment.Center };
        DockPanel.SetDock(caption, Dock.Left); row.Children.Add(caption); row.Children.Add(value); return row;
    }

    private void AddPairButton(Panel panel, string label, string left, string right)
    {
        var button = new Button { Content = label, Margin = new Thickness(8, 0, 4, 0) };
        button.Click += async (_, _) =>
        {
            var directory = FindSamplesDirectory();
            if (directory is null) { _summary.Text = "Sample folder not found. Choose the files manually, or build the Samples folder beside PE-Editor."; return; }
            await LoadPairAsync(Path.Combine(directory, left), Path.Combine(directory, right));
        };
        _loadActions.Add(button); panel.Children.Add(HelpUi.Beside(button, "CompareSamples"));
    }

    internal static string? FindSamplesDirectory()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "Samples");
            if (File.Exists(Path.Combine(candidate, "ConsoleDemo.exe"))) return candidate;
        }
        return null;
    }

    private async Task PickAsync(string path, bool left)
    {
        if (_busy) return; SetBusy(true);
        try
        {
            var input = await Task.Run(() => ReadInput(path)); if (_closed) return;
            if (left) _left = input; else _right = input;
            Result = null; FindingsGrid.ItemsSource = null; ShowSelection(); UpdatePaths();
            _summary.Text = "File loaded. Choose Compare to inspect these snapshots.";
        }
        catch (Exception ex) when (Expected(ex)) { if (!_closed) _summary.Text = "Could not read file: " + ex.Message; }
        finally { if (!_closed) SetBusy(false); }
    }

    internal async Task LoadPairAsync(string left, string right)
    {
        if (_busy) return; SetBusy(true);
        try
        {
            var pair = await Task.Run(() => { var a = ReadInput(left); var b = ReadInput(right); return (a, b, result: PeComparison.Compare(a.Bytes, b.Bytes)); });
            if (_closed) return;
            _left = pair.a; _right = pair.b; UpdatePaths(); Present(pair.result);
        }
        catch (Exception ex) when (Expected(ex)) { if (!_closed) _summary.Text = "Could not compare files: " + ex.Message; }
        finally { if (!_closed) SetBusy(false); }
    }

    private async Task CompareCurrentAsync()
    {
        if (_busy || _left is null || _right is null) return; SetBusy(true);
        var a = _left.Bytes; var b = _right.Bytes;
        try { var result = await Task.Run(() => PeComparison.Compare(a, b)); if (!_closed) Present(result); }
        catch (Exception ex) when (Expected(ex)) { if (!_closed) _summary.Text = "Could not compare files: " + ex.Message; }
        finally { if (!_closed) SetBusy(false); }
    }

    private void Present(PeComparisonResult result)
    {
        Result = result;
        var raw = result.ByteRanges.Select(range => new PeDifference("Bytes", $"Raw difference at 0x{range.Offset:X8}",
            range.Offset < _left!.Bytes.Length ? $"0x{range.Offset:X8}" : "Absent", range.Offset < _right!.Bytes.Length ? $"0x{range.Offset:X8}" : "Absent",
            "These bytes differ at the same file position. This is an exact positional comparison, not disassembly or an insertion-alignment algorithm. Different code, strings, resources, padding, linking or an inserted block can all explain raw changes. Use the structural findings for context; the bytes alone do not reveal intent.",
            DifferenceSeverity.Information, range.Offset < _left.Bytes.Length ? range.Offset : null, range.Offset < _right.Bytes.Length ? range.Offset : null,
            Math.Clamp(_left.Bytes.Length - range.Offset, 0, range.Length), Math.Clamp(_right.Bytes.Length - range.Offset, 0, range.Length)));
        FindingsGrid.ItemsSource = result.Differences.Concat(raw).OrderByDescending(d => d.Severity).ThenBy(d => d.Category == "Bytes").ThenBy(d => d.Category).ToArray();
        _summary.Text = (result.Identical ? "Byte-identical files." : $"{result.DifferentByteCount:N0} differing byte positions · {result.Differences.Count(d => d.Severity == DifferenceSeverity.Suspicious)} suspicious indicators · {result.Differences.Count(d => d.Severity == DifferenceSeverity.Review)} for review")
            + $"\nA SHA-256 {result.LeftSha256}\nB SHA-256 {result.RightSha256}"
            + (result.Limitations.Count > 0 ? "\n" + string.Join(" ", result.Limitations) : "");
        ApplyFilter();
    }

    internal void SetFindingFilter(string text, int severity = 0) { _filter.Text = text; _severity.SelectedIndex = severity; ApplyFilter(); }
    private void ApplyFilter()
    {
        if (FindingsGrid.ItemsSource is null) return;
        var query = _filter.Text.Trim();
        CollectionViewSource.GetDefaultView(FindingsGrid.ItemsSource).Filter = item => item is PeDifference d
            && (_severity.SelectedIndex switch { 1 => d.Severity != DifferenceSeverity.Information, 2 => d.Severity == DifferenceSeverity.Suspicious, 3 => d.Category == "Bytes", _ => true })
            && $"{d.Title} {d.Category} {d.LeftValue} {d.RightValue} {d.Explanation}".Contains(query, StringComparison.OrdinalIgnoreCase);
        FindingsGrid.SelectedIndex = FindingsGrid.Items.Count > 0 ? 0 : -1;
        ShowSelection();
    }

    private void ShowSelection()
    {
        var finding = FindingsGrid.SelectedItem as PeDifference;
        _title.Text = finding is null ? Result?.Identical == true ? "No byte differences" : "Select a finding" : finding.Title;
        _title.Foreground = HelpUi.Brush(finding?.Severity switch { DifferenceSeverity.Suspicious => "#FFB3C0", DifferenceSeverity.Review => "#F5CF87", _ => "#DAE8FA" });
        _detail.Text = finding is null ? "Select a row to read the evidence and possible causes. Choosing a row does not change either file." : $"A: {finding.LeftValue}\nB: {finding.RightValue}\n\n{finding.Explanation}";
        _openLeft.IsEnabled = !_busy && finding?.LeftOffset is not null;
        _openRight.IsEnabled = !_busy && finding?.RightOffset is not null;
        Preview.Show(_left?.Bytes ?? [], _right?.Bytes ?? [], finding);
    }

    private void Inspect(bool left)
    {
        if (FindingsGrid.SelectedItem is not PeDifference finding) return;
        var input = left ? _left : _right; var offset = left ? finding.LeftOffset : finding.RightOffset;
        if (input is null || offset is null) return;
        if (_editor.ShowComparisonEvidence(input, offset.Value, Math.Max(1, left ? finding.LeftLength : finding.RightLength), finding.Title))
        {
            Hide(); // Owned windows otherwise stay above the editor and obscure the highlighted bytes.
            _editor.Activate();
        }
    }

    private void AddColumn(string header, string binding, int width, string topic) => FindingsGrid.Columns.Add(new DataGridTextColumn
    {
        Header = HelpUi.Label(header, topic, true), Binding = new Binding(binding), MinWidth = 95,
        Width = width == 0 ? new DataGridLength(1, DataGridLengthUnitType.Star) : new DataGridLength(width),
        ElementStyle = new Style(typeof(TextBlock)) { Setters = { new Setter(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis) } }
    });
    private void SetBusy(bool value)
    {
        _busy = value; foreach (var action in _loadActions) action.IsEnabled = !value;
        _compare.IsEnabled = !value && _left is not null && _right is not null;
        if (value) _summary.Text = "Reading and comparing file snapshots…";
        ShowSelection();
    }
    private void UpdatePaths()
    {
        _leftPath.Text = _left is null ? "No baseline selected" : _left.Label + "  ·  " + _left.Path;
        _rightPath.Text = _right is null ? "No candidate selected" : _right.Label + "  ·  " + _right.Path;
        _leftPath.ToolTip = _leftPath.Text; _rightPath.ToolTip = _rightPath.Text;
    }
    private static ComparisonInput ReadInput(string path)
    { var document = PeDocument.Open(path); return new(Path.GetFileName(path), Path.GetFullPath(path), document.Data.ToArray()); }
    private static bool Expected(Exception ex) => ex is IOException or UnauthorizedAccessException or PeFormatException or ArgumentException or InvalidOperationException or NotSupportedException or System.Security.SecurityException;
    private static TextBlock PathLabel() => new() { TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center, Foreground = HelpUi.Brush("#C2D2E9"), Margin = new Thickness(8, 0, 8, 0) };
    private static void Add(Grid root, UIElement child, int row) { Grid.SetRow(child, row); root.Children.Add(child); }
}
