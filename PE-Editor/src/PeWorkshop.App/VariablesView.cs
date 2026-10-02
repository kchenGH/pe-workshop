using System.IO;
using System.Windows;
using System.Windows.Controls;
using PeWorkshop.Core;

namespace PeWorkshop.App;

public partial class MainWindow
{
    private CancellationTokenSource? _variableRead;
    internal Task VariablesLoadTask { get; private set; } = Task.CompletedTask;
    internal PeDebugSymbols? VariablesResult { get; private set; }

    private sealed record VariableRow(PeVariable Value)
    {
        public string Name => Value.Name;
        public string Kind => Value.Kind + (Value.IsDeclaration ? " (declaration)" : "");
        public string Type => Value.Type;
        public string Scope => Value.Scope;
        public string Declaration => (string.IsNullOrEmpty(Value.SourceFile) ? "File not recorded" : Value.SourceFile)
            + (Value.Line is { } line ? $":{line}" : "");
        public string Location => Value.Location;
        public override string ToString() => $"{Name} {Kind} {Type} {Scope} {Declaration} {Location}";
    }

    private void CancelVariableRead()
    {
        _variableRead?.Cancel();
        _variableRead = null;
    }

    private void OpenDebugSample_Click(object sender, RoutedEventArgs e)
    {
        var directory = ComparisonWindow.FindSamplesDirectory();
        var path = directory is null ? null : Path.Combine(directory, "DebugSymbolsDemo.exe");
        if (path is null || !File.Exists(path)) { SetStatus("Debug sample not found. Open your GCC-built executable, or rebuild Samples/build-debug-symbols.ps1."); return; }
        if (OpenPath(path)) Navigate("Variables");
    }

    private void ShowVariables()
    {
        var document = Document!;
        var snapshot = document.Data.ToArray();
        var cancellation = new CancellationTokenSource();
        _variableRead = cancellation;
        VariablesResult = null;
        var root = new Grid();
        root.RowDefinitions.Add(new() { Height = GridLength.Auto });
        root.RowDefinitions.Add(new() { Height = GridLength.Auto });
        root.RowDefinitions.Add(new());
        var actions = new WrapPanel { Margin = new Thickness(0, 0, 0, 12) };
        var demo = new Button { Content = "Open debug sample" };
        demo.Click += OpenDebugSample_Click;
        actions.Children.Add(HelpUi.Beside(demo, "VariablesSample"));
        actions.Children.Add(HelpUi.Beside(new TextBlock
        {
            Text = "Recorded symbols only · Runtime values require a debugger",
            Foreground = Brush("#9EB8D6"), VerticalAlignment = VerticalAlignment.Center,
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(16, 0, 0, 0)
        }, "VariablesRuntime"));
        root.Children.Add(actions);
        var status = new TextBlock
        {
            Text = "Reading DWARF debug symbols…", TextWrapping = TextWrapping.Wrap,
            Foreground = Brush("#AFC8E8"), FontSize = 12, LineHeight = 19
        };
        var statusPanel = HelpUi.Beside(new ScrollViewer
        {
            Content = status, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            MaxHeight = 108, Margin = new Thickness(0, 0, 0, 14)
        }, "VariablesStatus");
        Grid.SetRow(statusPanel, 1); root.Children.Add(statusPanel);
        ViewHost.Content = root;
        VariablesLoadTask = ReadVariablesAsync(document, snapshot, root, status, cancellation);
    }

    private async Task ReadVariablesAsync(PeDocument document, byte[] snapshot, Grid root, TextBlock status, CancellationTokenSource cancellation)
    {
        bool IsCurrent() => !cancellation.IsCancellationRequested && ReferenceEquals(Document, document)
            && ReferenceEquals(ViewHost.Content, root) && CurrentPage == "Variables";
        try
        {
            var result = await Task.Run(() => PeDwarfReader.Read(snapshot, cancellation.Token), cancellation.Token);
            if (!IsCurrent()) return;
            VariablesResult = result;
            var introduction = result.Status switch
            {
                DebugSymbolStatus.Available => "Recorded variable declarations decoded.",
                DebugSymbolStatus.Partial => "Partial symbol results — read the limitations below.",
                DebugSymbolStatus.NotFound => "No embedded DWARF variable information was found. Compile with GCC -g (or -g3) and retain the debug sections.",
                DebugSymbolStatus.Unsupported => "This debug format is not supported by the embedded DWARF reader. PDB and separate debug files are not loaded.",
                _ => "Debug information is damaged or inconsistent. Any recovered rows may be incomplete."
            };
            status.Text = $"{result.Status} · {result.Format} · {result.Variables.Count:N0} declarations\n{introduction}"
                + (result.Diagnostics.Count > 0 ? "\n" + string.Join("\n", result.Diagnostics) : "");
            status.Foreground = Brush(result.Status is DebugSymbolStatus.Available ? "#A8DACA" : "#DCC394");
            ShowTable(result.Variables.Select(v => new VariableRow(v)).ToArray(),
                ("NAME", "Name", 165), ("KIND", "Kind", 100), ("TYPE", "Type", 145),
                ("SCOPE", "Scope", 165), ("DECLARATION", "Declaration", 0), ("STORAGE", "Location", 200));
            var table = (UIElement)ViewHost.Content; ViewHost.Content = null;
            Grid.SetRow(table, 2); root.Children.Add(table); ViewHost.Content = root;
            ApplyFilter();
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        catch (Exception ex) when (IsExpected(ex))
        {
            if (IsCurrent()) status.Text = "Could not read variable symbols: " + ex.Message;
        }
        finally
        {
            if (ReferenceEquals(_variableRead, cancellation)) _variableRead = null;
            cancellation.Dispose();
        }
    }
}
