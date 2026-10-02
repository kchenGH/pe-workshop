using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using PeWorkshop.Core;

namespace PeWorkshop.App;

internal static class VariablesSmokeTest
{
    internal static void Run(MainWindow window, string output)
    {
        Check(window.Navigation.Items.Cast<ListBoxItem>().Any(item => item.Tag?.ToString() == "Variables"), "Variables navigation must be available for DWARF inspection.");
        var original = window.Document!;
        var visible = window.IsVisible;
        var width = window.Width; var height = window.Height;
        var samples = ComparisonWindow.FindSamplesDirectory() ?? throw new InvalidOperationException("Missing Samples directory.");
        var bytes = File.ReadAllBytes(Path.Combine(samples, "DebugSymbolsDemo.exe"));
        var document = new PeDocument(bytes);
        var welcome = new MainWindow { ShowInTaskbar = false, WindowStartupLocation = WindowStartupLocation.Manual, Left = -20000, Top = -20000 };
        try
        {
            welcome.Width = welcome.MinWidth; welcome.Height = welcome.MinHeight; welcome.Show(); Pump();
            Capture(welcome, Path.Combine(output, "welcome-small.png"));
            var shortcut = Descendants<Button>(welcome).Single(b => b.Content?.ToString() == "Explore debug symbols →");
            Check(shortcut.IsVisible && shortcut.ActualHeight > 0, "Welcome screen must expose the debug sample shortcut.");
            shortcut.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); Wait(welcome.VariablesLoadTask);
            Check(welcome.VariablesResult is { Status: DebugSymbolStatus.Available } && welcome.SidebarFile.Text == "DebugSymbolsDemo.exe", "Welcome shortcut must open the real debug sample in Variables.");
        }
        finally { welcome.Close(); }
        try
        {
            window.Show(); Pump();
            window.LoadDocument(document); window.Navigate("Variables"); Wait(window.VariablesLoadTask);
            var result = window.VariablesResult ?? throw new InvalidOperationException("Symbol read returned no result.");
            Check(result.Status == DebugSymbolStatus.Available, "Supplied DWARF sample must decode completely: " + string.Join("; ", result.Diagnostics));
            var local = result.Variables.Single(v => v.Name == "local_total");
            Check(local.Kind == "Local" && local.Type.Contains("int") && local.Scope.Contains("compute_score"), "Real local must have its name, type and function scope.");
            Check(local.SourceFile.EndsWith("debug_symbols.c") && local.Line > 0, "Real local must have its source declaration.");
            var grid = Descendants<DataGrid>(window.ViewHost).Single();
            Check(grid.Items.Count == result.Variables.Count, "All decoded declarations must reach the table.");
            window.FilterBox.Text = "local_total"; Pump();
            Check(grid.Items.Count == 1, "Variables must filter by source name.");
            grid.SelectedIndex = 0; Pump();
            Check(window.SelectionDescription.Text.Contains(local.Location) && window.SelectionDescription.Text.Contains("no current runtime value"), "Selection must explain storage and the runtime-value limit.");
            Check(window.EditButton.Visibility == Visibility.Collapsed && window.RevealHelp.TopicKey == "VariableReveal", "Variables must use read-only symbol actions and help.");
            foreach (var key in new[] { "Variables", "VariablesSample", "VariablesRuntime", "VariablesStatus", "VariableName", "VariableKind", "VariableType", "VariableScope", "VariableDeclaration", "VariableLocation", "VariableReveal" })
            {
                var topic = PeHelpCatalog.Get(key);
                Check(topic.Meaning.Length > 40 && topic.Usage.Length > 40 && topic.Editing.Length > 40, "Detailed symbol help missing: " + key);
            }
            var help = Descendants<HelpBadge>(grid).First(b => b.Topic?.Title == PeHelpCatalog.Get("VariableName").Title);
            var selection = grid.SelectedItem;
            var peer = System.Windows.Automation.Peers.UIElementAutomationPeer.CreatePeerForElement(help);
            ((System.Windows.Automation.Provider.IInvokeProvider)peer!.GetPattern(System.Windows.Automation.Peers.PatternInterface.Invoke)!).Invoke(); Pump();
            Check(help.IsHelpOpen && ReferenceEquals(selection, grid.SelectedItem) && !document.IsDirty, "Variable help must open without changing selection or bytes.");
            help.CloseHelp();
            window.FilterBox.Text = ""; Pump();
            Capture(window, Path.Combine(output, "variables.png"));
            window.Width = window.MinWidth; window.Height = window.MinHeight; Pump();
            Capture(window, Path.Combine(output, "variables-small.png"));
            Check(grid.ActualHeight >= 80 && window.RevealButton.IsVisible, $"Variable table and action must remain usable at minimum size (table height {grid.ActualHeight}, action visible {window.RevealButton.IsVisible}).");
            window.Width = width; window.Height = height; Pump();
            window.RevealButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); Pump();
            var hex = Descendants<HexView>(window).Single();
            Check(hex.SelectedOffset == local.DebugOffset && hex.HasEvidence, "View symbol must highlight its actual DWARF record.");
            Check(hex.ToolTip.ToString()!.Contains("DWARF record: local_total"), "Hex highlight must identify the symbol metadata.");
            Capture(window, Path.Combine(output, "variable-record.png"));
            Check(document.Data.Span.SequenceEqual(bytes) && !document.IsDirty, "Variable inspection must preserve file bytes.");

            window.Navigate("Variables"); var pending = window.VariablesLoadTask;
            window.Navigate("Headers"); var headers = window.ViewHost.Content; Wait(pending);
            Check(ReferenceEquals(headers, window.ViewHost.Content), "A late symbol result must not replace another page.");
            window.Navigate("Variables"); pending = window.VariablesLoadTask;
            window.LoadDocument(PeDocument.Open(Path.Combine(samples, "OriginalConsole.exe")));
            window.Navigate("Variables"); var replacement = window.VariablesLoadTask;
            Wait(pending); Wait(replacement);
            Check(window.VariablesResult is { Status: DebugSymbolStatus.NotFound, Variables.Count: 0 }, "New files must replace stale symbols and explain absent debug information.");
            Check(Descendants<TextBlock>(window.ViewHost).Any(t => t.Text.Contains("Compile with GCC")), "Absent symbols need compilation guidance.");
            Capture(window, Path.Combine(output, "variables-absent.png"));

            window.LoadDocument(document); window.Navigate("Variables"); pending = window.VariablesLoadTask;
            var section = document.Image.Sections.Single(s => s.Name == ".debug_info");
            document.ApplyPatch((int)section.RawOffset, Enumerable.Repeat((byte)0xFF, 12).ToArray(), "Malformed DWARF length for smoke test");
            window.RefreshWorkspace(); replacement = window.VariablesLoadTask;
            Wait(pending); Wait(replacement);
            Check(window.VariablesResult is { Status: DebugSymbolStatus.Malformed or DebugSymbolStatus.Partial }, "Edited malformed symbols must replace stale results with diagnostics.");
            Check(window.VariablesResult!.Diagnostics.Count > 0, "Malformed symbols must explain the error.");
            Capture(window, Path.Combine(output, "variables-malformed.png"));
            document.Undo(); window.RefreshWorkspace(); Wait(window.VariablesLoadTask);
            Check(window.VariablesResult is { Status: DebugSymbolStatus.Available } && !document.IsDirty, "Undo must refresh symbols from restored bytes.");
        }
        finally { window.Width = width; window.Height = height; window.LoadDocument(original); if (!visible) window.Hide(); }
    }

    private static void Wait(Task task)
    {
        var deadline = DateTime.UtcNow.AddSeconds(45);
        while (!task.IsCompleted)
        {
            if (DateTime.UtcNow > deadline) throw new TimeoutException("Symbol loading did not complete in 45 seconds.");
            Pump(); Thread.Sleep(1);
        }
        task.GetAwaiter().GetResult(); Pump();
    }
    private static void Capture(Window window, string path)
    {
        Pump(); var content = (FrameworkElement)window.Content;
        var bitmap = new RenderTargetBitmap((int)Math.Ceiling(content.ActualWidth), (int)Math.Ceiling(content.ActualHeight), 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(content); var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var stream = File.Create(path); encoder.Save(stream);
    }
    private static void Pump()
    { var frame = new DispatcherFrame(); Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() => frame.Continue = false)); Dispatcher.PushFrame(frame); }
    private static IEnumerable<T> Descendants<T>(DependencyObject root) where T : DependencyObject
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i); if (child is T value) yield return value;
            foreach (var descendant in Descendants<T>(child)) yield return descendant;
        }
    }
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
