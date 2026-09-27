using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using PeWorkshop.Core;

namespace PeWorkshop.App;

internal static class ComparisonSmokeTest
{
    internal static void Run(MainWindow editor, string output)
    {
        var samples = ComparisonWindow.FindSamplesDirectory() ?? throw new InvalidOperationException("Build the Samples folder before running comparison smoke checks.");
        var before = editor.Document!.Data.ToArray();
        var view = new ComparisonWindow(editor) { ShowInTaskbar = false, WindowStartupLocation = WindowStartupLocation.Manual, Left = -20000, Top = -20000 };
        try
        {
            view.Show(); Pump();
            Descendants<Button>(view).Single(button => button.Content?.ToString() == "Console vs GUI").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            WaitUntil(() => view.Result is not null);
            Check(view.Result is { Identical: false }, "Console/GUI samples must compare successfully.");
            Check(view.Result!.Differences.Any(d => d.Title.Contains("Subsystem", StringComparison.OrdinalIgnoreCase)), "Comparison must explain the console/GUI subsystem difference.");
            Check(view.Result.Differences.Any(d => d.Explanation.Contains("window", StringComparison.OrdinalIgnoreCase)), "Console/GUI comparison needs a relevant explanation.");
            Capture(view, Path.Combine(output, "compare-console-gui.png"));
            Wait(view.LoadPairAsync(Path.Combine(samples, "OriginalConsole.exe"), Path.Combine(samples, "ModifiedConsole.exe")));
            var result = view.Result!;
            Check(result.DifferentByteCount > 0 && result.Differences.Any(d => d.Severity == DifferenceSeverity.Suspicious), "Modified sample must produce suspicious evidence.");
            Check(result.Differences.Any(d => d.Title.Contains("entry", StringComparison.OrdinalIgnoreCase) && d.Severity == DifferenceSeverity.Suspicious), "Redirected entry point must be explained and highlighted.");
            view.SetFindingFilter("", 2);
            Check(view.FindingsGrid.Items.Count > 0 && view.FindingsGrid.Items.Cast<PeDifference>().All(d => d.Severity == DifferenceSeverity.Suspicious), "Suspicious filter must restrict findings.");
            var selected = (PeDifference)view.FindingsGrid.SelectedItem;
            Check(view.Explanation.Contains(selected.Explanation, StringComparison.Ordinal), "Selection must show the complete explanation.");
            Check(view.Preview.VisibleRight.Contains("B · CANDIDATE", StringComparison.Ordinal), "Comparison must show candidate evidence bytes.");
            Capture(view, Path.Combine(output, "compare-modified.png"));
            view.Width = view.MinWidth; view.Height = view.MinHeight; Pump();
            Capture(view, Path.Combine(output, "compare-modified-small.png"));
            view.SetFindingFilter("no-such-finding-unique");
            Check(view.FindingsGrid.Items.Count == 0, "Text filter must handle no matches.");
            view.SetFindingFilter("");
            var raw = view.FindingsGrid.Items.Cast<PeDifference>().First(d => d.Category == "Bytes" && d.RightLength > 64);
            view.FindingsGrid.SelectedItem = raw; Pump();
            Descendants<Button>(view.Preview).Single(button => button.Content?.ToString() == "Next →").RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); Pump();
            Check(view.Preview.VisibleRight.Contains($"{raw.RightOffset!.Value + 64:X8}", StringComparison.Ordinal), "Next must reveal the next page of evidence.");
            var added = view.FindingsGrid.Items.Cast<PeDifference>().FirstOrDefault(d => d.LeftOffset is null && d.RightOffset is not null);
            Check(added is not null, "Added section/bytes must have no fabricated baseline offset.");
            view.FindingsGrid.SelectedItem = added; Pump();
            Check(view.Preview.VisibleLeft.Contains("No stored evidence", StringComparison.Ordinal), "Absent baseline evidence must be explicit.");
            Check(editor.Document.Data.Span.SequenceEqual(before) && !editor.Document.IsDirty, "Comparing and selecting findings must not edit the main document.");

            var candidate = File.ReadAllBytes(Path.Combine(samples, "ModifiedConsole.exe"));
            Descendants<Button>(view).Single(button => button.Content?.ToString() == "B in editor").RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); Pump();
            Check(!view.IsVisible && editor.Document.Data.Span.SequenceEqual(candidate), "Inspect must reveal the candidate in the editor without the comparison covering it.");
            var hex = Descendants<HexView>(editor).Single();
            Check(hex.HasEvidence && hex.SelectedOffset == added!.RightOffset!.Value, "Main hex editor must highlight the evidence range at the correct offset.");
            Check(!editor.Document!.IsDirty, "Evidence highlighting must not alter bytes.");
            Capture(editor, Path.Combine(output, "compare-editor-highlight.png"));
            editor.LoadDocument(new PeDocument(before));
            editor.Navigate("Hex"); Pump();
            Check(!Descendants<HexView>(editor).Single().HasEvidence, "Loading another document must clear old comparison highlights.");

            var previousResult = view.Result;
            var invalid = Path.Combine(output, "invalid-comparison.exe"); File.WriteAllBytes(invalid, [1, 2, 3]);
            Wait(view.LoadPairAsync(Path.Combine(samples, "OriginalConsole.exe"), invalid));
            Check(ReferenceEquals(previousResult, view.Result) && editor.Document.Data.Span.SequenceEqual(before), "A malformed comparison must preserve the prior report and editor document.");
            Check(Descendants<TextBlock>(view).Any(text => text.Text.StartsWith("Could not compare files:", StringComparison.Ordinal)), "Malformed comparison needs a visible error.");

            Wait(view.LoadPairAsync(Path.Combine(samples, "OriginalConsole.exe"), Path.Combine(samples, "OriginalConsole.exe")));
            Check(view.Result is { Identical: true } && view.FindingsGrid.Items.Count == 0, "Identical files must have no fabricated changes.");

            var unequal = new ComparisonBytePreview();
            unequal.Show(new byte[128], new byte[128], new PeDifference("Sections", "Growing section", "3 bytes", "80 bytes", "Synthetic range boundary check", DifferenceSeverity.Information, 0, 0, 3, 80));
            Descendants<Button>(unequal).Single(button => button.Content?.ToString() == "Next →").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Check(unequal.VisibleLeft.Contains("No stored evidence on this page", StringComparison.Ordinal), "A shorter evidence range must not reveal unrelated following bytes on later pages.");
            Check(unequal.VisibleRight.Contains("00000040", StringComparison.Ordinal) && !unequal.VisibleRight.Contains("00000050", StringComparison.Ordinal), "Longer evidence must stop at its own range boundary.");
        }
        finally { view.Close(); }
    }

    private static void Wait(Task task)
    {
        var deadline = DateTime.UtcNow.AddSeconds(45);
        while (!task.IsCompleted)
        {
            if (DateTime.UtcNow > deadline) throw new TimeoutException("Comparison did not complete in 45 seconds.");
            Pump(); Thread.Sleep(1);
        }
        task.GetAwaiter().GetResult(); Pump();
    }

    private static void WaitUntil(Func<bool> completed)
    {
        var deadline = DateTime.UtcNow.AddSeconds(45);
        while (!completed())
        {
            if (DateTime.UtcNow > deadline) throw new TimeoutException("Comparison action did not finish in 45 seconds.");
            Pump(); Thread.Sleep(1);
        }
        Pump();
    }

    private static void Capture(Window window, string path)
    {
        Pump(); var content = (FrameworkElement)window.Content;
        var image = new RenderTargetBitmap((int)Math.Ceiling(content.ActualWidth), (int)Math.Ceiling(content.ActualHeight), 96, 96, PixelFormats.Pbgra32);
        image.Render(content); var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(image));
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
