using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using PeWorkshop.Core;

namespace PeWorkshop.App;

internal static class HelpSmokeTest
{
    public static void Run(MainWindow window, PeDocument document, string output)
    {
        // Inspect a native PE32+ file and our managed PE32 library, exercising both field layouts.
        foreach (var image in new[] { document.Image, PeImage.Parse(File.ReadAllBytes(typeof(PeImage).Assembly.Location)) })
            foreach (var field in image.Fields)
            {
                var topic = PeHelpCatalog.ForField(field);
                Check(topic.Meaning.Length > 30 && topic.Usage.Length > 20, $"Missing useful field help: {field.Group}/{field.Name}");
            }
        for (var index = 0; index < 16; index++) Check(PeHelpCatalog.ForDirectory(index).Meaning.Length > 30, "Missing directory help.");
        var coff = new PeField("COFF header", "Characteristics", 0, 2, 0, "");
        var section = new PeField("Section: .text", "Characteristics", 0, 4, 0, "");
        Check(PeHelpCatalog.ForField(coff) != PeHelpCatalog.ForField(section), "COFF and section flags need distinct explanations.");
        var certificate = new PeField("Directory: Certificate", "VirtualAddress", 0, 4, 0, "");
        var imports = new PeField("Directory: Import", "VirtualAddress", 0, 4, 0, "");
        Check(PeHelpCatalog.ForField(certificate) != PeHelpCatalog.ForField(imports), "Certificate offsets must not be explained as RVAs.");

        window.ShowInTaskbar = false;
        window.WindowStartupLocation = WindowStartupLocation.Manual;
        window.Left = -20000; window.Top = -20000;
        window.Show(); Pump();
        var before = document.Data.ToArray();
        foreach (var page in new[] { "Overview", "Headers", "Sections", "Directories", "Imports", "Exports", "Hex", "Changes" })
        {
            window.Navigate(page); window.UpdateLayout(); Pump();
            var badges = Descendants<HelpBadge>(window.ViewHost).ToArray();
            Check(badges.Length > 0, $"No help inside {page} view.");
            Check(badges.All(b => b.Topic is not null && b.ToolTip is ToolTip), $"Unbound help in {page}.");
        }
        window.Navigate("Headers"); window.UpdateLayout(); Pump();
        var table = Descendants<DataGrid>(window).Single();
        table.SelectedIndex = 1;
        table.CurrentCell = new DataGridCellInfo(table.SelectedItem, table.Columns[1]);
        Pump();
        var fieldBadge = Descendants<HelpBadge>(table).First(b => b.Topic?.Title == PeHelpCatalog.ForField(document.Image.Fields[0]).Title);
        var initialSelection = table.SelectedItem;
        var initialCell = table.CurrentCell;
        var initialTitle = window.SelectionTitle.Text;
        var initialDescription = window.SelectionDescription.Text;
        var selectionEvents = 0;
        table.SelectionChanged += (_, _) => selectionEvents++;
        MouseClick(fieldBadge);
        Check(table.SelectedItem == initialSelection, "Mouse field help must not select its unselected row.");
        Check(selectionEvents == 0, "Mouse field help must not transiently change row selection.");
        Check(table.CurrentCell == initialCell, "Mouse field help must preserve the current cell.");
        Check(window.SelectionTitle.Text == initialTitle && window.SelectionDescription.Text == initialDescription,
            "Mouse field help must preserve the current inspector.");
        Check(fieldBadge.IsHelpOpen, "Mouse press/release must open field help.");
        DismissWithEscape(fieldBadge);
        Check(table.SelectedItem == initialSelection && table.CurrentCell == initialCell,
            "Escape after mouse help must preserve selection and the current cell.");
        Check(window.SelectionTitle.Text == initialTitle && window.SelectionDescription.Text == initialDescription,
            "Escape after mouse help must preserve the inspector.");
        MouseClick(fieldBadge);
        DismissWithOutsideMouse(fieldBadge);
        Check(!fieldBadge.IsHelpOpen, "An outside mouse press must dismiss field help.");
        RaiseMouseButton(fieldBadge, Mouse.PreviewMouseDownEvent, Mouse.MouseDownEvent);
        Check(fieldBadge.IsPressed && !fieldBadge.IsHelpOpen, "Help must wait for mouse release.");
        fieldBadge.ReleaseMouseCapture();
        RaiseMouseButton(fieldBadge, Mouse.PreviewMouseUpEvent, Mouse.MouseUpEvent); Pump();
        Check(!fieldBadge.IsPressed && !fieldBadge.IsHelpOpen, "Losing capture must cancel a help press.");
        Invoke(fieldBadge); Check(fieldBadge.IsHelpOpen, "Clicking a field help icon must open help.");
        Check(table.SelectedItem == initialSelection, "Field help must not change row selection.");
        Check(table.Columns.All(c => c.SortDirection is null), "Field help must not sort the table.");
        DismissWithEscape(fieldBadge);
        Check(!fieldBadge.IsHelpOpen, "Escape must close help.");

        var headerBadge = Descendants<HelpBadge>((DependencyObject)table.Columns[0].Header).Single();
        MouseClick(headerBadge);
        Check(headerBadge.IsHelpOpen && table.Columns.All(c => c.SortDirection is null), "Mouse header help must open without sorting.");
        headerBadge.CloseHelp();

        var navBadge = Descendants<HelpBadge>(window.Navigation).First(b => b.TopicKey == "Hex");
        var pageBefore = window.Navigation.SelectedItem;
        var viewBefore = window.ViewHost.Content;
        MouseClick(navBadge);
        Check(navBadge.IsHelpOpen, "Mouse press/release must open navigation help.");
        Check(window.Navigation.SelectedItem == pageBefore && window.ViewHost.Content == viewBefore,
            "Mouse navigation help must preserve the selected page and its content.");
        navBadge.CloseHelp();
        Invoke(navBadge); Check(navBadge.IsHelpOpen, "Navigation help should open.");
        Check(window.Navigation.SelectedItem == pageBefore, "Reading navigation help must not navigate.");
        navBadge.CloseHelp();

        var saveBadge = Descendants<HelpBadge>(window).First(b => b.TopicKey == "SaveCopy");
        Invoke(saveBadge); Check(saveBadge.IsHelpOpen, "Save help should open independently of saving.");
        saveBadge.CloseHelp();
        saveBadge.Focus();
        var keySource = PresentationSource.FromVisual(saveBadge)!;
        saveBadge.RaiseEvent(new KeyEventArgs(Keyboard.PrimaryDevice, keySource, 0, Key.Enter) { RoutedEvent = Keyboard.KeyDownEvent });
        Pump(); Check(saveBadge.IsHelpOpen, "Keyboard Enter must activate the help icon.");
        DismissWithEscape(saveBadge);
        Check(AutomationProperties.GetName(saveBadge).StartsWith("Help: ", StringComparison.Ordinal), "Help needs an accessible name.");
        Check(document.Data.Span.SequenceEqual(before) && !document.IsDirty, "Reading help must never edit the document.");

        // Render explanatory content as well as the narrowest supported workspace.
        var example = new Border
        {
            Background = HelpUi.Brush("#253247"), Padding = new Thickness(20),
            Child = HelpUi.TopicContent(PeHelpCatalog.Get("RVA")), Width = 420
        };
        Render(example, 420, 410, Path.Combine(output, "help-rva.png"));
        window.Width = window.MinWidth; window.Height = window.MinHeight; Pump();
        window.Navigate("Overview"); Pump();
        Render((FrameworkElement)window.Content, 1034, 640, Path.Combine(output, "help-overview-small.png"));
        window.Navigate("Hex"); Pump();
        Render((FrameworkElement)window.Content, 1034, 640, Path.Combine(output, "help-hex-small.png"));
        window.Width = 1400; window.Height = 900;
        window.Navigate("Headers"); Pump();
        Render((FrameworkElement)window.Content, 1380, 820, Path.Combine(output, "help-headers.png"));
        foreach (var (width, height, size) in new[] { (1050d, 680d, "small"), (1400d, 900d, "normal") })
        {
            window.Width = width; window.Height = height; Pump();
            foreach (var page in new[] { "Overview", "Headers", "Sections", "Directories", "Imports", "Exports", "Hex", "Changes" })
            {
                window.Navigate(page); Pump();
                var previewTable = Descendants<DataGrid>(window.ViewHost).FirstOrDefault();
                if (previewTable?.Items.Count > 0) { previewTable.SelectedIndex = 0; Pump(); }
                CaptureWindow(window, Path.Combine(output, $"appearance-{page}-{size}.png"));
            }
        }
        CaptureDialogs(document, output);
        window.Width = 1400; window.Height = 900; window.Navigate("Overview"); window.Hide();
    }

    private static void CaptureDialogs(PeDocument document, string output)
    {
        var field = document.Image.Fields.Single(f => f.Group == "COFF header" && f.Name == "TimeDateStamp");
        foreach (var dialog in new Window[]
        {
            new EditFieldDialog(document, document.Image.Fields.Where(f => f.Group == "COFF header"), field),
            new RenameSectionDialog(document, document.Image.Sections[0])
        })
        {
            var name = dialog is EditFieldDialog ? "edit" : "rename";
            dialog.ShowInTaskbar = false; dialog.WindowStartupLocation = WindowStartupLocation.Manual;
            dialog.Left = -20000; dialog.Top = -20000;
            try
            {
                dialog.Show(); Pump();
                var dialogImage = CaptureWindow(dialog, Path.Combine(output, $"appearance-{name}.png"));
                var backgroundPixel = new byte[4];
                dialogImage.CopyPixels(new Int32Rect(2, 2, 1, 1), backgroundPixel, 4, 0);
                Check(backgroundPixel.Take(3).All(channel => channel < 70) && backgroundPixel[3] == 255,
                    $"The {name} dialog must have a dark surface behind its pale text.");
                if (dialog is EditFieldDialog)
                {
                    var selector = Descendants<ComboBox>(dialog).Single();
                    Check(Descendants<TextBlock>(selector).Any(text => text.Text == field.Name),
                        "The field selector must display the field name, not the internal PeField record.");
                }
                // Invalid values must keep the dialog open and leave the document intact.
                var original = document.Data.ToArray();
                Descendants<TextBox>(dialog).Single().Text = name == "edit" ? "invalid" : "Ω";
                Descendants<Button>(dialog).Single(b => b.IsDefault).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                Pump();
                Check(dialog.IsVisible && document.Data.Span.SequenceEqual(original), "Invalid dialog input must not apply an edit or dismiss the dialog.");
                CaptureWindow(dialog, Path.Combine(output, $"appearance-{name}-error.png"));
            }
            finally { dialog.Close(); }
        }
    }

    private static RenderTargetBitmap CaptureWindow(Window window, string path)
    {
        // Match the actual client area; fixed screenshot sizes can hide clipped controls.
        var content = (FrameworkElement)window.Content;
        var host = (FrameworkElement)VisualTreeHelper.GetParent(content);
        host.UpdateLayout();
        var image = new RenderTargetBitmap((int)Math.Ceiling(host.ActualWidth), (int)Math.Ceiling(host.ActualHeight), 96, 96, PixelFormats.Pbgra32);
        var background = new DrawingVisual();
        using (var drawing = background.RenderOpen())
            drawing.DrawRectangle(window.Background, null, new Rect(host.RenderSize));
        image.Render(background); image.Render(host);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(image));
        using var file = File.Create(path); encoder.Save(file);
        return image;
    }

    private static void MouseClick(HelpBadge badge)
    {
        // Follow MouseDevice's preview-to-bubble promotion. Raising only the direct
        // MouseLeftButtonDown event misses DataGridCell's handled-events class handler.
        RaiseMouseButton(badge, Mouse.PreviewMouseDownEvent, Mouse.MouseDownEvent);
        RaiseMouseButton(badge, Mouse.PreviewMouseUpEvent, Mouse.MouseUpEvent);
        Pump();
    }

    private static void RaiseMouseButton(UIElement target, RoutedEvent preview, RoutedEvent bubble)
    {
        var args = new MouseButtonEventArgs(Mouse.PrimaryDevice, Environment.TickCount, MouseButton.Left)
        { RoutedEvent = preview };
        target.RaiseEvent(args);
        if (!args.Handled)
        {
            args.RoutedEvent = bubble;
            target.RaiseEvent(args);
        }
    }

    private static void DismissWithOutsideMouse(HelpBadge badge)
    {
        var popupRoot = Mouse.Captured as UIElement;
        Check(popupRoot is not null && popupRoot != badge, "Open help must capture outside mouse input.");
        Check(popupRoot!.InputHitTest(Mouse.GetPosition(popupRoot)) is null,
            "Outside-click fixture requires the physical pointer outside the off-screen help popup.");
        RaiseMouseButton(popupRoot, Mouse.PreviewMouseDownEvent, Mouse.MouseDownEvent); Pump();
    }

    private static void Invoke(HelpBadge badge)
    {
        var peer = new ButtonAutomationPeer(badge);
        ((IInvokeProvider)peer.GetPattern(PatternInterface.Invoke)).Invoke(); Pump();
    }

    private static void DismissWithEscape(HelpBadge badge)
    {
        var focused = Keyboard.FocusedElement as UIElement ?? badge;
        focused.RaiseEvent(new KeyEventArgs(Keyboard.PrimaryDevice, PresentationSource.FromVisual(focused)!, 0, Key.Escape)
        { RoutedEvent = Keyboard.PreviewKeyDownEvent }); Pump();
    }

    private static void Pump()
    {
        var frame = new DispatcherFrame();
        Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() => frame.Continue = false));
        Dispatcher.PushFrame(frame);
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

    private static void Render(FrameworkElement element, int width, int height, string path)
    {
        element.Measure(new Size(width, height)); element.Arrange(new Rect(0, 0, width, height)); element.UpdateLayout();
        var image = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32); image.Render(element);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(image));
        using var file = File.Create(path); encoder.Save(file);
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
