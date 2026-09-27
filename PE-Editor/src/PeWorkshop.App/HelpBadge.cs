using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;

namespace PeWorkshop.App;

/// <summary>A separate help target: reading help never invokes the neighboring action.</summary>
public sealed class HelpBadge : Button
{
    public static readonly DependencyProperty TopicProperty = DependencyProperty.Register(
        nameof(Topic), typeof(HelpTopic), typeof(HelpBadge), new PropertyMetadata(null, TopicChanged));
    public static readonly DependencyProperty TopicKeyProperty = DependencyProperty.Register(
        nameof(TopicKey), typeof(string), typeof(HelpBadge), new PropertyMetadata(null,
            (d, e) => ((HelpBadge)d).Topic = e.NewValue is string key ? PeHelpCatalog.Get(key) : null));

    private ToolTip? _hoverTip;
    private Popup? _popup;
    public HelpTopic? Topic { get => (HelpTopic?)GetValue(TopicProperty); set => SetValue(TopicProperty, value); }
    public string? TopicKey { get => (string?)GetValue(TopicKeyProperty); set => SetValue(TopicKeyProperty, value); }
    public bool IsHelpOpen => _popup?.IsOpen == true || _hoverTip?.IsOpen == true;

    public HelpBadge()
    {
        Style = (Style)Application.Current.FindResource("HelpBadgeStyle");
        Content = "i";
        ToolTipService.SetInitialShowDelay(this, 250);
        ToolTipService.SetShowDuration(this, 120000);
        ToolTipService.SetBetweenShowDelay(this, 100);
        ToolTipService.SetShowOnDisabled(this, true);
        Unloaded += (_, _) => CloseHelp();
    }

    public HelpBadge(string key) : this() => TopicKey = key;
    public HelpBadge(HelpTopic topic) : this() => Topic = topic;

    private static void TopicChanged(DependencyObject sender, DependencyPropertyChangedEventArgs args)
    {
        var badge = (HelpBadge)sender;
        badge.CloseHelp();
        if (args.NewValue is not HelpTopic topic) { badge.ToolTip = null; return; }
        AutomationProperties.SetName(badge, "Help: " + topic.Title);
        AutomationProperties.SetHelpText(badge, topic.Meaning + " " + topic.Usage + " " + topic.Editing);
        badge._hoverTip = new ToolTip
        {
            Content = HelpUi.TopicContent(topic), Placement = PlacementMode.Bottom,
            PlacementTarget = badge, MaxWidth = 420, Padding = new Thickness(16)
        };
        badge.ToolTip = badge._hoverTip;
    }

    protected override void OnClick()
    {
        // Do not raise a bubbling Click event through table headers or navigation items.
        if (_popup?.IsOpen == true) { CloseHelp(); return; }
        if (Topic is null) return;
        var returnFocus = Keyboard.FocusedElement;
        if (_hoverTip is not null) _hoverTip.IsOpen = false;
        var content = HelpUi.TopicContent(Topic);
        var scroller = new ScrollViewer
        {
            Content = content, MaxHeight = Math.Max(180, Math.Min(480, SystemParameters.WorkArea.Height - 90)),
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Focusable = true
        };
        var surface = new Border
        {
            Child = scroller, Background = HelpUi.Brush("#253247"), BorderBrush = HelpUi.Brush("#607A9D"),
            BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6), Padding = new Thickness(17), Width = 410
        };
        _popup = new Popup
        {
            Child = surface, PlacementTarget = this, Placement = PlacementMode.Bottom,
            AllowsTransparency = true, StaysOpen = false, PopupAnimation = PopupAnimation.Fade
        };
        surface.PreviewKeyDown += (_, e) =>
        {
            if (e.Key == Key.Escape) { CloseHelp(); Keyboard.Focus(returnFocus); e.Handled = true; }
        };
        _popup.Opened += (_, _) => scroller.Focus();
        _popup.IsOpen = true;
    }

    protected override void OnPreviewMouseDown(MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Left) { base.OnPreviewMouseDown(e); return; }
        // DataGridCell processes even handled bubbling mouse presses. Consume the
        // preview instead: MouseDevice then never promotes it to MouseDown. Avoid
        // ButtonBase's mouse focus change, which would also move the current cell.
        e.Handled = true;
        if (CaptureMouse()) IsPressed = true;
    }

    protected override void OnPreviewMouseUp(MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Left) { base.OnPreviewMouseUp(e); return; }
        e.Handled = true;
        // ButtonBase still tracks IsPressed during captured mouse moves and clears
        // it on capture loss, preserving drag-out cancellation and keyboard input.
        var activate = IsMouseCaptured && IsPressed;
        if (IsMouseCaptured) ReleaseMouseCapture();
        IsPressed = false;
        if (activate) OnClick();
    }

    protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
        if (e.Key == Key.Escape) { CloseHelp(); e.Handled = true; }
        else if (e.Key == Key.F1) { OnClick(); e.Handled = true; }
        else base.OnPreviewKeyDown(e);
    }

    public void CloseHelp()
    {
        if (_hoverTip is not null) _hoverTip.IsOpen = false;
        if (_popup is not null) _popup.IsOpen = false;
    }
}

public static class HelpUi
{
    public static FrameworkElement Beside(UIElement element, string key) => Beside(element, PeHelpCatalog.Get(key));

    public static FrameworkElement Beside(UIElement element, HelpTopic topic)
    {
        var row = new DockPanel { LastChildFill = true };
        var help = new HelpBadge(topic) { HorizontalAlignment = HorizontalAlignment.Left };
        DockPanel.SetDock(help, Dock.Right); row.Children.Add(help); row.Children.Add(element);
        return row;
    }

    public static FrameworkElement Label(string text, string key, bool compact = false)
    {
        return Beside(new TextBlock
        {
            Text = text, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis,
            Foreground = Brush("#A0B4CF"), FontSize = compact ? 10 : 12,
            FontWeight = compact ? FontWeights.SemiBold : FontWeights.Normal
        }, key);
    }

    public static StackPanel TopicContent(HelpTopic topic)
    {
        var content = new StackPanel { MaxWidth = 372 };
        content.Children.Add(new TextBlock
        {
            Text = topic.Title, FontSize = 16, FontWeight = FontWeights.SemiBold,
            Foreground = Brush("#F2F6FE"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 11)
        });
        AddParagraph(content, "", topic.Meaning);
        AddParagraph(content, "HOW TO USE IT", topic.Usage);
        AddParagraph(content, "WHAT TO KEEP IN MIND", topic.Editing);
        content.Children.Add(new TextBlock
        {
            Text = "Click i to keep help open · Esc or click outside to close",
            TextWrapping = TextWrapping.Wrap, FontSize = 10, Foreground = Brush("#9EB5D4"), Margin = new Thickness(0, 12, 0, 0)
        });
        return content;
    }

    private static void AddParagraph(Panel panel, string heading, string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return;
        if (heading.Length > 0) panel.Children.Add(new TextBlock
        {
            Text = heading, Foreground = Brush("#9EBDE6"), FontSize = 10, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 12, 0, 5)
        });
        panel.Children.Add(new TextBlock
        {
            Text = text, FontSize = 12, LineHeight = 18, Foreground = Brush("#DCE7F7"), TextWrapping = TextWrapping.Wrap
        });
    }

    internal static SolidColorBrush Brush(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)); brush.Freeze(); return brush;
    }
}
