using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using PeWorkshop.Core;

namespace PeWorkshop.App;

/// <summary>Read-only bytes aligned to the selected finding's evidence on each side.</summary>
internal sealed class ComparisonBytePreview : Grid
{
    private readonly TextBlock _left = Pane();
    private readonly TextBlock _right = Pane();
    private readonly TextBlock _position = new() { Foreground = HelpUi.Brush("#9DB3D0"), FontSize = 11, VerticalAlignment = VerticalAlignment.Center };
    private readonly Button _previous = new() { Content = "← Previous", ToolTip = "Previous 64 evidence bytes", Padding = new Thickness(10, 3, 10, 3) };
    private readonly Button _next = new() { Content = "Next →", ToolTip = "Next 64 evidence bytes", Padding = new Thickness(10, 3, 10, 3) };
    private byte[] _a = [], _b = [];
    private PeDifference? _finding;
    private int _page;
    internal string VisibleLeft => new TextRange(_left.ContentStart, _left.ContentEnd).Text;
    internal string VisibleRight => new TextRange(_right.ContentStart, _right.ContentEnd).Text;

    public ComparisonBytePreview()
    {
        RowDefinitions.Add(new() { Height = GridLength.Auto });
        RowDefinitions.Add(new());
        RowDefinitions.Add(new() { Height = GridLength.Auto });
        ColumnDefinitions.Add(new()); ColumnDefinitions.Add(new());
        var header = new DockPanel();
        var controls = new StackPanel { Orientation = Orientation.Horizontal };
        controls.Children.Add(HelpUi.Beside(_previous, "CompareBytes")); controls.Children.Add(HelpUi.Beside(_next, "CompareBytes"));
        DockPanel.SetDock(controls, Dock.Right); header.Children.Add(controls);
        var caption = HelpUi.Beside(_position, "CompareBytes"); caption.HorizontalAlignment = HorizontalAlignment.Left;
        header.Children.Add(caption);
        SetColumnSpan(header, 2); Children.Add(header);
        SetRow(_left, 1); SetRow(_right, 1); SetColumn(_right, 1);
        Children.Add(_left); Children.Add(_right);
        var legend = new TextBlock
        {
            Text = "Pink: unequal bytes   ·   Amber: evidence range   ·   Each side starts at its own shown offset",
            Foreground = HelpUi.Brush("#AABED8"), FontSize = 10, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 5, 0, 0)
        };
        SetRow(legend, 2); SetColumnSpan(legend, 2); Children.Add(legend);
        _previous.Click += (_, _) => { _page = Math.Max(0, _page - 1); Draw(); };
        _next.Click += (_, _) => { _page++; Draw(); };
    }

    internal void Show(byte[] left, byte[] right, PeDifference? finding)
    { _a = left; _b = right; _finding = finding; _page = 0; Draw(); }

    private void Draw()
    {
        var pages = Math.Max(1, (Math.Max(_finding?.LeftLength ?? 0, _finding?.RightLength ?? 0) + 63) / 64);
        _page = Math.Clamp(_page, 0, pages - 1);
        _previous.IsEnabled = _page > 0; _next.IsEnabled = _page + 1 < pages;
        _position.Text = $"EVIDENCE BYTES · {_page + 1}/{pages}";
        DrawSide(_left, "A · BASELINE", _a, _b, _finding?.LeftOffset, _finding?.RightOffset, _finding?.LeftLength ?? 0, _finding?.RightLength ?? 0);
        DrawSide(_right, "B · CANDIDATE", _b, _a, _finding?.RightOffset, _finding?.LeftOffset, _finding?.RightLength ?? 0, _finding?.LeftLength ?? 0);
    }

    private void DrawSide(TextBlock target, string label, byte[] bytes, byte[] other, int? offset, int? otherOffset, int length, int otherLength)
    {
        target.Inlines.Clear(); target.Inlines.Add(new Run(label + "\n") { Foreground = HelpUi.Brush("#8FB8EE") });
        if (offset is null || offset < 0 || offset >= bytes.Length || length <= 0)
        { target.Inlines.Add("No stored evidence on this side."); return; }
        int available = Math.Min(length, bytes.Length - offset.Value);
        if (_page * 64 >= available)
        { target.Inlines.Add("No stored evidence on this page."); return; }
        for (var row = 0; row < 8; row++)
        {
            int relative = _page * 64 + row * 8, start = offset.Value + relative;
            if (relative >= available) break;
            target.Inlines.Add(new Run($"{start:X8}  ") { Foreground = HelpUi.Brush("#8CA4C4") });
            var ascii = new StringBuilder();
            for (var col = 0; col < 8; col++)
            {
                int index = start + col;
                if (relative + col >= available) { target.Inlines.Add("   "); continue; }
                long opposite = (long)(otherOffset ?? -1) + relative + col;
                bool differs = otherOffset is null || relative + col >= otherLength || opposite < 0 || opposite >= other.Length || bytes[index] != other[(int)opposite];
                var run = new Run(bytes[index].ToString("X2") + " ");
                if (differs) { run.Background = HelpUi.Brush("#633845"); run.Foreground = HelpUi.Brush("#FFE0E6"); }
                else if (relative + col < length) { run.Background = HelpUi.Brush("#57492C"); run.Foreground = HelpUi.Brush("#FFE6AC"); }
                target.Inlines.Add(run);
                ascii.Append(bytes[index] is >= 32 and <= 126 ? (char)bytes[index] : '·');
            }
            target.Inlines.Add(new Run(" " + ascii + "\n") { Foreground = HelpUi.Brush("#9DB1CA") });
        }
    }

    private static TextBlock Pane() => new()
    {
        FontFamily = new FontFamily("Consolas"), FontSize = 11, LineHeight = 20,
        Foreground = HelpUi.Brush("#D3DFEF"), Margin = new Thickness(0, 8, 10, 0)
    };
}
