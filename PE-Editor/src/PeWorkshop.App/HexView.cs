using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using PeWorkshop.Core;

namespace PeWorkshop.App;

/// <summary>Only visible rows are drawn; file size does not affect the visual tree.</summary>
public sealed class HexView : FrameworkElement
{
    private const double RowHeight = 24;
    private const double DataTop = 40;
    private const double HexLeft = 116;
    private const double ByteWidth = 27;
    private const double AsciiLeft = 576;
    private readonly Typeface _font = new("Consolas");
    private PeDocument? _document;
    private int _pendingNibble = -1;
    private int _evidenceOffset = -1, _evidenceLength;
    internal bool HasEvidence => _evidenceOffset >= 0 && _evidenceLength > 0;
    public int SelectedOffset { get; private set; }
    public int PageOffset { get; private set; }
    public int VisibleRows => Math.Max(1, (int)((ActualHeight - DataTop - 8) / RowHeight));
    public event Action<int>? SelectionChanged;
    public event Action<int, byte[]>? PatchRequested;

    public HexView()
    {
        Focusable = true;
        MinHeight = 180;
        MinWidth = 725;
        ClipToBounds = true;
        Cursor = Cursors.IBeam;
        ToolTip = "Click a byte and type two hex digits to replace it. Arrow keys move; mouse wheel scrolls.";
        System.Windows.Automation.AutomationProperties.SetName(this, "Hex bytes; use arrow keys to navigate and type two hexadecimal digits to edit");
    }

    public void SetDocument(PeDocument document)
    {
        if (!ReferenceEquals(_document, document)) ClearEvidence();
        _document = document;
        _pendingNibble = -1;
        SelectedOffset = Math.Clamp(SelectedOffset, 0, document.Data.Length - 1);
        PageOffset = Math.Clamp(PageOffset, 0, (document.Data.Length - 1) / 16 * 16);
        EnsureSelectionVisible();
        InvalidateVisual();
    }

    internal void HighlightEvidence(int offset, int length, string title)
    {
        if (_document is null || offset < 0 || offset >= _document.Data.Length) return;
        _evidenceOffset = offset; _evidenceLength = Math.Clamp(length, 1, _document.Data.Length - offset);
        ToolTip = $"Comparison evidence: {title}. Pink outlines mark the selected range; amber text marks unsaved edits.";
        GoTo(offset); InvalidateVisual();
    }

    internal void ClearEvidence()
    {
        _evidenceOffset = -1; _evidenceLength = 0;
        ToolTip = "Click a byte and type two hex digits to replace it. Arrow keys move; mouse wheel scrolls.";
        InvalidateVisual();
    }

    public void GoTo(int offset)
    {
        if (_document is null) return;
        SelectedOffset = Math.Clamp(offset, 0, _document.Data.Length - 1);
        EnsureSelectionVisible();
        _pendingNibble = -1;
        InvalidateVisual();
        SelectionChanged?.Invoke(SelectedOffset);
    }

    public void Page(int direction)
    {
        if (_document is null) return;
        Scroll(direction * VisibleRows * 16);
    }

    private void Scroll(int delta)
    {
        if (_document is null) return;
        var relativeOffset = Math.Clamp(SelectedOffset - PageOffset, 0, VisibleRows * 16 - 1);
        PageOffset = Math.Clamp(PageOffset + delta, 0, (_document.Data.Length - 1) / 16 * 16);
        SelectedOffset = Math.Min(PageOffset + relativeOffset, _document.Data.Length - 1);
        _pendingNibble = -1;
        InvalidateVisual();
        SelectionChanged?.Invoke(SelectedOffset);
    }

    private void EnsureSelectionVisible()
    {
        if (SelectedOffset < PageOffset || SelectedOffset >= PageOffset + VisibleRows * 16)
            PageOffset = SelectedOffset / 16 * 16;
    }

    protected override void OnRenderSizeChanged(SizeChangedInfo sizeInfo)
    {
        base.OnRenderSizeChanged(sizeInfo);
        EnsureSelectionVisible();
        InvalidateVisual();
        SelectionChanged?.Invoke(SelectedOffset);
    }

    protected override void OnRender(DrawingContext dc)
    {
        base.OnRender(dc);
        dc.DrawRectangle(Brush("#121923"), null, new Rect(RenderSize));
        dc.DrawRectangle(Brush("#1E2836"), null, new Rect(0, 0, ActualWidth, 32));
        Write(dc, "OFFSET", 18, 8, "#8EA5C2", 11);
        for (var col = 0; col < 16; col++) Write(dc, col.ToString("X2"), HexLeft + col * ByteWidth, 8, "#7790B0", 12);
        Write(dc, "DECODED TEXT", AsciiLeft, 8, "#8EA5C2", 11);
        if (_document is null) return;
        var bytes = _document.Data.Span;
        for (var row = 0; row < VisibleRows; row++)
        {
            var offset = PageOffset + row * 16;
            if (offset >= bytes.Length) break;
            var y = DataTop + row * RowHeight;
            Write(dc, offset.ToString("X8"), 18, y, "#7088A7");
            for (var col = 0; col < 16 && offset + col < bytes.Length; col++)
            {
                var index = offset + col;
                var selected = index == SelectedOffset;
                if (HasEvidence && index >= _evidenceOffset && index - _evidenceOffset < _evidenceLength)
                    dc.DrawRoundedRectangle(Brush("#59303F"), new Pen(Brush("#EE8BA7"), 1), new Rect(HexLeft + col * ByteWidth - 4, y - 3, 25, 22), 3, 3);
                if (selected)
                {
                    dc.DrawRoundedRectangle(Brush(IsKeyboardFocusWithin ? "#3B78CF" : "#2D517D"), null,
                        new Rect(HexLeft + col * ByteWidth - 4, y - 3, 25, 22), 3, 3);
                    dc.DrawRectangle(Brush("#294361"), null, new Rect(AsciiLeft + col * 8, y - 3, 8, 22));
                }
                var value = selected && _pendingNibble >= 0 ? $"{_pendingNibble:X}_" : bytes[index].ToString("X2");
                var color = selected ? "#FFFFFF" : _document.IsByteChanged(index) ? "#F4C179" : "#C3D3E9";
                Write(dc, value, HexLeft + col * ByteWidth, y, color);
                Write(dc, bytes[index] is >= 32 and < 127 ? ((char)bytes[index]).ToString() : "·", AsciiLeft + col * 8, y,
                    selected ? "#FFFFFF" : bytes[index] is >= 32 and < 127 ? "#95B6D8" : "#4F6680");
            }
        }
    }

    protected override void OnMouseDown(MouseButtonEventArgs e)
    {
        base.OnMouseDown(e);
        Focus();
        var point = e.GetPosition(this);
        var row = (int)((point.Y - DataTop) / RowHeight);
        var col = point.X >= AsciiLeft ? (int)((point.X - AsciiLeft) / 8) : (int)((point.X - HexLeft + 4) / ByteWidth);
        if (point.Y >= DataTop && point.X >= HexLeft - 4 && row < VisibleRows && col is >= 0 and < 16)
            GoTo(PageOffset + row * 16 + col);
        e.Handled = true;
    }

    protected override void OnMouseWheel(MouseWheelEventArgs e)
    {
        base.OnMouseWheel(e);
        if (_document is null) return;
        Scroll(-Math.Sign(e.Delta) * 48);
        e.Handled = true;
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        var next = e.Key switch
        {
            Key.Left => SelectedOffset - 1, Key.Right => SelectedOffset + 1,
            Key.Up => SelectedOffset - 16, Key.Down => SelectedOffset + 16,
            Key.PageUp => SelectedOffset - VisibleRows * 16, Key.PageDown => SelectedOffset + VisibleRows * 16,
            Key.Home => Keyboard.Modifiers.HasFlag(ModifierKeys.Control) ? 0 : SelectedOffset / 16 * 16,
            Key.End => Keyboard.Modifiers.HasFlag(ModifierKeys.Control) ? (_document?.Data.Length ?? 1) - 1 : SelectedOffset / 16 * 16 + 15,
            _ => -1
        };
        if (e.Key == Key.Escape) { _pendingNibble = -1; InvalidateVisual(); e.Handled = true; }
        if (next >= 0) { GoTo(next); e.Handled = true; }
    }

    protected override void OnTextInput(TextCompositionEventArgs e)
    {
        base.OnTextInput(e);
        if (_document is null || Keyboard.Modifiers.HasFlag(ModifierKeys.Control)) return;
        if (e.Text.Length != 1 || !int.TryParse(e.Text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var digit)) return;
        EnsureSelectionVisible();
        if (_pendingNibble < 0) _pendingNibble = digit;
        else
        {
            var value = (byte)((_pendingNibble << 4) | digit);
            _pendingNibble = -1;
            PatchRequested?.Invoke(SelectedOffset, [value]);
            GoTo(SelectedOffset + 1);
        }
        InvalidateVisual();
        e.Handled = true;
    }

    protected override void OnLostKeyboardFocus(KeyboardFocusChangedEventArgs e)
    {
        base.OnLostKeyboardFocus(e);
        _pendingNibble = -1;
        InvalidateVisual();
    }

    private void Write(DrawingContext dc, string text, double x, double y, string color, double size = 13) =>
        dc.DrawText(new FormattedText(text, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, _font, size,
            Brush(color), VisualTreeHelper.GetDpi(this).PixelsPerDip), new Point(x, y));

    private static SolidColorBrush Brush(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        brush.Freeze();
        return brush;
    }
}
