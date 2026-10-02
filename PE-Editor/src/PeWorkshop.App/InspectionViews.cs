using System.Collections;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using PeWorkshop.Core;

namespace PeWorkshop.App;

public partial class MainWindow
{
    private sealed record SectionRow(PeSection Value)
    {
        public string Name => Value.Name;
        public string Rva => $"0x{Value.VirtualAddress:X8}";
        public string VirtualSize => $"0x{Value.VirtualSize:X8}";
        public string Offset => $"0x{Value.RawOffset:X8}";
        public string Size => UiInput.Bytes(Value.RawSize);
        public string Permissions => Value.Permissions;
        public string Flags => $"0x{Value.Characteristics:X8}";
        public override string ToString() => $"{Name} {Rva} {VirtualSize} {Offset} {Size} {Permissions} {Flags}";
    }

    private sealed record DirectoryRow(PeDirectory Value)
    {
        public string Name => Value.Name;
        public int Index => Value.Index;
        public string Address => $"0x{Value.Address:X8}";
        public string Size => $"0x{Value.Size:X8}";
        public string Offset => Value.FileOffset is { } offset ? $"0x{offset:X8}" : "—";
        public string AddressType => Value.Index == 4 ? "File offset" : "RVA";
        public override string ToString() => $"{Index} {Name} {Address} {Size} {Offset} {AddressType}";
    }

    private sealed record ImportRow(PeImport Value)
    {
        public string Module => Value.Module;
        public string Name => Value.Ordinal is { } ordinal ? $"Ordinal #{ordinal}" : Value.Name;
        public string Hint => Value.Ordinal is not null ? "—" : $"0x{Value.Hint:X4}";
        public string Iat => $"0x{Value.IatRva:X8}";
        public override string ToString() => $"{Module} {Name} {Hint} {Iat}";
    }

    private sealed record ExportRow(PeExport Value)
    {
        public string Name => string.IsNullOrEmpty(Value.Name) ? "(ordinal only)" : Value.Name;
        public uint Ordinal => Value.Ordinal;
        public string Rva => $"0x{Value.Rva:X8}";
        public string Forwarder => Value.Forwarder ?? "—";
        public override string ToString() => $"{Name} {Ordinal} {Rva} {Forwarder}";
    }

    private sealed record ChangeRow(EditRecord Value)
    {
        public string Offset => Value.OffsetHex;
        public string Description => Value.Description;
        public int Length => Value.After.Length;
        public string Before => Preview(Value.Before);
        public string After => Preview(Value.After);
        private static string Preview(byte[] bytes) => string.Join(" ", bytes.Take(12).Select(b => b.ToString("X2"))) + (bytes.Length > 12 ? " …" : "");
        public override string ToString() => $"{Offset} {Description} {Length} {Before} {After}";
    }

    private void ShowFields(IEnumerable<PeField> fields) => ShowTable(fields.ToArray(),
        ("FIELD", "Name", 275), ("VALUE", "HexValue", 180), ("FILE OFFSET", "OffsetHex", 145), ("BYTES", "Size", 90), ("GROUP", "Group", 0));

    private void ShowSections()
    {
        if (Document is null) return;
        ShowTable(Document.Image.Sections.Select(s => new SectionRow(s)).ToArray(),
            ("NAME", "Name", 110), ("RVA", "Rva", 120), ("VIRTUAL SIZE", "VirtualSize", 120),
            ("RAW OFFSET", "Offset", 120), ("RAW SIZE", "Size", 105), ("ACCESS", "Permissions", 85), ("FLAGS", "Flags", 0));
        var dock = new DockPanel();
        var bar = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };
        var rename = new Button { Content = "Rename selected section" };
        rename.Click += (_, _) =>
        {
            if (_selected is not SectionRow row) { SetStatus("Select a section first."); return; }
            var dialog = new RenameSectionDialog(Document, row.Value) { Owner = this };
            if (dialog.ShowDialog() == true) { RefreshWorkspace(); SetStatus("Section renamed"); }
        };
        bar.Children.Add(HelpUi.Beside(rename, "RenameSection"));
        bar.Children.Add(HelpUi.Beside(new TextBlock { Text = "R  read     W  write     X  execute", Foreground = Brush("#7F97B5"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(18, 0, 0, 0), FontFamily = new FontFamily("Consolas"), FontSize = 12 }, "Permissions"));
        DockPanel.SetDock(bar, Dock.Top); dock.Children.Add(bar);
        var tableView = (UIElement)ViewHost.Content;
        ViewHost.Content = null;
        dock.Children.Add(tableView); ViewHost.Content = dock;
    }

    private void ShowDirectories()
    {
        if (Document is null) return;
        ShowTable(Document.Image.Directories.Select(d => new DirectoryRow(d)).ToArray(),
            ("#", "Index", 46), ("DIRECTORY", "Name", 0), ("ADDRESS", "Address", 130), ("SIZE", "Size", 120), ("FILE OFFSET", "Offset", 130), ("ADDRESS TYPE", "AddressType", 120));
    }

    private void ShowImports()
    {
        if (Document is null) return;
        ShowTable(Document.Image.Imports.Select(i => new ImportRow(i)).ToArray(),
            ("MODULE", "Module", 185), ("SYMBOL", "Name", 0), ("HINT", "Hint", 90), ("IAT RVA", "Iat", 130));
    }

    private void ShowExports()
    {
        if (Document is null) return;
        ShowTable(Document.Image.Exports.Select(e => new ExportRow(e)).ToArray(),
            ("SYMBOL", "Name", 0), ("ORDINAL", "Ordinal", 85), ("RVA", "Rva", 135), ("FORWARDER", "Forwarder", 210));
    }

    private void ShowChanges()
    {
        if (Document is null) return;
        ShowTable(Document.Changes.Reverse().Select(c => new ChangeRow(c)).ToArray(),
            ("DESCRIPTION", "Description", 0), ("OFFSET", "Offset", 120), ("BYTES", "Length", 64), ("BEFORE", "Before", 185), ("AFTER", "After", 185));
    }

    private void ShowTable(IEnumerable items, params (string Title, string Path, double Width)[] columns)
    {
        var grid = new DataGrid { ItemsSource = items };
        foreach (var column in columns)
        {
            DataGridColumn gridColumn;
            if (column.Path == "Name")
            {
                var row = new FrameworkElementFactory(typeof(DockPanel));
                var help = new FrameworkElementFactory(typeof(HelpBadge));
                help.SetValue(DockPanel.DockProperty, Dock.Right);
                help.SetBinding(HelpBadge.TopicProperty, new Binding { Converter = new RowTopicConverter() });
                row.AppendChild(help);
                var label = new FrameworkElementFactory(typeof(TextBlock));
                label.SetBinding(TextBlock.TextProperty, new Binding(column.Path));
                label.SetValue(TextBlock.FontFamilyProperty, new FontFamily("Consolas"));
                label.SetValue(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis);
                label.SetValue(VerticalAlignmentProperty, VerticalAlignment.Center);
                row.AppendChild(label);
                gridColumn = new DataGridTemplateColumn { CellTemplate = new DataTemplate { VisualTree = row }, SortMemberPath = column.Path };
            }
            else gridColumn = new DataGridTextColumn
            {
                Binding = new Binding(column.Path),
                ElementStyle = new Style(typeof(TextBlock))
                {
                    Setters = { new Setter(TextBlock.FontFamilyProperty, new FontFamily("Consolas")), new Setter(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis) }
                }
            };
            gridColumn.Header = HelpUi.Label(column.Title, ColumnHelp(column.Path), compact: true);
            gridColumn.Width = column.Width == 0 ? new DataGridLength(1, DataGridLengthUnitType.Star) : new DataGridLength(Math.Max(column.Width, column.Title.Length * 7 + 52));
            gridColumn.MinWidth = 75;
            grid.Columns.Add(gridColumn);
        }
        grid.SelectionChanged += (_, _) => SelectionChanged(grid.SelectedItem);
        grid.MouseDoubleClick += (_, e) =>
        {
            if (!IsHelpTarget(e.OriginalSource as DependencyObject) && ItemsControl.ContainerFromElement(grid, e.OriginalSource as DependencyObject) is DataGridRow) EditSelected();
        };
        var container = new Grid();
        container.Children.Add(grid);
        if (!items.Cast<object>().Any())
        {
            container.Children.Add(new TextBlock
            {
                Text = CurrentPage == "Changes" ? "Your edits will appear here. Select a header or a byte to make a change."
                    : CurrentPage == "Variables" ? "No variable declarations were decoded. See the symbol status above."
                    : "No entries in this table. Check Overview for any parsing diagnostics.",
                Foreground = Brush("#849BB9"), HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(30), IsHitTestVisible = false
            });
        }
        _activeTable = grid;
        ViewHost.Content = container;
    }

    private string ColumnHelp(string path) => (CurrentPage, path) switch
    {
        ("Headers", "Name") => "Field", ("Headers", "Size") => "ByteCount", ("Headers", "HexValue") => "Value",
        ("Headers", "OffsetHex") => "Offset", (_, "Group") => "Group",
        ("Sections", "Name") => "SectionName", ("Sections", "Rva") => "RVA", ("Sections", "VirtualSize") => "VirtualSize",
        ("Sections", "Offset") => "RawOffset", ("Sections", "Size") => "RawSize", (_, "Permissions") => "Permissions", (_, "Flags") => "SectionFlags",
        ("Directories", "Index") => "DirectoryIndex", ("Directories", "Name") => "DirectoryName", ("Directories", "Address") => "DirectoryAddress",
        ("Directories", "Size") => "DirectorySize", (_, "AddressType") => "AddressType",
        (_, "Module") => "Module", ("Imports", "Name") => "ImportSymbol", ("Exports", "Name") => "ExportSymbol",
        ("Variables", "Name") => "VariableName", ("Variables", "Kind") => "VariableKind", ("Variables", "Type") => "VariableType",
        ("Variables", "Scope") => "VariableScope", ("Variables", "Declaration") => "VariableDeclaration", ("Variables", "Location") => "VariableLocation",
        (_, "Hint") => "Hint", (_, "Iat") => "IAT", (_, "Ordinal") => "Ordinal", (_, "Forwarder") => "Forwarder",
        (_, "Rva") => "RVA", (_, "Offset") => "Offset", (_, "Description") => "Description",
        (_, "Length") => "ByteCount", (_, "Before") => "Before", (_, "After") => "After",
        _ => throw new InvalidOperationException($"Missing column help for {CurrentPage}/{path}.")
    };

    private static HelpTopic RowTopic(object item) => item switch
    {
        PeField field => PeHelpCatalog.ForField(field),
        SectionRow section => PeHelpCatalog.ForSection(section.Name),
        DirectoryRow directory => PeHelpCatalog.ForDirectory(directory.Index),
        ImportRow => PeHelpCatalog.Get("ImportSymbol"), ExportRow => PeHelpCatalog.Get("ExportSymbol"),
        ChangeRow => PeHelpCatalog.Get("Changes"), VariableRow => PeHelpCatalog.Get("VariableName"), _ => PeHelpCatalog.Get("Field")
    };

    private sealed class RowTopicConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => RowTopic(value);
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
    }

    private static bool IsHelpTarget(DependencyObject? element)
    {
        while (element is not null)
        {
            if (element is HelpBadge) return true;
            element = element is Visual ? VisualTreeHelper.GetParent(element) : LogicalTreeHelper.GetParent(element);
        }
        return false;
    }

    private void ApplyFilter()
    {
        if (_activeTable is null) return;
        var query = FilterBox.Text.Trim();
        var view = CollectionViewSource.GetDefaultView(_activeTable.ItemsSource);
        view.Filter = string.IsNullOrEmpty(query) ? null : item =>
        {
            var text = item is PeField field ? $"{field.Name} {field.HexValue} {field.OffsetHex} {field.Group} {field.Description}" : item.ToString();
            return text?.Contains(query, StringComparison.OrdinalIgnoreCase) == true;
        };
    }

    private void SelectionChanged(object? selected)
    {
        _selected = selected;
        InspectorPanel.Visibility = selected is null ? Visibility.Collapsed : Visibility.Visible;
        EditButton.Visibility = selected is PeField or SectionRow or DirectoryRow ? Visibility.Visible : Visibility.Collapsed;
        EditHelp.Visibility = EditButton.Visibility;
        SelectionHelp.Topic = selected is null ? null : RowTopic(selected);
        RevealButton.IsEnabled = true;
        RevealButton.Content = selected is VariableRow ? "View symbol in hex" : "View in hex";
        RevealHelp.TopicKey = selected is VariableRow ? "VariableReveal" : "Reveal";
        switch (selected)
        {
            case PeField field:
                SelectionTitle.Text = $"{field.Name}  ·  {field.HexValue}";
                SelectionDescription.Text = $"{field.OffsetHex} · {field.Size} bytes · {field.Description}"; break;
            case SectionRow section:
                SelectionTitle.Text = $"{section.Name}  ·  {section.Permissions}";
                SelectionDescription.Text = $"Virtual address {section.Rva} · Raw offset {section.Offset} · Flags {section.Flags}"; break;
            case DirectoryRow directory:
                SelectionTitle.Text = directory.Name;
                SelectionDescription.Text = $"{directory.AddressType} {directory.Address} · {directory.Size} bytes · Double-click to edit the address or size.";
                RevealButton.IsEnabled = directory.Value.FileOffset is not null; break;
            case ImportRow import:
                SelectionTitle.Text = $"{import.Module} ! {import.Name}";
                SelectionDescription.Text = $"Import address table RVA {import.Iat}"; break;
            case ExportRow export:
                SelectionTitle.Text = export.Name;
                SelectionDescription.Text = $"Ordinal {export.Ordinal} · RVA {export.Rva} · Forwarder {export.Forwarder}"; break;
            case ChangeRow change:
                SelectionTitle.Text = change.Description;
                SelectionDescription.Text = $"{change.Offset} · {change.Length} bytes changed · Ctrl+Z to undo the latest edit"; break;
            case VariableRow variable:
                SelectionTitle.Text = $"{variable.Name} · {variable.Type}";
                SelectionDescription.Text = $"{variable.Kind} · Scope: {variable.Scope}\nDeclaration: {variable.Declaration}\nStorage: {variable.Location}\nSymbol record at 0x{variable.Value.DebugOffset:X8}; no current runtime value is available.";
                RevealButton.IsEnabled = Document is not null && variable.Value.DebugOffset >= 0 && variable.Value.DebugLength > 0
                    && (long)variable.Value.DebugOffset + variable.Value.DebugLength <= Document.Data.Length;
                break;
        }
    }

    private UIElement BuildOverview()
    {
        var document = Document!;
        var image = document.Image;
        var content = new StackPanel();
        var cards = new Grid { Margin = new Thickness(0, 0, 0, 22) };
        for (var i = 0; i < 4; i++) cards.ColumnDefinitions.Add(new ColumnDefinition());
        AddCard(cards, 0, "FORMAT", image.Is64Bit ? "PE32+" : "PE32", image.Is64Bit ? "64-bit image" : "32-bit image");
        AddCard(cards, 1, "ARCHITECTURE", image.Architecture, $"Machine  0x{image.Machine:X4}");
        AddCard(cards, 2, "FILE SIZE", UiInput.Bytes(document.Data.Length), $"{document.Data.Length:N0} bytes on disk");
        AddCard(cards, 3, "SECTIONS", image.Sections.Count.ToString(CultureInfo.InvariantCulture), $"{image.Imports.Count:N0} imports  ·  {image.Exports.Count:N0} exports");
        content.Children.Add(cards);
        content.Children.Add(HelpUi.Label("IMAGE STRUCTURE", "ImageStructure", compact: true));
        var map = new Grid { Height = 40, Margin = new Thickness(0, 12, 0, 10) };
        var colors = new[] { "#497BBD", "#437F86", "#746CAC", "#997B4E", "#527890", "#8F6380" };
        var nonempty = image.Sections.Where(s => s.RawSize > 0).ToArray();
        for (var i = 0; i < nonempty.Length; i++)
        {
            var section = nonempty[i];
            map.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(section.RawSize, GridUnitType.Star), MinWidth = nonempty.Length <= 16 ? 42 : 0 });
            var part = new Border { Background = Brush(colors[i % colors.Length]), Margin = new Thickness(0, 0, 3, 0), CornerRadius = new CornerRadius(3), ToolTip = $"{section.Name} · {UiInput.Bytes(section.RawSize)} · RVA 0x{section.VirtualAddress:X8}", Cursor = System.Windows.Input.Cursors.Hand };
            part.Child = new TextBlock { Text = nonempty.Length <= 16 ? section.Name : "", FontFamily = new FontFamily("Consolas"), FontSize = 11, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            part.MouseLeftButtonUp += (_, _) => { Navigate("Hex"); _hex?.GoTo((int)section.RawOffset); };
            Grid.SetColumn(part, i); map.Children.Add(part);
        }
        content.Children.Add(map);
        var legend = new WrapPanel { Margin = new Thickness(0, 0, 0, 10) };
        for (var i = 0; i < nonempty.Length; i++)
        {
            var label = new TextBlock { Text = nonempty[i].Name, Foreground = Brush("#BACCE3"), FontFamily = new FontFamily("Consolas"), FontSize = 11, VerticalAlignment = VerticalAlignment.Center };
            var item = HelpUi.Beside(label, PeHelpCatalog.ForSection(nonempty[i].Name));
            item.Margin = new Thickness(0, 0, 14, 5);
            legend.Children.Add(item);
        }
        content.Children.Add(legend);
        content.Children.Add(new TextBlock { Text = "Raw section sizes · Select a section to inspect its bytes", Foreground = Brush("#758BA8"), FontSize = 11, Margin = new Thickness(0, 0, 0, 24) });

        var details = new Grid { Margin = new Thickness(0, 0, 0, 22) };
        details.ColumnDefinitions.Add(new ColumnDefinition()); details.ColumnDefinitions.Add(new ColumnDefinition());
        var left = new StackPanel { Margin = new Thickness(0, 0, 20, 0) };
        var right = new StackPanel();
        left.Children.Add(HelpUi.Label("IMAGE METADATA", "ImageMetadata", compact: true)); right.Children.Add(HelpUi.Label("FILE DETAILS", "FileDetails", compact: true));
        AddMetadata(left, "Entry point RVA", $"0x{image.EntryPoint:X8}", "EntryPoint");
        AddMetadata(left, "Image base", $"0x{image.ImageBase:X16}", "ImageBase");
        AddMetadata(left, "Image size", $"0x{image.SizeOfImage:X8}", "ImageSize");
        AddMetadata(left, "Subsystem", SubsystemName(image.Subsystem), "Subsystem");
        AddMetadata(right, "PE header offset", $"0x{image.PeOffset:X8}", "PeOffset");
        AddMetadata(right, "Header size", $"0x{image.SizeOfHeaders:X8}", "HeaderSize");
        AddMetadata(right, "Stored checksum", $"0x{image.StoredChecksum:X8}", "Checksum");
        AddMetadata(right, "COFF timestamp", $"0x{image.TimeDateStamp:X8}", "Timestamp");
        Grid.SetColumn(right, 1); details.Children.Add(left); details.Children.Add(right); content.Children.Add(details);

        var diagnostics = new StackPanel();
        diagnostics.Children.Add(HelpUi.Beside(new TextBlock { Text = image.Warnings.Count == 0 ? "Structure parsed successfully" : $"{image.Warnings.Count} parsing diagnostics", FontWeight = FontWeights.SemiBold, Foreground = Brush(image.Warnings.Count == 0 ? "#92D8C0" : "#EAC181") }, "Diagnostics"));
        diagnostics.Children.Add(HelpUi.Beside(new TextBlock { Text = image.HasCertificate ? "Embedded certificate data is present. Edits can invalidate the signature; certificate trust is not verified." : "No embedded certificate table. Catalog signatures are not checked.", Foreground = Brush("#99B0C9"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 9, 0, 0), FontSize = 12 }, "Certificate"));
        foreach (var warning in image.Warnings)
            diagnostics.Children.Add(new TextBlock { Text = "• " + warning, Foreground = Brush("#D7B98B"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 7, 0, 0), FontSize = 12 });
        content.Children.Add(new Border { Background = Brush("#172833"), BorderBrush = Brush("#284556"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6), Padding = new Thickness(17), Child = diagnostics });
        return new ScrollViewer { Content = content, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
    }

    private static void AddCard(Grid grid, int index, string caption, string value, string detail)
    {
        var key = index switch { 0 => "Format", 1 => "Architecture", 2 => "FileSize", _ => "Sections" };
        var stack = new StackPanel(); stack.Children.Add(HelpUi.Label(caption, key, compact: true));
        stack.Children.Add(new TextBlock { Text = value, FontSize = 27, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 10, 0, 9) });
        stack.Children.Add(new TextBlock { Text = detail, FontSize = 11, Foreground = Brush("#8BA3C0"), TextTrimming = TextTrimming.CharacterEllipsis });
        var card = new Border { Background = Brush("#19222F"), BorderBrush = Brush("#2C394C"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6), Padding = new Thickness(17), Margin = new Thickness(0, 0, index == 3 ? 0 : 10, 0), Child = stack };
        Grid.SetColumn(card, index); grid.Children.Add(card);
    }

    private static void AddMetadata(Panel panel, string name, string value, string helpKey)
    {
        var row = new DockPanel { Margin = new Thickness(0, 14, 0, 0) };
        var label = HelpUi.Label(name, helpKey); label.Width = 174; label.Margin = new Thickness(0, 0, 12, 0);
        DockPanel.SetDock(label, Dock.Left); row.Children.Add(label);
        row.Children.Add(new TextBlock { Text = value, FontFamily = new FontFamily("Consolas"), FontSize = 12, TextWrapping = TextWrapping.Wrap }); panel.Children.Add(row);
    }

    private static string SubsystemName(ushort value) => value switch
    {
        1 => "Native", 2 => "Windows GUI", 3 => "Windows console", 7 => "POSIX console", 9 => "Windows CE",
        10 => "EFI application", 11 => "EFI boot service driver", 12 => "EFI runtime driver", 14 => "Xbox", 16 => "Windows boot application", _ => $"Unknown (0x{value:X4})"
    };

    private static SolidColorBrush Brush(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)); brush.Freeze(); return brush;
    }
}
