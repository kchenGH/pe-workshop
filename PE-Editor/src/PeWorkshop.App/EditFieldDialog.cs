using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using PeWorkshop.Core;

namespace PeWorkshop.App;

public sealed class EditFieldDialog : Window
{
    private readonly PeDocument _document;
    private readonly ComboBox _fields;
    private readonly TextBox _value;
    private readonly TextBlock _description;
    private readonly TextBlock _error;
    private readonly HelpBadge _fieldHelp = new();

    public EditFieldDialog(PeDocument document, IEnumerable<PeField> fields, PeField? selected = null)
    {
        _document = document;
        Title = "Edit PE field";
        Width = 560; Height = 420; ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var root = new StackPanel { Margin = new Thickness(24) };
        root.Children.Add(HelpUi.Beside(new TextBlock { Text = "Edit field", FontSize = 23, FontWeight = FontWeights.SemiBold }, "Edit"));
        _fields = new ComboBox { ItemsSource = fields.ToArray(), DisplayMemberPath = "Name", Margin = new Thickness(0, 18, 0, 12) };
        _description = new TextBlock { TextWrapping = TextWrapping.Wrap, Foreground = Brushes.LightSteelBlue, Height = 65 };
        _value = new TextBox { FontFamily = new FontFamily("Consolas"), FontSize = 16 };
        System.Windows.Automation.AutomationProperties.SetName(_value, "Field value in decimal or hexadecimal");
        _error = new TextBlock { Foreground = Brushes.Salmon, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 10, 0, 0), MinHeight = 34 };
        var fieldRow = new DockPanel(); DockPanel.SetDock(_fieldHelp, Dock.Right);
        fieldRow.Children.Add(_fieldHelp); fieldRow.Children.Add(_fields);
        root.Children.Add(fieldRow); root.Children.Add(_description); root.Children.Add(HelpUi.Beside(_value, "Value"));
        root.Children.Add(HelpUi.Beside(new TextBlock { Text = "Use 0x for hexadecimal, or enter a decimal value.", Foreground = Brushes.LightSlateGray, FontSize = 11, Margin = new Thickness(0, 8, 0, 0) }, "NumericInput"));
        root.Children.Add(_error);
        var actions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 8, 0, 0) };
        var cancel = new Button { Content = "Cancel", IsCancel = true, Margin = new Thickness(0, 0, 8, 0) };
        var apply = new Button { Content = "Apply change", IsDefault = true, Style = (Style)FindResource("PrimaryButton") };
        apply.Click += (_, _) => Apply();
        actions.Children.Add(HelpUi.Beside(cancel, "Cancel")); actions.Children.Add(HelpUi.Beside(apply, "Apply")); root.Children.Add(actions);
        _fields.SelectionChanged += (_, _) => SelectField();
        _fields.SelectedItem = selected ?? ((PeField[])_fields.ItemsSource).FirstOrDefault();
        Content = root;
        Loaded += (_, _) => { _value.Focus(); _value.SelectAll(); };
    }

    private void SelectField()
    {
        if (_fields.SelectedItem is not PeField field) return;
        _value.Text = field.HexValue;
        _fieldHelp.Topic = PeHelpCatalog.ForField(field);
        _description.Text = $"{field.OffsetHex}  ·  {field.Size} bytes  ·  {field.Group}\n{field.Description}";
        _error.Text = "";
    }

    private void Apply()
    {
        if (_fields.SelectedItem is not PeField field) return;
        try { _document.SetField(field, _value.Text); DialogResult = true; }
        catch (Exception ex) when (ex is PeFormatException or ArgumentException or FormatException or OverflowException or InvalidOperationException)
        { _error.Text = ex.Message; }
    }
}

public sealed class RenameSectionDialog : Window
{
    public RenameSectionDialog(PeDocument document, PeSection section)
    {
        Title = "Rename section"; Width = 420; Height = 245; ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var root = new StackPanel { Margin = new Thickness(24) };
        root.Children.Add(HelpUi.Beside(new TextBlock { Text = "Section name", FontSize = 21, FontWeight = FontWeights.SemiBold }, "SectionName"));
        var input = new TextBox { Text = section.Name, MaxLength = 8, FontFamily = new FontFamily("Consolas"), Margin = new Thickness(0, 14, 0, 8) };
        var error = new TextBlock { Text = "1–8 printable ASCII characters", Foreground = Brushes.LightSteelBlue, TextWrapping = TextWrapping.Wrap, Height = 34 };
        var apply = new Button { Content = "Rename", IsDefault = true, HorizontalAlignment = HorizontalAlignment.Right };
        apply.Click += (_, _) =>
        {
            try { document.RenameSection(section, input.Text); DialogResult = true; }
            catch (Exception ex) when (ex is ArgumentException or PeFormatException or InvalidOperationException) { error.Text = ex.Message; }
        };
        var cancel = new Button { Content = "Cancel", IsCancel = true, Margin = new Thickness(0, 0, 8, 0) };
        var actions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        actions.Children.Add(HelpUi.Beside(cancel, "Cancel")); actions.Children.Add(HelpUi.Beside(apply, "RenameSection"));
        root.Children.Add(HelpUi.Beside(input, "SectionNames")); root.Children.Add(error); root.Children.Add(actions); Content = root;
        Loaded += (_, _) => { input.Focus(); input.SelectAll(); };
    }
}
