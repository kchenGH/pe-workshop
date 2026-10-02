using System.IO;
using System.Windows;

namespace PeWorkshop.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if (e.Args.Length > 0 && e.Args[0] == "--smoke-test")
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            var output = Path.GetFullPath(e.Args.ElementAtOrDefault(1) ?? "artifacts/smoke");
            Directory.CreateDirectory(output);
            try
            {
                UiSmokeTest.Run(output);
                File.WriteAllText(Path.Combine(output, "result.txt"), "PASS: WPF open, navigation, edit, undo/redo, save, help coverage, help interaction, appearance, comparison, DWARF variables, evidence highlights, cancellation, and render checks.\n");
                Shutdown(0);
            }
            catch (Exception ex)
            {
                File.WriteAllText(Path.Combine(output, "result.txt"), ex.ToString());
                Shutdown(1);
            }
            return;
        }

        var window = new MainWindow();
        MainWindow = window;
        window.Show();
        if (e.Args.Length > 0)
            window.OpenPath(e.Args[0]);
    }
}
