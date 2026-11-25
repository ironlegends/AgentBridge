using Microsoft.Extensions.Logging.Abstractions;
using Spectre.Console;
using System.CommandLine;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using WinApp.Cli.Commands;
using WinApp.Cli.Helpers;
using WinApp.Cli.Services;

internal static class BackgroundMessageContract
{
    private sealed class PassiveForm : Form
    {
        protected override bool ShowWithoutActivation => true;
    }
    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    internal static int Run()
    {
        using var ready = new ManualResetEventSlim();
        Form? target = null, guard = null;
        TextBox? editor = null;
        Exception? startupError = null;
        string text = "";
        var ui = new Thread(() => {
            try
            {
                using var targetWindow = new PassiveForm { Text = "Agent Bridge background message target", Width = 420, Height = 170 };
                using var guardWindow = new PassiveForm { Text = "Agent Bridge focus preservation witness", Width = 420, Height = 170, Left = 500 };
                using var box = new TextBox { Name = "AgentBridgeMessageEditor", AccessibleName = "AgentBridgeMessageEditor", Width = 300 };
                box.TextChanged += (_, _) => Volatile.Write(ref text, box.Text);
                target = targetWindow; guard = guardWindow; editor = box;
                targetWindow.Controls.Add(box);
                targetWindow.Shown += (_, _) => {
                    guardWindow.Show();
                    guardWindow.BeginInvoke(new Action(() => ready.Set()));
                };
                Application.Run(targetWindow);
            }
            catch (Exception error) { startupError = error; ready.Set(); }
        }) { IsBackground = true };
        ui.SetApartmentState(ApartmentState.STA); ui.Start();
        int failures = 0;
        try
        {
            if (!ready.Wait(TimeSpan.FromSeconds(5)) || startupError != null || target == null || guard == null || editor == null)
                throw new Exception("native child HWND fixture failed", startupError);
            long targetHwnd = target.Handle.ToInt64(), childHwnd = editor.Handle.ToInt64();
            var before = GetForegroundWindow();
            if (before == IntPtr.Zero || before == target.Handle || childHwnd == targetHwnd) throw new Exception("independent foreground witness unavailable");
            var query = new SystemUiQuery(); var selectors = new SelectorService();
            var automation = new UiAutomationService(NullLogger<UiAutomationService>.Instance, selectors);
            var session = new UiSessionService(automation, query, NullLogger<UiSessionService>.Instance);
            var command = new UiSendKeysCommand();
            var handler = new UiSendKeysCommand.Handler(session, automation, selectors, new RealKeyboardInput(),
                new RealForegroundGuard(), query, AnsiConsole.Console, NullLogger<UiSendKeysCommand>.Instance);
            command.SetAction((parsed, cancellation) => handler.InvokeAsync(parsed, cancellation));
            int Call(params string[] arguments) => command.Parse(arguments).InvokeAsync().GetAwaiter().GetResult();
            void Check(string name, Action test)
            {
                try { test(); Console.WriteLine("PASS " + name); }
                catch (Exception error) { failures++; Console.WriteLine("FAIL " + name + ": " + error.Message); }
            }
            Check("post-message reaches real child HWND without changing foreground", () => {
                int result = Call("background-message-proof", "-w", targetHwnd.ToString(), "--target", "AgentBridgeMessageEditor",
                    "--via", "post-message", "--no-focus", "--verbatim", "--json");
                var until = DateTime.UtcNow.AddSeconds(2);
                while (result == 0 && Volatile.Read(ref text) != "background-message-proof" && DateTime.UtcNow < until) Thread.Sleep(20);
                if (result != 0 || Volatile.Read(ref text) != "background-message-proof" || GetForegroundWindow() != before)
                    throw new Exception("child HWND effect or preserved foreground missing");
                if (query.GetRootWindow(childHwnd) != targetHwnd || query.GetProcessIdForWindow(childHwnd) != Environment.ProcessId)
                    throw new Exception("target HWND identity changed");
            });
            Check("no-focus rejects SendInput before any effect", () => {
                string initial = Volatile.Read(ref text);
                if (Call("rejected", "-w", targetHwnd.ToString(), "--via", "send-input", "--no-focus", "--verbatim", "--json") == 0 ||
                    Volatile.Read(ref text) != initial || GetForegroundWindow() != before)
                    throw new Exception("unsafe transport accepted");
            });
        }
        finally
        {
            if (target != null && !target.IsDisposed) target.BeginInvoke(new Action(target.Close));
            if (!ui.Join(TimeSpan.FromSeconds(5))) throw new Exception("message fixture cleanup incomplete");
        }
        Console.WriteLine($"RESULT failures={failures}");
        return failures == 0 ? 0 : 1;
    }
}
