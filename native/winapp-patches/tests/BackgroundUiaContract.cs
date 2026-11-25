using Microsoft.Extensions.Logging.Abstractions;
using Spectre.Console;
using System.CommandLine;
using System.Runtime.InteropServices;
using WinApp.Cli.Commands;
using WinApp.Cli.Helpers;
using WinApp.Cli.Services;

internal static class BackgroundUiaContract
{
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    internal static int Run()
    {
        using var ready = new ManualResetEventSlim();
        System.Windows.Window? target = null;
        Exception? startupError = null;
        int invoked = 0;
        long hwnd = 0;
        string text = "";
        double offset = 0;
        var ui = new Thread(() => {
            try
            {
                var app = new System.Windows.Application();
                var panel = new System.Windows.Controls.StackPanel();
                var button = new System.Windows.Controls.Button { Content = "Background invoke witness", Height = 40 };
                var editor = new System.Windows.Controls.TextBox { Height = 35 };
                var items = new System.Windows.Controls.StackPanel();
                for (int i = 0; i < 80; i++) items.Children.Add(new System.Windows.Controls.TextBlock { Text = "Background row " + i, Height = 24 });
                var scroll = new System.Windows.Controls.ScrollViewer { Height = 160, Content = items,
                    VerticalScrollBarVisibility = System.Windows.Controls.ScrollBarVisibility.Visible };
                System.Windows.Automation.AutomationProperties.SetAutomationId(button, "BackgroundInvoke");
                System.Windows.Automation.AutomationProperties.SetAutomationId(editor, "BackgroundValue");
                System.Windows.Automation.AutomationProperties.SetAutomationId(scroll, "BackgroundScroll");
                button.Click += (_, _) => Interlocked.Increment(ref invoked);
                editor.TextChanged += (_, _) => Volatile.Write(ref text, editor.Text);
                scroll.ScrollChanged += (_, _) => Volatile.Write(ref offset, scroll.VerticalOffset);
                panel.Children.Add(button); panel.Children.Add(editor); panel.Children.Add(scroll);
                target = new System.Windows.Window { Title = "Agent Bridge semantic background witness", Width = 500, Height = 350,
                    ShowActivated = false, Content = panel };
                target.Loaded += (_, _) => {
                    Interlocked.Exchange(ref hwnd, new System.Windows.Interop.WindowInteropHelper(target).Handle.ToInt64());
                    ready.Set();
                };
                app.Run(target);
            }
            catch (Exception error) { startupError = error; ready.Set(); }
        }) { IsBackground = true };
        ui.SetApartmentState(ApartmentState.STA); ui.Start();
        int failures = 0;
        try
        {
            if (!ready.Wait(TimeSpan.FromSeconds(5)) || startupError != null || target == null)
                throw new Exception("WPF semantic fixture failed", startupError);
            if (Volatile.Read(ref hwnd) == 0) throw new Exception("fixture HWND unavailable");
            var before = GetForegroundWindow();
            if (before == IntPtr.Zero || before.ToInt64() == hwnd) throw new Exception("independent foreground witness unavailable");
            void Check(string name, Action test)
            {
                try { test(); Console.WriteLine("PASS " + name); }
                catch (Exception error) { failures++; Console.WriteLine("FAIL " + name + ": " + error.Message); }
            }
            int Call(string verb, params string[] arguments)
            {
                var selectors = new SelectorService();
                var automation = new UiAutomationService(NullLogger<UiAutomationService>.Instance, selectors);
                var session = new UiSessionService(automation, new SystemUiQuery(), NullLogger<UiSessionService>.Instance);
                Command command;
                if (verb == "invoke")
                {
                    command = new UiInvokeCommand();
                    var handler = new UiInvokeCommand.Handler(session, automation, selectors, AnsiConsole.Console, NullLogger<UiInvokeCommand>.Instance);
                    command.SetAction((parsed, cancellation) => handler.InvokeAsync(parsed, cancellation));
                }
                else if (verb == "set-value")
                {
                    command = new UiSetValueCommand();
                    var handler = new UiSetValueCommand.Handler(session, automation, selectors, AnsiConsole.Console, NullLogger<UiSetValueCommand>.Instance);
                    command.SetAction((parsed, cancellation) => handler.InvokeAsync(parsed, cancellation));
                }
                else
                {
                    command = new UiScrollCommand();
                    var handler = new UiScrollCommand.Handler(session, automation, selectors, new RealMouseInput(), new RealForegroundGuard(), AnsiConsole.Console, NullLogger<UiScrollCommand>.Instance);
                    command.SetAction((parsed, cancellation) => handler.InvokeAsync(parsed, cancellation));
                }
                return command.Parse(arguments).InvokeAsync().GetAwaiter().GetResult();
            }
            void Until(Func<bool> ready)
            {
                var until = DateTime.UtcNow.AddSeconds(2);
                while (!ready() && DateTime.UtcNow < until) Thread.Sleep(10);
                if (!ready()) throw new Exception("real control effect missing");
                if (GetForegroundWindow() != before) throw new Exception("semantic action changed foreground");
            }
            Check("InvokePattern no-focus has real effect without activation", () => {
                if (Call("invoke", "BackgroundInvoke", "-w", hwnd.ToString(), "--no-focus", "--json") != 0) throw new Exception("no-focus invoke rejected");
                Until(() => Volatile.Read(ref invoked) == 1);
            });
            Check("ValuePattern no-focus has real effect without activation", () => {
                if (Call("set-value", "BackgroundValue", "background-value-proof", "-w", hwnd.ToString(), "--no-focus", "--json") != 0) throw new Exception("no-focus set-value rejected");
                Until(() => Volatile.Read(ref text) == "background-value-proof");
            });
            Check("ScrollPattern no-focus has real effect without activation", () => {
                if (Call("scroll", "BackgroundScroll", "--to", "bottom", "-w", hwnd.ToString(), "--no-focus", "--json") != 0) throw new Exception("no-focus scroll rejected");
                Until(() => Volatile.Read(ref offset) > 100);
            });
            Check("no-focus wheel is rejected before effects", () => {
                var previous = Volatile.Read(ref offset);
                if (Call("scroll", "BackgroundScroll", "--wheel", "1", "-w", hwnd.ToString(), "--no-focus", "--json") == 0 ||
                    Volatile.Read(ref offset) != previous || GetForegroundWindow() != before) throw new Exception("unsafe wheel accepted");
            });
        }
        finally
        {
            if (target != null) target.Dispatcher.BeginInvoke(new Action(target.Close));
            if (!ui.Join(TimeSpan.FromSeconds(5))) throw new Exception("semantic fixture cleanup incomplete");
        }
        Console.WriteLine($"RESULT failures={failures}");
        return failures == 0 ? 0 : 1;
    }
}
