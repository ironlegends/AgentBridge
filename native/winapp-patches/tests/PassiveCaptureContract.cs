using Microsoft.Extensions.Logging.Abstractions;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using WinApp.Cli.Models;
using WinApp.Cli.Services;

internal static class PassiveCaptureContract
{
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(IntPtr hwnd);

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.SequenceEqual(new[] { "--background" })) return BackgroundMessageContract.Run();
        if (args.SequenceEqual(new[] { "--uia-background" })) return BackgroundUiaContract.Run();
        var service = new UiAutomationService(NullLogger<UiAutomationService>.Instance, null!);
        int failures = 0;
        void Check(string name, Action test)
        {
            try { test(); Console.WriteLine("PASS " + name); }
            catch (Exception error) { failures++; Console.WriteLine("FAIL " + name + ": " + error.Message); }
            finally { UiAutomationService.ResetNativeSeams(); }
        }
        byte[] clear = [255, 255, 255, 255];
        Check("successful passive frame is preserved", () => {
            int focus = 0, captures = 0;
            UiAutomationService.s_captureFromWindow = (_, _, _) => { captures++; return clear; };
            UiAutomationService.s_foregroundWindowForBlankRetry = _ => focus++;
            UiAutomationService.s_sleepForBlankRetry = _ => { };
            var pixels = service.CaptureFromWindowWithBlankRetry(default, 1, 1);
            if (focus != 0 || captures != 1 || !pixels.SequenceEqual(clear)) throw new Exception("valid capture contract");
        });
        Check("blank retry never requests foreground", () => {
            int focus = 0, captures = 0;
            UiAutomationService.s_captureFromWindow = (_, _, _) => ++captures == 1 ? new byte[4] : clear;
            UiAutomationService.s_foregroundWindowForBlankRetry = _ => focus++;
            UiAutomationService.s_sleepForBlankRetry = _ => { };
            var pixels = service.CaptureFromWindowWithBlankRetry(default, 1, 1);
            if (focus != 0 || captures != 2 || !pixels.SequenceEqual(clear)) throw new Exception("implicit foreground request");
        });
        Check("two blank frames fail explicitly without foreground", () => {
            int focus = 0;
            UiAutomationService.s_captureFromWindow = (_, _, _) => new byte[4];
            UiAutomationService.s_foregroundWindowForBlankRetry = _ => focus++;
            UiAutomationService.s_sleepForBlankRetry = _ => { };
            bool refused = false;
            try { service.CaptureFromWindowWithBlankRetry(default, 1, 1); }
            catch (InvalidOperationException) { refused = true; }
            if (!refused || focus != 0) throw new Exception("invalid passive frame accepted or foreground requested");
        });
        Check("real minimized window is refused without restoration", () => {
            using var ready = new ManualResetEventSlim();
            Form? window = null;
            Exception? failure = null;
            IntPtr handle = IntPtr.Zero;
            var thread = new Thread(() => {
                try
                {
                    using var form = new Form { Text = "Agent Bridge passive minimized capture fixture",
                        Width = 420, Height = 160, ShowInTaskbar = true };
                    window = form;
                    form.Controls.Add(new Label { Text = "Dedicated screenshot contract fixture", AutoSize = true });
                    form.Shown += (_, _) => form.BeginInvoke(new Action(() => {
                        handle = form.Handle; form.WindowState = FormWindowState.Minimized; ready.Set();
                    }));
                    Application.Run(form);
                }
                catch (Exception error) { failure = error; ready.Set(); }
            }) { IsBackground = true };
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            try
            {
                if (!ready.Wait(TimeSpan.FromSeconds(5)) || failure != null || !IsIconic(handle))
                    throw new Exception("real minimized fixture was not ready", failure);
                var session = new UiSessionInfo { ProcessId = Environment.ProcessId,
                    ProcessName = "WinApp.Cli.Tests", WindowHandle = handle.ToInt64(), IsExplicitWindow = true };
                Exception? captureFailure = null;
                try
                {
                    using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(6));
                    service.ScreenshotAsync(session, null, false, false, cancellation.Token).GetAwaiter().GetResult();
                }
                catch (Exception error) { captureFailure = error; }
                if (!IsIconic(handle) || captureFailure is not InvalidOperationException ||
                    !captureFailure.Message.Contains("minimized", StringComparison.OrdinalIgnoreCase))
                    throw new Exception("passive screenshot restored the real minimized window or failed without a precise refusal");
            }
            finally
            {
                if (window != null && !window.IsDisposed) window.BeginInvoke(new Action(window.Close));
                if (!thread.Join(TimeSpan.FromSeconds(5))) throw new Exception("fixture cleanup incomplete");
            }
        });
        Console.WriteLine($"RESULT failures={failures}");
        return failures == 0 ? 0 : 1;
    }
}
