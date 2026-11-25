using Microsoft.Extensions.Logging.Abstractions;
using System.CommandLine;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using WinApp.Cli.Commands;
using WinApp.Cli.Models;
using WinApp.Cli.Services;

internal static class ExactPassiveContract
{
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();

    [STAThread]
    private static int Main()
    {
        int failures=0;
        void Check(string name, Action body)
        {
            try { body(); Console.WriteLine("PASS "+name); }
            catch(Exception error) { failures++; Console.WriteLine("FAIL "+name+": "+error.Message); }
            finally { UiAutomationService.ResetNativeSeams(); }
        }

        Check("private exact-passive flag is recognized", () => {
            var command=new UiScreenshotCommand();
            if (!command.Options.Any(option=>option.Name.TrimStart('-')=="exact-passive"))
                throw new Exception("exact passive option not registered; parser may consume it as selector");
            var parsed=command.Parse(["-w","1","--exact-passive","--json"]);
            if (parsed.Errors.Count!=0) throw new Exception("exact passive option unavailable");
        });

        Check("wrong PID for a real hidden HWND refuses before UIA root or capture", () => {
            var before=GetForegroundWindow();
            var window=new NativeWindow();
            try
            {
                window.CreateHandle(new CreateParams { Caption="Agent Bridge exact passive hidden contract", Width=64, Height=64, Style=0 });
                if(window.Handle==IntPtr.Zero) throw new Exception("hidden fixture not created");
                var service=new UiAutomationService(NullLogger<UiAutomationService>.Instance,null!);
                UiAutomationService.s_getRootElement=(_,_)=>throw new Exception("unexpected UIA root resolution");
                UiAutomationService.s_captureFromWindow=(_,_,_)=>throw new Exception("unexpected capture");
                UiAutomationService.s_foregroundWindowForBlankRetry=_=>throw new Exception("unexpected activation");
                var session=new UiSessionInfo {
                    ProcessId=Environment.ProcessId==int.MaxValue?1:Environment.ProcessId+1,
                    ProcessName="hidden-fixture",WindowHandle=window.Handle.ToInt64(),IsExplicitWindow=true
                };
                Exception? failure=null;
                try { service.ScreenshotAsync(session,null,false,false,CancellationToken.None).GetAwaiter().GetResult(); }
                catch(Exception error) { failure=error; }
                if(failure is not InvalidOperationException || failure.Message!="Passive window capture target changed.")
                    throw new Exception("wrong identity was not refused before native capture: "+failure?.Message);
            }
            finally { window.DestroyHandle(); }
            if(GetForegroundWindow()!=before) throw new Exception("foreground changed");
        });

        Console.WriteLine($"RESULT failures={failures}");
        return failures==0?0:1;
    }
}
