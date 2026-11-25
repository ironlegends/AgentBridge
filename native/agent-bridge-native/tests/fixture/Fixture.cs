using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using Application = System.Windows.Application;
using Button = System.Windows.Controls.Button;
using TextBox = System.Windows.Controls.TextBox;

internal static class Fixture
{
    private sealed class NativeEditHost : HwndHost
    {
        private sealed class NativeEditPeer(NativeEditHost owner) : FrameworkElementAutomationPeer(owner)
        {
            protected override string GetClassNameCore() => "NativeEditHost";
            protected override string GetAutomationIdCore() => "NativeKeysBox";
            protected override AutomationControlType GetAutomationControlTypeCore() => AutomationControlType.Edit;
            protected override bool IsHwndHost => true;
            protected override HostedWindowWrapper GetHostRawElementProviderCore() => new(((NativeEditHost)Owner).Handle);
            public IRawElementProviderSimple? Provider => ProviderFromPeer(this);
        }
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateWindowExW(int exStyle, string className, string name, int style,
            int x, int y, int width, int height, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr parameter);
        [DllImport("user32.dll")] private static extern bool DestroyWindow(IntPtr hwnd);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowTextW(IntPtr hwnd, StringBuilder text, int count);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr GetModuleHandleW(string? module);
        protected override HandleRef BuildWindowCore(HandleRef parent)
        {
            var hwnd = CreateWindowExW(0x200, "EDIT", "", unchecked((int)0x50010080), 0, 0, 400, 32,
                parent.Handle, IntPtr.Zero, GetModuleHandleW(null), IntPtr.Zero);
            if (hwnd == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            return new HandleRef(this, hwnd);
        }
        protected override void DestroyWindowCore(HandleRef hwnd) => DestroyWindow(hwnd.Handle);
        protected override AutomationPeer OnCreateAutomationPeer() => new NativeEditPeer(this);
        protected override IntPtr WndProc(IntPtr hwnd, int message, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            if (message == 0x003d) // WM_GETOBJECT: signed, 32-bit object identifier
            {
                if (unchecked((int)lParam.ToInt64()) == AutomationInteropProvider.RootObjectId
                    && UIElementAutomationPeer.CreatePeerForElement(this) is NativeEditPeer peer
                    && peer.Provider is IRawElementProviderSimple provider)
                {
                    handled = true;
                    return AutomationInteropProvider.ReturnRawElementProvider(hwnd, wParam, lParam, provider);
                }
                // HwndHost's default handler can pass a null provider to
                // ReturnRawElementProvider. For an actual native EDIT HWND,
                // unhandled accessibility requests belong to the original
                // control procedure (its native accessibility proxy).
                // Never swallow an exception or claim a provider that is absent.
                handled = false;
                return IntPtr.Zero;
            }
            return base.WndProc(hwnd, message, wParam, lParam, ref handled);
        }
        public string ReadText() { var text = new StringBuilder(4097); if (Handle != IntPtr.Zero) GetWindowTextW(Handle, text, text.Capacity); return text.ToString(); }
    }
    [DllImport("kernel32.dll")] private static extern IntPtr GetConsoleWindow();
    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Length < 1 || args.Length > 2 || !Path.IsPathFullyQualified(args[0])
            || (args.Length == 2 && args[1] != "--passive")) return 2;
        bool passive = args.Length == 2;
        var app = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
        string state = args[0];
        var panel = new StackPanel { Margin = new Thickness(22) };
        var window = new Window { Title = "Agent Bridge Native Fixture " + Environment.ProcessId,
            Width = 760, Height = 730, Left = 70, Top = 60, Content = panel, ShowActivated = !passive };
        int invoked = 0, hovered = 0, dragged = 0, changed = 0;
        bool down = false, closed = false, rendered = false;
        var invoke = new Button { Content = "Invoke or click fixture", Height = 38, Margin = new Thickness(0, 0, 0, 12) };
        var value = new TextBox { Height = 32, Margin = new Thickness(0, 0, 0, 12) };
        var keys = new TextBox { Height = 32, Margin = new Thickness(0, 0, 0, 12) };
        var nativeKeys = new NativeEditHost { Height = 32, Margin = new Thickness(0, 0, 0, 12) };
        var hover = new Button { Content = "Hover fixture", Height = 38, Margin = new Thickness(0, 0, 0, 12) };
        var scrollItems = new StackPanel();
        for (int i = 0; i < 80; i++) scrollItems.Children.Add(new TextBlock { Text = "Fixture row " + i, Height = 24 });
        var scroll = new ScrollViewer { Height = 180, Content = scrollItems,
            VerticalScrollBarVisibility = ScrollBarVisibility.Visible, Margin = new Thickness(0, 0, 0, 12) };
        var dragGrid = new Grid { Height = 80 };
        dragGrid.ColumnDefinitions.Add(new ColumnDefinition()); dragGrid.ColumnDefinitions.Add(new ColumnDefinition());
        var source = new Button { Content = "Drag source", Margin = new Thickness(0, 0, 24, 0) };
        var target = new Button { Content = "Drag destination", Margin = new Thickness(24, 0, 0, 0) };
        Grid.SetColumn(target, 1); dragGrid.Children.Add(source); dragGrid.Children.Add(target);
        AutomationProperties.SetAutomationId(invoke, "InvokeButton");
        AutomationProperties.SetAutomationId(value, "ValueBox");
        AutomationProperties.SetAutomationId(keys, "KeysBox");
        AutomationProperties.SetAutomationId(nativeKeys, "NativeKeysHost");
        AutomationProperties.SetAutomationId(hover, "HoverButton");
        AutomationProperties.SetAutomationId(scroll, "ScrollHost");
        AutomationProperties.SetAutomationId(source, "DragSource");
        AutomationProperties.SetAutomationId(target, "DragTarget");
        void Write()
        {
            string json = JsonSerializer.Serialize(new { pid = Environment.ProcessId,
                hwnd = new WindowInteropHelper(window).Handle.ToInt64(), console = GetConsoleWindow() != IntPtr.Zero,
                invoked, hovered, dragged, changed, value = value.Text, keys = keys.Text,
                native_keys = nativeKeys.ReadText(), native_keys_hwnd = nativeKeys.Handle.ToInt64(),
                scroll_offset = scroll.VerticalOffset, closed, rendered });
            string temporary = state + ".pending";
            File.WriteAllText(temporary, json); File.Move(temporary, state, true);
        }
        invoke.Click += (_, _) => { invoked++; Write(); };
        hover.MouseEnter += (_, _) => { hovered++; Write(); };
        value.TextChanged += (_, _) => { changed++; Write(); };
        keys.TextChanged += (_, _) => Write();
        string previousNativeText = "";
        var nativePoll = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(50) };
        nativePoll.Tick += (_, _) => { string current = nativeKeys.ReadText(); if (current != previousNativeText) { previousNativeText = current; Write(); } };
        scroll.ScrollChanged += (_, _) => Write();
        source.PreviewMouseLeftButtonDown += (_, _) => { down = true; source.CaptureMouse(); };
        source.PreviewMouseLeftButtonUp += (_, _) => {
            if (down) {
                var point = Mouse.GetPosition(target);
                if (point.X >= 0 && point.Y >= 0 && point.X <= target.ActualWidth && point.Y <= target.ActualHeight) dragged++;
                down = false; source.ReleaseMouseCapture(); Write();
            }
        };
        foreach (UIElement control in new UIElement[] { invoke, value, keys, nativeKeys, hover, scroll, dragGrid }) panel.Children.Add(control);
        window.Loaded += (_, _) => { nativePoll.Start(); Write(); };
        window.ContentRendered += (_, _) => { rendered = true; Write(); };
        window.Closed += (_, _) => { closed = true; nativePoll.Stop(); Write(); };
        new Thread(() => {
            try { while (Console.OpenStandardInput().ReadByte() != -1) { } }
            finally { app.Dispatcher.BeginInvoke(() => window.Close()); }
        }) { IsBackground = true }.Start();
        return app.Run(window);
    }
}
