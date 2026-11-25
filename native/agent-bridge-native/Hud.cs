// Adapted from DeskMCP control-panel/wpf/AgentDesktopControl.cs (Apache-2.0).
// The file-based coordinator is intentionally not part of this private helper.
using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using Ellipse = System.Windows.Shapes.Ellipse;
namespace AgentBridge.Native;
internal static class AgentDesktopWindowMover
{
    private static readonly Guid ClsidVirtualDesktopManager = new Guid("AA509086-5CA9-4C25-8F95-589D3C07B48A");
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(IntPtr hwnd);

    [ComImport]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [Guid("A5CD92FF-29BE-454C-8D04-D82879FB3F1B")]
    private interface IVirtualDesktopManager
    {
        [return: MarshalAs(UnmanagedType.Bool)]
        bool IsWindowOnCurrentVirtualDesktop(IntPtr topLevelWindow);
        Guid GetWindowDesktopId(IntPtr topLevelWindow);
        void MoveWindowToDesktop(IntPtr topLevelWindow, ref Guid desktopId);
    }

    public static void MoveOwnWindow(Window window, Guid desktopId)
    {
        if (window == null) throw new ArgumentNullException(nameof(window));
        if (desktopId == Guid.Empty) throw new ArgumentException("Agent Desktop id cannot be empty.", nameof(desktopId));
        IntPtr hwnd = new WindowInteropHelper(window).EnsureHandle();
        IVirtualDesktopManager manager = CreateManager();
        try
        {
            manager.MoveWindowToDesktop(hwnd, ref desktopId);
            Guid actual = manager.GetWindowDesktopId(hwnd);
            if (actual != desktopId)
                throw new InvalidOperationException(
                    "Windows did not place Agent Desktop safety window '" + window.Title +
                    "' (HWND " + hwnd.ToInt64().ToString() +
                    ") on the bound virtual desktop. Target=" + desktopId.ToString("D") +
                    ", actual=" + actual.ToString("D") + ".");
        }
        finally
        {
            if (Marshal.IsComObject(manager)) Marshal.FinalReleaseComObject(manager);
        }
    }

    public static void VerifyOwnWindowOnDesktop(Window window, Guid desktopId, string role)
    {
        if (window == null || desktopId == Guid.Empty) throw new NativeFailure("HUD_" + role + "_INVALID_BINDING");
        IntPtr hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd == IntPtr.Zero) throw new NativeFailure("HUD_" + role + "_HANDLE_MISSING");
        if (!IsWindowVisible(hwnd) || IsIconic(hwnd)) throw new NativeFailure("HUD_" + role + "_NOT_VISIBLE");
        Guid actual;
        try
        {
            IVirtualDesktopManager manager = CreateManager();
            try { actual = manager.GetWindowDesktopId(hwnd); }
            finally
            {
                if (Marshal.IsComObject(manager)) Marshal.FinalReleaseComObject(manager);
            }
        }
        catch (InvalidComObjectException) { throw new NativeFailure("HUD_" + role + "_COM_RELEASED"); }
        catch (COMException) { throw new NativeFailure("HUD_" + role + "_COM_QUERY_FAILED"); }
        if (actual == Guid.Empty) throw new NativeFailure("HUD_" + role + "_DESKTOP_UNREGISTERED");
        if (actual != desktopId) throw new NativeFailure("HUD_" + role + "_DESKTOP_CHANGED");
    }

    private static IVirtualDesktopManager CreateManager()
    {
        Type type = Type.GetTypeFromCLSID(ClsidVirtualDesktopManager, true)
            ?? throw new InvalidOperationException("Windows VirtualDesktopManager is unavailable.");
        object? instance = Activator.CreateInstance(type);
        if (instance == null) throw new InvalidOperationException("Windows VirtualDesktopManager could not be created.");
        return (IVirtualDesktopManager)instance;
    }
}

internal sealed class AgentDesktopOverlay : IDisposable
{
    private const int GwlExStyle = -20;
    private const long WsExTransparent = 0x00000020L;
    private const long WsExNoActivate = 0x08000000L;
    private const double EdgeThickness = 7.0;

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW", SetLastError = true)]
    private static extern IntPtr GetWindowLongPtr(IntPtr hwnd, int index);

    [DllImport("user32.dll", EntryPoint = "SetWindowLongPtrW", SetLastError = true)]
    private static extern IntPtr SetWindowLongPtr(IntPtr hwnd, int index, IntPtr value);

    private readonly Window edgeWindow;
    private readonly Window hudWindow;
    private readonly Action exitAction;
    private bool shown;
    private bool disposed;

    public AgentDesktopOverlay(string taskLabel, Action onExit)
    {
        exitAction = onExit ?? throw new ArgumentNullException(nameof(onExit));
        double left = SystemParameters.VirtualScreenLeft;
        double top = SystemParameters.VirtualScreenTop;
        double width = Math.Max(1, SystemParameters.VirtualScreenWidth);
        double height = Math.Max(1, SystemParameters.VirtualScreenHeight);

        edgeWindow = CreateEdge(left, top, width, height);
        hudWindow = CreateHud(taskLabel);
    }

    public bool IsShown => shown && !disposed;
    internal ulong[] WindowHandles => new[] { unchecked((ulong)new WindowInteropHelper(edgeWindow).Handle.ToInt64()), unchecked((ulong)new WindowInteropHelper(hudWindow).Handle.ToInt64()) };

    public async Task ShowOnDesktopAsync(Guid desktopId, Func<bool> stillAuthorized)
    {
        if (disposed) throw new ObjectDisposedException(nameof(AgentDesktopOverlay));
        if (stillAuthorized == null) throw new ArgumentNullException(nameof(stillAuthorized));
        if (shown) return;

        IntPtr edgeHwnd = new WindowInteropHelper(edgeWindow).EnsureHandle();
        edgeWindow.BeginAnimation(UIElement.OpacityProperty, null);
        edgeWindow.Opacity = 0;
        IntPtr hudHwnd = new WindowInteropHelper(hudWindow).EnsureHandle();
        hudWindow.Opacity = 0;
        hudWindow.IsHitTestVisible = false;

        edgeWindow.Show();
        hudWindow.Show();

        // Windows 11 only assigns a newly shown WPF HWND to the Virtual Desktop
        // shell after it has lived through a UI turn. Do not mutate the extended
        // window style until after registration or the shell can report Guid.Empty.
        await Task.Delay(150);
        if (disposed) throw new ObjectDisposedException(nameof(AgentDesktopOverlay));

        ApplyEdgeExtendedStyle(edgeHwnd);
        ApplyHudExtendedStyle(hudHwnd);
        AgentDesktopWindowMover.MoveOwnWindow(edgeWindow, desktopId);
        AgentDesktopWindowMover.MoveOwnWindow(hudWindow, desktopId);
        if (!stillAuthorized()) throw new InvalidOperationException("Agent Desktop control changed before the safety HUD became visible.");

        StartEdgePulse(edgeWindow);
        hudWindow.IsHitTestVisible = true;
        hudWindow.Opacity = 1;
        shown = true;
    }

    private Window CreateEdge(double left, double top, double width, double height)
    {
        Color blue = Color.FromRgb(10, 132, 255);
        Border line = new Border
        {
            Background = Brushes.Transparent,
            BorderBrush = new SolidColorBrush(Color.FromArgb(225, blue.R, blue.G, blue.B)),
            BorderThickness = new Thickness(EdgeThickness),
            IsHitTestVisible = false,
            Effect = new DropShadowEffect
            {
                Color = blue,
                BlurRadius = 22,
                ShadowDepth = 0,
                Opacity = 0.92
            }
        };
        Window edge = new Window
        {
            Title = "Agent Bridge Agent Desktop Edge",
            Left = left,
            Top = top,
            Width = Math.Max(1, width),
            Height = Math.Max(1, height),
            WindowStyle = WindowStyle.None,
            ResizeMode = ResizeMode.NoResize,
            AllowsTransparency = true,
            Background = Brushes.Transparent,
            ShowInTaskbar = false,
            ShowActivated = false,
            Topmost = true,
            Focusable = false,
            IsHitTestVisible = false,
            Content = line,
            Opacity = 0.72
        };
        return edge;
    }

    private static void StartEdgePulse(Window edge)
    {
        edge.Opacity = 0.72;
        DoubleAnimation pulse = new DoubleAnimation(0.48, 0.92, TimeSpan.FromMilliseconds(1250))
        {
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut }
        };
        edge.BeginAnimation(UIElement.OpacityProperty, pulse);
    }

    private Window CreateHud(string taskLabel)
    {
        Color blue = Color.FromRgb(10, 132, 255);
        Grid grid = new Grid { Margin = new Thickness(14, 9, 10, 9) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        Ellipse dot = new Ellipse
        {
            Width = 9,
            Height = 9,
            Fill = new SolidColorBrush(blue),
            Margin = new Thickness(0, 0, 11, 0),
            VerticalAlignment = VerticalAlignment.Center,
            Effect = new DropShadowEffect { Color = blue, BlurRadius = 13, ShadowDepth = 0, Opacity = 1 }
        };
        Grid.SetColumn(dot, 0);
        grid.Children.Add(dot);

        StackPanel labels = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        labels.Children.Add(new TextBlock
        {
            Text = "Agent is controlling this desktop",
            Foreground = Brushes.White,
            FontSize = 12.5,
            FontWeight = FontWeights.SemiBold
        });
        labels.Children.Add(new TextBlock
        {
            Text = String.IsNullOrWhiteSpace(taskLabel) ? "Agent Bridge Agent Desktop" : taskLabel.Trim(),
            Foreground = new SolidColorBrush(Color.FromRgb(174, 174, 182)),
            FontSize = 10,
            Margin = new Thickness(0, 2, 10, 0),
            MaxWidth = 260,
            TextTrimming = TextTrimming.CharacterEllipsis
        });
        Grid.SetColumn(labels, 1);
        grid.Children.Add(labels);

        Button exit = new Button
        {
            Content = "Exit Agent Control",
            Padding = new Thickness(13, 7, 13, 7),
            Margin = new Thickness(12, 0, 0, 0),
            Foreground = Brushes.White,
            Background = new SolidColorBrush(Color.FromRgb(46, 46, 50)),
            BorderBrush = new SolidColorBrush(Color.FromArgb(70, 255, 255, 255)),
            BorderThickness = new Thickness(1),
            FontSize = 10.5,
            FontWeight = FontWeights.SemiBold,
            Cursor = System.Windows.Input.Cursors.Hand
        };
        exit.Click += delegate { exitAction(); };
        Grid.SetColumn(exit, 2);
        grid.Children.Add(exit);

        Border shell = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(244, 22, 22, 25)),
            BorderBrush = new SolidColorBrush(Color.FromArgb(180, blue.R, blue.G, blue.B)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(18),
            Child = grid,
            Effect = new DropShadowEffect { Color = blue, BlurRadius = 24, ShadowDepth = 0, Opacity = 0.34 }
        };

        double hudWidth = 515;
        double hudHeight = 62;
        double workLeft = SystemParameters.WorkArea.Left;
        double workTop = SystemParameters.WorkArea.Top;
        double workWidth = SystemParameters.WorkArea.Width;
        return new Window
        {
            Title = "Agent Bridge Agent Desktop Control",
            Width = hudWidth,
            Height = hudHeight,
            Left = workLeft + Math.Max(0, (workWidth - hudWidth) / 2.0),
            Top = workTop + 14,
            WindowStyle = WindowStyle.None,
            ResizeMode = ResizeMode.NoResize,
            AllowsTransparency = true,
            Background = Brushes.Transparent,
            ShowInTaskbar = false,
            ShowActivated = false,
            Topmost = true,
            Content = shell
        };
    }

    private static void ApplyEdgeExtendedStyle(IntPtr hwnd)
    {
        long style = GetWindowLongPtr(hwnd, GwlExStyle).ToInt64();
        style |= WsExTransparent | WsExNoActivate;
        SetWindowLongPtr(hwnd, GwlExStyle, new IntPtr(style));
    }

    private static void ApplyHudExtendedStyle(IntPtr hwnd)
    {
        // Keep the HUD as a normal Virtual Desktop window. WS_EX_TOOLWINDOW can
        // detach a topmost WPF window from Virtual Desktop ownership after a
        // desktop switch, making it appear on Desktop 1 as well.
        long style = GetWindowLongPtr(hwnd, GwlExStyle).ToInt64();
        SetWindowLongPtr(hwnd, GwlExStyle, new IntPtr(style));
    }

    public bool IsOnDesktop(Guid desktopId)
    {
        if (!IsShown || desktopId == Guid.Empty) return false;
        AgentDesktopWindowMover.VerifyOwnWindowOnDesktop(edgeWindow, desktopId, "EDGE");
        AgentDesktopWindowMover.VerifyOwnWindowOnDesktop(hudWindow, desktopId, "CONTROL");
        return true;
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        shown = false;
        try { edgeWindow.BeginAnimation(UIElement.OpacityProperty, null); edgeWindow.Close(); } catch { }
        try { hudWindow.Close(); } catch { }
    }
}
