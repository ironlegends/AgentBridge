// Agent Bridge native desktop adapter. Portions adapted from DeskMCP
// agent-desktop-host/Program.cs (Apache-2.0, see THIRD-PARTY-NOTICES.md).
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AgentBridge.Native;

internal sealed class NativeFailure(string code) : Exception(code)
{
    internal string Code { get; } = code;
}

internal sealed record DesktopInfo(string desktop_id, int desktop_number);
internal sealed record WindowCandidate(ulong hwnd, uint pid);
internal sealed record NativeWindow(ulong hwnd, uint pid, uint tid, ulong birth,
    string image, string class_name, string title, int left, int top, int width, int height,
    bool foreground, string desktop_id, int desktop_number, bool visible, bool is_hud);

internal sealed class NativeApi : IDisposable
{
    internal const string VdaSha256 = "716c4ed3a38eaf3f318ae670949799f74d8030c7f79a117e903bcb73b14354b4";
    private readonly IntPtr library;
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int IntFn();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate Guid IdFn(int number);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int MoveFn(IntPtr hwnd, int number);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int RemoveFn(int number, int fallback);
    private readonly IntFn count, current, create;
    private readonly IdFn id;
    private readonly MoveFn move;
    private readonly RemoveFn remove;

    internal NativeApi()
    {
        string path = Path.Combine(AppContext.BaseDirectory, "VirtualDesktopAccessor.dll");
        using (FileStream input = File.OpenRead(path))
            if (Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant() != VdaSha256)
                throw new NativeFailure("VDA_PIN_MISMATCH");
        library = NativeLibrary.Load(path);
        try
        {
            count = Export<IntFn>("GetDesktopCount");
            current = Export<IntFn>("GetCurrentDesktopNumber");
            create = Export<IntFn>("CreateDesktop");
            id = Export<IdFn>("GetDesktopIdByNumber");
            move = Export<MoveFn>("MoveWindowToDesktopNumber");
            remove = Export<RemoveFn>("RemoveDesktop");
            _ = Current();
        }
        catch { NativeLibrary.Free(library); throw; }
    }
    private T Export<T>(string name) where T : Delegate =>
        Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));
    internal List<DesktopInfo> Desktops()
    {
        int total = count();
        if (total < 1 || total > 128) throw new NativeFailure("DESKTOP_BACKEND_UNAVAILABLE");
        var result = new List<DesktopInfo>();
        for (int number = 0; number < total; number++)
        {
            Guid value = id(number);
            if (value == Guid.Empty) throw new NativeFailure("DESKTOP_BACKEND_UNAVAILABLE");
            result.Add(new(value.ToString("D"), number + 1));
        }
        return result;
    }
    internal DesktopInfo Current()
    {
        int number = current();
        var desktops = Desktops();
        if (number < 0 || number >= desktops.Count) throw new NativeFailure("DESKTOP_BACKEND_UNAVAILABLE");
        return desktops[number];
    }
    internal DesktopInfo Verify(string desktopId, int number, bool allowUser = false)
    {
        if (number == 1 && !allowUser) throw new NativeFailure("DESKTOP_ONE_RESERVED");
        if (number < 1 || number > 128 || !Guid.TryParseExact(desktopId, "D", out Guid target) || target == Guid.Empty)
            throw new NativeFailure("INVALID_DESKTOP_BINDING");
        var desktops = Desktops();
        if (number > desktops.Count || desktops[number-1].desktop_id != target.ToString("D"))
            throw new NativeFailure("DESKTOP_BINDING_CHANGED");
        return desktops[number-1];
    }
    internal DesktopInfo Create()
    {
        int created = create();
        var desktops = Desktops();
        if (created < 1 || created >= desktops.Count) throw new NativeFailure("DESKTOP_CREATE_FAILED");
        return desktops[created];
    }
    internal void Remove(string desktopId, int number)
    {
        Verify(desktopId, number);
        // Removal moves remaining windows to a fallback. Refuse that side effect.
        foreach (ulong hwnd in WindowHandles())
        {
            try { if (WindowDesktop(new IntPtr((long)hwnd)).ToString("D") == desktopId)
                throw new NativeFailure("DESKTOP_NOT_EMPTY"); }
            catch (COMException) { }
        }
        if (remove(number - 1, 0) != 1) throw new NativeFailure("DESKTOP_REMOVE_FAILED");
        if (Desktops().Any(item => item.desktop_id == desktopId)) throw new NativeFailure("DESKTOP_REMOVE_UNCONFIRMED");
    }
    internal static List<ulong> WindowHandles()
    {
        var result = new List<ulong>();
        bool overflow = false;
        if (!EnumWindows((hwnd, _) => {
            if (result.Count == 2048) { overflow = true; return false; }
            result.Add(unchecked((ulong)hwnd.ToInt64())); return true;
        }, IntPtr.Zero) && !overflow) throw new NativeFailure("WINDOW_ENUMERATION_FAILED");
        if (overflow) throw new NativeFailure("WINDOW_ENUMERATION_LIMIT");
        return result;
    }
    internal NativeWindow Window(ulong raw)
    {
        var hwnd = new IntPtr(unchecked((long)raw));
        if (raw == 0 || !IsWindow(hwnd)) throw new NativeFailure("WINDOW_GONE");
        uint tid = GetWindowThreadProcessId(hwnd, out uint pid);
        if (tid == 0 || pid == 0) throw new NativeFailure("WINDOW_GONE");
        using SafeProcessHandle process = OpenProcess(0x1000 | 0x00100000, false, pid);
        if (process.IsInvalid || WaitForSingleObject(process, 0) != 0x102)
            throw new NativeFailure("WINDOW_PROCESS_UNAVAILABLE");
        if (!GetProcessTimes(process, out FileTime born, out _, out _, out _))
            throw new NativeFailure("WINDOW_BIRTH_UNAVAILABLE");
        var image = new StringBuilder(32768); uint size = 32768;
        if (!QueryFullProcessImageName(process, 0, image, ref size))
            throw new NativeFailure("WINDOW_IMAGE_UNAVAILABLE");
        var className = new StringBuilder(512);
        if (GetClassName(hwnd, className, className.Capacity) == 0) throw new NativeFailure("WINDOW_CLASS_UNAVAILABLE");
        var title = new StringBuilder(4096); GetWindowText(hwnd, title, title.Capacity);
        if (!GetWindowRect(hwnd, out Rect rect)) throw new NativeFailure("WINDOW_RECT_UNAVAILABLE");
        Guid desktop = WindowDesktop(hwnd);
        int number = Desktops().FindIndex(item => item.desktop_id == desktop.ToString("D")) + 1;
        if (desktop == Guid.Empty || number == 0) throw new NativeFailure("WINDOW_DESKTOP_UNAVAILABLE");
        if (!IsWindow(hwnd) || GetWindowThreadProcessId(hwnd, out uint afterPid) != tid || afterPid != pid)
            throw new NativeFailure("WINDOW_IDENTITY_CHANGED");
        return new(raw, pid, tid, ((ulong)born.high << 32) | born.low, image.ToString(),
            className.ToString(), title.ToString(), rect.left, rect.top, Math.Max(0, rect.right-rect.left),
            Math.Max(0, rect.bottom-rect.top), GetForegroundWindow() == hwnd,
            desktop.ToString("D"), number, IsWindowVisible(hwnd), pid == Environment.ProcessId);
    }
    internal List<WindowCandidate> Candidates()
    {
        var result = new List<WindowCandidate>();
        foreach (ulong hwnd in WindowHandles())
        {
            var handle = new IntPtr(unchecked((long)hwnd));
            if (IsWindowVisible(handle) && GetWindowThreadProcessId(handle, out uint pid) != 0 && pid != Environment.ProcessId)
                result.Add(new(hwnd, pid));
        }
        return result;
    }
    internal void Move(NativeWindow expected, string desktopId, int number)
    {
        Verify(desktopId, number);
        NativeWindow actual = Window(expected.hwnd);
        if (!SameIdentity(expected, actual) || actual.is_hud) throw new NativeFailure("WINDOW_IDENTITY_CHANGED");
        var hwnd = new IntPtr(unchecked((long)expected.hwnd));
        if (move(hwnd, number-1) != 1) throw new NativeFailure("WINDOW_PLACEMENT_FAILED");
        NativeWindow placed = Window(expected.hwnd);
        if (!SameIdentity(expected, placed) || placed.desktop_id != desktopId)
            throw new NativeFailure("WINDOW_PLACEMENT_UNCONFIRMED");
    }
    internal static bool SameIdentity(NativeWindow a, NativeWindow b) =>
        a.hwnd == b.hwnd && a.pid == b.pid && a.tid == b.tid && a.birth == b.birth &&
        String.Equals(a.image, b.image, StringComparison.OrdinalIgnoreCase) && a.class_name == b.class_name;
    internal static Guid WindowDesktop(IntPtr hwnd)
    {
        var manager = (IVirtualDesktopManager)(Activator.CreateInstance(Type.GetTypeFromCLSID(
            new Guid("AA509086-5CA9-4C25-8F95-589D3C07B48A"), true)!) ?? throw new NativeFailure("DESKTOP_COM_UNAVAILABLE"));
        try { return manager.GetWindowDesktopId(hwnd); }
        finally { Marshal.FinalReleaseComObject(manager); }
    }
    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("A5CD92FF-29BE-454C-8D04-D82879FB3F1B")]
    private interface IVirtualDesktopManager
    {
        [return: MarshalAs(UnmanagedType.Bool)] bool IsWindowOnCurrentVirtualDesktop(IntPtr window);
        Guid GetWindowDesktopId(IntPtr window);
        void MoveWindowToDesktop(IntPtr window, ref Guid desktopId);
    }
    [StructLayout(LayoutKind.Sequential)] private struct FileTime { internal uint low, high; }
    [StructLayout(LayoutKind.Sequential)] private struct Rect { internal int left, top, right, bottom; }
    private delegate bool EnumWindowsFn(IntPtr hwnd, IntPtr state);
    [DllImport("user32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool EnumWindows(EnumWindowsFn callback, IntPtr state);
    [DllImport("kernel32.dll", EntryPoint="GetConsoleWindow")] internal static extern IntPtr ConsoleWindow();
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IsWindow(IntPtr hwnd);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="GetClassNameW")] private static extern int GetClassName(IntPtr hwnd, StringBuilder value, int length);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="GetWindowTextW")] private static extern int GetWindowText(IntPtr hwnd, StringBuilder value, int length);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetWindowRect(IntPtr hwnd, out Rect value);
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("kernel32.dll", SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetProcessTimes(SafeProcessHandle process, out FileTime creation, out FileTime exit, out FileTime kernel, out FileTime user);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="QueryFullProcessImageNameW")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, StringBuilder image, ref uint size);
    public void Dispose() => NativeLibrary.Free(library);
}
