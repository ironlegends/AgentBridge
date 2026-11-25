using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading.Channels;
using System.Windows;
using System.Windows.Threading;

namespace AgentBridge.Native;

internal sealed class Lease(string id, ulong generation, DesktopInfo desktop, AgentDesktopOverlay hud)
{
    internal string Id { get; } = id;
    internal ulong Generation { get; } = generation;
    internal DesktopInfo Desktop { get; } = desktop;
    internal AgentDesktopOverlay Hud { get; } = hud;
    internal long Started { get; } = Stopwatch.GetTimestamp();
    internal bool Ready { get; set; }
}

internal sealed class NativeHost : IDisposable
{
    private const int MaxFrame = 1048576;
    private readonly Application app;
    private readonly NativeApi api;
    private readonly Dictionary<string, Lease> leases = new();
    private readonly Stream input = Console.OpenStandardInput();
    private readonly Stream output = Console.OpenStandardOutput();
    private readonly Channel<byte[]> outgoing = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(8) {
        SingleReader = true, SingleWriter = false, FullMode = BoundedChannelFullMode.Wait
    });
    private readonly DispatcherTimer timer;
    private long ownerHeartbeat = Stopwatch.GetTimestamp();
    private int queued, ended;
    private ulong beatSequence;

    internal NativeHost(Application application)
    {
        app = application;
        api = new NativeApi();
        timer = new DispatcherTimer(DispatcherPriority.Send, app.Dispatcher) { Interval = TimeSpan.FromMilliseconds(450) };
        timer.Tick += (_, _) => Tick();
    }
    internal void Start()
    {
        new Thread(ReadLoop) { IsBackground = true, Name = "AgentBridge.Native.Input" }.Start();
        new Thread(WriteLoop) { IsBackground = true, Name = "AgentBridge.Native.Output" }.Start();
        timer.Start();
    }
    private bool OwnerFresh => Stopwatch.GetElapsedTime(Interlocked.Read(ref ownerHeartbeat)).TotalMilliseconds <= 2500;
    private void Send(object value)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        if (bytes.Length > MaxFrame || !outgoing.Writer.TryWrite(bytes)) Finish(2);
    }
    private void WriteLoop()
    {
        try
        {
            byte[] header = new byte[4];
            while (outgoing.Reader.WaitToReadAsync().AsTask().GetAwaiter().GetResult())
                while (outgoing.Reader.TryRead(out byte[]? bytes))
                {
                    BinaryPrimitives.WriteInt32LittleEndian(header, bytes.Length);
                    output.Write(header); output.Write(bytes); output.Flush();
                }
        }
        catch { Finish(2); }
    }
    private void ReadLoop()
    {
        try
        {
            byte[] header = new byte[4];
            while (Volatile.Read(ref ended) == 0)
            {
                int first = input.ReadByte();
                if (first < 0) { Finish(0); return; }
                header[0] = (byte)first; input.ReadExactly(header.AsSpan(1));
                int size = BinaryPrimitives.ReadInt32LittleEndian(header);
                if (size <= 0 || size > MaxFrame) throw new NativeFailure("NATIVE_FRAME_LIMIT");
                byte[] bytes = new byte[size]; input.ReadExactly(bytes);
                using JsonDocument document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 24 });
                JsonElement request = document.RootElement;
                Fields(request, "v", "id", "op", "args");
                if (request.GetProperty("v").GetInt32() != 1) throw new NativeFailure("NATIVE_PROTOCOL_MISMATCH");
                ulong id = request.GetProperty("id").GetUInt64();
                string op = Text(request, "op", 64);
                JsonElement args = request.GetProperty("args");
                if (args.ValueKind != JsonValueKind.Object) throw new NativeFailure("INVALID_NATIVE_REQUEST");
                if (id == 0)
                {
                    if (op != "owner_heartbeat") throw new NativeFailure("INVALID_NATIVE_HEARTBEAT");
                    Fields(args); Interlocked.Exchange(ref ownerHeartbeat, Stopwatch.GetTimestamp()); continue;
                }
                if (Interlocked.Increment(ref queued) > 32) throw new NativeFailure("NATIVE_REQUEST_LIMIT");
                JsonElement copy = args.Clone();
                app.Dispatcher.BeginInvoke(async () => {
                    try
                    {
                        object result = await Handle(op, copy);
                        Send(new { v = 1, id, ok = true, result });
                    }
                    catch (Exception error) { Send(new { v = 1, id, ok = false,
                        error = error is NativeFailure known ? known.Code : "NATIVE_OPERATION_FAILED",
                        diagnostic = new { type = error.GetType().Name, hresult = error.HResult,
                            inner_type = error.InnerException?.GetType().Name, inner_hresult = error.InnerException?.HResult } }); }
                    finally { Interlocked.Decrement(ref queued); }
                });
            }
        }
        catch { Finish(2); }
    }
    private async Task<object> Handle(string op, JsonElement args)
    {
        switch (op)
        {
            case "hello":
                Fields(args);
                return new { pid = Environment.ProcessId, console = NativeApi.ConsoleWindow() != IntPtr.Zero,
                    virtual_desktops = true, protocol = 1 };
            case "desktops":
                Fields(args);
                return new { desktops = api.Desktops(), current_desktop_id = api.Current().desktop_id };
            case "create_desktop":
                Fields(args); return api.Create();
            case "remove_desktop":
            {
                Fields(args, "desktop_id", "desktop_number");
                string desktop = Text(args, "desktop_id", 36); int number = Number(args, "desktop_number", 1, 128);
                if (number == 1) throw new NativeFailure("DESKTOP_ONE_RESERVED");
                if (leases.Values.Any(lease => lease.Desktop.desktop_id == desktop)) throw new NativeFailure("DESKTOP_OCCUPIED");
                api.Remove(desktop, number); return new { removed = true };
            }
            case "start_lease":
            {
                Fields(args, "lease_id", "generation", "desktop_id", "desktop_number", "task_label");
                string id = Uuid(args, "lease_id"); ulong generation = args.GetProperty("generation").GetUInt64();
                if (generation == 0 || !OwnerFresh) throw new NativeFailure("OWNER_HEARTBEAT_STALE");
                var desktop = api.Verify(Uuid(args, "desktop_id"), Number(args, "desktop_number", 1, 128));
                if (leases.Count >= 16 || leases.ContainsKey(id) || leases.Values.Any(value => value.Desktop == desktop))
                    throw new NativeFailure("DESKTOP_OCCUPIED");
                string label = Text(args, "task_label", 200);
                var hud = new AgentDesktopOverlay(label, () => Revoke(id, "user_exit"));
                var lease = new Lease(id, generation, desktop, hud); leases.Add(id, lease);
                try
                {
                    await hud.ShowOnDesktopAsync(Guid.Parse(desktop.desktop_id), () =>
                        OwnerFresh && leases.TryGetValue(id, out Lease? current) && ReferenceEquals(current, lease));
                    Verify(lease); lease.Ready = true; return View(lease);
                }
                catch { Revoke(id, "hud_not_ready"); throw; }
            }
            case "stop_lease":
                Fields(args, "lease_id"); Revoke(Uuid(args, "lease_id"), "stopped"); return new { stopped = true };
            case "lease_status":
            {
                Fields(args, "lease_id"); string id = Uuid(args, "lease_id");
                if (!leases.TryGetValue(id, out Lease? lease)) return new { active = false };
                try { Verify(lease, allowArming: true); return View(lease); }
                catch (Exception error) { Revoke(id, error is NativeFailure known ? known.Code : "NATIVE_LEASE_CHECK_FAILED"); return new { active = false }; }
            }
            case "window_identity":
                Fields(args, "hwnd"); return api.Window(args.GetProperty("hwnd").GetUInt64());
            case "window_candidates":
                Fields(args); return new { windows = api.Candidates() };
            case "move_window":
            {
                Fields(args, "lease_id", "generation", "window");
                string id = Uuid(args, "lease_id"); ulong generation = args.GetProperty("generation").GetUInt64();
                if (!leases.TryGetValue(id, out Lease? lease) || lease.Generation != generation)
                    throw new NativeFailure("LEASE_EXPIRED");
                Verify(lease);
                NativeWindow expected = args.GetProperty("window").Deserialize<NativeWindow>() ?? throw new NativeFailure("INVALID_WINDOW_IDENTITY");
                api.Move(expected, lease.Desktop.desktop_id, lease.Desktop.desktop_number);
                Verify(lease); return api.Window(expected.hwnd);
            }
            case "shutdown":
                Fields(args); Finish(0); return new { stopped = true };
            default: throw new NativeFailure("UNKNOWN_NATIVE_OPERATION");
        }
    }
    private void Verify(Lease lease, bool allowArming = false)
    {
        if (!OwnerFresh) throw new NativeFailure("OWNER_HEARTBEAT_STALE");
        api.Verify(lease.Desktop.desktop_id, lease.Desktop.desktop_number);
        // A lease is not active while WPF registers its HWNDs with the shell.
        // Keep monitoring ownership, but do not dispose an in-flight arm.
        if (allowArming && !lease.Ready && Stopwatch.GetElapsedTime(lease.Started).TotalMilliseconds <= 3500) return;
        if (!lease.Hud.IsOnDesktop(Guid.Parse(lease.Desktop.desktop_id))) throw new NativeFailure("HUD_NOT_READY");
    }
    private object View(Lease lease) => new { active = lease.Ready, arming = !lease.Ready, lease_id = lease.Id, generation = lease.Generation,
        desktop_id = lease.Desktop.desktop_id, desktop_number = lease.Desktop.desktop_number,
        hud_ready = lease.Ready && lease.Hud.IsShown, hud_visible = lease.Ready && api.Current().desktop_id == lease.Desktop.desktop_id,
        hud_windows = lease.Hud.WindowHandles };
    private void Revoke(string id, string reason)
    {
        if (!leases.Remove(id, out Lease? lease)) return;
        lease.Hud.Dispose();
        Send(new { v = 1, @event = "revoked", lease_id = id, generation = lease.Generation, reason });
    }
    private void Tick()
    {
        if (Volatile.Read(ref ended) != 0) return;
        foreach (Lease lease in leases.Values.ToArray())
        {
            try { Verify(lease, allowArming: true); }
            catch (Exception error) { Revoke(lease.Id, error is NativeFailure known ? known.Code : "NATIVE_LEASE_CHECK_FAILED"); }
        }
        try { Send(new { v = 1, @event = "heartbeat", sequence = ++beatSequence,
            current_desktop_id = api.Current().desktop_id, leases = leases.Values.Select(View).ToArray() }); }
        catch { Finish(2); }
    }
    internal void Finish(int exitCode)
    {
        if (Interlocked.Exchange(ref ended, 1) != 0) return;
        app.Dispatcher.BeginInvoke(() => {
            timer.Stop();
            foreach (Lease lease in leases.Values) lease.Hud.Dispose();
            leases.Clear(); outgoing.Writer.TryComplete(); app.Shutdown(exitCode);
        });
    }
    private static void Fields(JsonElement value, params string[] permitted)
    {
        if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Any(property => !permitted.Contains(property.Name)))
            throw new NativeFailure("INVALID_NATIVE_REQUEST");
    }
    private static string Text(JsonElement value, string field, int maximum)
    {
        string result = value.GetProperty(field).GetString() ?? throw new NativeFailure("INVALID_NATIVE_REQUEST");
        if (result.Length == 0 || result.Length > maximum || result.Contains('\0')) throw new NativeFailure("INVALID_NATIVE_REQUEST");
        return result;
    }
    private static string Uuid(JsonElement value, string field)
    {
        string result = Text(value, field, 36);
        if (!Guid.TryParseExact(result, "D", out Guid id) || id == Guid.Empty) throw new NativeFailure("INVALID_NATIVE_REQUEST");
        return id.ToString("D");
    }
    private static int Number(JsonElement value, string field, int minimum, int maximum)
    {
        int number = value.GetProperty(field).GetInt32();
        if (number < minimum || number > maximum) throw new NativeFailure("INVALID_NATIVE_REQUEST");
        return number;
    }
    public void Dispose()
    {
        timer.Stop(); foreach (Lease lease in leases.Values) lease.Hud.Dispose(); leases.Clear();
        outgoing.Writer.TryComplete(); api.Dispose();
    }
}

internal static class Program
{
    [STAThread]
    public static int Main()
    {
        try
        {
            var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
            using var host = new NativeHost(app);
            app.DispatcherUnhandledException += (_, error) => { error.Handled = true; host.Finish(2); };
            host.Start(); return app.Run();
        }
        catch { Console.Error.WriteLine("NATIVE_INITIALIZATION_FAILED"); return 2; }
    }
}
