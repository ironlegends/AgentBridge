"""Exercise the real WinExe and Windows desktop API through its private pipes."""
from pathlib import Path
import ctypes, json, os, queue, struct, subprocess, sys, threading, time, unittest, uuid

class Client:
    def __init__(self, executable):
        self.process = subprocess.Popen([str(executable)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
        self.frames = queue.Queue()
        self.seq = 0
        self.events = []
        self.lock = threading.Lock()
        self.closed = False
        self.beating = True
        self.reader = threading.Thread(target=self.read_loop, daemon=True)
        self.reader.start()
        self.beats = threading.Thread(target=self.beat_loop, daemon=True)
        self.beats.start()

    def read_loop(self):
        try:
            while True:
                header = self.process.stdout.read(4)
                if not header: return
                if len(header) != 4: raise AssertionError("short native header")
                size, = struct.unpack("<I", header)
                if not 0 < size <= 1048576: raise AssertionError("native frame exceeds bound")
                raw = self.process.stdout.read(size)
                if len(raw) != size: raise AssertionError("short native frame")
                self.frames.put(json.loads(raw))
        except BaseException as e: self.frames.put(e)

    def send(self, item):
        raw = json.dumps(item, separators=(",", ":")).encode()
        with self.lock:
            self.process.stdin.write(struct.pack("<I", len(raw)) + raw)
            self.process.stdin.flush()

    def beat_loop(self):
        while not self.closed:
            if self.beating:
                try: self.send({"v": 1, "id": 0, "op": "owner_heartbeat", "args": {}})
                except (OSError, ValueError): return
            time.sleep(.45)

    def call(self, op, args=None, timeout=5):
        self.seq += 1
        request_id = self.seq
        self.send({"v": 1, "id": request_id, "op": op, "args": args or {}})
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            item = self.frames.get(timeout=max(.001, deadline-time.monotonic()))
            if isinstance(item, BaseException): raise item
            if item.get("event"):
                self.events.append(item)
                continue
            if item.get("id") == 0: continue
            if item.get("id") != request_id: raise AssertionError("wrong correlation")
            if item.get("v") != 1: raise AssertionError("wrong protocol")
            if not item.get("ok"): raise AssertionError(json.dumps({"error": item.get("error"), "diagnostic": item.get("diagnostic")}))
            return item["result"]
        raise AssertionError("native IPC deadline")

    def close(self):
        self.closed = True
        try: self.process.stdin.close()
        except OSError: pass
        try: self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill(); self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        self.beats.join(timeout=2)
        self.process.stdout.close()
        self.process.stderr.close()

class NativeProtocol(unittest.TestCase):
    def setUp(self): self.client = Client(Path(os.environ["AGENT_BRIDGE_NATIVE_TEST_EXE"]))
    def tearDown(self): self.client.close()

    def test_hello_reports_actual_hidden_native_backend(self):
        hello = self.client.call("hello")
        self.assertEqual(hello["pid"], self.client.process.pid)
        self.assertFalse(hello["console"])
        self.assertTrue(hello["virtual_desktops"])
        state = self.client.call("desktops")
        self.assertGreaterEqual(len(state["desktops"]), 1)
        self.assertEqual(state["desktops"][0]["desktop_number"], 1)
        self.assertEqual(len(state["current_desktop_id"]), 36)

    def test_real_desktop_hud_and_owner_heartbeat_loss(self):
        before = self.client.call("desktops")
        library = ctypes.CDLL(str(Path(os.environ["AGENT_BRIDGE_NATIVE_TEST_EXE"]).parent / "VirtualDesktopAccessor.dll"))
        library.GetDesktopCount.restype = ctypes.c_int
        library.GetWindowDesktopNumber.argtypes = [ctypes.c_void_p]
        library.GetWindowDesktopNumber.restype = ctypes.c_int
        created = None
        lease = str(uuid.uuid4())
        try:
            created = self.client.call("create_desktop")
            self.assertEqual(library.GetDesktopCount(), len(before["desktops"]) + 1)
            self.assertGreaterEqual(created["desktop_number"], 2)
            ready = self.client.call("start_lease", {**created, "lease_id": lease,
                "generation": 1, "task_label": "Agent Bridge dedicated native protocol test"})
            self.assertTrue(ready["hud_ready"])
            self.assertEqual(len(ready["hud_windows"]), 2)
            for hwnd in ready["hud_windows"]:
                self.assertTrue(ctypes.windll.user32.IsWindow(ctypes.c_void_p(hwnd)))
                self.assertEqual(library.GetWindowDesktopNumber(ctypes.c_void_p(hwnd)), created["desktop_number"] - 1)
            after = self.client.call("desktops")
            self.assertEqual(after["current_desktop_id"], before["current_desktop_id"], "helper must never switch user desktops")
            self.client.beating = False
            time.sleep(2.9)
            expired = self.client.call("lease_status", {"lease_id": lease})
            self.assertFalse(expired["active"])
            for hwnd in ready["hud_windows"]:
                self.assertFalse(ctypes.windll.user32.IsWindow(ctypes.c_void_p(hwnd)))
        finally:
            self.client.beating = True
            if created:
                self.client.call("stop_lease", {"lease_id": lease})
                self.client.call("remove_desktop", {"desktop_id": created["desktop_id"], "desktop_number": created["desktop_number"]})
                self.assertEqual(library.GetDesktopCount(), len(before["desktops"]))

    def test_desktop_one_cannot_be_leased_or_removed(self):
        first = self.client.call("desktops")["desktops"][0]
        with self.assertRaisesRegex(AssertionError, "DESKTOP_ONE_RESERVED"):
            self.client.call("start_lease", {**first, "lease_id": str(uuid.uuid4()),
                "generation": 1, "task_label": "must be rejected"})
        with self.assertRaisesRegex(AssertionError, "DESKTOP_ONE_RESERVED"):
            self.client.call("remove_desktop", first)

    def test_hud_visibility_is_required_for_active_control(self):
        before = self.client.call("desktops")
        created = None
        lease = str(uuid.uuid4())
        try:
            created = self.client.call("create_desktop")
            ready = self.client.call("start_lease", {**created, "lease_id": lease,
                "generation": 1, "task_label": "Agent Bridge visible HUD qualification"})
            for hwnd in ready["hud_windows"]:
                self.assertTrue(ctypes.windll.user32.IsWindowVisible(ctypes.c_void_p(hwnd)), "ready HUD must have actual visible window styles")
            ctypes.windll.user32.ShowWindow(ctypes.c_void_p(ready["hud_windows"][0]), 0)
            hidden = self.client.call("lease_status", {"lease_id": lease})
            self.assertFalse(hidden["active"], "hiding a safety HUD must revoke authority before another action")
            for hwnd in ready["hud_windows"]:
                self.assertFalse(ctypes.windll.user32.IsWindow(ctypes.c_void_p(hwnd)), "revocation closes both HUD HWNDs")
            self.assertEqual(self.client.call("desktops")["current_desktop_id"], before["current_desktop_id"])
        finally:
            if created:
                self.client.call("stop_lease", {"lease_id": lease})
                self.client.call("remove_desktop", created)
                self.assertEqual(self.client.call("desktops")["desktops"], before["desktops"])

    def test_hud_remains_bound_while_owner_is_idle_and_healthy(self):
        before = self.client.call("desktops")
        library = ctypes.CDLL(str(Path(os.environ["AGENT_BRIDGE_NATIVE_TEST_EXE"]).parent / "VirtualDesktopAccessor.dll"))
        library.GetWindowDesktopNumber.argtypes = [ctypes.c_void_p]
        library.GetWindowDesktopNumber.restype = ctypes.c_int
        created = None
        lease = str(uuid.uuid4())
        try:
            created = self.client.call("create_desktop")
            ready = self.client.call("start_lease", {**created, "lease_id": lease,
                "generation": 1, "task_label": "Agent Bridge idle HUD qualification"})
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                status = self.client.call("lease_status", {"lease_id": lease})
                self.assertTrue(status["active"], json.dumps(self.client.events[-12:]))
                self.assertTrue(status["hud_ready"])
                for hwnd in ready["hud_windows"]:
                    self.assertTrue(ctypes.windll.user32.IsWindow(ctypes.c_void_p(hwnd)))
                    self.assertEqual(library.GetWindowDesktopNumber(ctypes.c_void_p(hwnd)), created["desktop_number"] - 1)
                self.assertEqual(self.client.call("desktops")["current_desktop_id"], before["current_desktop_id"])
                time.sleep(.2)
        finally:
            if created:
                self.client.call("stop_lease", {"lease_id": lease})
                self.client.call("remove_desktop", created)
                self.assertEqual(self.client.call("desktops")["desktops"], before["desktops"])

if __name__ == "__main__": unittest.main(verbosity=2)
