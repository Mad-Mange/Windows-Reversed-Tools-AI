"""Equivalence tests: the Rust translation (aicalc.exe) against the original
calc.exe it was decompiled from.

    python -m unittest tests.test_equivalence -v

Static checks compare the two PE images (headers, mitigations, imports,
resources, embedded TraceLogging metadata). Rendering checks draw the icons
the shell shows for each file and compare them pixel by pixel. Runtime checks
launch both executables, verify exit codes and the Calculator window they
open, and compare screenshots of that window pixel by pixel.

Environment:
    AICALC_EXE        path of the clone (default: release build output)
    AICALC_SKIP_GUI   set to 1 to skip tests that open Calculator windows
    AICALC_ARTIFACTS  where screenshots are written (default: tests/artifacts)

The ETW runtime test needs an elevated prompt (trace sessions require admin)
and is skipped otherwise.
"""

import ctypes
import ctypes.wintypes as wt
import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

import pefile
from PIL import Image, ImageChops, ImageGrab

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / "calc.exe"
CLONE = Path(os.environ.get("AICALC_EXE", ROOT / "target" / "i686-pc-windows-msvc" / "release" / "aicalc.exe"))
ARTIFACTS = Path(os.environ.get("AICALC_ARTIFACTS", ROOT / "tests" / "artifacts"))
SKIP_GUI = os.environ.get("AICALC_SKIP_GUI") == "1"

PROVIDER_GUID = "{0905CA09-610E-401E-B650-2F212980B9E0}"

user32 = ctypes.WinDLL("user32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
dwmapi = ctypes.WinDLL("dwmapi")

# Physical-pixel coordinates for window rects and screen captures.
try:
    user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))  # PER_MONITOR_AWARE_V2
except Exception:
    pass
# Inherited by launched children: no hard-error dialogs if an image fails to load.
kernel32.SetErrorMode(0x0001 | 0x0002 | 0x8000)


def load(path):
    return pefile.PE(str(path), fast_load=False)


def setUpModule():
    for p in (ORIGINAL, CLONE):
        if not p.is_file():
            raise unittest.SkipTest(f"missing {p} (build with `cargo build --release`)")


# ---------------------------------------------------------------- PE image


class TestImage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = load(ORIGINAL)
        cls.b = load(CLONE)

    def same(self, getter, what):
        self.assertEqual(getter(self.a), getter(self.b), what)

    def test_machine_and_format(self):
        self.assertEqual(self.b.FILE_HEADER.Machine, 0x14C, "x86 image")
        self.same(lambda p: p.FILE_HEADER.Machine, "machine")
        self.same(lambda p: p.OPTIONAL_HEADER.Magic, "PE32")
        self.same(lambda p: p.FILE_HEADER.Characteristics, "file characteristics (no LAA, 32-bit, executable)")

    def test_subsystem_and_versions(self):
        oh = lambda p: p.OPTIONAL_HEADER
        self.same(lambda p: oh(p).Subsystem, "subsystem (Windows GUI)")
        self.same(lambda p: (oh(p).MajorSubsystemVersion, oh(p).MinorSubsystemVersion), "subsystem version")
        self.same(lambda p: (oh(p).MajorOperatingSystemVersion, oh(p).MinorOperatingSystemVersion), "OS version")
        self.same(lambda p: (oh(p).MajorImageVersion, oh(p).MinorImageVersion), "image version")
        self.same(lambda p: oh(p).Reserved1, "Win32VersionValue")

    def test_memory_layout(self):
        for field in ("ImageBase", "SectionAlignment", "FileAlignment", "SizeOfStackReserve",
                      "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags"):
            self.same(lambda p: getattr(p.OPTIONAL_HEADER, field), field)

    def test_security_mitigations(self):
        names = ["IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
                 "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
                 "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", "IMAGE_DLLCHARACTERISTICS_NO_BIND",
                 "IMAGE_DLLCHARACTERISTICS_APPCONTAINER", "IMAGE_DLLCHARACTERISTICS_GUARD_CF",
                 "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"]
        for n in names:
            self.same(lambda p: bool(getattr(p.OPTIONAL_HEADER, n)), n)
        self.assertTrue(self.b.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF)
        # NO_SEH may differ: the original contains SEH handlers (its CRT's
        # __try/__except); the Rust image has none, and says so.
        if self.b.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH:
            lc = self.b.DIRECTORY_ENTRY_LOAD_CONFIG.struct
            self.assertEqual(lc.SEHandlerCount, 0)

    def test_load_config(self):
        la = self.a.DIRECTORY_ENTRY_LOAD_CONFIG.struct
        lb = self.b.DIRECTORY_ENTRY_LOAD_CONFIG.struct
        self.assertEqual(la.Size, lb.Size, "load config size")
        self.assertEqual(la.GuardFlags, lb.GuardFlags, "CFG guard flags")
        self.assertGreater(lb.GuardCFFunctionCount, 0)
        for pe, lc in ((self.a, la), (self.b, lb)):
            base = pe.OPTIONAL_HEADER.ImageBase
            self.assertNotEqual(lc.SecurityCookie, 0, "security cookie (required for subsystem 10.0 x86 images)")
            cookie = struct.unpack("<I", pe.get_data(lc.SecurityCookie - base, 4))[0]
            self.assertEqual(cookie, 0xBB40E64E, "default cookie seed")
            # The CFG check pointer initially targets a no-op return
            # (`ret` or `ret 0`: the check is fastcall, nothing to pop).
            fptr = struct.unpack("<I", pe.get_data(lc.GuardCFCheckFunctionPointer - base, 4))[0]
            code = bytes(pe.get_data(fptr - base, 3))
            self.assertTrue(code[:1] == b"\xC3" or code == b"\xC2\x00\x00", code.hex())

    def test_checksum(self):
        for pe in (self.a, self.b):
            self.assertEqual(pe.OPTIONAL_HEADER.CheckSum, pe.generate_checksum())

    def test_no_exports_tls_or_clr(self):
        for pe in (self.a, self.b):
            dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
            for idx in (0, 9, 14):  # export, TLS, COM descriptor
                self.assertEqual(dirs[idx].Size, 0)

    def imports(self, pe):
        out = set()
        for d in pe.DIRECTORY_ENTRY_IMPORT:
            for i in d.imports:
                out.add((d.dll.decode().lower(), i.name.decode() if i.name else f"#{i.ordinal}"))
        return out

    def test_imports(self):
        a, b = self.imports(self.a), self.imports(self.b)
        # Everything the application logic calls comes from the same DLL.
        for entry in [("shell32.dll", "ShellExecuteW"), ("advapi32.dll", "EventRegister"),
                      ("advapi32.dll", "EventSetInformation"), ("advapi32.dll", "EventWriteTransfer"),
                      ("api-ms-win-core-processthreads-l1-1-0.dll", "GetStartupInfoW"),
                      ("kernel32.dll", "GetSystemTimeAsFileTime"), ("kernel32.dll", "GetCurrentProcessId"),
                      ("kernel32.dll", "GetCurrentThreadId"), ("kernel32.dll", "GetTickCount"),
                      ("kernel32.dll", "QueryPerformanceCounter")]:
            self.assertIn(entry, a)
            self.assertIn(entry, b)
        # Only substitutions for msvcrt's _wcmdln/exit are new; no C runtime DLLs at all.
        self.assertEqual(b - a, {("kernel32.dll", "GetCommandLineW"), ("kernel32.dll", "ExitProcess")})
        for dll, _ in b:
            self.assertFalse(dll.startswith(("vcruntime", "msvcp", "api-ms-win-crt", "ucrtbase", "msvcrt")), dll)


# ---------------------------------------------------------------- resources


def resources(pe):
    out = {}
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        tname = str(t.name) if t.name else t.id
        for n in t.directory.entries:
            nname = str(n.name) if n.name else n.id
            for lang in n.directory.entries:
                ds = lang.data.struct
                out[(tname, nname, lang.id)] = pe.get_data(ds.OffsetToData, ds.Size)
    return out


class TestResources(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pa, cls.pb = load(ORIGINAL), load(CLONE)
        cls.a, cls.b = resources(cls.pa), resources(cls.pb)

    def test_same_resource_entries(self):
        self.assertEqual(sorted(map(str, self.a)), sorted(map(str, self.b)))

    def test_icons_byte_identical(self):
        for key in self.a:
            if key[0] in (3, 14):  # RT_ICON, RT_GROUP_ICON
                self.assertEqual(self.a[key], self.b[key], key)

    def test_manifest_byte_identical(self):
        self.assertEqual(self.a[(24, 1, 1033)], self.b[(24, 1, 1033)])

    def test_version_info(self):
        va, vb = self.a[(16, 1, 1033)], self.b[(16, 1, 1033)]
        n = struct.unpack_from("<H", va, 0)[0]
        self.assertEqual(n, struct.unpack_from("<H", vb, 0)[0], "VS_VERSIONINFO length")
        self.assertEqual(va[:n], vb[:n], "VS_VERSIONINFO block")
        # Beyond wLength there is only zero padding (the original carries 4 extra bytes).
        self.assertFalse(any(va[n:]) or any(vb[n:]))

        def strings(pe):
            d = {}
            for fi in pe.FileInfo[0]:
                if fi.Key == b"StringFileInfo":
                    for st in fi.StringTable:
                        d.update(st.entries)
            return d
        self.assertEqual(strings(self.pa), strings(self.pb))
        self.assertEqual(strings(self.pb)[b"FileDescription"], b"Windows Calculator")


# ---------------------------------------------------------------- TraceLogging metadata


TLG_MAGIC = struct.pack("<Q", 0xBB8A052B88040E86)


def tracelogging_run(data):
    """Returns the ETW0 header + all metadata blobs + end marker."""
    start = data.find(b"ETW0" + struct.pack("<HBB", 16, 0, 0) + TLG_MAGIC)
    assert start >= 0, "no _tlgHeader"
    pos = start + 16
    blobs = []
    while True:
        kind = data[pos]
        if kind == 1:  # _TlgBlobEnd
            return data[start:pos + 1], blobs
        if kind == 6:  # _TlgBlobEvent4: type, channel, level, opcode, keyword, size...
            size = 12 + struct.unpack_from("<H", data, pos + 12)[0]
        elif kind == 4:  # _TlgBlobProvider3: type, GUID, size...
            size = 17 + struct.unpack_from("<H", data, pos + 17)[0]
        else:
            raise AssertionError(f"unexpected blob type {kind}")
        blobs.append(data[pos:pos + size])
        pos += size


class TestTraceLoggingMetadata(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = ORIGINAL.read_bytes()
        cls.b = CLONE.read_bytes()

    def test_metadata_run_identical(self):
        run_a, blobs_a = tracelogging_run(self.a)
        run_b, blobs_b = tracelogging_run(self.b)
        self.assertEqual(run_a, run_b)
        self.assertEqual(len(blobs_b), 2)

    def test_metadata_content(self):
        _, blobs = tracelogging_run(self.b)
        event, provider = blobs
        self.assertEqual(event[1:4], bytes([11, 5, 0]))  # channel, level, opcode
        self.assertEqual(struct.unpack_from("<Q", event, 4)[0], 0x0002000000000000)
        self.assertIn(b"CalculatorWinMain\0\"CalculatorStarted\"\0\x02", event)
        self.assertEqual(str(uuid.UUID(bytes_le=provider[1:17])).upper(), PROVIDER_GUID[1:-1])
        self.assertIn(b"MicrosoftCalculator\0", provider)
        self.assertEqual(uuid.UUID(bytes_le=provider[-16:]), uuid.UUID("4f50731a-89cf-4782-b3e0-dce8c90476ba"))

    def test_payload_and_uri_strings(self):
        for data in (self.a, self.b):
            self.assertIn(b"CalculatorStarted\0", data)
            self.assertIn("ms-calculator:\0".encode("utf-16-le"), data)


# ---------------------------------------------------------------- icon rendering


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wt.DWORD), ("biWidth", wt.LONG), ("biHeight", wt.LONG), ("biPlanes", wt.WORD),
                ("biBitCount", wt.WORD), ("biCompression", wt.DWORD), ("biSizeImage", wt.DWORD),
                ("biXPelsPerMeter", wt.LONG), ("biYPelsPerMeter", wt.LONG), ("biClrUsed", wt.DWORD),
                ("biClrImportant", wt.DWORD)]


class SHFILEINFOW(ctypes.Structure):
    _fields_ = [("hIcon", wt.HICON), ("iIcon", ctypes.c_int), ("dwAttributes", wt.DWORD),
                ("szDisplayName", wt.WCHAR * 260), ("szTypeName", wt.WCHAR * 80)]


user32.PrivateExtractIconsW.argtypes = [wt.LPCWSTR, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                        ctypes.POINTER(wt.HICON), ctypes.POINTER(wt.UINT), wt.UINT, wt.UINT]
user32.DrawIconEx.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int, wt.HICON, ctypes.c_int, ctypes.c_int,
                              wt.UINT, wt.HBRUSH, wt.UINT]
user32.DestroyIcon.argtypes = [wt.HICON]
gdi32.CreateDIBSection.argtypes = [wt.HDC, ctypes.c_void_p, wt.UINT, ctypes.POINTER(ctypes.c_void_p),
                                   wt.HANDLE, wt.DWORD]
gdi32.CreateDIBSection.restype = wt.HBITMAP
gdi32.CreateCompatibleDC.argtypes = [wt.HDC]
gdi32.CreateCompatibleDC.restype = wt.HDC
gdi32.SelectObject.argtypes = [wt.HDC, wt.HGDIOBJ]
gdi32.SelectObject.restype = wt.HGDIOBJ
gdi32.DeleteObject.argtypes = [wt.HGDIOBJ]
gdi32.DeleteDC.argtypes = [wt.HDC]
shell32.SHGetFileInfoW.argtypes = [wt.LPCWSTR, wt.DWORD, ctypes.POINTER(SHFILEINFOW), wt.UINT, wt.UINT]
shell32.SHGetFileInfoW.restype = ctypes.c_size_t


def render_icon(hicon, size, background):
    """Draws an icon over a solid background; returns raw BGRA pixels."""
    bmi = BITMAPINFOHEADER(ctypes.sizeof(BITMAPINFOHEADER), size, -size, 1, 32, 0, 0, 0, 0, 0, 0)
    bits = ctypes.c_void_p()
    hdc = gdi32.CreateCompatibleDC(None)
    hbm = gdi32.CreateDIBSection(hdc, ctypes.byref(bmi), 0, ctypes.byref(bits), None, 0)
    old = gdi32.SelectObject(hdc, hbm)
    try:
        ctypes.memmove(bits, bytes(background) * (size * size), size * size * 4)
        if not user32.DrawIconEx(hdc, 0, 0, hicon, size, size, 0, None, 3):  # DI_NORMAL
            raise ctypes.WinError(ctypes.get_last_error())
        return ctypes.string_at(bits, size * size * 4)
    finally:
        gdi32.SelectObject(hdc, old)
        gdi32.DeleteObject(hbm)
        gdi32.DeleteDC(hdc)


def extract_icon(path, size):
    hicon = wt.HICON()
    icon_id = wt.UINT()
    n = user32.PrivateExtractIconsW(str(path), 0, size, size, ctypes.byref(hicon), ctypes.byref(icon_id), 1, 0)
    if n != 1 or not hicon:
        raise AssertionError(f"no icon at {size}px in {path}")
    return hicon


class TestIconRendering(unittest.TestCase):
    """Pixel comparison of the icon Explorer / the taskbar / Alt+Tab would show."""

    SIZES = [16, 20, 24, 30, 32, 36, 40, 48, 60, 64, 72, 96, 128, 256]
    BACKGROUNDS = [(0, 0, 0, 255), (255, 255, 255, 255), (255, 0, 255, 255)]

    def save(self, name, size, raw):
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        Image.frombuffer("RGBA", (size, size), raw, "raw", "BGRA", 0, 1).save(ARTIFACTS / name)

    def test_extracted_icons_pixel_identical(self):
        for size in self.SIZES:
            for bg in self.BACKGROUNDS:
                ha, hb = extract_icon(ORIGINAL, size), extract_icon(CLONE, size)
                try:
                    ra, rb = render_icon(ha, size, bg), render_icon(hb, size, bg)
                finally:
                    user32.DestroyIcon(ha)
                    user32.DestroyIcon(hb)
                if ra != rb:
                    self.save(f"icon{size}_original.png", size, ra)
                    self.save(f"icon{size}_aicalc.png", size, rb)
                self.assertEqual(ra, rb, f"{size}px icon over {bg}")

    def test_shell_icons_pixel_identical(self):
        for flags, size in ((0x100, 32), (0x101, 16)):  # SHGFI_ICON | LARGEICON / SMALLICON
            rendered = []
            for path in (ORIGINAL, CLONE):
                info = SHFILEINFOW()
                self.assertTrue(shell32.SHGetFileInfoW(str(path), 0, ctypes.byref(info), ctypes.sizeof(info), flags))
                try:
                    rendered.append(render_icon(info.hIcon, size, (40, 40, 40, 255)))
                finally:
                    user32.DestroyIcon(info.hIcon)
            self.assertEqual(rendered[0], rendered[1], f"shell icon {size}px")


# ---------------------------------------------------------------- runtime


EnumWindowsProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


def calculator_windows():
    found = []

    def cb(hwnd, _):
        if user32.IsWindowVisible(hwnd):
            cls = ctypes.create_unicode_buffer(256)
            title = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, cls, 256)
            user32.GetWindowTextW(hwnd, title, 256)
            if cls.value == "ApplicationFrameWindow" and title.value == "Calculator":
                found.append(hwnd)
        return True

    user32.EnumWindows(EnumWindowsProc(cb), 0)
    return found


def window_bounds(hwnd):
    r = wt.RECT()
    dwmapi.DwmGetWindowAttribute(wt.HWND(hwnd), 9, ctypes.byref(r), ctypes.sizeof(r))  # DWMWA_EXTENDED_FRAME_BOUNDS
    return r.left, r.top, r.right, r.bottom


def close_window(hwnd, timeout=10.0):
    user32.PostMessageW(wt.HWND(hwnd), 0x0010, 0, 0)  # WM_CLOSE
    end = time.time() + timeout
    while time.time() < end:
        if hwnd not in calculator_windows():
            return True
        time.sleep(0.2)
    return False


def capture_stable(hwnd, timeout=12.0):
    """Screenshot of the window once two consecutive frames agree (launch animation over)."""
    prev = None
    end = time.time() + timeout
    while time.time() < end:
        time.sleep(0.4)
        img = ImageGrab.grab(bbox=window_bounds(hwnd), all_screens=True)
        if prev is not None and prev.size == img.size and ImageChops.difference(prev, img).getbbox() is None:
            return img
        prev = img
    return prev


class Launch:
    def __init__(self, exe, args=()):
        before = set(calculator_windows())
        t0 = time.time()
        self.process = subprocess.Popen([str(exe), *args])
        self.exit_code = self.process.wait(30)
        self.duration = time.time() - t0
        self.hwnd = None
        end = time.time() + 20
        while time.time() < end and self.hwnd is None:
            new = [h for h in calculator_windows() if h not in before]
            self.hwnd = new[0] if new else None
            time.sleep(0.2)


@unittest.skipIf(SKIP_GUI, "AICALC_SKIP_GUI=1")
class TestRuntime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if calculator_windows():
            raise unittest.SkipTest("close the open Calculator window(s) first; the test opens and closes its own")

    def launch_and_close(self, exe, args=(), capture=False):
        run = Launch(exe, args)
        try:
            self.assertEqual(run.exit_code, 0, f"{exe.name} exit code")
            self.assertIsNotNone(run.hwnd, f"{exe.name} did not open Calculator")
            shot = capture_stable(run.hwnd) if capture else None
            return run, shot
        finally:
            if run.hwnd is not None:
                self.assertTrue(close_window(run.hwnd), "Calculator did not close")
                time.sleep(0.5)

    def test_launch_without_arguments(self):
        for exe in (ORIGINAL, CLONE):
            run, _ = self.launch_and_close(exe)
            self.assertLess(run.duration, 10)

    def test_arguments_are_ignored(self):
        for exe in (ORIGINAL, CLONE):
            self.launch_and_close(exe, ["/x", "some value", "--help"])

    def test_window_pixel_identical(self):
        # Warm-up so both measured launches start from the same saved app state.
        self.launch_and_close(ORIGINAL)
        last = None
        for attempt in range(2):
            run_a, shot_a = self.launch_and_close(ORIGINAL, capture=True)
            run_b, shot_b = self.launch_and_close(CLONE, capture=True)
            ARTIFACTS.mkdir(parents=True, exist_ok=True)
            shot_a.save(ARTIFACTS / "window_original.png")
            shot_b.save(ARTIFACTS / "window_aicalc.png")
            if shot_a.size == shot_b.size:
                diff = ImageChops.difference(shot_a.convert("RGB"), shot_b.convert("RGB"))
                if diff.getbbox() is None:
                    return
                diff.save(ARTIFACTS / "window_diff.png")
            last = (shot_a.size, shot_b.size)
        self.fail(f"Calculator window differs between launches (sizes {last}); see {ARTIFACTS}")


# ---------------------------------------------------------------- ETW (elevated only)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


@unittest.skipIf(SKIP_GUI, "AICALC_SKIP_GUI=1")
@unittest.skipUnless(is_admin(), "ETW trace sessions require an elevated prompt")
class TestEtwRuntime(unittest.TestCase):
    """Captures the provider's real ETW output for both executables."""

    def trace(self, exe, keywords, level):
        name = f"aicalc-test-{uuid.uuid4().hex[:8]}"
        with tempfile.TemporaryDirectory() as tmp:
            etl = Path(tmp) / "trace.etl"
            xml = Path(tmp) / "trace.xml"
            subprocess.run(["logman", "create", "trace", name, "-p", PROVIDER_GUID, f"0x{keywords:x}", str(level),
                            "-o", str(etl), "-ets"], check=True, capture_output=True)
            try:
                run = Launch(exe)
                if run.hwnd is not None:
                    close_window(run.hwnd)
            finally:
                subprocess.run(["logman", "stop", name, "-ets"], check=True, capture_output=True)
            subprocess.run(["tracerpt", str(etl), "-of", "XML", "-o", str(xml), "-y"], check=True, capture_output=True)
            return self.events(xml)

    @staticmethod
    def events(xml):
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        out = []
        for ev in ET.parse(xml).getroot().findall("e:Event", ns):
            prov = ev.find("e:System/e:Provider", ns)
            if prov is None or (prov.get("Guid") or "").upper() != PROVIDER_GUID:
                continue
            sysnode = ev.find("e:System", ns)
            fields = {k: (sysnode.findtext(f"e:{k}", namespaces=ns) or "") for k in ("Level", "Opcode", "Keywords", "Task", "Channel")}
            data = [(d.get("Name"), d.text) for d in ev.findall("e:EventData/e:Data", ns)]
            task = ev.find("e:RenderingInfo/e:Task", ns)
            out.append((prov.get("Name"), task.text if task is not None else None, tuple(sorted(fields.items())), tuple(data)))
        return out

    def test_event_emitted_identically(self):
        a = self.trace(ORIGINAL, 0x0002000000000000, 5)
        b = self.trace(CLONE, 0x0002000000000000, 5)
        self.assertEqual(len(a), 1, a)
        self.assertEqual(a, b)

    def test_filtered_out_identically(self):
        for keywords, level in ((0x0000800000000000, 5), (0x0002000000000000, 4)):
            self.assertEqual(self.trace(ORIGINAL, keywords, level), [])
            self.assertEqual(self.trace(CLONE, keywords, level), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
