"""Loopback-only browser test server with synthetic video and recorded (never injected) input.

Run: python tests/browser_server.py
The printed pairing URL is temporary and belongs only to this test process.
"""
import asyncio
import contextlib
from fractions import Fraction
import os
from pathlib import Path
import secrets
import ssl
import struct
import sys
import tempfile
import threading
import time
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "relay")]

# These test doubles must precede the host import; this server can never drive a real keyboard or mouse.
inputs = ModuleType("winput")
inputs.calls = []
for operation in ("move", "key", "button", "wheel", "text"):
    setattr(inputs, operation, lambda *args, name=operation: inputs.calls.append((name, *args)))
inputs.init = inputs.refresh = lambda: None
sys.modules["winput"] = inputs
sys.modules["capture"] = ModuleType("capture")

import av  # noqa: E402
from av.video.frame import PictureType  # noqa: E402
from aiohttp import web  # noqa: E402

import host  # noqa: E402
import mkcert  # noqa: E402
import quic  # noqa: E402
import relay  # noqa: E402
from protocol import SCREEN, VIDEO  # noqa: E402
from limits import STATE  # noqa: E402


class QuietUi:
    def __init__(self, *args):
        pass

    def __getattr__(self, name):
        return lambda *args: None


class SyntheticStreamer(threading.Thread):
    def __init__(self, emit, kbps, fps, after=None):
        super().__init__(daemon=True)
        self.emit, self.fps, self.kbps = emit, min(fps, 30), kbps
        self.need_key, self.running = True, True
        self.seq = self.acked = 0

    def stop(self):
        self.running = False

    def configure(self, kbps, fps):
        self.kbps, self.fps = kbps, min(fps, 30)

    def ack(self, seq):
        self.acked = max(self.acked, seq)

    def take_stats(self):
        return 0, 0, 0, 0, self.kbps, 0

    def run(self):
        codec = av.CodecContext.create("libx264", "w")
        codec.width, codec.height, codec.pix_fmt = 640, 360, "yuv420p"
        codec.time_base, codec.framerate = Fraction(1, 1000), 30
        codec.options = {"preset": "ultrafast", "tune": "zerolatency", "profile": "high"}
        codec.max_b_frames = 0
        codec.gop_size = 100000
        codec.open()
        self.emit(struct.pack("<BHH", SCREEN, 640, 360))
        while self.running:
            if self.seq - self.acked >= 2:
                time.sleep(0.01)
                continue
            frame = av.VideoFrame(640, 360, "yuv420p")
            for index, plane in enumerate(frame.planes):
                plane.update(bytes([64 + self.seq % 80 if index == 0 else 128]) * plane.buffer_size)
            frame.pts = int(time.perf_counter() * 1000)
            frame.pict_type = PictureType.I if self.need_key else PictureType.NONE
            self.need_key = False
            for packet in codec.encode(frame):
                self.seq += 1
                self.emit(struct.pack("<BBI", VIDEO, packet.is_keyframe, self.seq) + bytes(packet))
            time.sleep(1 / self.fps)


async def main():
    cert_directory = tempfile.TemporaryDirectory(prefix="minidesk-browser-tls-")
    certs = Path(cert_directory.name)
    tls = "--quic" in sys.argv
    ssl_context = None
    if tls:
        ca_key, ca_cert = mkcert.make_ca()
        key, cert = mkcert.make_server_cert(ca_key, ca_cert, "127.0.0.1")
        (certs / "ca.crt").write_bytes(mkcert.pem_cert(ca_cert))
        (certs / "server.crt").write_bytes(mkcert.pem_cert(cert))
        (certs / "server.key").write_bytes(mkcert.pem_key(key))
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certs / "server.crt", certs / "server.key")
    stopped = asyncio.Event()
    controller = None
    app = relay.make_app("browser-test")

    async def state(_request):
        return web.json_response({"active": controller.active is not None, "sessions": len(controller.sessions),
                                  "input": inputs.calls, "revision": controller.key_revision})

    async def kick(_request):
        controller.kick()
        return web.json_response({"ok": True})

    async def reset(_request):
        controller.reset_key()
        return web.json_response({"key": controller.cfg["key"]})

    async def stop(_request):
        stopped.set()
        return web.json_response({"ok": True})

    async def clear(_request):
        inputs.calls.clear()
        return web.json_response({"ok": True})

    app.router.add_get("/test/state", state)
    app.router.add_post("/test/kick", kick)
    app.router.add_post("/test/reset", reset)
    app.router.add_post("/test/stop", stop)
    app.router.add_post("/test/clear", clear)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ssl_context).start()
    port = runner.addresses[0][1]
    base = f"http{'s' if tls else ''}://127.0.0.1:{port}"
    if tls:
        await quic.start(app, "127.0.0.1", port)
    key = host.b64(secrets.token_bytes(32))
    cfg = {"relay": base, "token": "browser-test", "id": "browserhost01", "key": key, "lan_port": 0}
    if tls:
        cfg["ca"] = str(certs / "ca.crt")
    host.Ui, host.Streamer = QuietUi, SyntheticStreamer

    async def pick_route():
        return None

    with tempfile.TemporaryDirectory(prefix="minidesk-browser-") as directory:
        host.CONFIG_PATH = os.path.join(directory, "config.json")
        controller = host.Host(cfg)
        controller.pick_route = pick_route
        task = asyncio.create_task(controller.run())
        try:
            for _ in range(50):
                if cfg["id"] in app[STATE]["hosts"]:
                    break
                await asyncio.sleep(0.02)
            print(f"{base}/#{cfg['id']}.{key}.BrowserTest", flush=True)
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stopped.wait(), 600)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await runner.cleanup()
            await asyncio.sleep(0.25 if tls else 0)
            cert_directory.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
