"""MiniDesk host: stays online at the relay, streams the screen and injects input for paired clients.

First run:   python host.py --relay https://your.server --token SECRET --pair   (deploy.py does this for you)
Afterwards:  python host.py            (settings live in config.json)
--pair prints the QR codes in the terminal; --reset-key unpairs every phone;
--shortcut puts a "MiniDesk" shortcut on the desktop. Every click on it brings up the connect window with the
QR codes: it starts MiniDesk in the background, or shows the window of the one already running.
"""
import argparse
import asyncio
import base64
import ctypes
import ipaddress
import json
import logging
import logging.handlers
import os
import queue
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse

import aiohttp
from aiohttp import web

import mkcert
import winput
from configuration import b64, read_config, save_config, unb64
from protocol import LAN
from session import Session
from secure import AuthError, host_handshake
from stream import Streamer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "relay"))
try:  # UDP transport to the relay; without aioquic sessions use the relay's WebSockets
    import quic
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.events import ConnectionTerminated, StreamDataReceived
except ImportError:
    quic = None

CONFIG_PATH = os.path.join(HERE, "config.json")
CA_PATH = mkcert.CA_CRT  # private CA from mkcert.py, when the relay has no domain
WEB_DIR = os.path.join(HERE, "relay", "web")  # the web client, also served on the LAN port
LAN_CERT, LAN_KEY = os.path.join(mkcert.CERTS, "lan.crt"), os.path.join(mkcert.CERTS, "lan.key")
MAX_MSG = 64 << 10  # host only receives handshake/control messages; video goes in the opposite direction
CLOSE_KICKED, CLOSE_REPLACED = 4001, 4002  # sent as BYE: the client shows them instead of reconnecting
SHOW_EVENT = "Local\\MiniDeskShow"  # set by a second start from the shortcut: the running one shows its window
RESET_EVENT, RESET_DONE = "Local\\MiniDeskReset", "Local\\MiniDeskResetDone"
GREEN, ORANGE, RED, BLUE, GRAY = "#30a14e", "#d97706", "#d70015", "#0a84ff", "#8e8e93"  # connect window
log = logging.getLogger("host")


_wifi_cache = {}  # sorted IP tuple -> Wi-Fi addresses among them (asking PowerShell takes ~0.5 s)


def wifi_ips():
    """IPv4 addresses of Wi-Fi adapters."""
    ps = ("Get-NetAdapter -Physical | Where-Object PhysicalMediaType -match '802.11' | "
          "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object IPAddress")
    try:
        return set(subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True,
                                  timeout=10, creationflags=subprocess.CREATE_NO_WINDOW).stdout.split())
    except (OSError, subprocess.SubprocessError):
        return set()


def lan_ips():
    """Private IPv4 addresses of this PC: Wi-Fi ones first (that is where phones are), then the default route."""
    ips = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("8.8.8.8", 80))  # no packet is sent; this only picks the outgoing interface
            ips.append(s.getsockname()[0])
        except OSError:
            pass
    try:
        for *_, addr in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.append(addr[0])
    except OSError:
        pass
    ok = lambda ip: ipaddress.ip_address(ip).is_private and not ip.startswith(("127.", "169.254."))  # noqa: E731
    ips = list(dict.fromkeys(ip for ip in ips if ok(ip)))
    key = tuple(sorted(ips))
    if key not in _wifi_cache:
        _wifi_cache.clear()
        _wifi_cache[key] = wifi_ips()
    return sorted(ips, key=lambda ip: ip not in _wifi_cache[key])[:4]


class WsLink:
    """A session over a WebSocket: LAN direct, or the relay's TCP fallback."""

    def __init__(self, ws):
        self.ws = ws

    async def recv(self):
        m = await self.ws.receive()
        return m.data if m.type == aiohttp.WSMsgType.BINARY else None

    async def send(self, data, video=False):
        await self.ws.send_bytes(data)

    async def close(self, code=1000):
        await self.ws.close(code=code)


if quic:
    class QuicLink(quic.Swept):
        """A session over QUIC (UDP) to the relay: control messages framed on stream 0, each video frame on a
        unidirectional stream of its own, so a lost packet delays only that frame (see relay/quic.py)."""

        def __init__(self, *args, **kw):
            super().__init__(*args, **kw)
            self.inbox, self.unframer = asyncio.Queue(maxsize=256), quic.Unframer()
            self.ended = False

        @classmethod
        async def open(cls, host, port, local_ip, pins, sid):
            loop = asyncio.get_running_loop()
            conn = QuicConnection(configuration=quic.configuration(
                True, alpn_protocols=[quic.HOST_ALPN], verify_mode=ssl.CERT_NONE, server_name=host))
            transport, link = await loop.create_datagram_endpoint(lambda: cls(conn),
                                                                  local_addr=(local_ip or "0.0.0.0", 0))
            quic.keep_listening(transport)
            try:
                link.connect((host, port))
                await asyncio.wait_for(link.wait_connected(), 5)
                # Authenticate the relay by the certificate hash it published over HTTPS (/wt, CA-verified).
                if base64.b64encode(quic.cert_hash(conn.tls._peer_certificate)).decode() not in pins:
                    raise ConnectionError("relay QUIC certificate does not match /wt")
            except BaseException:
                link._transport.close()
                raise
            conn.send_stream_data(0, sid.encode() + b"\n")
            link.transmit()
            return link

        def quic_event_received(self, event):
            super().quic_event_received(event)
            if isinstance(event, StreamDataReceived) and event.stream_id == 0:
                try:
                    for m in self.unframer.feed(event.data):
                        self.inbox.put_nowait(m)
                except (ValueError, asyncio.QueueFull):
                    self.ended = True
                    quic.Swept.close(self)
            elif isinstance(event, ConnectionTerminated):
                self.ended = True
            if self.ended:
                while not self.inbox.empty():
                    self.inbox.get_nowait()
                self.inbox.put_nowait(None)

        async def recv(self):
            if self.ended and self.inbox.empty():
                return None
            return await self.inbox.get()

        async def send(self, data, video=False):
            if self.ended:
                raise ConnectionError("QUIC connection closed")
            if video:
                stream = self._quic.get_next_available_stream_id(is_unidirectional=True)
                self._quic.send_stream_data(stream, data, end_stream=True)
            else:
                self._quic.send_stream_data(0, quic.frame(data))
            self.transmit()

        async def close(self, code=0):
            self.ended = True
            try:
                quic.Swept.close(self)
                await asyncio.wait_for(self.wait_closed(), 2)
            except asyncio.TimeoutError:
                pass
            finally:
                self._transport.close()  # cancellation during shutdown must not orphan the UDP socket


class Ui:
    """Tk on its own thread: the connect window (QR codes and status; it comes up on every click of the desktop
    shortcut) and the bar at the top of the screen while a phone is in control."""

    FONT, WHITE, INK = "Microsoft YaHei UI", "#ffffff", "#1c1c1e"

    def __init__(self, links, on_disconnect, on_quit, show_event=None):
        self.q = queue.Queue()
        self.links, self.on_disconnect, self.on_quit = links, on_disconnect, on_quit
        self.show_event = show_event  # set by a second start from the shortcut: bring up the window
        threading.Thread(target=self._run, daemon=True, name="ui").start()

    def bar(self, text):
        self.q.put(("bar", text))

    def hide_bar(self):
        self.q.put(("bar", None))

    def status(self, text, color):
        self.q.put(("status", (text, color)))

    def open(self):
        self.q.put(("open", None))

    def close(self):
        self.q.put(("close", None))

    def _run(self):
        import tkinter as tk

        font, white = self.FONT, self.WHITE
        root = tk.Tk()  # the bar
        root.withdraw()
        root.overrideredirect(True)
        root.attributes("-topmost", True)
        root.attributes("-alpha", 0.9)
        label = tk.Label(root, bg=self.INK, fg=white, font=(font, 10), padx=12, pady=5)
        label.pack(side="left")
        stop = tk.Label(root, text="断开", bg="#ff453a", fg=white, font=(font, 10), padx=12, pady=5, cursor="hand2")
        stop.pack(side="left")
        stop.bind("<Button-1>", lambda _e: self.on_disconnect())

        win = tk.Toplevel(root, bg=white, padx=24, pady=18)  # the connect window
        win.withdraw()
        win.title("MiniDesk")
        win.resizable(False, False)
        win.protocol("WM_DELETE_WINDOW", win.withdraw)  # closing it leaves MiniDesk running in the background
        try:
            win.iconbitmap(os.path.join(HERE, "minidesk.ico"))
        except tk.TclError:
            pass
        module = max(4, round(win.winfo_fpixels("1i") / 96 * 5))  # QR module size, scaled with the display
        state = tk.Label(win, font=(font, 11), bg=white, anchor="w")
        state.pack(fill="x")
        canvas = tk.Canvas(win, bg=white, highlightthickness=0)
        canvas.pack(pady=(12, 6))
        caption = tk.Label(win, font=(font, 10), bg=white, wraplength=360)
        caption.pack()
        tabs = tk.Frame(win, bg=white)
        tabs.pack(pady=10)
        tk.Label(win, bg=white, fg=GRAY, font=(font, 9), justify="left",
                 text="连接过的手机直接打开书签或主屏图标就能连，不用再扫。\n二维码里有配对密钥，只给自己的手机扫。").pack()
        tk.Button(win, text="退出 MiniDesk", font=(font, 9), relief="flat", fg=GRAY, bg=white, cursor="hand2",
                  command=self.on_quit).pack(pady=(10, 0))

        def draw(links, i):
            m = qr_matrix(links[i][2])
            canvas.config(width=len(m) * module, height=len(m) * module)
            canvas.delete("all")
            for y, row in enumerate(m):
                x = 0
                while x < len(row):  # one rectangle per run of dark modules
                    if not row[x]:
                        x += 1
                        continue
                    x0 = x
                    while x < len(row) and row[x]:
                        x += 1
                    canvas.create_rectangle(x0 * module, y * module, x * module, (y + 1) * module, fill="#000", width=0)
            caption.config(text=links[i][1])
            for j, b in enumerate(tabs.winfo_children()):
                b.config(fg=white if j == i else self.INK, bg=BLUE if j == i else "#e5e5ea")

        def open_window():
            links = self.links()
            for b in tabs.winfo_children():
                b.destroy()
            for i, (name, _, _) in enumerate(links):
                tk.Button(tabs, text=name, font=(font, 9), relief="flat", padx=10, cursor="hand2",
                          command=lambda i=i: draw(links, i)).pack(side="left", padx=3)
            draw(links, 0)
            win.update_idletasks()
            win.geometry(f"+{(win.winfo_screenwidth() - win.winfo_reqwidth()) // 2}"
                         f"+{(win.winfo_screenheight() - win.winfo_reqheight()) // 3}")
            win.deiconify()
            win.lift()
            win.attributes("-topmost", True)  # in front of whatever was clicked from, then an ordinary window
            win.after(500, win.attributes, "-topmost", False)
            win.focus_force()

        def poll():
            while not self.q.empty():
                what, arg = self.q.get()
                if what == "bar" and arg is None:
                    root.withdraw()
                elif what == "bar":
                    label.config(text="● " + arg)
                    root.update_idletasks()
                    root.geometry(f"+{(root.winfo_screenwidth() - root.winfo_reqwidth()) // 2}+0")
                    root.deiconify()
                elif what == "status":
                    state.config(text="● " + arg[0], fg=arg[1])
                elif what == "open":
                    open_window()
                elif what == "close":
                    win.withdraw()
            if self.show_event and ctypes.windll.kernel32.WaitForSingleObject(self.show_event, 0) == 0:
                open_window()
            root.after(150, poll)

        poll()
        root.mainloop()


class Host:
    def __init__(self, cfg, open_window=False, show_event=None, reset_event=None, reset_done=None):
        self.open_window = open_window  # started from the desktop shortcut
        self.show_event = show_event
        self.cfg = dict(cfg)
        self.reset_event, self.reset_done = reset_event, reset_done
        self.key_revision = 0
        self.sessions, self.tasks = set(), set()
        self.lan_runner = None
        self.handshakes = 0
        self.lan_clients = 0
        self.key = unb64(cfg["key"])
        self.relay = cfg["relay"]
        base = self.relay.replace("http", "ws", 1)  # http -> ws, https -> wss
        self.token = cfg["token"]
        self.ctl_url = base + "/ws/host?" + urllib.parse.urlencode({"id": cfg["id"], "token": cfg["token"]})
        self.session_url = f"{base}/ws/s/"
        self.lan_port = cfg.get("lan_port", 47250)
        self.lan_ssl, self.lan_hosts = None, []
        self.active = None  # the session in control; a newly chosen one replaces it
        self.ssl = ssl.create_default_context()
        ca = cfg.get("ca", CA_PATH)
        if os.path.exists(ca):
            self.ssl.load_verify_locations(ca)
        self.ui = None
        self.state = ("正在连接服务器…", GRAY)  # shown in the connect window while no phone is in control
        self.route = None  # local address the relay is reached from (see pick_route)
        self.wt = None  # relay's /wt: UDP port + certificate hashes

    # -- session control --
    def activate(self, session):
        """Make `session` the one in control; returns the replaced session's streamer thread, if any."""
        prev = None
        if self.active is not None and self.active is not session:
            prev = self.active.streamer
            self.active.close(CLOSE_REPLACED)
        self.active = session
        log.info("手机已连接（%s），正在被远程控制", session.via)
        if self.ui:
            self.ui.close()  # out of the way of the screen the phone is looking at
            self.ui.bar(f"手机正在控制此电脑（{session.via}）")
            self.ui.status(f"手机正在控制此电脑（{session.via}）", BLUE)
        if urls := self.lan_urls():
            session.out.put_nowait(bytes([LAN]) + json.dumps(urls).encode())
        return prev

    def deactivate(self, session):
        if self.active is session:
            self.active = None
            log.info("手机已断开")
            if self.ui:
                self.ui.hide_bar()
                self.ui.status(*self.state)

    def set_state(self, text, color):
        self.state = (text, color)
        if self.ui and not self.active:
            self.ui.status(text, color)

    def links(self):
        """The connect window's QR codes (called on the window's thread: no PowerShell lookups here)."""
        return pairing_links(self.cfg, self.lan_hosts if self.lan_ssl else [])

    def kick(self):
        if self.active:
            self.active.close(CLOSE_KICKED)

    def reset_key(self):
        """Persist first; then revoke all old sessions and in-progress handshakes on this loop."""
        cfg = dict(self.cfg, key=b64(secrets.token_bytes(32)))
        save_config(CONFIG_PATH, cfg)
        self.cfg, self.key = cfg, unb64(cfg["key"])
        self.key_revision += 1
        for session in tuple(self.sessions):
            session.close(CLOSE_KICKED)
        if self.ui:
            self.ui.open()
        log.info("配对密钥已更新，旧配对和会话已撤销")

    async def watch_commands(self):
        k = ctypes.windll.kernel32
        while True:
            if k.WaitForSingleObject(self.reset_event, 0) == 0:
                try:
                    self.reset_key()
                except (OSError, ValueError):
                    log.exception("配对密钥更新失败，原配置已保留")
                else:
                    k.SetEvent(ctypes.c_void_p(self.reset_done))
            await asyncio.sleep(0.15)

    def spawn(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)

        def finished(done):
            self.tasks.discard(done)
            if not done.cancelled() and done.exception():
                log.warning("后台连接任务失败: %s", type(done.exception()).__name__)

        task.add_done_callback(finished)
        return task

    async def serve(self, link, via):
        async def recv():
            data = await asyncio.wait_for(link.recv(), 10)
            if data is None:
                raise AuthError("closed during handshake")
            return data

        session = None
        revision = self.key_revision
        if self.handshakes >= 8 or len(self.sessions) >= 12:
            await link.close(1013)
            return
        self.handshakes += 1
        try:
            try:
                ch = await asyncio.wait_for(host_handshake(recv, link.send, self.key), 10)
                if revision != self.key_revision:
                    raise AuthError("pairing key revoked")
            finally:
                self.handshakes -= 1
            session = Session(self, link, ch, via, input_api=winput, streamer_factory=Streamer)
            self.sessions.add(session)
            await session.run()
        except (AuthError, asyncio.TimeoutError, ConnectionError, aiohttp.ClientError) as e:
            log.warning("连接结束: %s", type(e).__name__)
        finally:
            if session:
                self.sessions.discard(session)
            else:
                await link.close()

    # -- relay --
    async def run(self):
        loop, task = asyncio.get_running_loop(), asyncio.current_task()
        self.ui = Ui(self.links, lambda: loop.call_soon_threadsafe(self.kick),
                     lambda: loop.call_soon_threadsafe(task.cancel), self.show_event)
        self.ui.status(*self.state)
        http, route, backoff = None, "unset", 1
        try:
            await self.start_lan()
            if self.reset_event:
                self.spawn(self.watch_commands())
            if self.open_window:
                self.ui.open()
            while True:
                addr = await self.pick_route()
                if addr != route or http is None:  # a new path: sessions on the old one belong to the old network
                    if http:
                        await http.close()
                    route = self.route = addr
                    local = (addr, 0) if addr else None
                    http = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=self.ssl, local_addr=local))
                try:
                    async with http.ws_connect(self.ctl_url, heartbeat=20) as ctl:
                        log.info("已上线，等待手机连接")
                        if quic:
                            self.spawn(self.prefetch_wt(http))  # ready before the first UDP session
                        self.set_state("已上线，手机可以连接了", GREEN)
                        backoff = 1
                        async for m in ctl:
                            if m.type == aiohttp.WSMsgType.TEXT and m.data.startswith("q:"):
                                self.spawn(self.accept_quic(http, m.data[2:]))
                            elif m.type == aiohttp.WSMsgType.TEXT:
                                self.spawn(self.accept(http, m.data))
                    log.warning("与中转服务器的连接断开")
                    self.set_state("和服务器的连接断开，正在重连…", ORANGE)
                except aiohttp.WSServerHandshakeError as e:
                    log.error("中转服务器拒绝注册 (HTTP %s)，检查 token", e.status)
                    self.set_state("服务器拒绝注册：token 不一致，请重新运行 deploy.py", RED)
                except (aiohttp.ClientError, OSError) as e:
                    log.warning("连不上中转服务器: %s", str(e).replace(self.token, "***"))  # keep the token out of logs
                    self.set_state("连不上服务器，正在自动重试…（同一 Wi-Fi 仍可直连）", ORANGE)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30)
        finally:
            for session in tuple(self.sessions):
                session.close(CLOSE_KICKED)
            tasks = tuple(self.tasks)
            for pending in tasks:
                pending.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if http:
                await http.close()
            if self.lan_runner:
                await self.lan_runner.cleanup()
            # aiohttp closes SSL transports asynchronously; let their callbacks finish before asyncio.run exits.
            await asyncio.sleep(0.25 if self.relay.startswith("https:") or self.lan_ssl else 0)

    async def pick_route(self):
        """Local address to reach the relay from: None = default route, or a NIC's address.

        With a TUN-mode proxy (Clash and the like) the default route detours every packet through the proxy
        (measured: 520 ms vs 90 ms per round trip here). Binding the socket to a physical NIC's address sends it
        out directly. Each candidate gets two full HTTPS round trips. The fastest NIC wins unless the default
        route is clearly faster: two samples on a congested link are noisy, and UDP through a TUN proxy is less
        dependable. The default route stays in use when no NIC gets through.
        """
        async def probe(addr):  # best of two tries: one failed try does not rule a path out
            connector = aiohttp.TCPConnector(ssl=self.ssl, local_addr=(addr, 0) if addr else None, force_close=True)
            best = float("inf")
            async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=4)) as s:
                for _ in range(2):
                    t0 = time.perf_counter()
                    try:
                        async with s.get(self.relay + "/s/icon.svg") as r:
                            await r.read()
                        best = min(best, time.perf_counter() - t0)
                    except (aiohttp.ClientError, OSError, asyncio.TimeoutError):
                        pass
            return best

        candidates = [None, *lan_ips()]
        times = await asyncio.gather(*map(probe, candidates))
        nics = [i for i in range(1, len(times)) if times[i] != float("inf")]
        best = min(nics, key=times.__getitem__) if nics else 0
        if times[0] < times[best] * 0.8:
            best = 0
        name = lambda a: f"网卡 {a}" if a else "默认路由"  # noqa: E731
        results = ", ".join(f"{name(a)} {t * 1000:.0f} ms" if t != float("inf") else f"{name(a)} 不通"
                            for a, t in zip(candidates, times))
        log.info("线路测速: %s → 使用%s", results, name(candidates[best]))
        return candidates[best]

    async def accept(self, http, sid):
        try:
            async with http.ws_connect(self.session_url + sid, max_msg_size=MAX_MSG, heartbeat=20) as ws:
                await self.serve(WsLink(ws), "经服务器·TCP")
        except aiohttp.ClientError as e:
            log.warning("会话连接失败: %s", e)

    async def fetch_wt(self, http):
        """The relay's UDP port and certificate hashes, cached: a session should not wait an extra round trip."""
        async with http.get(self.relay + "/wt") as r:
            r.raise_for_status()
            self.wt = await r.json()
        return self.wt

    async def prefetch_wt(self, http):
        try:
            await self.fetch_wt(http)
        except (aiohttp.ClientError, OSError, asyncio.TimeoutError, ValueError):
            pass  # relay without UDP, or a hiccup: accept_quic fetches on demand

    async def accept_quic(self, http, sid):
        """A phone came in over WebTransport: join it with a QUIC connection from the same network path."""
        if not quic:
            return log.warning("手机走 UDP 连接，但本机没装 aioquic（pip install aioquic）")
        try:
            info = self.wt or await self.fetch_wt(http)
            link = await QuicLink.open(urllib.parse.urlsplit(self.relay).hostname, info["port"], self.route,
                                       info["hashes"], sid)
        except (aiohttp.ClientError, OSError, asyncio.TimeoutError, ConnectionError, KeyError) as e:
            self.wt = None  # refetch next time: the relay may have rotated its certificate
            return log.warning("UDP 会话连接失败: %s", e or type(e).__name__)
        try:
            await self.serve(link, "经服务器·UDP")
        finally:
            await link.close()

    # -- LAN direct: wss://<lan-ip>:<lan_port>/ws, certified by the private CA the phones already trust --
    async def start_lan(self):
        if not self.lan_port or not mkcert.load_ca():
            return
        self.lan_ssl = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        if not self.lan_urls():
            self.lan_ssl = None
            return

        async def handler(req):
            if self.lan_clients >= 16:
                raise web.HTTPTooManyRequests()
            log.info("局域网直连请求来自 %s", req.remote)
            ws = web.WebSocketResponse(max_msg_size=MAX_MSG, heartbeat=20)
            self.lan_clients += 1
            try:
                await ws.prepare(req)
                await self.serve(WsLink(ws), "局域网直连")
            finally:
                self.lan_clients -= 1
            return ws

        # The PC also serves the web client. Browsers block a page from a public address (the relay) from
        # opening connections to private ones (Chrome's Local Network Access), but a page loaded from
        # https://<lan-ip>:<port>/ may connect to its own origin: /ws/c/<id> is what that page dials.
        async def index(_req):
            return web.FileResponse(os.path.join(WEB_DIR, "index.html"), headers={"Cache-Control": "no-cache"})

        async def manifest(_req):  # its own name, so the home-screen icon is told apart from the relay one
            with open(os.path.join(WEB_DIR, "manifest.json"), encoding="utf-8") as f:
                m = json.load(f)
            return web.json_response(dict(m, name="MiniDesk 局域网", short_name="MiniDesk 局域网"))

        async def client_cache_headers(req, response):
            if req.path in ("/s/app.js", "/s/client-core.js"):
                response.headers["Cache-Control"] = "no-cache, max-age=0, must-revalidate"

        app = web.Application()
        app.on_response_prepare.append(client_cache_headers)
        app.router.add_get("/ws", handler)
        app.router.add_get("/ws/c/{id}", handler)
        app.router.add_get("/", index)
        app.router.add_get("/s/manifest.json", manifest)
        app.router.add_static("/s/", WEB_DIR)
        runner = self.lan_runner = web.AppRunner(app, access_log=None, shutdown_timeout=3)
        await runner.setup()
        try:
            await web.TCPSite(runner, "0.0.0.0", self.lan_port, ssl_context=self.lan_ssl).start()
            log.info("局域网直连已开启: %s", ", ".join(self.lan_hosts))
        except OSError as e:
            log.warning("局域网直连端口 %d 不可用: %s", self.lan_port, e)
            self.lan_ssl = None
            await runner.cleanup()
            self.lan_runner = None

    def lan_urls(self):
        """Current LAN URLs; re-issues the certificate when the PC's addresses changed (DHCP, new Wi-Fi)."""
        if not self.lan_ssl:
            return []
        ips = lan_ips()
        if ips and ips != self.lan_hosts:
            ca_key, ca_cert = mkcert.load_ca()
            key, cert = mkcert.make_server_cert(ca_key, ca_cert, *ips)
            with open(LAN_KEY, "wb") as f:
                f.write(mkcert.pem_key(key))
            with open(LAN_CERT, "wb") as f:
                f.write(mkcert.pem_cert(cert))
            self.lan_ssl.load_cert_chain(LAN_CERT, LAN_KEY)  # applies to new connections
            self.lan_hosts = ips
        return [f"wss://{ip}:{self.lan_port}/ws" for ip in self.lan_hosts]


def load_config(a):
    cfg = read_config(CONFIG_PATH)
    if a.relay:
        cfg["relay"] = a.relay.rstrip("/")
    if a.token:
        cfg["token"] = a.token
    cfg.setdefault("id", secrets.token_hex(5))
    if a.reset_key or "key" not in cfg:
        cfg["key"] = b64(secrets.token_bytes(32))
        a.pair = True
    save_config(CONFIG_PATH, cfg)
    return cfg


def pairing_links(cfg, ips):
    """(tab, caption, url) of every QR code, the everyday one first. The pairing key rides in the fragment,
    which the browser never sends anywhere; a phone keeps it, so it only has to scan once."""
    name = urllib.parse.quote(os.environ.get("COMPUTERNAME") or socket.gethostname())
    pairing = f"{cfg['id']}.{cfg['key']}.{name}"
    links = [("经服务器", "用手机浏览器扫码，连接这台电脑", f"{cfg['relay']}/#{pairing}")]
    port = cfg.get("lan_port", 47250)
    if port and ips and mkcert.load_ca():
        links.append(("同一 Wi-Fi 直连", f"和电脑在同一 Wi-Fi 时用这个入口，直连电脑、不经服务器（{ips[0]}）",
                      f"https://{ips[0]}:{port}/#{pairing}"))
    if os.path.exists(CA_PATH):
        links.append(("新手机先装证书", "每台新手机先做一次：扫码下载证书，安装并信任", f"{cfg['relay']}/s/ca.crt"))
    return links


def qr_matrix(url):
    import qrcode

    qr = qrcode.QRCode(border=2)
    qr.add_data(url)
    qr.make(fit=True)
    return qr.get_matrix()


def show_pairing(cfg):
    import qrcode

    for _, caption, url in pairing_links(cfg, lan_ips()):
        print(caption)
        qr = qrcode.QRCode(border=2)
        qr.add_data(url)
        qr.print_ascii(invert=True)
        print(url + "\n", flush=True)


_mutex = None


def first_instance():
    global _mutex
    k = ctypes.windll.kernel32
    k.CreateMutexW.restype = ctypes.c_void_p
    _mutex = k.CreateMutexW(None, False, "Local\\MiniDeskHost")
    if not _mutex:
        raise ctypes.WinError()
    return ctypes.windll.kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS


SHORTCUT = "[IO.Path]::Combine([Environment]::GetFolderPath('Desktop'), 'MiniDesk.lnk')"


def show_running():
    """Ask the instance already running to bring up its connect window."""
    k = ctypes.windll.kernel32
    k.OpenEventW.restype = ctypes.c_void_p
    ev = k.OpenEventW(0x0002, False, SHOW_EVENT)  # EVENT_MODIFY_STATE
    if not ev:
        return False
    k.SetEvent(ctypes.c_void_p(ev))
    k.CloseHandle(ctypes.c_void_p(ev))
    return True


def reset_running():
    """Ask the owning process to rotate its key, and wait for successful persistence/revocation."""
    k = ctypes.windll.kernel32
    k.OpenEventW.restype = ctypes.c_void_p
    k.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    request = k.OpenEventW(0x0002, False, RESET_EVENT)
    done = k.OpenEventW(0x100002, False, RESET_DONE)  # SYNCHRONIZE | EVENT_MODIFY_STATE
    try:
        if not request or not done:
            return False
        k.ResetEvent(ctypes.c_void_p(done))
        k.SetEvent(ctypes.c_void_p(request))
        return k.WaitForSingleObject(ctypes.c_void_p(done), 5000) == 0
    finally:
        for handle in (request, done):
            if handle:
                k.CloseHandle(ctypes.c_void_p(handle))


def message_box(text):
    """Information box that closes itself after 5 s (the shortcut has no console to print to)."""
    box = ctypes.windll.user32.MessageBoxTimeoutW
    box.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_ushort, ctypes.c_uint]
    box(None, text, "MiniDesk", 0x40 | 0x40000, 0, 5000)  # MB_ICONINFORMATION | MB_TOPMOST


def make_shortcut():
    """Desktop shortcut that starts the host hidden (pythonw), or says it already runs. No autostart."""
    pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    ps = (f"$s = (New-Object -ComObject WScript.Shell).CreateShortcut({SHORTCUT}); $s.TargetPath = '{pyw}'; "
          f"$s.Arguments = '\"{os.path.join(HERE, 'host.py')}\" --start'; $s.WorkingDirectory = '{HERE}'; "
          f"$s.IconLocation = '{os.path.join(HERE, 'minidesk.ico')}'; $s.Save()")
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=True)
    print("已在桌面创建快捷方式「MiniDesk」：双击即启动并弹出连接二维码（已在运行时只弹二维码）。")


def main():
    p = argparse.ArgumentParser(description="MiniDesk host")
    p.add_argument("--relay", help="relay URL, e.g. https://desk.example.com")
    p.add_argument("--token", help="relay host token")
    p.add_argument("--pair", action="store_true", help="show the pairing QR codes")
    p.add_argument("--reset-key", action="store_true", help="new pairing key (unpairs all phones)")
    p.add_argument("--shortcut", action="store_true", help="create the desktop shortcut")
    p.add_argument("--start", action="store_true", help="(desktop shortcut) start and show the connect window")
    a = p.parse_args()
    if sys.stdout:  # None under pythonw: log to a file instead
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    else:
        handler = logging.handlers.RotatingFileHandler(os.path.join(HERE, "host.log"), maxBytes=1 << 20,
                                                       backupCount=1, encoding="utf-8")
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", handlers=[handler])
    logging.getLogger("quic").setLevel(logging.WARNING)  # aioquic logs every handshake at INFO
    if a.shortcut:
        return make_shortcut()
    first = first_instance()
    if not first:
        if a.reset_key:
            if not reset_running():
                p.error("未能确认密钥重置。请退出正在运行的 MiniDesk 后重新执行 --reset-key。")
            print("配对密钥已更新，旧手机和会话已断开。")
        if a.pair and sys.stdout:
            show_pairing(read_config(CONFIG_PATH))
        if not a.start:
            print("MiniDesk 已在运行。改了 --relay/--token 的话，先在连接窗口点「退出 MiniDesk」再启动。")
        elif not show_running():  # an older version is running: it has no window to bring up
            message_box("MiniDesk 已经在运行，手机可以直接连接。")
        return
    try:
        cfg = load_config(a)
    except (OSError, ValueError) as e:
        p.error(str(e))
    if a.pair and sys.stdout:
        show_pairing(cfg)
    winput.init()
    k = ctypes.windll.kernel32
    k.CreateEventW.restype = ctypes.c_void_p
    k.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    show_event = k.CreateEventW(None, False, False, SHOW_EVENT)  # auto-reset
    reset_event = k.CreateEventW(None, False, False, RESET_EVENT)
    reset_done = k.CreateEventW(None, True, False, RESET_DONE)
    try:
        asyncio.run(Host(cfg, open_window=a.start, show_event=show_event,
                         reset_event=reset_event, reset_done=reset_done).run())
    except (KeyboardInterrupt, asyncio.CancelledError):  # Ctrl+C, or 退出 MiniDesk in the connect window
        log.info("已退出")
    finally:
        for handle in (show_event, reset_event, reset_done, _mutex):
            if handle:
                k.CloseHandle(ctypes.c_void_p(handle))


if __name__ == "__main__":
    main()
