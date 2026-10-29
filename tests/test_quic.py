"""UDP path end to end: a WebTransport "phone" (aioquic) -> relay (QUIC) -> host (QUIC), real screen and encoder.

  python tests/test_quic.py              functional test
  python tests/test_quic.py --loss 0.05 [--cc reno]
      drop 5% of the packets each way (and add 40 ms each way) on the phone's leg, animate the screen for 10 s and
      report frame rate, throughput and ping; --cc reno swaps in loss-based congestion control for comparison

The phone side mirrors relay/web/app.js: control messages framed on its bidi stream, one video frame per uni stream.
"""
import asyncio
import base64
import contextlib
import logging
import os
import random
import secrets
import socket
import ssl
import struct
import sys
import tempfile
import time
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "relay")]

import aiohttp  # noqa: E402
import av  # noqa: E402
from aiohttp import web  # noqa: E402
from aioquic.h3.connection import H3_ALPN, H3Connection  # noqa: E402
from aioquic.h3.events import HeadersReceived, WebTransportStreamDataReceived  # noqa: E402
from aioquic.quic.connection import QuicConnection  # noqa: E402
from aioquic.quic.events import StreamDataReceived  # noqa: E402

import mkcert  # noqa: E402
import quic  # noqa: E402
import relay  # noqa: E402
import winput  # noqa: E402
from host import Host, b64  # noqa: E402
from protocol import ACK, BYE, CONFIG, KEYFRAME, NOTE, PING, PONG, SCREEN, VIDEO  # noqa: E402
from secure import client_handshake  # noqa: E402


class Phone(quic.Swept):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.h3 = H3Connection(self._quic, enable_webtransport=True)
        self.session, self.ctl = None, None
        self.status = asyncio.get_event_loop().create_future()
        self.inbox, self.unframer, self.uni = asyncio.Queue(), quic.Unframer(), {}

    def quic_event_received(self, event):
        super().quic_event_received(event)
        # aioquic's H3 client does not register the WebTransport bidi streams it creates, and would parse the
        # relay's raw bytes on them as HTTP/3 frames; browsers do it right. Read our control stream directly.
        if isinstance(event, StreamDataReceived) and event.stream_id == self.ctl:
            for m in self.unframer.feed(event.data):
                self.inbox.put_nowait(m)
            return
        for e in self.h3.handle_event(event):
            if isinstance(e, HeadersReceived) and e.stream_id == self.session and not self.status.done():
                self.status.set_result(dict(e.headers)[b":status"])
            elif isinstance(e, WebTransportStreamDataReceived):
                if e.stream_id == self.ctl:
                    for m in self.unframer.feed(e.data):
                        self.inbox.put_nowait(m)
                else:  # a video frame: one uni stream each
                    self.uni[e.stream_id] = self.uni.get(e.stream_id, b"") + e.data
                    if e.stream_ended:
                        self.inbox.put_nowait(self.uni.pop(e.stream_id))

    async def open(self, authority, path):
        self.session = self._quic.get_next_available_stream_id()
        self.h3.send_headers(self.session, [(b":method", b"CONNECT"), (b":scheme", b"https"),
                                            (b":authority", authority.encode()), (b":path", path.encode()),
                                            (b":protocol", b"webtransport")])
        self.transmit()
        status = await asyncio.wait_for(self.status, 15)
        assert status == b"200", status
        self.ctl = self.h3.create_webtransport_stream(self.session)

    async def send(self, data):
        self._quic.send_stream_data(self.ctl, quic.frame(data))
        self.transmit()


class LossyProxy(asyncio.DatagramProtocol):
    """UDP proxy that drops `loss` of the packets in each direction and delays the rest by `delay` seconds."""

    def __init__(self, target, loss, delay):
        self.target, self.loss, self.delay, self.client, self.up = target, loss, delay, None, None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        loop = asyncio.get_running_loop()
        if random.random() < self.loss:
            return
        if addr != self.target:  # phone -> relay
            self.client = addr
            loop.call_later(self.delay, self.transport.sendto, data, self.target)
        elif self.client:
            loop.call_later(self.delay, self.transport.sendto, data, self.client)


async def main():
    loss = float(sys.argv[sys.argv.index("--loss") + 1]) if "--loss" in sys.argv else 0.0
    delay = float(sys.argv[sys.argv.index("--delay") + 1]) if "--delay" in sys.argv else 0.04
    if "--cc" in sys.argv:
        quic.CC = sys.argv[sys.argv.index("--cc") + 1]
    winput.init()
    tmp = tempfile.mkdtemp()
    ca_key, ca_cert = mkcert.make_ca()
    k, c = mkcert.make_server_cert(ca_key, ca_cert, "127.0.0.1")
    pems = {"ca.crt": mkcert.pem_cert(ca_cert), "s.crt": mkcert.pem_cert(c), "s.key": mkcert.pem_key(k)}
    for name, data in pems.items():
        with open(os.path.join(tmp, name), "wb") as f:
            f.write(data)
    sctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    sctx.load_cert_chain(os.path.join(tmp, "s.crt"), os.path.join(tmp, "s.key"))
    with socket.socket() as s1, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s2:
        s1.bind(("127.0.0.1", 0))
        s2.bind(("127.0.0.1", 0))
        port, lan_port = s1.getsockname()[1], s2.getsockname()[1]

    key = secrets.token_bytes(32)
    ca = os.path.join(tmp, "ca.crt")
    if "--relay" in sys.argv:  # a relay running elsewhere: another Python/aioquic, or the real server (https)
        base, token = sys.argv[sys.argv.index("--relay") + 1], sys.argv[sys.argv.index("--token") + 1]
        runner = None
        if base.startswith("https"):
            ca = mkcert.CA_CRT  # the deployment's private CA
        http_ssl = ssl.create_default_context(cafile=ca) if base.startswith("https") else False
    else:
        token = secrets.token_urlsafe(16)
        app = relay.make_app(token)
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", port, ssl_context=sctx).start()
        qserver = await quic.start(app, "127.0.0.1", port)
        base, http_ssl = f"https://127.0.0.1:{port}", ssl.create_default_context(cafile=os.path.join(tmp, "ca.crt"))
    host = Host({"relay": base, "token": token, "id": "testhost01", "key": b64(key), "ca": ca, "lan_port": lan_port})
    host_task = asyncio.create_task(host.run())
    if runner:
        for _ in range(100):
            if "testhost01" in app["hosts"]:
                break
            await asyncio.sleep(0.1)
        assert "testhost01" in app["hosts"], "host did not register"
    else:  # wait until the host reports it registered (route probing over a slow link takes a while)
        online, loop = asyncio.Event(), asyncio.get_running_loop()

        class Online(logging.Handler):
            def emit(self, record):
                if "已上线" in record.getMessage():
                    loop.call_soon_threadsafe(online.set)

        logging.getLogger("host").addHandler(Online())
        logging.getLogger("host").setLevel(logging.INFO)
        await asyncio.wait_for(online.wait(), 60)

    notes = []

    class Notes(logging.Handler):
        def emit(self, record):
            if "手机报告" in record.getMessage():
                notes.append(record.getMessage())

    logging.getLogger("host").addHandler(Notes())
    logging.getLogger("host").setLevel(logging.INFO)

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=http_ssl)) as http:
        info = await (await http.get(base + "/wt")).json()
    target = (urllib.parse.urlsplit(base).hostname, info["port"])
    if loss:
        _, proxy = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: LossyProxy(target, loss, delay), local_addr=("127.0.0.1", 0))
        target = proxy.transport.get_extra_info("sockname")
        print(f"phone leg: {loss:.0%} packet loss each way, +{delay * 1000:.0f} ms each way")

    cfg = quic.configuration(True, alpn_protocols=H3_ALPN, max_datagram_frame_size=65536, verify_mode=ssl.CERT_NONE)
    conn = QuicConnection(configuration=cfg)
    bind = sys.argv[sys.argv.index("--bind") + 1] if "--bind" in sys.argv else "127.0.0.1"  # NIC for real servers
    transport, phone = await asyncio.get_running_loop().create_datagram_endpoint(lambda: Phone(conn),
                                                                                 local_addr=(bind, 0))
    quic.keep_listening(transport)
    phone.connect(target)
    await asyncio.wait_for(phone.wait_connected(), 5)
    assert base64.b64encode(quic.cert_hash(conn.tls._peer_certificate)).decode() in info["hashes"]
    print("relay certificate matches the pinned hash from /wt: OK")
    t0 = time.perf_counter()
    await phone.open(f"{target[0]}:{info['port']}", "/wt/c/testhost01")
    ch = await client_handshake(lambda: asyncio.wait_for(phone.inbox.get(), 10), phone.send, key)
    print(f"WebTransport session + handshake: {(time.perf_counter() - t0) * 1000:.0f} ms")
    await phone.send(ch.seal(struct.pack("<BIB", CONFIG, 8000, 60)))
    await phone.send(ch.seal(bytes([NOTE]) + "经服务器·UDP 用了 61 秒后断开：测试".encode()))

    dec = av.CodecContext.create("h264", "r")
    screen, frames, keys, pong, seqs, bye = None, 0, 0, None, [], None
    early, next_seq = {}, None
    requested = False
    deadline = time.perf_counter() + (12 if loss else 6)
    while time.perf_counter() < deadline:
        try:
            m = ch.open(await asyncio.wait_for(phone.inbox.get(), 1))
        except asyncio.TimeoutError:
            continue
        if m[0] == SCREEN:
            screen = struct.unpack_from("<HH", m, 1)
        elif m[0] == VIDEO:
            key_flag, seq = struct.unpack_from("<BI", m, 1)
            seqs.append(seq)
            keys += key_flag
            await phone.send(ch.seal(struct.pack("<BI", ACK, seq)))
            # Frames have their own streams and may complete out of order: decode in sequence (as app.js does).
            early[seq] = m
            if next_seq is None and key_flag:
                next_seq = seq
            while next_seq in early:
                for f in dec.decode(av.Packet(early.pop(next_seq)[6:])):
                    assert (f.width, f.height) == screen
                    frames += 1
                next_seq += 1
            if frames and not requested:
                requested = True
                await phone.send(ch.seal(bytes([KEYFRAME])))
                await phone.send(ch.seal(struct.pack("<Bd", PING, time.perf_counter())))
        elif m[0] == PONG:
            pong = (time.perf_counter() - struct.unpack_from("<d", m, 1)[0]) * 1000
        if not loss and requested and keys >= 2 and pong is not None:
            break
    reordered = sum(1 for a, b in zip(seqs, seqs[1:]) if b < a)
    print(f"screen {screen}, {len(seqs)} video frames over uni streams ({reordered} arrived out of order), "
          f"decoded {frames}, keyframes {keys}, ping {pong:.0f} ms")
    assert screen and frames and keys >= 2 and pong is not None
    assert notes and "用了 61 秒后断开" in notes[0], notes
    print("disconnect report from the phone reaches the host log: OK")

    if loss or "--measure" in sys.argv:  # busy screen for 8 s (through the lossy leg, if any)
        import statistics
        import subprocess
        from bench_cpu import ANIM
        from test_adapt import BUSY  # --busy: content that needs many Mbps
        anim = subprocess.Popen([sys.executable, "-c", BUSY if "--busy" in sys.argv else ANIM])
        await asyncio.sleep(1.5)
        n0, bytes_, pings, t_start, t_ping = frames, 0, [], time.perf_counter(), 0.0
        while (now := time.perf_counter()) - t_start < 8:
            if now - t_ping > 0.25:
                t_ping = now
                await phone.send(ch.seal(struct.pack("<Bd", PING, now)))
            try:
                m = ch.open(await asyncio.wait_for(phone.inbox.get(), 0.25))
            except asyncio.TimeoutError:
                continue
            if m[0] == PONG:
                pings.append((time.perf_counter() - struct.unpack_from("<d", m, 1)[0]) * 1000)
            elif m[0] == VIDEO:
                seq = struct.unpack_from("<I", m, 2)[0]
                bytes_ += len(m)
                await phone.send(ch.seal(struct.pack("<BI", ACK, seq)))
                if "--nodecode" in sys.argv:  # decoding here would stall the event loop the relay and host share
                    frames += 1
                    continue
                early[seq] = m
                while next_seq in early:
                    for _ in dec.decode(av.Packet(early.pop(next_seq)[6:])):
                        frames += 1
                    next_seq += 1
        anim.kill()
        span = time.perf_counter() - t_start
        pings.sort()
        print(f"[{quic.CC}] busy screen, {loss:.0%} added loss: {(frames - n0) / span:.0f} fps decoded, "
              f"{bytes_ * 8 / span / 1e6:.1f} Mbps, ping median {statistics.median(pings):.0f} ms, "
              f"p95 {pings[int(len(pings) * .95)]:.0f} ms, max {pings[-1]:.0f} ms")

    host.kick()  # the PC's "断开" button: the phone must get BYE 4001 over the control stream
    while bye is None:
        m = ch.open(await asyncio.wait_for(phone.inbox.get(), 5))
        if m[0] == BYE:
            bye = struct.unpack_from("<H", m, 1)[0]
    assert bye == 4001, bye
    print("kicked from the PC: BYE 4001 over UDP: OK")

    transport.close()
    if loss:
        proxy.transport.close()
    host_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await host_task
    if runner:
        qserver.close()
        await runner.cleanup()
    print("ALL OK")


if __name__ == "__main__":
    asyncio.run(main())
