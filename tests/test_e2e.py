"""End-to-end over a local relay with the real screen: python tests/test_e2e.py [--tls]

--tls serves the relay with a throwaway private CA (mkcert.py), like a domain-less deployment.
"""
import asyncio
import contextlib
import os
import secrets
import socket
import ssl
import struct
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "relay")]

import json  # noqa: E402

import aiohttp  # noqa: E402
import av  # noqa: E402
from aiohttp import web  # noqa: E402

import mkcert  # noqa: E402
from limits import STATE  # noqa: E402
import relay  # noqa: E402
import winput  # noqa: E402
from host import Host, b64  # noqa: E402
from protocol import ACK, CONFIG, CURSOR, KEYFRAME, LAN, PING, PONG, SCREEN, VIDEO  # noqa: E402
from secure import AuthError, client_handshake  # noqa: E402


async def connect(http, url, key):
    ws = await http.ws_connect(url, max_msg_size=8 << 20)

    async def recv():
        m = await ws.receive(timeout=5)
        if m.type != aiohttp.WSMsgType.BINARY:
            raise AuthError(f"closed: {m.type} {ws.close_code}")
        return m.data

    return ws, await client_handshake(recv, ws.send_bytes, key), recv


async def main():
    winput.init()
    token, key = secrets.token_urlsafe(16), secrets.token_bytes(32)
    app = relay.make_app(token)
    runner = web.AppRunner(app)
    await runner.setup()
    tls = "--tls" in sys.argv
    server_ctx = client_ctx = None
    with socket.socket() as probe:  # a free port: a real host may already hold the default LAN port
        probe.bind(("0.0.0.0", 0))
        lan_port = probe.getsockname()[1]
    cfg = {"token": token, "id": "testhost01", "key": b64(key), "lan_port": lan_port}
    if tls:
        tmp = tempfile.mkdtemp()
        ca_key, ca_cert = mkcert.make_ca()
        srv_key, srv_cert = mkcert.make_server_cert(ca_key, ca_cert, "127.0.0.1")
        files = {"ca.crt": mkcert.pem_cert(ca_cert), "server.crt": mkcert.pem_cert(srv_cert),
                 "server.key": mkcert.pem_key(srv_key)}
        for name, data in files.items():
            with open(os.path.join(tmp, name), "wb") as f:
                f.write(data)
        server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server_ctx.load_cert_chain(os.path.join(tmp, "server.crt"), os.path.join(tmp, "server.key"))
        client_ctx = ssl.create_default_context(cafile=os.path.join(tmp, "ca.crt"))
        cfg["ca"] = os.path.join(tmp, "ca.crt")
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=server_ctx)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    scheme = "s" if tls else ""
    http_base, ws_base = f"http{scheme}://127.0.0.1:{port}", f"ws{scheme}://127.0.0.1:{port}"
    cfg["relay"] = http_base
    host = Host(cfg)
    host_task = asyncio.create_task(host.run())
    for _ in range(50):
        if "testhost01" in app[STATE]["hosts"]:
            break
        await asyncio.sleep(0.05)
    assert "testhost01" in app[STATE]["hosts"], "host did not register"
    url = f"{ws_base}/ws/c/testhost01"

    if tls:  # a client that does not trust the private CA must fail
        async with aiohttp.ClientSession() as http:
            try:
                await http.get(http_base + "/")
                raise AssertionError("untrusted certificate accepted")
            except aiohttp.ClientConnectorCertificateError:
                print("untrusted client rejected the certificate: OK")

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=client_ctx)) as http:
        if tls and os.path.exists(os.path.join(ROOT, "relay", "web", "ca.crt")):
            r = await http.get(http_base + "/s/ca.crt")
            print(f"/s/ca.crt -> {r.status} {r.content_type}")
            assert r.status == 200 and r.content_type == "application/x-x509-ca-cert"
        # unknown host id -> 4404
        ws = await http.ws_connect(f"{ws_base}/ws/c/nobody")
        await ws.receive()
        assert ws.close_code == 4404, ws.close_code
        print("offline host rejected: OK")

        # wrong key -> handshake fails
        try:
            await connect(http, url, secrets.token_bytes(32))
            raise AssertionError("wrong key accepted")
        except AuthError:
            print("wrong key rejected: OK")

        t0 = time.perf_counter()
        ws, ch, recv = await connect(http, url, key)
        t_hs = time.perf_counter() - t0
        await ws.send_bytes(ch.seal(struct.pack("<BIB", CONFIG, 8000, 60)))
        dec = av.CodecContext.create("h264", "r")
        screen, frames, keyframes, t_first, pong, lan_urls = None, 0, 0, None, None, []
        unacked = []
        requested = False
        deadline = time.perf_counter() + 3
        while time.perf_counter() < deadline:
            try:
                m = ch.open(await recv())
            except asyncio.TimeoutError:
                break
            if m[0] == SCREEN:
                screen = struct.unpack_from("<HH", m, 1)
            elif m[0] == VIDEO:
                key_flag, seq = struct.unpack_from("<BI", m, 1)
                for f in dec.decode(av.Packet(m[6:])):
                    assert (f.width, f.height) == screen, (f.width, f.height, screen)
                    frames += 1
                    t_first = t_first or time.perf_counter() - t0
                keyframes += key_flag
                if key_flag and requested:
                    assert b"\x00\x00\x01\x67" in m[6:200], "requested IDR lacks SPS"
                await ws.send_bytes(ch.seal(struct.pack("<BI", ACK, seq)))
                if not requested and frames:
                    requested = True
                    await ws.send_bytes(ch.seal(bytes([KEYFRAME])))
                    await ws.send_bytes(ch.seal(struct.pack("<Bd", PING, time.perf_counter())))
            elif m[0] == PONG:
                pong = (time.perf_counter() - struct.unpack_from("<d", m, 1)[0]) * 1000
            elif m[0] == LAN:
                lan_urls = json.loads(m[1:])
            elif m[0] == CURSOR:
                pass
            if requested and keyframes >= 2 and pong is not None and lan_urls:
                break
        print(f"screen {screen}, decoded {frames} frames, keyframes {keyframes}, ping {pong:.1f} ms")
        print(f"handshake {t_hs * 1000:.1f} ms, first decoded frame {t_first * 1000:.0f} ms after connect")
        assert screen and frames and keyframes >= 2

        # Flow control: stop acking and force frames; the host must stall at the window (<= 30, typically 2-3).
        for _ in range(10):
            await ws.send_bytes(ch.seal(bytes([KEYFRAME])))
            await asyncio.sleep(0.15)
        while True:
            try:
                m = ch.open(await asyncio.wait_for(recv(), 0.5))
            except asyncio.TimeoutError:
                break
            if m[0] == VIDEO:
                unacked.append(struct.unpack_from("<I", m, 2)[0])
        print(f"without ACKs the host stopped after {len(unacked)} frames: OK")
        assert len(unacked) <= 4, unacked

        # LAN direct: the client switches over; the relay session is told it was replaced (4002).
        print(f"LAN URLs advertised: {lan_urls}")
        assert lan_urls
        lan_ctx = ssl.create_default_context(cafile=mkcert.CA_CRT)
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=lan_ctx)) as lan:
            dws, dch, drecv = await connect(lan, lan_urls[0], key)
            await dws.send_bytes(dch.seal(struct.pack("<BIB", CONFIG, 8000, 60)))
            while not ws.closed:
                await ws.receive(timeout=5)
            assert ws.close_code == 4002, ws.close_code
            print("relay session replaced by LAN direct (4002): OK")
            got = set()
            while not {SCREEN, VIDEO} <= got:
                m = dch.open(await drecv())
                got.add(m[0])
                if m[0] == VIDEO:
                    await dws.send_bytes(dch.seal(struct.pack("<BI", ACK, struct.unpack_from("<I", m, 2)[0])))
            print("video over LAN direct: OK")
            host.kick()  # the "断开" button on the PC
            while not dws.closed:
                await dws.receive(timeout=5)
            assert dws.close_code == 4001, dws.close_code
            print("kicked from the PC (4001): OK")

            # The PC serves the web client too, and the page's own-origin path /ws/c/<id> reaches the host.
            base = lan_urls[0].replace("wss://", "https://").rsplit("/ws", 1)[0]
            page = await (await lan.get(base + "/")).text()
            manifest = await (await lan.get(base + "/s/manifest.json")).json()
            script = await lan.get(base + "/s/client-core.js?v=2")
            assert "must-revalidate" in script.headers["Cache-Control"]
            assert "s/app.js" in page and "局域网" in manifest["name"], manifest
            pws, pch, _ = await connect(lan, lan_urls[0].replace("/ws", "/ws/c/testhost01"), key)
            await pws.close()
            print("web client served on the LAN port, /ws/c/<id> handshake: OK")

    host_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await host_task
    await runner.cleanup()
    print("ALL OK")


if __name__ == "__main__":
    asyncio.run(main())
