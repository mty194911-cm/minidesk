"""MiniDesk relay: serves the web client and splices client <-> host WebSockets.

It only forwards ciphertext (see secure.py); the host token just keeps strangers from registering hosts.

  /ws/host?id=..&token=..   host control channel: receives a session id per incoming client
  /ws/s/<sid>               host data connection for one session
  /ws/c/<id>                client connection to host <id>
  /wt                       where the UDP (WebTransport) side listens and which certificate hashes to pin;
                            the UDP side itself is in quic.py

Run: python relay.py --token SECRET [--port 8080] [--cert fullchain.pem --key privkey.pem] [--log relay.log]
     UDP uses the same port number unless --quic-port says otherwise (0 = off).
"""
import argparse
import asyncio
import hmac
import logging
import logging.handlers
import os
import secrets
import ssl

from aiohttp import WSMsgType, web

WEB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
MAX_MSG = 8 << 20
log = logging.getLogger("relay")


async def host_control(req):
    hid = req.query.get("id", "")
    if not hmac.compare_digest(req.query.get("token", ""), req.app["token"]) or not 8 <= len(hid) <= 64:
        raise web.HTTPForbidden()
    ws = web.WebSocketResponse(heartbeat=20)
    await ws.prepare(req)
    hosts = req.app["hosts"]
    old, hosts[hid] = hosts.get(hid), ws
    if old is not None:
        await old.close()
    log.info("host %s online", hid)
    try:
        async for _ in ws:
            pass
    finally:
        if hosts.get(hid) is ws:
            del hosts[hid]
        log.info("host %s offline", hid)
    return ws


async def host_session(req):
    fut = req.app["pending"].get(req.match_info["sid"])
    if fut is None or fut.done():
        raise web.HTTPNotFound()
    ws = web.WebSocketResponse(max_msg_size=MAX_MSG)
    await ws.prepare(req)
    closed = asyncio.get_running_loop().create_future()
    fut.set_result((ws, closed))
    await closed  # the client handler owns the splice; keep this connection open until it ends
    return ws


async def client(req):
    ws = web.WebSocketResponse(heartbeat=20, max_msg_size=MAX_MSG)
    await ws.prepare(req)
    ctl = req.app["hosts"].get(req.match_info["id"])
    if ctl is None:
        await ws.close(code=4404, message=b"host offline")
        return ws
    sid = secrets.token_urlsafe(18)
    fut = req.app["pending"][sid] = asyncio.get_running_loop().create_future()
    try:
        await ctl.send_str(sid)
        hws, closed = await asyncio.wait_for(fut, 10)
    except (asyncio.TimeoutError, ConnectionError):
        await ws.close(code=4408, message=b"host did not answer")
        return ws
    finally:
        req.app["pending"].pop(sid, None)
    try:
        await asyncio.gather(pipe(ws, hws), pipe(hws, ws))
    finally:
        closed.set_result(None)
    return ws


async def pipe(src, dst):
    try:
        async for m in src:
            if m.type == WSMsgType.BINARY:
                await dst.send_bytes(m.data)
    except ConnectionError:
        pass
    finally:  # forward application close codes (4xxx: kicked/replaced) so the client knows not to reconnect
        code = src.close_code or 1000
        await dst.close(code=code if code >= 4000 else 1000)


async def index(_req):
    return web.FileResponse(os.path.join(WEB, "index.html"), headers={"Cache-Control": "no-cache"})


async def ca_cert(_req):  # this content type makes phones offer to install the private CA (mkcert.py)
    path = os.path.join(WEB, "ca.crt")
    if not os.path.exists(path):
        raise web.HTTPNotFound()
    return web.FileResponse(path, headers={"Content-Type": "application/x-x509-ca-cert"})


async def wt_info(req):
    if "wt" not in req.app:
        raise web.HTTPNotFound()
    return web.json_response(req.app["wt"], headers={"Cache-Control": "no-store"})


def make_app(token):
    app = web.Application()
    app["token"], app["hosts"], app["pending"] = token, {}, {}
    app.router.add_get("/wt", wt_info)
    app.router.add_get("/ws/host", host_control)
    app.router.add_get("/ws/s/{sid}", host_session)
    app.router.add_get("/ws/c/{id}", client)
    app.router.add_get("/", index)
    app.router.add_get("/s/ca.crt", ca_cert)
    app.router.add_static("/s/", WEB)
    return app


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--token", default=os.environ.get("MINIDESK_TOKEN"), help="host registration secret")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--cert", help="TLS certificate chain (omit when behind a TLS reverse proxy)")
    p.add_argument("--key", help="TLS private key")
    p.add_argument("--log", help="log file (for running in the background, e.g. as a Windows startup task)")
    p.add_argument("--quic-port", type=int, help="UDP port for QUIC/WebTransport (default: same as --port, 0 = off)")
    a = p.parse_args()
    if not a.token:
        p.error("--token or MINIDESK_TOKEN is required")
    ctx = None
    if a.cert:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(a.cert, a.key)
    handlers = None
    if a.log:
        handlers = [logging.handlers.RotatingFileHandler(a.log, maxBytes=1 << 20, backupCount=2, encoding="utf-8")]
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", handlers=handlers)
    if os.name == "nt":  # 1 ms timers: QUIC paces packets and acks with timers; Windows' default 15.6 ms adds latency
        import ctypes
        ctypes.windll.winmm.timeBeginPeriod(1)
    asyncio.run(serve_all(a, ctx))


async def serve_all(a, ctx):
    app = make_app(a.token)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, a.host, a.port, ssl_context=ctx).start()
    log.info("relay listening on port %d%s", a.port, " (TLS)" if ctx else "")
    quic_port = a.port if a.quic_port is None else a.quic_port
    if quic_port:
        try:
            import quic
        except ImportError:
            log.warning("aioquic not installed: UDP disabled, clients use WebSockets")
        else:
            await quic.start(app, a.host, quic_port)
    await asyncio.Event().wait()


if __name__ == "__main__":
    main()
