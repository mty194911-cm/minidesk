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
import json
import logging
import logging.handlers
import os
import secrets
import ssl

from aiohttp import WSMsgType, web

from limits import Admission, HOST_ID, MAX_CONTROL, MAX_MESSAGE, PAIR_TIMEOUT, STATE

WEB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
MAX_MSG = MAX_MESSAGE
log = logging.getLogger("relay")


async def host_control(req):
    hid = req.query.get("id", "")
    token = req.query.get("token", "")
    if not token.isascii() or not hmac.compare_digest(token, req.app[STATE]["token"]) or not HOST_ID.fullmatch(hid):
        raise web.HTTPForbidden()
    if hid not in req.app[STATE]["hosts"] and len(req.app[STATE]["hosts"]) >= 64:
        raise web.HTTPServiceUnavailable()
    ws = web.WebSocketResponse(heartbeat=20, max_msg_size=1024)
    await ws.prepare(req)
    hosts = req.app[STATE]["hosts"]
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
    fut = req.app[STATE]["pending"].get(req.match_info["sid"])
    if fut is None or fut.done():
        raise web.HTTPNotFound()
    ws = web.WebSocketResponse(max_msg_size=MAX_MSG)
    await ws.prepare(req)
    if fut.done():  # another upgrade or a timeout may have won while prepare() yielded
        await ws.close()
        return ws
    closed = asyncio.get_running_loop().create_future()
    fut.set_result((ws, closed))
    await closed  # the client handler owns the splice; keep this connection open until it ends
    return ws


async def client(req):
    hid = req.match_info["id"]
    release = req.app[STATE]["admission"].acquire(req.remote, hid)
    if release is None:
        raise web.HTTPTooManyRequests(headers={"Retry-After": "2"})
    try:
        return await client_session(req, hid)
    finally:
        release()


async def client_session(req, hid):
    ws = web.WebSocketResponse(heartbeat=20, max_msg_size=MAX_CONTROL)
    await ws.prepare(req)
    req.app[STATE]["sockets"].add(ws)
    try:
        return await splice(req, ws, hid)
    finally:
        req.app[STATE]["sockets"].discard(ws)
        await ws.close()


async def splice(req, ws, hid):
    ctl = req.app[STATE]["hosts"].get(hid)
    if ctl is None:
        await ws.close(code=4404, message=b"host offline")
        return ws
    sid = secrets.token_urlsafe(18)
    fut = req.app[STATE]["pending"][sid] = asyncio.get_running_loop().create_future()
    try:
        await ctl.send_str(sid)
        hws, closed = await asyncio.wait_for(fut, PAIR_TIMEOUT)
    except (asyncio.TimeoutError, ConnectionError):
        await ws.close(code=4408, message=b"host did not answer")
        return ws
    finally:
        req.app[STATE]["pending"].pop(sid, None)
    try:
        await asyncio.gather(pipe(ws, hws), pipe(hws, ws))
    finally:
        if not closed.done():
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
    if "wt" not in req.app[STATE]:
        raise web.HTTPNotFound()
    return web.json_response(req.app[STATE]["wt"], headers={"Cache-Control": "no-store"})


async def client_cache_headers(req, response):
    if req.path in ("/s/app.js", "/s/client-core.js"):
        response.headers["Cache-Control"] = "no-cache, max-age=0, must-revalidate"


def make_app(token):
    app = web.Application()
    app[STATE] = {"token": token, "hosts": {}, "pending": {}, "quic_pending": {},
                  "admission": Admission(), "quic_admission": Admission(per_host=128),
                  "sockets": set(), "quic_protocols": set()}
    app.on_shutdown.append(shutdown)
    app.on_cleanup.append(cleanup_quic)
    app.on_response_prepare.append(client_cache_headers)
    app.router.add_get("/wt", wt_info)
    app.router.add_get("/ws/host", host_control)
    app.router.add_get("/ws/s/{sid}", host_session)
    app.router.add_get("/ws/c/{id}", client)
    app.router.add_get("/", index)
    app.router.add_get("/s/ca.crt", ca_cert)
    app.router.add_static("/s/", WEB)
    return app


async def shutdown(app):
    for future in (*app[STATE]["pending"].values(), *app[STATE]["quic_pending"].values()):
        if not future.done():
            future.cancel()
    await asyncio.gather(*(ws.close(code=1001) for ws in (*app[STATE]["hosts"].values(), *app[STATE]["sockets"])),
                         return_exceptions=True)
    for protocol in tuple(app[STATE]["quic_protocols"]):
        protocol.close()


async def cleanup_quic(app):
    if "quic_cleanup" in app[STATE]:
        await app[STATE]["quic_cleanup"](app)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--token", default=os.environ.get("MINIDESK_TOKEN"), help="host registration secret")
    p.add_argument("--config", help="protected JSON file containing the host registration token")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--cert", help="TLS certificate chain (omit when behind a TLS reverse proxy)")
    p.add_argument("--key", help="TLS private key")
    p.add_argument("--log", help="log file (for running in the background, e.g. as a Windows startup task)")
    p.add_argument("--quic-port", type=int, help="UDP port for QUIC/WebTransport (default: same as --port, 0 = off)")
    a = p.parse_args()
    if a.config and not a.token:
        try:
            with open(a.config, encoding="utf-8") as file:
                a.token = json.load(file).get("token")
        except (OSError, ValueError, AttributeError) as e:
            p.error(f"cannot read relay configuration: {type(e).__name__}")
    if not a.token:
        p.error("--token or MINIDESK_TOKEN is required")
    if not isinstance(a.token, str) or not a.token.isascii():
        p.error("token must be ASCII text")
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
    qserver = None
    try:
        await web.TCPSite(runner, a.host, a.port, ssl_context=ctx).start()
        log.info("relay listening on port %d%s", a.port, " (TLS)" if ctx else "")
        quic_port = a.port if a.quic_port is None else a.quic_port
        if quic_port:
            try:
                import quic
            except ImportError:
                log.warning("aioquic not installed: UDP disabled, clients use WebSockets")
            else:
                qserver = await quic.start(app, a.host, quic_port)
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()
        if qserver:
            qserver.close()
        await asyncio.sleep(0.25 if ctx else 0)


if __name__ == "__main__":
    main()
