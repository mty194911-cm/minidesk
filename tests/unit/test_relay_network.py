import asyncio
import json

import aiohttp
from aiohttp import web
from aioquic.asyncio.client import connect

from limits import Admission, STATE
import quic
import relay


def test_http_admission_rejects_before_upgrade_and_releases_capacity():
    async def run():
        app = relay.make_app("test")
        app[STATE]["admission"] = Admission(total=1)
        release = app[STATE]["admission"].acquire("127.0.0.1", "testhost01")
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", 0).start()
        base = f"http://127.0.0.1:{runner.addresses[0][1]}"
        try:
            async with aiohttp.ClientSession() as client:
                async with client.get(base + "/s/client-core.js") as script:
                    assert script.status == 200 and "must-revalidate" in script.headers["Cache-Control"]
                async with client.get(base + "/ws/c/testhost01") as response:
                    assert response.status == 429
                release()
                async with client.ws_connect(base + "/ws/c/testhost01") as ws:
                    await ws.receive()
                    assert ws.close_code == 4404
            async def released():
                while app[STATE]["admission"].count:
                    await asyncio.sleep(0.001)
            await asyncio.wait_for(released(), 1)
        finally:
            await runner.cleanup()
    asyncio.run(run())


def test_oversized_unpaired_quic_id_is_closed_without_stopping_listener():
    async def run():
        import ssl

        app = relay.make_app("test")
        runner = web.AppRunner(app)
        await runner.setup()
        server = await quic.start(app, "127.0.0.1", 0)
        port = server._transport.get_extra_info("sockname")[1]
        cfg = quic.configuration(True, alpn_protocols=[quic.HOST_ALPN], verify_mode=ssl.CERT_NONE)
        try:
            for _ in range(2):
                async with connect("127.0.0.1", port, configuration=cfg) as peer:
                    peer._quic.send_stream_data(0, b"x" * 25)
                    peer.transmit()
                    await asyncio.wait_for(peer.wait_closed(), 2)
        finally:
            await runner.cleanup()
        assert not app[STATE]["quic_protocols"]
        assert app[STATE]["quic_admission"].count == 0
    asyncio.run(run())


def test_service_can_load_registration_secret_from_protected_config(tmp_path, monkeypatch):
    path = tmp_path / "relay.json"
    path.write_text(json.dumps({"token": "test-token"}), encoding="utf-8")
    monkeypatch.setattr(relay.os, "environ", {})
    monkeypatch.setattr("sys.argv", ["relay.py", "--config", str(path), "--quic-port", "0"])
    captured = []
    monkeypatch.setattr(relay, "serve_all", lambda args, ctx: captured.append(args.token))
    monkeypatch.setattr(relay.asyncio, "run", lambda value: None)
    relay.main()
    assert captured == ["test-token"]
