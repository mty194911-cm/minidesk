import asyncio
import importlib.util
import os
from pathlib import Path
import secrets
import sys
from types import ModuleType, SimpleNamespace

import pytest

from configuration import b64, read_config, save_config
from secure import client_handshake


@pytest.fixture
def host_module(monkeypatch):
    # Import the real host controller without loading a Windows DLL or desktop capture.
    inputs = ModuleType("winput")
    inputs.calls = []
    for name in ("move", "key", "button", "text", "wheel"):
        setattr(inputs, name, lambda *args, operation=name: inputs.calls.append((operation, *args)))
    stream = ModuleType("stream")
    stream.Streamer = object
    monkeypatch.setitem(sys.modules, "winput", inputs)
    monkeypatch.setitem(sys.modules, "stream", stream)
    spec = importlib.util.spec_from_file_location("host_under_test", Path(__file__).parents[2] / "host.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def config():
    return {"relay": "https://127.0.0.1", "token": "test", "id": "testhost01", "lan_port": 0,
            "key": b64(secrets.token_bytes(32))}


def test_live_reset_updates_memory_file_and_revokes_sessions(host_module, tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    cfg = config()
    save_config(path, cfg)
    monkeypatch.setattr(host_module, "CONFIG_PATH", str(path))
    host = host_module.Host(cfg)
    closed = []

    class Session:
        def close(self, code):
            closed.append(code)

    host.sessions.add(Session())
    host.reset_key()
    assert host.cfg["key"] != cfg["key"]
    assert host.key == host_module.unb64(read_config(path)["key"])
    assert host.key_revision == 1 and closed == [4001]


def test_failed_reset_keeps_live_key_and_sessions(host_module, monkeypatch):
    cfg = config()
    host = host_module.Host(cfg)

    def fail(*args):
        raise OSError("disk error")

    monkeypatch.setattr(host_module, "save_config", fail)
    with pytest.raises(OSError):
        host.reset_key()
    assert host.cfg == cfg and host.key_revision == 0


def test_quic_close_cancellation_still_closes_udp_socket(host_module, monkeypatch):
    async def run():
        link = object.__new__(host_module.QuicLink)
        closed = []
        link._transport = SimpleNamespace(close=lambda: closed.append(True))
        monkeypatch.setattr(host_module.quic.Swept, "close", lambda self: None)

        async def wait_closed():
            await asyncio.Event().wait()

        link.wait_closed = wait_closed
        task = asyncio.create_task(link.close())
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert closed == [True]
    asyncio.run(run())


def test_reset_revokes_handshake_that_started_with_old_key(host_module, tmp_path, monkeypatch):
    async def run():
        cfg = config()
        host = host_module.Host(cfg)
        monkeypatch.setattr(host_module, "CONFIG_PATH", str(tmp_path / "config.json"))
        incoming, outgoing = asyncio.Queue(), asyncio.Queue()

        class Link:
            closed = False

            async def recv(self):
                return await incoming.get()

            async def send(self, data):
                await outgoing.put(data)

            async def close(self):
                self.closed = True

        link = Link()
        serving = asyncio.create_task(host.serve(link, "test"))

        async def recv():
            response = await outgoing.get()
            host.reset_key()  # while an old-key handshake is between its two messages
            return response

        await client_handshake(recv, incoming.put, host_module.unb64(cfg["key"]))
        await asyncio.wait_for(serving, 1)
        assert link.closed and not host.sessions and host.active is None
        assert not host_module.winput.calls
    asyncio.run(run())


def test_second_instance_never_rotates_configuration_by_itself(host_module, monkeypatch):
    monkeypatch.setattr(host_module, "first_instance", lambda: False)
    monkeypatch.setattr(host_module, "reset_running", lambda: False)
    monkeypatch.setattr(sys, "argv", ["host.py", "--reset-key"])
    calls = []
    monkeypatch.setattr(host_module, "load_config", lambda args: calls.append(args))
    with pytest.raises(SystemExit):
        host_module.main()
    assert calls == []


@pytest.mark.skipif(os.name != "nt", reason="Windows named-event IPC")
def test_live_reset_command_reaches_running_instance(host_module, tmp_path, monkeypatch):
    async def run():
        k = host_module.ctypes.windll.kernel32
        k.CreateEventW.restype = host_module.ctypes.c_void_p
        k.WaitForSingleObject.argtypes = [host_module.ctypes.c_void_p, host_module.ctypes.c_uint]
        suffix = secrets.token_hex(8)
        request_name, done_name = f"Local\\MiniDeskTestReset{suffix}", f"Local\\MiniDeskTestDone{suffix}"
        monkeypatch.setattr(host_module, "RESET_EVENT", request_name)
        monkeypatch.setattr(host_module, "RESET_DONE", done_name)
        monkeypatch.setattr(host_module, "CONFIG_PATH", str(tmp_path / "config.json"))
        request = k.CreateEventW(None, False, False, request_name)
        done = k.CreateEventW(None, True, False, done_name)
        cfg = config()
        host = host_module.Host(cfg, reset_event=request, reset_done=done)
        task = asyncio.create_task(host.watch_commands())
        try:
            assert await asyncio.wait_for(asyncio.to_thread(host_module.reset_running), 6)
            assert host.key_revision == 1 and host.cfg["key"] != cfg["key"]
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            for handle in (request, done):
                k.CloseHandle(host_module.ctypes.c_void_p(handle))
    asyncio.run(run())
