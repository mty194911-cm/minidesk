import asyncio
import struct
from types import SimpleNamespace

import pytest

from protocol import BUTTON, CONFIG, KEY, MOVE, PING, PONG, SCREEN, TEXT, VIDEO
from session import MAX_TEXT, OutboundQueue, Session


class Input:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        return lambda *args: self.calls.append((name, *args))


class Streamer:
    def __init__(self, *args, **kwargs):
        self.running = False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False

    def join(self, timeout):
        pass


class Host:
    def __init__(self):
        self.active = None

    def activate(self, session):
        previous = self.active
        if previous:
            previous.close(4002)
        self.active = session
        return previous.streamer if previous else None

    def deactivate(self, session):
        if self.active is session:
            self.active = None


def session(host=None, link=None):
    api = Input()
    channel = SimpleNamespace(open=lambda value: value, seal=lambda value: value)
    return Session(host or Host(), link, channel, "test", input_api=api, streamer_factory=Streamer)


def activate(value):
    value.handle(struct.pack("<BIB", CONFIG, 8000, 60), lambda data: None)


def test_input_requires_activation_and_stops_immediately_on_close():
    value = session()
    key = struct.pack("<BHB", KEY, 0x1D, 1)
    value.handle(key, None)
    assert value.input.calls == []
    activate(value)
    value.handle(key, None)
    value.close(4001)
    value.handle(key, None)
    assert value.input.calls == [("key", 0x1D, 1), ("key", 0x1D, False)]
    assert not value.streamer.running


def test_takeover_releases_old_keys_before_new_input_and_cleanup_is_idempotent():
    host = Host()
    old, new = session(host), session(host)
    key = struct.pack("<BHB", KEY, 0x1D, 1)
    activate(old)
    old.handle(key, None)
    activate(new)
    new.handle(key, None)
    old.release_input()
    old.handle(key, None)
    assert old.input.calls == [("key", 0x1D, 1), ("key", 0x1D, False)]
    assert new.input.calls == [("key", 0x1D, 1)]
    assert host.active is new


@pytest.mark.parametrize("message", [b"", bytes([MOVE]), bytes([BUTTON, 3, 1]),
                                    struct.pack("<BHB", KEY, 0xAB01, 1),
                                    struct.pack("<BHB", KEY, 0x1D, 2),
                                    bytes([TEXT]) + b"x" * (MAX_TEXT + 1), bytes([TEXT, 0xFF])])
def test_malformed_input_is_rejected_before_native_injection(message):
    value = session()
    activate(value)
    with pytest.raises(ValueError):
        value.handle(message, None)
    assert value.input.calls == []


def test_unicode_text_and_button_release():
    value = session()
    activate(value)
    value.handle(bytes([TEXT]) + "你好🙂".encode(), None)
    value.handle(bytes([BUTTON, 0, 1]), None)
    value.close(4001)
    value.close(4002)
    assert value.input.calls == [("text", "你好🙂"), ("button", 0, 1), ("button", 0, False)]


class Link:
    def __init__(self, fail=False):
        self.inbox, self.sent = asyncio.Queue(), []
        self.closed, self.fail = False, fail
        self.close_codes = []

    async def recv(self):
        return await self.inbox.get()

    async def send(self, value, **kwargs):
        if self.fail:
            raise ConnectionError("simulated send failure")
        self.sent.append(value)

    async def close(self, code=1000):
        self.closed = True
        self.close_codes.append(code)


def test_send_failure_terminates_session_and_releases_input():
    async def run():
        link = Link(fail=True)
        value = session(link=link)
        activate(value)
        value.handle(struct.pack("<BHB", KEY, 0x1D, 1), None)
        link.inbox.put_nowait(bytes([PING]))
        await asyncio.wait_for(value.run(), 1)
        assert link.closed and value.host.active is None
        assert value.input.calls[-1] == ("key", 0x1D, False)
    asyncio.run(run())


def test_explicit_close_delivers_bye_even_if_peer_keeps_read_side_open():
    async def run():
        link = Link()
        value = session(link=link)
        task = asyncio.create_task(value.run())
        await asyncio.sleep(0)
        value.close(4001)
        await asyncio.wait_for(task, 1)
        assert link.closed
        assert link.close_codes[-1] == 4001
        assert struct.unpack("<BH", link.sent[-1]) == (0x7F, 4001)
    asyncio.run(run())


def test_session_cancellation_releases_buttons_and_closes_link():
    async def run():
        link = Link()
        value = session(link=link)
        activate(value)
        value.handle(bytes([BUTTON, 0, 1]), None)
        task = asyncio.create_task(value.run())
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert link.closed and value.host.active is None
        assert value.input.calls[-1] == ("button", 0, False)
    asyncio.run(run())


def test_pong_bypasses_unsent_video_without_reordering_reference_frames_or_screen_metadata():
    async def run():
        queue = OutboundQueue(96)
        messages = [bytes([VIDEO, 1]), bytes([SCREEN]), bytes([VIDEO, 2])]
        for message in messages:
            queue.put_nowait(message)
        queue.put_nowait(bytes([PONG]))
        assert await queue.get() == bytes([PONG])
        assert [await queue.get() for _ in messages] == messages
    asyncio.run(run())
