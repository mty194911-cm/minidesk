import asyncio
import struct
from types import SimpleNamespace

import pytest

from limits import Admission, MAX_CONTROL
from quic import RelayProtocol, Unframer, frame


def test_admission_limits_release_and_counter_cleanup():
    limits = Admission(total=3, per_ip=2, per_host=1)
    first = limits.acquire("a", "host1")
    assert first
    assert limits.acquire("b", "host1") is None
    second = limits.acquire("a", "host2")
    assert second
    assert limits.acquire("a", "host3") is None
    third = limits.acquire("b", "host3")
    assert third
    assert limits.acquire("c", "host4") is None
    for release in (first, first, second, third):
        release()
    assert limits.count == 0 and not limits.ips and not limits.hosts


@pytest.mark.parametrize("length", [0, MAX_CONTROL + 1, 0xFFFFFFFF])
def test_oversized_frame_rejected_from_header_without_waiting_for_body(length):
    parser = Unframer()
    with pytest.raises(ValueError):
        parser.feed(struct.pack("<I", length))
    assert not parser.buf


def test_fragmented_and_batched_frames():
    parser = Unframer()
    data = frame(b"a") + frame(b"hello") + frame(b"x" * MAX_CONTROL)
    result = []
    for offset in range(0, len(data), 137):
        result.extend(parser.feed(data[offset:offset + 137]))
        assert len(parser.buf) <= MAX_CONTROL + 4
    assert result == [b"a", b"hello", b"x" * MAX_CONTROL]
    assert not parser.buf


def bare_protocol():
    protocol = object.__new__(RelayProtocol)
    protocol.peer, protocol.sid_buf, protocol.joined = None, b"", False
    protocol.ctl_backlog = b""
    protocol.app = {"quic_pending": {}}
    protocol.close = lambda: setattr(protocol, "closing", True)
    protocol.closing = False
    return protocol


def test_unauthenticated_session_id_is_bounded():
    protocol = bare_protocol()
    protocol.host_data(SimpleNamespace(stream_id=0, data=b"x" * (2 << 20)))
    assert protocol.closing and not protocol.sid_buf


def test_session_id_and_following_bytes_in_same_packet_are_not_lost():
    async def run():
        protocol = bare_protocol()
        sid = "a" * 24
        future = asyncio.get_running_loop().create_future()
        protocol.app["quic_pending"][sid] = future
        protocol.host_data(SimpleNamespace(stream_id=0, data=sid.encode() + b"\nhello"))
        assert future.result() is protocol
        assert protocol.joined and protocol.ctl_backlog == b"hello"
        assert not protocol.sid_buf
    asyncio.run(run())


def test_unpaired_host_cannot_open_video_streams():
    protocol = bare_protocol()
    protocol.host_data(SimpleNamespace(stream_id=2, data=b"video", end_stream=True))
    assert protocol.closing
