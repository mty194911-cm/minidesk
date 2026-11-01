import asyncio
import secrets

import pytest
from cryptography.exceptions import InvalidTag

from secure import AuthError, Channel, client_handshake, host_handshake


def test_handshake_bidirectional_reordering_and_replay():
    async def run():
        key = secrets.token_bytes(32)
        c2h, h2c = asyncio.Queue(), asyncio.Queue()
        host, client = await asyncio.gather(host_handshake(c2h.get, h2c.put, key),
                                            client_handshake(h2c.get, c2h.put, key))
        packets = [host.seal(bytes([n])) for n in range(3)]
        assert [client.open(packets[n]) for n in (2, 0, 1)] == [b"\x02", b"\x00", b"\x01"]
        with pytest.raises(InvalidTag):
            client.open(packets[0])
        assert host.open(client.seal(b"input")) == b"input"
    asyncio.run(run())


@pytest.mark.parametrize("length", [0, 7, 8, 23])
def test_short_ciphertext_is_rejected_as_authentication_failure(length):
    channel = Channel(secrets.token_bytes(32), secrets.token_bytes(32))
    with pytest.raises(InvalidTag):
        channel.open(bytes(length))


def test_tampering_does_not_consume_counter():
    key = secrets.token_bytes(32)
    sender, receiver = Channel(key, key), Channel(key, key)
    good = sender.seal(b"frame")
    bad = bytearray(good)
    bad[-1] ^= 1
    with pytest.raises(InvalidTag):
        receiver.open(bad)
    assert receiver.open(good) == b"frame"


def test_invalid_host_hello_length():
    async def run():
        async def recv():
            return b"bad"

        async def send(data):
            pass

        with pytest.raises(AuthError):
            await client_handshake(recv, send, secrets.token_bytes(32))
    asyncio.run(run())
