"""Paired-key handshake + AEAD channel. Mirrors relay/web/app.js, so only WebCrypto primitives are used:
ECDH P-256, HMAC/HKDF-SHA256, AES-256-GCM.

  C -> H  cpub(65) | nc(16)
  H -> C  hpub(65) | ns(16) | HMAC(K, "minidesk host" | T)        T = cpub|hpub|nc|ns
  C -> H  HMAC(K, "minidesk client" | T)
  keys    HKDF(ECDH, salt=K, info="minidesk session" | T) -> host->client | client->host

K is the 256-bit pairing key from the QR code; the relay never sees it, so it can neither read nor impersonate.
"""
import hashlib
import hmac
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PUB = 65


class AuthError(Exception):
    pass


class Channel:
    """AES-GCM; each sealed message is [u64 counter][ciphertext+tag].

    The counter travels with the message because over QUIC every video frame has its own stream, so messages
    can arrive out of order. Replays are refused with a sliding window of recently seen counters.
    """

    WINDOW = 4096

    def __init__(self, send_key, recv_key):
        self._tx, self._rx = AESGCM(send_key), AESGCM(recv_key)
        self._ntx = 0
        self._max, self._seen = -1, set()

    def seal(self, data):
        n, self._ntx = self._ntx, self._ntx + 1
        nonce = struct.pack(">4xQ", n)
        return nonce[4:] + self._tx.encrypt(nonce, data, None)

    def open(self, data):
        (n,) = struct.unpack_from(">Q", data)
        if n <= self._max - self.WINDOW or n in self._seen:
            raise InvalidTag  # replayed or too old
        plain = self._rx.decrypt(struct.pack(">4xQ", n), data[8:], None)  # raises InvalidTag if forged
        self._seen.add(n)
        if n > self._max:
            self._max = n
            if len(self._seen) > 2 * self.WINDOW:
                self._seen = {s for s in self._seen if s > n - self.WINDOW}
        return plain


def _mac(key, label, transcript):
    return hmac.new(key, label + transcript, hashlib.sha256).digest()


def _keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key().public_bytes(serialization.Encoding.X962,
                                                serialization.PublicFormat.UncompressedPoint)


def _session_keys(priv, peer_pub, key, transcript):
    shared = priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub))
    okm = HKDF(hashes.SHA256(), 64, salt=key, info=b"minidesk session" + transcript).derive(shared)
    return okm[:32], okm[32:]  # host->client, client->host


async def host_handshake(recv, send, key):
    """recv()/send(b): one binary message each. Raises AuthError if the peer does not hold `key`."""
    hello = await recv()
    if len(hello) != PUB + 16:
        raise AuthError("bad hello")
    cpub, nc = hello[:PUB], hello[PUB:]
    priv, hpub = _keypair()
    ns = os.urandom(16)
    t = cpub + hpub + nc + ns
    await send(hpub + ns + _mac(key, b"minidesk host", t))
    if not hmac.compare_digest(await recv(), _mac(key, b"minidesk client", t)):
        raise AuthError("bad key")
    try:
        h2c, c2h = _session_keys(priv, cpub, key, t)
    except ValueError as e:  # invalid curve point
        raise AuthError(str(e)) from None
    return Channel(send_key=h2c, recv_key=c2h)


async def client_handshake(recv, send, key):
    """Python counterpart of the browser client (used by tests)."""
    priv, cpub = _keypair()
    nc = os.urandom(16)
    await send(cpub + nc)
    r = await recv()
    hpub, ns, tag = r[:PUB], r[PUB:PUB + 16], r[PUB + 16:]
    t = cpub + hpub + nc + ns
    if not hmac.compare_digest(tag, _mac(key, b"minidesk host", t)):
        raise AuthError("host does not hold the key")
    await send(_mac(key, b"minidesk client", t))
    h2c, c2h = _session_keys(priv, hpub, key, t)
    return Channel(send_key=c2h, recv_key=h2c)
