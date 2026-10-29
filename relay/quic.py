"""UDP side of the relay. Phones connect with WebTransport (HTTP/3 over QUIC), hosts with raw QUIC (ALPN "minidesk").

One phone session <-> one host QUIC connection:
  host stream 0 (bidi)   <->  the phone's first bidi stream: framed control messages, [u32 len][sealed]
  each host uni stream    ->  a new uni stream to the phone: one video frame each
Bytes are forwarded as they arrive and stay encrypted end to end (secure.py). A frame has its own stream, so a
lost packet only delays that frame, not everything sent after it as on TCP.

Also used by host.py: the congestion controller, framing and the QUIC client configuration.
"""
import asyncio
import base64
import collections
import datetime
import hashlib
import logging
import math
import os
import secrets
import struct

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived, WebTransportStreamDataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.congestion.base import register_congestion_control
from aioquic.quic.congestion.reno import RenoCongestionControl
from aioquic.quic.events import ConnectionTerminated, ProtocolNegotiated, StreamDataReceived
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HOST_ALPN = "minidesk"
log = logging.getLogger("relay")


class SteadyCongestionControl(RenoCongestionControl):
    """Loss-tolerant window: 2 x (max delivery rate x min RTT), never cut on loss.

    Loss-based control (Reno/CUBIC, and TCP) halves its window on every loss; on a lossy long-haul link at peak
    hours that collapsed throughput to ~0.7 Mbps. Here the window only follows what the path delivers (like BBR),
    and the encoder's own rate control (stream.py: end-to-end ACK window + adaptive bitrate) avoids overload.

    Based on Reno only so that hooks newer aioquic versions add to the abstract base (1.7 added
    on_persistent_congestion; missing it made every connection fail) always have an implementation.
    """

    def __init__(self, *, max_datagram_size):
        super().__init__(max_datagram_size=max_datagram_size)
        self._mds = max_datagram_size
        self.congestion_window = 64 * max_datagram_size
        self._min_rtt, self._min_rtt_t = math.inf, 0.0
        self._acked, self._acked_t = 0, None
        self._rates = collections.deque()  # (time, bytes/s) over the last 2 s

    def on_packet_sent(self, *, packet):
        self.bytes_in_flight += packet.sent_bytes

    def on_packet_acked(self, *, now, packet):
        self.bytes_in_flight -= packet.sent_bytes
        self._acked += packet.sent_bytes
        if self._acked_t is None:
            self._acked_t = now
            return
        span = now - self._acked_t
        if span >= max(0.05, self._min_rtt if self._min_rtt != math.inf else 0.05):
            self._rates.append((now, self._acked / span))
            self._acked, self._acked_t = 0, now
            while self._rates and now - self._rates[0][0] > 2.0:
                self._rates.popleft()
            rate = max(r for _, r in self._rates)
            rtt = self._min_rtt if self._min_rtt != math.inf else 0.1
            self.congestion_window = max(64 * self._mds, int(2 * rate * rtt) + 16 * self._mds)

    def on_packets_expired(self, *, packets):
        for p in packets:
            self.bytes_in_flight -= p.sent_bytes

    def on_packets_lost(self, *, now, packets):  # retransmitted by QUIC; deliberately no window cut
        for p in packets:
            self.bytes_in_flight -= p.sent_bytes

    def on_rtt_measurement(self, *, now, rtt):
        if rtt < self._min_rtt or now - self._min_rtt_t > 10:  # windowed minimum
            self._min_rtt, self._min_rtt_t = rtt, now

    def on_persistent_congestion(self):  # everything sent over a long span was lost: start over from the floor
        self._rates.clear()
        self.congestion_window = 64 * self._mds


register_congestion_control("steady", SteadyCongestionControl)


CC = "steady"  # tests switch this to "reno" to compare


def configuration(is_client, **kw):
    return QuicConfiguration(is_client=is_client, congestion_control_algorithm=CC, idle_timeout=30,
                             max_data=16 << 20, max_stream_data=8 << 20, **kw)


def sweep(conn):
    """Help aioquic retire finished streams; works with aioquic 1.3 through 1.7.

    With a stream per video frame and steady traffic, finished streams sat behind busy ones in aioquic's send
    queue, which only discards what it walks past before a packet fills up; and aioquic 1.3 never marked our
    send-only streams finished at all. Thousands piled up and every packet walked them all (profiled: 14 M walks
    a minute, +20 ms latency and growing). Here they are marked finished and moved to the front of the queue, so
    aioquic's own discard runs on the next packet, with the stream-credit bookkeeping of whichever version it is
    (1.7 grants the peer a new stream per discarded one; removing streams by hand would starve it).
    """
    local = 0 if conn._is_client else 1
    for sid, st in conn._streams.items():
        if sid & 2 and sid & 1 == local and st.sender.is_finished:
            st.receiver.is_finished = True  # 1.3: a send-only stream's receive side never finished by itself
    queue = conn._streams_queue
    if any(st.is_finished for st in queue):
        conn._streams_queue = [st for st in queue if st.is_finished] + [st for st in queue if not st.is_finished]


class Swept(QuicConnectionProtocol):
    """Protocol base that sweeps finished streams at most every 0.5 s while events flow."""

    _swept = 0.0

    def quic_event_received(self, event):
        now = self._loop.time()
        if now - self._swept > 0.5:
            self._swept = now
            sweep(self._quic)


def keep_listening(transport):
    """Windows turns an ICMP "port unreachable" from a vanished peer into an error on the socket's next receive,
    and asyncio's proactor then stops reading that UDP socket for good: one phone going away would make the
    relay deaf to everyone. SIO_UDP_CONNRESET off keeps it listening (reproduced: 0 of 3 datagrams received
    after such an error without it, 3 of 3 with it)."""
    if os.name != "nt":
        return
    import ctypes

    ioctl = ctypes.windll.ws2_32.WSAIoctl
    ioctl.argtypes = [ctypes.c_size_t, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
                      ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p, ctypes.c_void_p]
    off, returned = ctypes.c_int(0), ctypes.c_ulong()
    ioctl(transport.get_extra_info("socket").fileno(), 0x9800000C, ctypes.byref(off), 4, None, 0,  # SIO_UDP_CONNRESET
          ctypes.byref(returned), None, None)


def frame(data):
    return struct.pack("<I", len(data)) + data


class Unframer:
    """Reassembles [u32 len][payload] messages from a byte stream."""

    def __init__(self):
        self.buf = b""

    def feed(self, data):
        self.buf += data
        out = []
        while len(self.buf) >= 4:
            (n,) = struct.unpack_from("<I", self.buf)
            if len(self.buf) < 4 + n:
                break
            out.append(self.buf[4:4 + n])
            self.buf = self.buf[4 + n:]
        return out


def make_cert():
    """Self-signed ECDSA certificate valid for 13 days: browsers pin it by hash (serverCertificateHashes),
    which Chrome only accepts for certificates valid at most 14 days."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "minidesk-relay")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=13))
            # Chrome's parser for pinned certificates rejects certificates without extensions
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("minidesk-relay")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


def cert_hash(cert):
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).digest()


class RelayProtocol(Swept):
    """One QUIC connection to the relay: a phone (HTTP/3 WebTransport) or a host (raw QUIC). Paired via `peer`."""

    def __init__(self, *args, app, **kw):
        super().__init__(*args, **kw)
        self.app, self.kind, self.peer, self.h3 = app, None, None, None
        self.session_id = None  # phone: WebTransport session (the CONNECT stream)
        self.ctl, self.ctl_backlog = None, b""  # phone: its control stream; host data that arrived before it
        self.uni = {}  # phone: host uni stream -> phone uni stream
        self.sid_buf = b""  # host: "<session id>\n" opens stream 0

    def quic_event_received(self, event):
        super().quic_event_received(event)
        if isinstance(event, ProtocolNegotiated):
            self.kind = "host" if event.alpn_protocol == HOST_ALPN else "phone"
            if self.kind == "phone":
                self.h3 = H3Connection(self._quic, enable_webtransport=True)
        elif isinstance(event, ConnectionTerminated):
            self.end_peer()
        if self.kind == "phone":
            for e in self.h3.handle_event(event):
                self.phone_event(e)
        elif self.kind == "host" and isinstance(event, StreamDataReceived):
            self.host_data(event)

    # -- phone side --
    def phone_event(self, e):
        if isinstance(e, HeadersReceived):
            h = dict(e.headers)
            path = h.get(b":path", b"").decode()
            if (h.get(b":method") == b"CONNECT" and h.get(b":protocol") == b"webtransport"
                    and path.startswith("/wt/c/") and self.session_id is None):
                self.session_id = e.stream_id
                asyncio.ensure_future(self.open_session(path[len("/wt/c/"):]))
            else:
                self.h3.send_headers(e.stream_id, [(b":status", b"404")], end_stream=True)
                self.transmit()
        elif isinstance(e, WebTransportStreamDataReceived) and e.session_id == self.session_id:
            if self.ctl is None:
                self.ctl = e.stream_id
                if self.ctl_backlog:
                    self.send_ctl(self.ctl_backlog)
                    self.ctl_backlog = b""
            if e.stream_id == self.ctl and self.peer:
                self.peer.send_ctl(e.data)
        elif isinstance(e, DataReceived) and e.stream_id == self.session_id and e.stream_ended:
            self.close()  # the browser closed the session

    async def open_session(self, host_id):
        """Wake the host over its control WebSocket, wait for its QUIC connection, then accept the session."""
        ctl = self.app["hosts"].get(host_id)
        if ctl is None:
            return self.reject(b"404")  # host offline
        sid = secrets.token_urlsafe(18)
        fut = self.app["pending"][sid] = asyncio.get_running_loop().create_future()
        try:
            await ctl.send_str("q:" + sid)
            host = await asyncio.wait_for(fut, 10)
        except (asyncio.TimeoutError, ConnectionError):
            return self.reject(b"504")
        finally:
            self.app["pending"].pop(sid, None)
        self.peer, host.peer = host, self
        self.h3.send_headers(self.session_id, [(b":status", b"200"), (b"sec-webtransport-http3-draft", b"draft02")])
        self.transmit()

    def reject(self, status):
        self.h3.send_headers(self.session_id, [(b":status", status)], end_stream=True)
        self.transmit()

    def send_ctl(self, data):
        if self.kind == "host":
            self._quic.send_stream_data(0, data)
        elif self.ctl is None:
            self.ctl_backlog += data
            return
        else:
            self._quic.send_stream_data(self.ctl, data)
        self.transmit()

    def forward_frame(self, host_stream, data, end):
        sid = self.uni.get(host_stream)
        if sid is None:
            sid = self.uni[host_stream] = self.h3.create_webtransport_stream(self.session_id, is_unidirectional=True)
        self._quic.send_stream_data(sid, data, end_stream=end)
        if end:
            del self.uni[host_stream]
        self.transmit()

    # -- host side --
    def host_data(self, e):
        if e.stream_id != 0:  # a unidirectional stream: one video frame
            if self.peer:
                self.peer.forward_frame(e.stream_id, e.data, e.end_stream)
        elif self.peer:
            self.peer.send_ctl(e.data)
        else:  # first bytes: the session id the relay handed out over the host's control WebSocket
            self.sid_buf += e.data
            if b"\n" in self.sid_buf:
                sid, rest = self.sid_buf.split(b"\n", 1)
                fut = self.app["pending"].get(sid.decode(errors="replace"))
                if fut is None or fut.done():
                    return self.close()
                fut.set_result(self)
                if rest:
                    self.peer.send_ctl(rest)

    # -- teardown --
    def end_peer(self):
        p, self.peer = self.peer, None
        if p:
            p.peer = None
            p.close()

    def close(self):
        self.end_peer()
        self._quic.close()
        self.transmit()


async def start(app, host, port):
    """Serve QUIC on UDP `port` and return the server (close() stops it). Rotates the certificate weekly;
    app["wt"] tells clients where and what to pin."""
    cfg = configuration(False, alpn_protocols=H3_ALPN + [HOST_ALPN], max_datagram_frame_size=65536)
    hashes_ = []

    def rotate():
        cfg.certificate, cfg.private_key = make_cert()  # new connections use it; existing ones keep theirs
        hashes_.insert(0, base64.b64encode(cert_hash(cfg.certificate)).decode())
        del hashes_[2:]  # current + previous
        app["wt"] = {"port": port, "hashes": list(hashes_)}

    rotate()
    server = await serve(host, port, configuration=cfg,
                         create_protocol=lambda *a, **kw: RelayProtocol(*a, app=app, **kw))
    keep_listening(server._transport)
    log.info("UDP (QUIC/WebTransport) on port %d", port)

    async def rotate_weekly():
        while True:
            await asyncio.sleep(7 * 86400)
            rotate()

    asyncio.ensure_future(rotate_weekly())
    return server
