"""Capture -> encode pipeline in one thread.

A frame is only grabbed when the screen changed AND the network is not queueing: the bytes the client has not
acknowledged yet must fit in what the path delivers within the base round trip plus a small allowance. Dropping
happens before the encoder (dropping encoded P-frames would corrupt the picture), and this end-to-end gate bounds
the queueing delay itself, whatever frame rate the path can carry and however much the relay or network buffers.
"""
import collections
import logging
import math
import struct
import threading
import time
from fractions import Fraction

import av
from av.video.frame import PictureType

import capture
import winput
from protocol import CURSOR, SCREEN, VIDEO

log = logging.getLogger("stream")
MIN_KBPS = 800
MAX_IN_FLIGHT = 30  # frames; a safety bound, the byte budget in _queueing is what normally applies

# Low-latency H.264: no B-frames, no lookahead, IDR only on demand.
ENCODERS = [
    ("h264_nvenc", "bgra", {"preset": "p1", "tune": "ull", "zerolatency": "1", "delay": "0",
                            "rc": "cbr", "forced-idr": "1", "profile": "high"}),
    ("libx264", "yuv420p", {"preset": "ultrafast", "tune": "zerolatency", "profile": "high"}),
]


def make_encoder(w, h, fps, kbps):
    errors = []
    for name, pix_fmt, opts in ENCODERS:
        try:
            c = av.CodecContext.create(name, "w")
            c.width, c.height, c.pix_fmt = w, h, pix_fmt
            c.time_base = Fraction(1, 1000)
            c.framerate = fps
            c.bit_rate = kbps * 1000
            c.gop_size = 1 << 30
            c.max_b_frames = 0
            # VBV of ~3 frames caps frame-size spikes, which is what turns into latency on the wire.
            c.options = dict(opts, bufsize=str(kbps * 1000 * 3 // fps))
            c.open()
            return c
        except Exception as e:  # encoder not available on this machine
            errors.append(f"{name}: {e}")
    raise RuntimeError("no H.264 encoder: " + "; ".join(errors))


def new_frame(w, h):
    return av.VideoFrame(w, h, "bgra")


class Streamer(threading.Thread):
    """emit(bytes) receives plaintext protocol messages and must be thread-safe."""

    def __init__(self, emit, kbps, fps, after=None):
        super().__init__(daemon=True, name="streamer")
        self.emit = emit
        self.after = after  # previous streamer: only one desktop duplication per output at a time
        self.cap_kbps = self.kbps = kbps  # quality cap from the client; kbps adapts below it
        self.fps = fps
        self.running = True
        self.need_key = True
        self.need_reconfig = False
        self._target = 0
        self._cv = threading.Condition()
        self._seq = self._acked = 0
        self._sent_at = {}  # seq -> (send time, bytes), oldest first
        self._unacked = 0  # bytes in _sent_at
        self._rtt_buckets = collections.deque(maxlen=10)  # windowed min RTT over ~10 s
        self._rtt_t, self._rtt_min, self._base_rtt = 0.0, math.inf, math.inf
        self._pts = self._enc_kbps = 0
        # evidence gathered between adaptation steps: time the gate held frames back, round trips, bytes acked
        self._blocked, self._rtt_lo, self._rtt_sum = 0.0, math.inf, 0.0
        self._rtt_n = self._acked_bytes = 0
        self._adapt_t = 0.0
        self._spread = 0.0  # how far round trips average above the fastest one (jitter, loss), smoothed
        self._rate = 0  # kbps delivered in the last step
        self._capacity = 3000  # kbps the path carries, measured when it was the limit; a guess until then
        self._ceiling = math.inf  # bitrate at the last congestion: approach it slowly
        self._calm = 0  # steps since the last congestion
        self._st_frames = self._st_bytes = self._st_rtt_n = 0  # for take_stats()
        self._st_rtt_sum = 0.0

    def configure(self, kbps, fps):
        self.cap_kbps = self._target = kbps
        if fps != self.fps:
            self.fps = fps
            self.need_reconfig = True

    def stop(self):
        self.running = False
        with self._cv:
            self._cv.notify()

    def ack(self, seq):
        now = time.perf_counter()
        with self._cv:
            sent = self._sent_at.pop(seq, None)
            self._acked = max(self._acked, seq)
            if sent is not None:
                self._unacked -= sent[1]
                self._acked_bytes += sent[1]
                self._rtt_sample(now - sent[0], now)
            self._cv.notify()

    def _rtt_sample(self, rtt, now):
        if now - self._rtt_t > 1.0:
            self._rtt_buckets.append(self._rtt_min)
            self._rtt_t, self._rtt_min = now, rtt
        else:
            self._rtt_min = min(self._rtt_min, rtt)
        self._base_rtt = min(self._rtt_min, *self._rtt_buckets)
        self._rtt_lo = min(self._rtt_lo, rtt)
        self._rtt_sum += rtt
        self._rtt_n += 1
        self._st_rtt_sum += rtt
        self._st_rtt_n += 1

    def allowance(self):
        """Time in flight tolerated above the base round trip: how far round trips average above the fastest
        one. That is jitter, larger frames and retransmissions, not queueing (a queue delays the fastest frame
        too). Capped at half the base, 150 ms at least, so that our own queue swinging on 4G cannot widen it."""
        return min(max(0.05, self._spread), max(0.15, 0.5 * self._base_rtt))

    def _queueing(self, now):
        """True while a new frame would wait behind others. By Little's law, in-flight bytes / delivery rate is
        the time a frame spends in flight, so in-flight bytes are held to (base RTT + allowance) worth of the
        measured rate: 1.1x what got through in the last step (the margin lets it grow), or the path's capacity
        (so busy content after a quiet spell is not held to what the quiet spell sent). ARCHITECTURE.md has the
        designs this replaced and why they queued."""
        if self._base_rtt == math.inf:  # nothing acknowledged yet: a keyframe and one more
            return self._seq - self._acked >= 2
        if self._seq - self._acked >= MAX_IN_FLIGHT:
            return True
        if len(self._sent_at) < 2:  # keep loss recovery going: QUIC spots a lost packet by the ones after it
            return False
        while self._sent_at:  # later frames got through long ago: this one never will
            seq, (t, n) = next(iter(self._sent_at.items()))
            if seq > self._acked or now - t < 2.0:
                break
            del self._sent_at[seq]
            self._unacked -= n
        rate = max(1.1 * self._rate, self._capacity)
        return self._unacked > rate * 125 * (self._base_rtt + self.allowance())

    def take_stats(self):
        """(frames, bytes, mean RTT s, base RTT s, kbps, queueing allowance s) since the previous call."""
        with self._cv:
            mean = self._st_rtt_sum / self._st_rtt_n if self._st_rtt_n else 0.0
            allowance = self.allowance() if self._base_rtt != math.inf else 0.0
            st = (self._st_frames, self._st_bytes, mean, self._base_rtt, self.kbps, allowance)
            self._st_frames = self._st_bytes = self._st_rtt_n = 0
            self._st_rtt_sum = 0.0
        return st

    def _open(self, w, h):
        self._enc_kbps = self.kbps
        self.need_key = True
        return make_encoder(w, h, self.fps, self.kbps)

    def _set_kbps(self, enc, kbps):
        self.kbps = kbps
        # NVENC/x264 take a new bitrate live (no keyframe); the VBV is sized at open, so rebuild when far off.
        if self._enc_kbps / 2 <= kbps <= self._enc_kbps * 2:
            enc.bit_rate = kbps * 1000
        else:
            self.need_reconfig = True
        return enc

    def _adapt(self, enc):
        """Every 0.5 s. Congestion is a standing queue (even the fastest round trip of the step rose above the
        base, while the gate held frames back, or by a lot; loss and jitter only delay single frames) or the
        average round trip doubling (on 4G some frames slip through fast while the rest queue). Then drop to
        ~85% of what got delivered, by 40% at most (light content sends little anyway); an encoder that cannot
        go lower is left to the gate. Otherwise, after 1 s, climb 25% per step, only 5% within 0.8-1.2x the rate
        that last congested, and never past 1.5x the path's capacity: probing straight past those sawed."""
        now = time.perf_counter()
        period = now - self._adapt_t
        if period < 0.5:
            return enc
        self._adapt_t = now
        with self._cv:
            blocked, n, lo, rtt_sum, base = self._blocked, self._rtt_n, self._rtt_lo, self._rtt_sum, self._base_rtt
            delivered = self._rate = self._acked_bytes * 8 / period / 1000
            self._blocked, self._rtt_lo, self._rtt_sum = 0.0, math.inf, 0.0
            self._rtt_n = self._acked_bytes = 0
        if n < 3:  # (nearly) static screen: too few round trips to tell
            return enc
        mean = rtt_sum / n
        self._spread += 0.2 * (mean - lo - self._spread)
        queueing, allowance = lo - base, self.allowance()  # a standing queue delays even the fastest frame
        if (queueing > allowance / 2 and blocked > 0.2 * period or queueing > allowance
                or mean - base > max(base, 0.15)):
            self._capacity += 0.3 * (delivered - self._capacity)  # the path's limit (smoothed: ACKs come in bursts)
            self._calm = 0
            self._ceiling = self.kbps
            kbps = max(MIN_KBPS, min(self.kbps, int(max(delivered, 0.7 * self.kbps) * 0.85)))
        else:  # holding back without a queue is the gate's caution (loss, jitter): no measure of the path
            self._capacity = max(self._capacity, delivered)
            self._calm += 1
            if self._calm < 2:
                return enc
            fast = not 0.8 * self._ceiling <= self.kbps <= 1.2 * self._ceiling
            kbps = int(self.kbps * 1.25) + 200 if fast else int(self.kbps * 1.05) + 50
            kbps = min(self.cap_kbps, kbps, max(self.kbps, int(1.5 * self._capacity)))
        return self._set_kbps(enc, kbps) if kbps != self.kbps else enc

    def run(self):
        if self.after:
            self.after.join(2)
        last_error = None
        while self.running:
            try:
                self._run_once()
                last_error = None
            except Exception as e:  # e.g. secure desktop (UAC/lock screen) denies duplication
                if str(e) != last_error:  # once per cause, not every 0.5 s while the screen is locked
                    log.warning("暂时无法采集屏幕（锁屏/UAC/切换桌面时正常）: %s", e)
                    last_error = str(e)
                time.sleep(0.5)

    def _run_once(self):
        cap = capture.Capturer()
        w, h = cap.width, cap.height
        enc = self._open(w, h)
        log.info("streaming %dx%d with %s", w, h, enc.codec.name)
        winput.refresh()
        self.emit(struct.pack("<BHH", SCREEN, w, h))
        # Two buffers take turns (the encoder copies its input before encode() returns): allocating a fresh
        # 15 MB frame each time cost ~1000 page faults per frame.
        frame, last, cursor = new_frame(w, h), new_frame(w, h), None
        have_last, refine, next_t = False, 0, 0.0
        while self.running:
            if self._target:
                kbps, self._target = self._target, 0
                enc = self._set_kbps(enc, kbps)
            enc = self._adapt(enc)
            if self.need_reconfig:
                self.need_reconfig = False
                enc = self._open(w, h)
            with self._cv:
                if self._queueing(time.perf_counter()):
                    t0 = time.perf_counter()
                    while self.running and self._queueing(time.perf_counter()):
                        self._cv.wait(0.25)  # an ACK notifies
                    self._blocked += time.perf_counter() - t0
            delay = next_t - time.perf_counter()
            if delay > 0:
                time.sleep(delay)

            r = cap.grab(100, frame.planes[0], frame.planes[0].line_size)
            if r == capture.LOST:  # resolution change, desktop switch...
                return
            c = (cap.pointer_x, cap.pointer_y, cap.pointer_visible)
            if c != cursor:
                cursor = c
                self.emit(struct.pack("<Bhhb", CURSOR, *c))
            if r == capture.FRAME:
                last, frame, have_last = frame, last, True
                refine = 2
                next_t = time.perf_counter() + 1 / self.fps
                self._encode(enc, last)
            elif r == capture.TIMEOUT and have_last and (self.need_key or refine):
                # Static screen: serve keyframe requests, and re-encode twice so text sharpens.
                if not self.need_key:
                    refine -= 1
                self._encode(enc, last)

    def _encode(self, enc, frame):
        if enc.pix_fmt != "bgra":
            frame = frame.reformat(format=enc.pix_fmt)
        self._pts = max(self._pts + 1, int(time.perf_counter() * 1000))
        frame.pts = self._pts
        frame.pict_type = PictureType.I if self.need_key else PictureType.NONE
        self.need_key = False
        for p in enc.encode(frame):
            with self._cv:
                self._seq += 1
                seq = self._seq
                data = struct.pack("<BBI", VIDEO, p.is_keyframe, seq) + bytes(p)
                self._sent_at[seq] = (time.perf_counter(), len(data))
                self._unacked += len(data)
                self._st_frames += 1
                self._st_bytes += len(data)
            self.emit(data)
