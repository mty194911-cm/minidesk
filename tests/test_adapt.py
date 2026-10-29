"""Adaptive bitrate and queueing against a simulated link, with real capture/encode: python tests/test_adapt.py

An evening relay path (200 ms round trip, jitter, 3 Mbps dipping to 1.5 Mbps) must keep frames from queueing
and the bitrate from sawing; a fast link afterwards must let the bitrate climb back to the cap. A 4G-like path
(330 ms, capacity jumping between 2 and 10 Mbps every 0.25 s) must not let the queue swing out of bounds.
"""
import heapq
import os
import random
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import winput  # noqa: E402
from protocol import VIDEO  # noqa: E402
from stream import Streamer  # noqa: E402

BUSY = r"""
import random, time, tkinter as tk
r = tk.Tk(); r.geometry('1400x900+50+50'); r.attributes('-topmost', True)
c = tk.Canvas(r, bg='black', highlightthickness=0); c.pack(fill='both', expand=True); t0 = time.time()
def step():
    c.delete('all')
    for _ in range(300):
        x, y = random.randrange(1400), random.randrange(900)
        c.create_rectangle(x, y, x + 60, y + 40, fill='#%06x' % random.randrange(1 << 24), outline='')
    r.after(15, step) if time.time() - t0 < 60 else r.destroy()
step(); r.mainloop()
"""

# (seconds, link bit/s, or a range it jumps around in every 0.25 s)
PHASES = [(8, 3e6), (6, 1.5e6), (6, 3e6), (8, 50e6)]
CELL = [(14, (2e6, 10e6))]
SETTLE = 2  # seconds at the start of a phase left out of its numbers


class Link:
    """Sends frames one after another at `bw` bit/s, then delivers the ACK after `rtt` seconds plus jitter."""

    def __init__(self, bw, rtt=0.04, jitter=0.0):
        self.bw, self.rtt, self.jitter, self.free_at = bw, rtt, jitter, 0.0
        self.rand = random.Random(1)
        self.acks, self.cv, self.streamer = [], threading.Condition(), None
        self.frames = []  # (send time, round trip, bytes)
        threading.Thread(target=self._run, daemon=True).start()

    def emit(self, data):
        if data[0] != VIDEO:
            return
        now = time.perf_counter()
        with self.cv:
            self.free_at = max(now, self.free_at) + len(data) * 8 / self.bw
            extra = self.rand.expovariate(1 / self.jitter) if self.jitter else 0.0
            if self.jitter and self.rand.random() < 0.03:  # the odd spike of a mobile + international path
                extra += 0.12
            at = self.free_at + self.rtt + extra
            self.frames.append((now, at - now, len(data)))
            heapq.heappush(self.acks, (at, struct.unpack_from("<I", data, 2)[0]))
            self.cv.notify()

    def _run(self):
        while True:
            with self.cv:
                while not self.acks or self.acks[0][0] > time.perf_counter():
                    self.cv.wait(max(0.001, self.acks[0][0] - time.perf_counter()) if self.acks else 0.1)
                _, seq = heapq.heappop(self.acks)
            self.streamer.ack(seq)


def simulate(cls=Streamer, phases=PHASES, rtt=0.2, jitter=0.015):
    """Runs `phases`; per phase returns (link, fps, sent Mbps, round trip p50 ms, p95 ms, bitrate min, max kbps)."""
    link = Link(bw=3e6, rtt=rtt, jitter=jitter)
    rand = random.Random(2)
    s = link.streamer = cls(link.emit, kbps=8000, fps=60)
    s.start()
    t0, rates, end = time.perf_counter(), [], 0
    for span, bw in phases:
        end += span
        while (t := time.perf_counter() - t0) < end:
            link.bw = rand.uniform(*bw) if isinstance(bw, tuple) else bw
            rates.append((t, s.kbps))
            time.sleep(0.25)
    s.stop()
    s.join(2)  # one desktop duplication at a time
    out, start = [], 0
    for span, bw in phases:
        lo, hi = start + SETTLE, start + span
        sent = [(r, n) for at, r, n in link.frames if lo <= at - t0 < hi]
        rtts = sorted(r for r, n in sent)
        kbps = [k for t, k in rates if lo <= t < hi]
        name = "-".join(f"{b / 1e6:g}" for b in bw) if isinstance(bw, tuple) else f"{bw / 1e6:g}"
        out.append((name, len(sent) / (hi - lo), sum(n for r, n in sent) * 8 / (hi - lo) / 1e6,
                    rtts[len(rtts) // 2] * 1000, rtts[int(len(rtts) * .95)] * 1000, min(kbps), max(kbps)))
        start += span
    return out


def report(name, phases):
    print(name)
    for bw, fps, mbps, p50, p95, lo, hi in phases:
        print(f"  {bw:>4} Mbps link: {fps:3.0f} fps, {mbps:4.1f} Mbps, "
              f"round trip p50 {p50:4.0f} ms / p95 {p95:4.0f} ms, bitrate {lo}-{hi} kbps")


def main():
    winput.init()
    busy = subprocess.Popen([sys.executable, "-c", BUSY])
    time.sleep(1)
    try:
        phases = simulate()
        cell = simulate(phases=CELL, rtt=0.33, jitter=0.03)
    finally:
        busy.kill()
    report("200 ms relay path, busy screen:", phases)
    report("330 ms 4G-like path, busy screen:", cell)
    for bw, _, _, _, p95, _, _ in phases[:3]:
        assert p95 < 500, f"frames queue on a {bw} Mbps link: p95 round trip {p95:.0f} ms"
    lo, hi = phases[1][5:]  # a steady link: the others start with a climb back
    assert hi < 1.5 * lo, f"bitrate saws on a 1.5 Mbps link: {lo}-{hi} kbps"
    assert hi <= 2000, "did not back off on a 1.5 Mbps link"
    assert phases[3][6] >= 6000, "did not recover on a fast link"
    assert cell[0][4] < 800, f"frames queue on a 4G-like path: p95 round trip {cell[0][4]:.0f} ms"
    print("ALL OK")


if __name__ == "__main__":
    main()
