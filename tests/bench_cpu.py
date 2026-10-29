"""Host CPU cost of streaming (capture + encode, network replaced by instant ACKs): python tests/bench_cpu.py"""
import os
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import winput  # noqa: E402
from protocol import VIDEO  # noqa: E402
from stream import Streamer  # noqa: E402

# full-window motion at ~60 fps: a moving gradient bar over a 1600x1000 window
ANIM = r"""
import tkinter as tk, time
r = tk.Tk(); r.geometry('1600x1000+40+40'); r.attributes('-topmost', True)
c = tk.Canvas(r, bg='white', highlightthickness=0); c.pack(fill='both', expand=True)
bars = [c.create_rectangle(0, i * 50, 200, i * 50 + 50, fill='#%02x60c0' % (i * 12), outline='') for i in range(20)]
t0 = time.time()
def step():
    t = time.time() - t0
    for i, b in enumerate(bars):
        x = (t * 600 + i * 70) % 1600
        c.coords(b, x, i * 50, x + 200, i * 50 + 50)
    r.after(16, step) if t < 11 else r.destroy()
step(); r.mainloop()
"""


def main():
    winput.init()
    anim = subprocess.Popen([sys.executable, "-c", ANIM])
    time.sleep(1.5)
    sent = [0, 0]

    def emit(data):  # stand-in for the network: acknowledge every frame at once
        if data[0] == VIDEO:
            sent[0] += 1
            sent[1] += len(data)
            s.ack(struct.unpack_from("<I", data, 2)[0])

    s = Streamer(emit, kbps=8000, fps=60)
    s.start()
    time.sleep(1.5)  # skip encoder start-up
    f0, b0, c0, t0 = sent[0], sent[1], time.process_time(), time.perf_counter()
    time.sleep(6)
    cpu, wall = time.process_time() - c0, time.perf_counter() - t0
    frames = sent[0] - f0
    s.stop()
    anim.wait()
    print(f"{frames / wall:.0f} fps, {(sent[1] - b0) * 8 / wall / 1e6:.1f} Mbps, "
          f"host CPU {cpu / wall * 100:.0f}% of one core ({cpu / max(frames, 1) * 1000:.2f} ms per frame)")


if __name__ == "__main__":
    main()
