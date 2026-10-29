"""Benchmark capture -> NVENC on the real desktop. Run from minidesk/: python tests/bench_pipeline.py"""
import os
import statistics
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import av  # noqa: E402
import capture  # noqa: E402
import winput  # noqa: E402
from stream import make_encoder, new_frame  # noqa: E402

ANIM = r"""
import tkinter as tk, time
r = tk.Tk(); r.geometry('600x400+100+100'); r.attributes('-topmost', True)
c = tk.Canvas(r, bg='white'); c.pack(fill='both', expand=True)
b = c.create_rectangle(0, 0, 80, 80, fill='red'); t0 = time.time()
def step():
    x = (time.time() - t0) * 400 % 520
    c.coords(b, x, 150, x + 80, 230); r.after(4, step) if time.time() - t0 < 6 else r.destroy()
step(); r.mainloop()
"""


def nal_types(data):
    out, i = [], 0
    while (i := data.find(b"\x00\x00\x01", i)) != -1:
        i += 3
        out.append(data[i] & 0x1F)
    return out


def main():
    winput.init()
    cap = capture.Capturer()
    w, h = cap.width, cap.height
    print(f"screen {w}x{h}")
    enc = make_encoder(w, h, fps=60, kbps=8000)
    print(f"encoder {enc.codec.name}")

    anim = subprocess.Popen([sys.executable, "-c", ANIM])
    time.sleep(0.8)
    grab_ms, enc_ms, sizes, frames = [], [], [], 0
    t_end = time.perf_counter() + 4
    frame = new_frame(w, h)
    first = True
    while time.perf_counter() < t_end:
        t0 = time.perf_counter()
        r = cap.grab(100, frame.planes[0], frame.planes[0].line_size)
        t1 = time.perf_counter()
        if r != capture.FRAME:
            continue
        frame.pts = int(t1 * 1000)
        if first:
            frame.pict_type = av.video.frame.PictureType.I
        pkts = enc.encode(frame)
        t2 = time.perf_counter()
        frame = new_frame(w, h)
        for p in pkts:
            data = bytes(p)
            if first:
                print("first packet NAL types:", nal_types(data)[:6])
                sps = data[data.find(b"\x00\x00\x01\x67") + 4:][:3]
                print(f"SPS profile_idc={sps[0]} constraints=0x{sps[1]:02x} level_idc={sps[2]}")
                first = False
            sizes.append(len(data))
        grab_ms.append((t1 - t0) * 1000)
        enc_ms.append((t2 - t1) * 1000)
        frames += 1
    anim.wait()

    print(f"frames {frames} in 4s = {frames / 4:.0f} fps (display-driven)")
    print(f"grab+copy wait: median {statistics.median(grab_ms):.2f} ms")
    p95 = sorted(enc_ms)[int(len(enc_ms) * .95)]
    print(f"encode:         median {statistics.median(enc_ms):.2f} ms, p95 {p95:.2f} ms")
    print(f"packet size:    median {statistics.median(sizes) / 1024:.1f} KB, max {max(sizes) / 1024:.1f} KB")

    # pure copy cost: time the memcpy part by grabbing with 0 timeout repeatedly is display-bound, so time a raw copy
    import numpy as np
    src = np.random.randint(0, 255, h * w * 4, dtype=np.uint8)
    dst = np.empty_like(src)
    t0 = time.perf_counter()
    for _ in range(50):
        np.copyto(dst, src)
    print(f"reference memcpy {w}x{h} BGRA: {(time.perf_counter() - t0) / 50 * 1000:.2f} ms")


if __name__ == "__main__":
    main()
