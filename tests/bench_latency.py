"""Repeatable pipeline benchmarks without windows, desktop input, or network configuration changes.

python tests/bench_latency.py --source output/performance/baseline --output output/performance/before.json
python tests/bench_latency.py --output output/performance/after.json

Pacing/idle numbers use a virtual clock with fixed capture/encode costs; encoding numbers use real PyAV.
"""
import argparse
import heapq
import importlib.util
import json
import os
import random
from pathlib import Path
import statistics
import sys
import threading
import time
from types import ModuleType, SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def load_stream(directory):
    capture = ModuleType("capture")
    capture.FRAME, capture.TIMEOUT, capture.POINTER, capture.LOST = 1, 0, 2, -1
    inputs = ModuleType("winput")
    inputs.refresh = lambda: None
    sys.modules["capture"], sys.modules["winput"] = capture, inputs
    spec = importlib.util.spec_from_file_location("stream_benchmark", directory / "stream.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pacing(module, static=False, pointer_only=False):
    clock = SimpleNamespace(now=0.0)
    capture_ms, encode_ms = 3, 6
    request_at = 0.130
    output, response = [], []
    requested = False

    class Capture:
        width, height = 640, 360
        pointer_x = pointer_y = pointer_visible = 0

        def grab(self, timeout, out, pitch):
            nonlocal requested
            if not static or not output:
                clock.now += capture_ms / 1000
                result = module.capture.FRAME
            else:
                clock.now += timeout / 1000
                result = module.capture.POINTER if pointer_only else module.capture.TIMEOUT
            if static and clock.now >= request_at and not requested:
                requested = True
                streamer.need_key = True
            if len(output) >= 120 or static and clock.now > 0.3:
                streamer.running = False
            return result

    class Pipeline(module.Streamer):
        def _open(self, w, h):
            return SimpleNamespace(codec=SimpleNamespace(name="virtual"))

        def _adapt(self, encoder):
            return encoder

        def _queueing(self, now):
            return False

        def _encode(self, encoder, frame):
            clock.now += encode_ms / 1000
            if requested and self.need_key and not response:
                response.append((clock.now - request_at) * 1000)
            self.need_key = False
            output.append(clock.now)

    original_time, original_capture = module.time, getattr(module.capture, "Capturer", None)
    module.time = SimpleNamespace(perf_counter=lambda: clock.now, sleep=lambda delay: setattr(clock, "now", clock.now + delay))
    module.capture.Capturer = Capture
    streamer = Pipeline(lambda data: None, 8000, 60)
    try:
        streamer._run_once()
    finally:
        module.time = original_time
        module.capture.Capturer = original_capture
    intervals = [b - a for a, b in zip(output, output[1:])]
    return {"model": "virtual clock; capture 3 ms + encode 6 ms, target 60 fps",
            "fps": round(1 / statistics.mean(intervals), 2) if not static else None,
            "encoded_before_100ms": sum(value < .1 for value in output) if static else None,
            "idle_keyframe_response_ms": round(response[0], 2) if response else None}


def encoder(module):
    import numpy as np

    results = []
    for width, height in [(2560, 1440), (1920, 1080), (1280, 720)]:
        frame = module.new_frame(width, height)
        pixels = np.random.default_rng(42).integers(0, 256, frame.planes[0].buffer_size, dtype=np.uint8)
        frame.planes[0].update(pixels)
        codec = module.make_encoder(width, height, 60, 8000)
        times, sizes = [], []
        for seq in range(45):
            frame.pts = seq * 17
            frame.pict_type = module.PictureType.I if seq == 0 else module.PictureType.NONE
            started = time.perf_counter()
            packets = codec.encode(frame if codec.pix_fmt == "bgra" else frame.reformat(format=codec.pix_fmt))
            elapsed = (time.perf_counter() - started) * 1000
            if seq >= 5:
                times.append(elapsed)
                sizes.extend(packet.size for packet in packets)
        results.append({"resolution": f"{width}x{height}", "codec": codec.name,
                        "encode_p50_ms": round(statistics.median(times), 2),
                        "encode_p95_ms": round(sorted(times)[int(len(times) * .95)], 2),
                        "packet_mean_bytes": round(statistics.mean(sizes))})
    return results


def live_pacing(module, duration):
    """Real wall-clock pacing and NVENC, with a fixed synthetic capture workload; no screen access."""
    samples = []

    class Capture:
        width, height = 2560, 1440
        pointer_x = pointer_y = pointer_visible = 0
        pixels = bytes([64, 128, 192, 255]) * (width * height)

        def grab(self, timeout, out, pitch):
            time.sleep(0.003)
            out.update(self.pixels)
            return module.capture.FRAME

    original = module.capture.Capturer
    module.capture.Capturer = Capture

    def emit(data):
        if data[0] == module.VIDEO:
            import struct
            samples.append(time.perf_counter())
            streamer.ack(struct.unpack_from("<I", data, 2)[0])

    if os.name == "nt":
        import ctypes
        ctypes.windll.winmm.timeBeginPeriod(1)
    streamer = module.Streamer(emit, 8000, 60)
    try:
        streamer.start()
        time.sleep(.75)
        started, cpu = time.perf_counter(), time.process_time()
        time.sleep(duration)
        ended, cpu = time.perf_counter(), time.process_time() - cpu
    finally:
        streamer.stop()
        streamer.join(2)
        module.capture.Capturer = original
        if os.name == "nt":
            ctypes.windll.winmm.timeEndPeriod(1)
    frames = [sample for sample in samples if started <= sample < ended]
    intervals = [(b - a) * 1000 for a, b in zip(frames, frames[1:])]
    return {"model": "real NVENC 2560x1440; synthetic 3 ms capture wait + BGRA copy; instant ACK; no desktop access",
            "frames": len(frames), "fps": round(len(frames) / (ended - started), 2),
            "frame_interval_p50_ms": round(statistics.median(intervals), 2),
            "frame_interval_p95_ms": round(sorted(intervals)[int(len(intervals) * .95)], 2),
            "cpu_ms_per_frame": round(cpu * 1000 / len(frames), 2)}


def network_run(module, cellular=False):
    """Real encoder/flow controller over a serialized, bandwidth-limited simulated link."""
    phases = [(12, (2e6, 10e6))] if cellular else [(4, 3e6), (4, 1.5e6), (4, 3e6)]
    cv, pending, records = threading.Condition(), [], []
    rand, capacities = random.Random(1), random.Random(2)
    running, free_at, bandwidth = True, 0.0, 3e6

    class Capture:
        width, height = 2560, 1440
        pointer_x = pointer_y = pointer_visible = 0
        pixels = bytes([64, 128, 192, 255]) * (width * height)

        def grab(self, timeout, out, pitch):
            time.sleep(.003)
            out.update(self.pixels)
            return module.capture.FRAME

    def emit(data):
        nonlocal free_at
        if data[0] != module.VIDEO:
            return
        import struct
        now = time.perf_counter()
        with cv:
            free_at = max(free_at, now) + len(data) * 8 / bandwidth
            delivered = free_at + (.33 if cellular else .2) + rand.expovariate(1 / (.03 if cellular else .015))
            records.append((now, delivered - now, len(data)))
            heapq.heappush(pending, (delivered, struct.unpack_from("<I", data, 2)[0]))
            cv.notify()

    def acknowledge():
        while running:
            with cv:
                if not pending or pending[0][0] > time.perf_counter():
                    cv.wait(max(.001, pending[0][0] - time.perf_counter()) if pending else .1)
                    continue
                _, seq = heapq.heappop(pending)
            streamer.ack(seq)

    original = module.capture.Capturer
    module.capture.Capturer = Capture
    if os.name == "nt":
        import ctypes
        ctypes.windll.winmm.timeBeginPeriod(1)
    streamer = module.Streamer(emit, 8000, 60)
    worker = threading.Thread(target=acknowledge, daemon=True)
    rates = []
    try:
        started = time.perf_counter()
        worker.start()
        streamer.start()
        boundary = started
        for seconds, limit in phases:
            boundary += seconds
            next_change = 0
            if not isinstance(limit, tuple):
                bandwidth = limit
            while time.perf_counter() < boundary:
                if isinstance(limit, tuple) and time.perf_counter() >= next_change:
                    bandwidth = capacities.uniform(*limit)
                    next_change = time.perf_counter() + .25
                rates.append((time.perf_counter() - started, streamer.kbps))
                time.sleep(.05)
    finally:
        streamer.stop()
        streamer.join(2)
        running = False
        with cv:
            cv.notify()
        worker.join(2)
        module.capture.Capturer = original
        if os.name == "nt":
            ctypes.windll.winmm.timeEndPeriod(1)
    result, at = [], 0
    for seconds, bits in phases:
        frames = [(rtt * 1000, size) for sent, rtt, size in records if at + 1 <= sent - started < at + seconds]
        rtts = sorted(rtt for rtt, _ in frames)
        result.append({"link_mbps": [value / 1e6 for value in bits] if isinstance(bits, tuple) else bits / 1e6,
                       "fps": round(len(frames) / (seconds - 1), 1),
                       "ack_p50_ms": round(statistics.median(rtts)), "ack_p95_ms": round(rtts[int(len(rtts) * .95)]),
                       "bitrate_kbps": round(statistics.mean(rate for stamp, rate in rates if at + 1 <= stamp < at + seconds))})
        at += seconds
    model = "330 ms RTT + jitter, 2-10 Mbps changing every 0.25 s" if cellular else "200 ms RTT + jitter, 3 -> 1.5 -> 3 Mbps"
    return {"model": "real NVENC, generated uniform screen; simulated " + model,
            "phases": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--skip-encoder", action="store_true")
    parser.add_argument("--live", action="store_true", help="real-clock NVENC pacing with generated frames")
    parser.add_argument("--duration", type=float, default=4)
    parser.add_argument("--network", action="store_true", help="12-second bandwidth drop/recovery benchmark")
    parser.add_argument("--network-profile", choices=["relay", "cellular"], default="relay")
    args = parser.parse_args()
    module = load_stream(args.source.resolve())
    result = {"source": str(args.source), "pacing": pacing(module), "idle": pacing(module, static=True)}
    if not args.skip_encoder:
        result["encoding"] = encoder(module)
    if args.live:
        result["live_pacing"] = live_pacing(module, args.duration)
    if args.network:
        result["network"] = network_run(module, args.network_profile == "cellular")
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
