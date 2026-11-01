import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace

import pytest

from bench_latency import load_stream, pacing


def test_invented_and_duplicate_acks_do_not_open_flow_control_window(monkeypatch):
    monkeypatch.setitem(sys.modules, "capture", ModuleType("capture"))
    monkeypatch.setitem(sys.modules, "winput", ModuleType("winput"))
    spec = importlib.util.spec_from_file_location("stream_under_test", Path(__file__).parents[2] / "stream.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    streamer = module.Streamer(lambda data: None, 8000, 60)
    streamer._seq = 2
    streamer._sent_at = {1: (module.time.perf_counter(), 100), 2: (module.time.perf_counter(), 200)}
    streamer._unacked = 300
    streamer.ack(0xFFFFFFFF)
    assert streamer._acked == 0 and streamer._unacked == 300
    assert streamer._queueing(module.time.perf_counter())
    streamer.ack(2)
    assert streamer._acked == 2 and streamer._unacked == 100
    streamer.ack(2)
    assert streamer._unacked == 100 and streamer._acked_bytes == 200
    streamer.ack(1)
    assert streamer._unacked == 0 and streamer._acked_bytes == 300


def test_capture_cost_is_inside_frame_budget_and_idle_recovery_is_bounded(monkeypatch):
    monkeypatch.setitem(sys.modules, "capture", ModuleType("capture"))
    monkeypatch.setitem(sys.modules, "winput", ModuleType("winput"))
    module = load_stream(Path(__file__).parents[2])
    assert pacing(module)["fps"] == pytest.approx(60, abs=0.1)
    idle = pacing(module, static=True)
    assert idle["idle_keyframe_response_ms"] < 30 and idle["encoded_before_100ms"] == 1
    assert pacing(module, static=True, pointer_only=True)["idle_keyframe_response_ms"] < 30


def test_changing_capture_fps_preserves_encoder_reference_chain(monkeypatch):
    monkeypatch.setitem(sys.modules, "capture", ModuleType("capture"))
    monkeypatch.setitem(sys.modules, "winput", ModuleType("winput"))
    module = load_stream(Path(__file__).parents[2])
    streamer = module.Streamer(lambda data: None, 8000, 60)
    streamer.configure(8000, 30)
    assert streamer.fps == 30 and not streamer.need_reconfig


def test_congestion_is_reacted_to_before_half_a_second(monkeypatch):
    monkeypatch.setitem(sys.modules, "capture", ModuleType("capture"))
    monkeypatch.setitem(sys.modules, "winput", ModuleType("winput"))
    module = load_stream(Path(__file__).parents[2])
    module.time = SimpleNamespace(perf_counter=lambda: .3)
    streamer = module.Streamer(lambda data: None, 8000, 60)
    streamer._enc_kbps, streamer._base_rtt = 8000, .2
    streamer._rtt_n, streamer._rtt_lo, streamer._rtt_sum = 12, .21, .33 * 12
    streamer._acked_bytes = 40000
    streamer._adapt(SimpleNamespace(bit_rate=8000000))
    assert streamer.kbps < 8000


def test_faster_sampling_does_not_speed_up_rate_probes(monkeypatch):
    monkeypatch.setitem(sys.modules, "capture", ModuleType("capture"))
    monkeypatch.setitem(sys.modules, "winput", ModuleType("winput"))
    module = load_stream(Path(__file__).parents[2])
    clock = SimpleNamespace(now=0)
    module.time = SimpleNamespace(perf_counter=lambda: clock.now)
    streamer = module.Streamer(lambda data: None, 4000, 60)
    streamer.cap_kbps, streamer._enc_kbps, streamer._base_rtt = 8000, 4000, .2
    rates = []
    for step in range(4):
        clock.now = (step + 1) * .25
        streamer._rtt_n, streamer._rtt_lo, streamer._rtt_sum = 8, .205, .21 * 8
        streamer._acked_bytes = 125000
        streamer._adapt(SimpleNamespace(bit_rate=4000000))
        rates.append(streamer.kbps)
    assert rates[:3] == [4000, 4000, 4000] and rates[3] > 4000


def test_backpressure_keeps_running_adaptation_and_can_be_stopped(monkeypatch):
    monkeypatch.setitem(sys.modules, "capture", ModuleType("capture"))
    monkeypatch.setitem(sys.modules, "winput", ModuleType("winput"))
    module = load_stream(Path(__file__).parents[2])
    streamer = module.Streamer(lambda data: None, 8000, 60)
    streamer._queueing = lambda now: True
    calls = []

    def adapt(encoder):
        calls.append(encoder)
        streamer.stop()
        return encoder

    streamer._adapt = adapt
    encoder = object()
    assert streamer._wait_for_budget(encoder) is encoder
    assert calls == [encoder] and streamer._blocked > 0
