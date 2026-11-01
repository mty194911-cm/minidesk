"""Run existing E2E tests with temporary certificates and loopback networking.

Examples:
  python tests/run_integration.py e2e-tls --synthetic
  python tests/run_integration.py quic --synthetic --loss 0.1
  python tests/run_integration.py quic   # Windows: actual screen capture/encode
"""
import argparse
import asyncio
import importlib.util
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "relay"), str(ROOT / "tests")]


async def run(args):
    if args.synthetic:
        import browser_server  # installs input/capture test doubles before the host import
    import host
    import mkcert

    class QuietUi:
        def __init__(self, *args, **kwargs):
            pass

        def __getattr__(self, name):
            return lambda *args, **kwargs: None

    class Animation:
        def __init__(self, *args, **kwargs):
            pass

        def kill(self):
            pass

    name = "test_e2e.py" if args.mode == "e2e-tls" else "test_quic.py"
    with tempfile.TemporaryDirectory(prefix="minidesk-integration-") as directory:
        temp = Path(directory)
        ca_key, ca_cert = mkcert.make_ca()
        ca_path = temp / "ca.crt"
        ca_path.write_bytes(mkcert.pem_cert(ca_cert))
        spec = importlib.util.spec_from_file_location("integration_case", ROOT / "tests" / name)
        case = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(case)
        argv = [name] + (["--tls"] if args.mode == "e2e-tls" else [])
        if args.loss:
            argv += ["--loss", str(args.loss), "--nodecode"]
        with patch.object(host, "Ui", QuietUi), patch.object(host, "lan_ips", lambda: ["127.0.0.1"]), \
             patch.object(host, "LAN_CERT", str(temp / "lan.crt")), \
             patch.object(host, "LAN_KEY", str(temp / "lan.key")), \
             patch.object(host, "CA_PATH", str(ca_path)), \
             patch.object(mkcert, "CA_CRT", str(ca_path)), \
             patch.object(mkcert, "load_ca", lambda: (ca_key, ca_cert)), \
             patch.object(sys, "argv", argv):
            if args.synthetic:
                with patch.object(host, "Streamer", browser_server.SyntheticStreamer), \
                     patch("subprocess.Popen", Animation):
                    await asyncio.wait_for(case.main(), 50)
            else:
                await asyncio.wait_for(case.main(), 50)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["e2e-tls", "quic"])
    parser.add_argument("--synthetic", action="store_true", help="generate video; never capture or inject real input")
    parser.add_argument("--loss", type=float, default=0, help="QUIC packet loss ratio, 0..1")
    args = parser.parse_args()
    if not 0 <= args.loss < 1 or args.loss and args.mode != "quic":
        parser.error("--loss requires quic mode and a ratio in [0, 1)")
    asyncio.run(run(args))
