from pathlib import Path
import secrets
import shutil
import sys
import zipfile

from configuration import b64, read_config, save_config
import deploy


def test_package_includes_shared_modules_and_preserves_existing_pairing(tmp_path, monkeypatch):
    relay = tmp_path / "relay"
    relay.mkdir()
    source = Path(deploy.RELAY)
    for name in ("relay.py", "quic.py", "limits.py", "install.ps1", "install.cmd", "requirements.txt"):
        shutil.copyfile(source / name, relay / name)
    shutil.copytree(source / "web", relay / "web", ignore=shutil.ignore_patterns("ca.crt"))
    certificates = tmp_path / "certs"
    certificates.mkdir()

    def issue(address):
        (certificates / "server.crt").write_text("test certificate")
        (certificates / "server.key").write_text("test server private key")
        (certificates / "ca.key").write_text("test CA private key: must never be packaged")

    path = tmp_path / "config.json"
    cfg = {"relay": "https://127.0.0.1", "token": "keep-token", "id": "testhost01",
           "key": b64(secrets.token_bytes(32))}
    save_config(path, cfg)
    archive = tmp_path / "dist" / "relay.zip"
    monkeypatch.setattr(deploy, "CONFIG_PATH", str(path))
    monkeypatch.setattr(deploy, "RELAY", str(relay))
    monkeypatch.setattr(deploy, "ZIP", str(archive))
    monkeypatch.setattr(deploy.mkcert, "CERTS", str(certificates))
    monkeypatch.setattr(deploy.mkcert, "issue", issue)
    monkeypatch.setattr(sys, "argv", ["deploy.py", "203.0.113.7", "--port", "8443"])
    deploy.main()
    saved = read_config(path)
    assert saved["key"] == cfg["key"] and saved["token"] == cfg["token"]
    assert saved["relay"] == "https://203.0.113.7:8443"
    with zipfile.ZipFile(archive) as package:
        names = package.namelist()
        for name in ("limits.py", "requirements.txt", "web/client-core.js", "server.key"):
            assert "minidesk-relay/" + name in names
        assert not any(name.endswith("ca.key") or name.endswith("config.json") for name in names)
