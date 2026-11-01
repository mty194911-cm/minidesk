import secrets

import pytest

import configuration


def config():
    return {"relay": "https://127.0.0.1", "token": "test", "id": "testhost01",
            "key": configuration.b64(secrets.token_bytes(32))}


def test_atomic_save_and_unicode_roundtrip(tmp_path):
    path = tmp_path / "config.json"
    cfg = dict(config(), name="我的电脑")
    configuration.save_config(path, cfg)
    assert configuration.read_config(path) == cfg
    assert list(tmp_path.iterdir()) == [path]


def test_failed_replacement_preserves_existing_configuration(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    cfg = config()
    configuration.save_config(path, cfg)

    def fail(*args):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(configuration.os, "replace", fail)
    with pytest.raises(OSError):
        configuration.save_config(path, dict(cfg, key=configuration.b64(secrets.token_bytes(32))))
    assert configuration.read_config(path) == cfg
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("overrides", [{"relay": "file:///tmp"}, {"relay": "https://user:pass@host"},
                                        {"relay": "https://host/#secret"}, {"key": "bad"},
                                        {"id": "bad/id"}, {"token": "中文"}, {"lan_port": -1},
                                        {"lan_port": True}, {"version": 99}])
def test_invalid_configuration_does_not_overwrite_file(tmp_path, overrides):
    path = tmp_path / "config.json"
    cfg = config()
    configuration.save_config(path, cfg)
    with pytest.raises(ValueError):
        configuration.save_config(path, dict(cfg, **overrides))
    assert configuration.read_config(path) == cfg
