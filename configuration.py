"""Validated host configuration, saved with atomic replacement."""
import base64
import json
import os
import re
import tempfile
from urllib.parse import urlsplit


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(value):
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def read_config(path):
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as file:
        cfg = json.load(file)
    if not isinstance(cfg, dict):
        raise ValueError("config.json 必须是 JSON 对象")
    return cfg


def validate_config(cfg):
    if cfg.get("version", 1) != 1:
        raise ValueError("不支持的配置版本")
    if not isinstance(cfg.get("relay"), str):
        raise ValueError("需要有效的 relay 地址")
    relay = urlsplit(cfg["relay"])
    if (relay.scheme not in ("http", "https") or not relay.hostname or relay.username or relay.password
            or relay.query or relay.fragment or relay.path not in ("", "/")):
        raise ValueError("relay 必须是 http(s)://地址[:端口]")
    if relay.port is not None and not 1 <= relay.port <= 65535:
        raise ValueError("relay 端口无效")
    token = cfg.get("token", "")
    if not isinstance(token, str) or not 1 <= len(token) <= 256 or not token.isascii():
        raise ValueError("需要有效的服务器 token")
    if not isinstance(cfg.get("id"), str) or not re.fullmatch(r"[\w-]{8,64}", cfg["id"], re.ASCII):
        raise ValueError("设备 ID 无效")
    if not isinstance(cfg.get("key"), str) or len(unb64(cfg["key"])) != 32:
        raise ValueError("配对密钥必须是 32 字节")
    port = cfg.get("lan_port", 47250)
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("lan_port 必须在 0—65535 之间")


def save_config(path, cfg):
    validate_config(cfg)
    directory = os.path.dirname(os.path.abspath(path))
    fd, temporary = tempfile.mkstemp(prefix=".minidesk-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(cfg, file, indent=2, ensure_ascii=False)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
