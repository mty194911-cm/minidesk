"""Build the relay package for your server and point host.py at it.

  python deploy.py 203.0.113.7 [--port 443]

Creates dist/minidesk-relay.zip: the relay, the web client, a TLS certificate for that IP (mkcert.py) and the
host token. On a Windows server: unzip, double-click install.cmd (relay/install.ps1 sets up Python, a startup
task and the firewall). On Linux: run relay.py with the certificate and token (see README.md). Re-run to
upgrade. The zip holds the server key and the token: delete it once installed.
"""
import argparse
import json
import os
import secrets
import zipfile

import mkcert

HERE = os.path.dirname(os.path.abspath(__file__))
RELAY = os.path.join(HERE, "relay")
ZIP = os.path.join(HERE, "dist", "minidesk-relay.zip")
CONFIG_PATH = os.path.join(HERE, "config.json")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("ip", help="the server's public IP address")
    p.add_argument("--port", type=int, default=443)
    a = p.parse_args()
    mkcert.issue(a.ip)

    cfg = {}
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, encoding="utf-8") as f:
            cfg = json.load(f)
    cfg["token"] = cfg.get("token") or secrets.token_urlsafe(24)
    cfg["relay"] = f"https://{a.ip}" + ("" if a.port == 443 else f":{a.port}")

    os.makedirs(os.path.dirname(ZIP), exist_ok=True)
    with zipfile.ZipFile(ZIP, "w", zipfile.ZIP_DEFLATED) as z:
        root = "minidesk-relay/"
        for name in ("relay.py", "quic.py", "install.ps1", "install.cmd"):
            z.write(os.path.join(RELAY, name), root + name)
        for name in sorted(os.listdir(os.path.join(RELAY, "web"))):
            z.write(os.path.join(RELAY, "web", name), root + "web/" + name)
        for name in ("server.crt", "server.key"):
            z.write(os.path.join(mkcert.CERTS, name), root + name)
        z.writestr(root + "relay.json", json.dumps({"token": cfg["token"], "port": a.port}))

    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    print(f"""
安装包已生成：{ZIP}
1. 把这个 zip 复制到服务器上并解压（Windows 服务器可用远程桌面直接粘贴）
2. Windows：双击解压出来的 install.cmd，等它显示绿色的 OK；Linux：按 README.md 运行 relay.py
3. 云服务商控制台的安全组放行 TCP {a.port} 和 UDP {a.port}（UDP 是晚高峰抗丢包的关键）
4. 回到这台电脑：双击桌面上的 MiniDesk，会弹出连接二维码（没有快捷方式就先 python host.py --shortcut）
装好后删掉服务器上的 zip 和解压目录（里面有服务器私钥和 token）。
这台电脑也需要 aioquic：pip install aioquic""")


if __name__ == "__main__":
    main()
