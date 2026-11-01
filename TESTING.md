# 回归与验证

运行普通回归不需要屏幕、GPU、生产配置或 Windows 原生扩展：

```bash
python -m venv .venv
# 激活环境后
python -m pip install -r requirements-dev.txt
python -m pytest -q
ruff check .
```

安装 Node.js 后，pytest 也会调用 `node --test tests/client_core.test.cjs`，覆盖接收队列关闭/限额、IME 事件序列和大段 Unicode 分块。未安装 Node 时会明确显示跳过。

`requirements-tested.txt` 记录 Python 3.10 的直接依赖基线，可用 `pip install -r requirements-dev.txt -c requirements-tested.txt` 安装。它不锁定所有间接依赖。本次也在独立 Python 3.12 环境验证了 aioquic 1.7.0、PyAV 15.0.0、aiohttp 3.13.2、cryptography 46.0.5。aioquic 1.7 要求 Python 3.11+，见 [PyPI 包元数据](https://pypi.org/project/aioquic/1.7.0/)。Python 3.10 由 pip 选择兼容的 1.3 系列。

集成测试使用真实 TCP/TLS/QUIC 连接和视频编码。`--synthetic` 使用生成画面，输入只记录到测试替身，能在无桌面的环境运行：

```bash
python tests/run_integration.py e2e-tls --synthetic
python tests/run_integration.py quic --synthetic
python tests/run_integration.py quic --synthetic --loss 0.1
```

这三个命令仅监听 loopback，使用临时 CA 与 LAN 证书，不改写项目中的部署密钥。最后一个命令为手机链路每个方向随机丢包 10%，每个方向增加 40 ms 延迟；画面是低复杂度合成内容，结果只用于恢复行为回归，不代表高动态桌面的吞吐基准。

在已经编译好扩展的 Windows 上，去掉 `--synthetic`，可以验证真实 DXGI 和编码器：

```bash
python tests/run_integration.py e2e-tls
python tests/run_integration.py quic
```

原有 `test_adapt.py`、`test_ime.py`、`bench_*.py` 保留为显式手工测试；它们可能打开窗口、改变输入法或注入键盘，不在普通 pytest 与 CI 中执行。

真实浏览器回归采用 Playwright CLI，需要 Node.js、npm 和本机 Chrome。先启动只生成合成画面、永不注入真实输入的测试服务：

```bash
python tests/browser_server.py --quic
```

另开终端，把下面的 `临时配对URL` 替换成服务输出的完整 URL：

```bash
npx --yes --package @playwright/cli playwright-cli -s=minidesk open "临时配对URL" --config tests/browser.config.json
npx --yes --package @playwright/cli playwright-cli -s=minidesk snapshot
npx --yes --package @playwright/cli playwright-cli -s=minidesk run-code --filename tests/browser_regression.js
npx --yes --package @playwright/cli playwright-cli -s=minidesk close
```

不传 `--quic` 可测试 WebSocket 后备。浏览器回归检查实际 H.264 解码、连续字符、composition 去重、pointercancel、失焦释放、12 帧真实访问单元突发不误降帧、持续积压降帧与平稳后的回升、踢出不自动重连，以及密钥撤销与重新配对。证书忽略仅限这个隔离浏览器配置，不修改系统信任。测试服务最多运行十分钟，可用 Ctrl+C 提前退出。

CI 配置覆盖 Linux/Windows 的 Python 3.10 + aioquic 1.3，以及 Python 3.12 + aioquic 1.7，运行单元测试与合成画面的 TLS/QUIC 集成；真实浏览器与硬件采集目前为本机显式验证项。添加 CI 配置不等于远端 CI 已经运行。

退出会等待 SSL 底层传输的关闭回调，参见 [aiohttp 的优雅退出说明](https://docs.aiohttp.org/en/stable/client_advanced.html#graceful-shutdown)。QUIC 连接即使在取消退出时，也会在 finally 中关闭 UDP socket。

Windows/Python 3.10.0 的测试中，如果先停 HTTPS 测试服务、再关闭仍有连接的 Chrome，解释器退出时仍可能出现底层 SSL transport 清理警告。正常的回归收尾顺序是先执行 `playwright-cli close`，再停止测试服务；本次该顺序下检查到的残留 transport 为 0。它是目前保留的旧运行时边界，不能据此宣称强制退出场景均无警告。

2026-11-01 的本机验证覆盖两套环境各 57 项 pytest 回归、15 项 Node 状态测试、Chrome 的 WebSocket/WebTransport 回归、原生 TLS/LAN/QUIC 链路，以及合成画面的 10% 丢包。性能基准与比较方法见 [PERFORMANCE.md](PERFORMANCE.md)。没有进行手机真机和长期公网压力测试，不据此宣称所有设备上的帧率提升。
