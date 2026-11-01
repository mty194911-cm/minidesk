"""Authenticated session lifecycle and exclusive desktop input ownership.

The input API and streamer factory are injected so protocol/state tests need no desktop.
"""
import asyncio
import logging
import struct

from cryptography.exceptions import InvalidTag

from protocol import ACK, BUTTON, BYE, CONFIG, KEY, KEYFRAME, MOVE, NOTE, PING, PONG, SCREEN, TEXT, VIDEO, WHEEL

log = logging.getLogger("host")
MAX_TEXT = 16 << 10
MAX_OUT = 96  # the streamer's ACK gate normally bounds video to at most 30 frames
INPUT_TYPES = {MOVE, BUTTON, WHEEL, KEY, TEXT}
SIZES = {MOVE: 5, BUTTON: 3, WHEEL: 5, KEY: 4, ACK: 5, KEYFRAME: 1, CONFIG: 6}


class OutboundQueue:
    """Keep video reference order while allowing control replies ahead of unsent video."""

    def __init__(self, maxsize):
        self.queue = asyncio.PriorityQueue(maxsize=maxsize)
        self.serial = 0

    def put_nowait(self, data):
        self.serial += 1
        self.queue.put_nowait((1 if data[0] in (VIDEO, SCREEN) else 0, self.serial, data))

    async def get(self):
        return (await self.queue.get())[2]

    def get_nowait(self):
        return self.queue.get_nowait()[2]

    def empty(self):
        return self.queue.empty()


class Session:
    def __init__(self, host, link, ch, via, *, input_api, streamer_factory):
        self.host, self.link, self.ch, self.via = host, link, ch, via
        self.input = input_api
        self.streamer_factory = streamer_factory
        self.out = OutboundQueue(maxsize=MAX_OUT)
        self.streamer = None
        self.closing = False
        self.close_code = 1000
        self.keys, self.buttons = set(), set()
        self._close_requested = asyncio.Event()

    def emit(self, data):
        """Runs on the event loop, including callbacks scheduled by the capture thread."""
        if self.closing:
            return
        try:
            self.out.put_nowait(data)
        except asyncio.QueueFull:
            # Dropping an encoded P-frame breaks its dependents. End the entire session instead.
            self.close(1013)

    async def run(self):
        loop = asyncio.get_running_loop()
        emit = lambda data: loop.call_soon_threadsafe(self.emit, data)  # noqa: E731
        reader = asyncio.create_task(self.receive_loop(emit))
        sender = asyncio.create_task(self.send_loop())
        stats = asyncio.create_task(self.stats_loop())
        closer = asyncio.create_task(self._close_requested.wait())
        tasks = (reader, sender, stats, closer)
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if closer in done and not sender.done():
                # Stop input immediately, while allowing a bounded interval to deliver BYE.
                reader.cancel()
                await asyncio.wait({sender}, timeout=1)
            for task in done:
                if not task.cancelled() and task.exception():
                    error = task.exception()
                    if isinstance(error, (InvalidTag, ValueError, struct.error)):
                        log.warning("无效的会话消息，断开: %s", type(error).__name__)
                    else:
                        log.warning("会话结束（%s）: %s", self.via, type(error).__name__)
        finally:
            self.closing = True
            self.release_input()
            self.host.deactivate(self)
            if self.streamer:
                self.streamer.stop()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            try:
                await asyncio.wait_for(self.link.close(self.close_code), 2)
            except (OSError, asyncio.TimeoutError):
                pass
            if self.streamer:
                await loop.run_in_executor(None, self.streamer.join, 2)

    async def receive_loop(self, emit):
        while (raw := await self.link.recv()) is not None:
            self.handle(self.ch.open(raw), emit)

    async def send_loop(self):
        while True:
            plain = await self.out.get()
            if plain[0] == BYE and struct.unpack_from("<H", plain, 1)[0] < 4000:
                return await self.link.close(struct.unpack_from("<H", plain, 1)[0])
            await self.link.send(self.ch.seal(plain), video=plain[0] == VIDEO)
            if plain[0] == BYE:
                return await self.link.close(struct.unpack_from("<H", plain, 1)[0])

    def release_input(self):
        for sc in self.keys:
            self.input.key(sc, False)
        for button in self.buttons:
            self.input.button(button, False)
        self.keys.clear()
        self.buttons.clear()

    def close(self, code):
        if self.closing:
            return
        self.closing = True
        self.close_code = code
        self.release_input()  # before another session can acquire the desktop
        if self.streamer:
            self.streamer.stop()
        while not self.out.empty():
            self.out.get_nowait()
        self.out.put_nowait(struct.pack("<BH", BYE, code))
        self._close_requested.set()

    async def stats_loop(self, every=10):
        while True:
            await asyncio.sleep(every)
            if not self.streamer:
                continue
            frames, size, rtt, base, kbps, allowance = self.streamer.take_stats()
            if frames:
                log.info("%s: %.0f fps, %.1f Mbps, 往返 平均 %.0f ms / 最低 %.0f ms, 码率 %d kbps, 排队上限 %.0f ms",
                         self.via, frames / every, size * 8 / every / 1e6, rtt * 1000,
                         base * 1000 if base != float("inf") else 0, kbps, allowance * 1000)

    def handle(self, m, emit):
        if self.closing:
            return
        if not m:
            raise ValueError("empty message")
        t = m[0]
        if t in SIZES and len(m) != SIZES[t]:
            raise ValueError("invalid message length")
        if t in INPUT_TYPES and self.host.active is not self:
            return
        if t == MOVE:
            self.input.move(*struct.unpack_from("<HH", m, 1))
        elif t == BUTTON:
            b, down = m[1], m[2]
            if b > 2 or down > 1:
                raise ValueError("invalid button")
            (self.buttons.add if down else self.buttons.discard)(b)
            self.input.button(b, down)
        elif t == WHEEL:
            self.input.wheel(*struct.unpack_from("<hh", m, 1))
        elif t == KEY:
            sc, down = struct.unpack_from("<HB", m, 1)
            if sc >> 8 not in (0, 0xE0) or not sc & 0xFF or down > 1:
                raise ValueError("invalid key")
            (self.keys.add if down else self.keys.discard)(sc)
            self.input.key(sc, down)
        elif t == TEXT:
            if not 1 < len(m) <= MAX_TEXT + 1:
                raise ValueError("text too long")
            self.input.text(m[1:].decode("utf-8"))
        elif t == ACK and self.streamer:
            self.streamer.ack(struct.unpack_from("<I", m, 1)[0])
        elif t == KEYFRAME and self.streamer:
            self.streamer.need_key = True
        elif t == CONFIG:
            kbps, fps = struct.unpack_from("<IB", m, 1)
            kbps, fps = min(max(kbps, 800), 50000), min(max(fps, 5), 120)
            if self.streamer:
                self.streamer.configure(kbps, fps)
            else:
                prev = self.host.activate(self)
                self.streamer = self.streamer_factory(emit, kbps, fps, after=prev)
                self.streamer.start()
        elif t == PING:
            if len(m) > 65:
                raise ValueError("ping too long")
            self.emit(bytes([PONG]) + m[1:])
        elif t == NOTE:
            if len(m) > 1025:
                raise ValueError("note too long")
            log.info("手机报告: %s", m[1:301].decode("utf-8", "replace").replace("\n", " ").replace("\r", " "))
