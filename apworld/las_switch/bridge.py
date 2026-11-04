"""PC-hosted, loopback-only newline JSON bridge. This is a new LAS protocol."""
import asyncio
import json
import logging

from .core.data import PROTOCOL

log = logging.getLogger("LASBridge")
MAX_LINE = 65536


class Bridge:
    def __init__(self, expected, on_state, *, allow_mock=False, required_capabilities=None):
        self.expected = expected
        self.on_state = on_state
        self.allow_mock = allow_mock
        # Normal clients always require the full contract. A bounded development
        # harness may explicitly test a smaller protocol surface without asking
        # the native module to advertise capabilities it does not implement.
        self.required_capabilities = ({'atomic_delivery_v1', 'persistent_checks_v1',
            'reward_suppression_v1', 'victory_v1', 'indexed_rewards_v1',
            'progressive_rewards_v1', 'dungeon_rewards_v1'}
            if required_capabilities is None else set(required_capabilities))
        self.server = None
        self.writer = None
        self.hello = None
        self.state = None
        self.lock = asyncio.Lock()

    async def start(self, port=17778):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", port, limit=MAX_LINE)
        return self.server.sockets[0].getsockname()[1]

    async def close(self):
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def send(self, packet):
        async with self.lock:
            writer = self.writer
            if writer is None or writer.is_closing():
                return False
            raw = json.dumps(packet, separators=(",", ":")).encode() + b"\n"
            if len(raw) > MAX_LINE:
                raise ValueError("Bridge packet too large")
            writer.write(raw)
            await writer.drain()
            return True

    def validate_hello(self, hello):
        if not isinstance(hello, dict) or hello.get("t") != "hello" or type(hello.get("protocol")) is not int or hello["protocol"] != PROTOCOL:
            raise ValueError("Wrong bridge protocol")
        if hello.get("implementation") == "mock" and not self.allow_mock:
            raise ValueError("Mock game disabled; use --allow-mock explicitly")
        if hello.get("implementation") not in {"mock", "native"}:
            raise ValueError("Unknown game implementation")
        for key, value in self.expected.items():
            if hello.get(key) != value:
                raise ValueError(f"Bridge identity mismatch: {key}")
        if not isinstance(hello.get("save_id"), str) or not hello["save_id"]:
            raise ValueError("Missing save ID")
        capabilities = hello.get("capabilities")
        if not isinstance(capabilities, list) or not self.required_capabilities.issubset(capabilities):
            raise ValueError("Required game-side capabilities are unavailable")

    async def _handle(self, reader, writer):
        claimed = False
        try:
            raw = await asyncio.wait_for(reader.readline(), 10)
            hello = json.loads(raw)
            self.validate_hello(hello)
            if self.writer is not None:
                raise ValueError("Another game is already connected")
            self.writer, self.hello = writer, hello
            claimed = True
            await self.send({"t": "hello_ack", "protocol": PROTOCOL, "ok": True})
            while True:
                raw = await asyncio.wait_for(reader.readline(), 30)
                if not raw:
                    break
                packet = json.loads(raw)
                if not isinstance(packet, dict):
                    raise ValueError("Bridge packet must be an object")
                if packet.get("t") == "state":
                    self.state = packet
                    await self.on_state(packet)
                elif packet.get("t") == "ping":
                    await self.send({"t": "pong"})
                else:
                    raise ValueError("Unsupported game message")
        except (ValueError, TypeError, OSError, asyncio.TimeoutError, asyncio.LimitOverrunError) as exc:
            log.warning("Game bridge disconnected: %s", exc)
            if not writer.is_closing():
                writer.write((json.dumps({"t": "error", "message": str(exc)}) + "\n").encode())
        finally:
            if claimed and self.writer is writer:
                self.writer = self.hello = self.state = None
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
