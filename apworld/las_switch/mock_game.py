"""Explicit test game, connected through the real TCP bridge, with durable saves."""
import argparse
import asyncio
from contextlib import closing
import json
import sqlite3

from .core.data import ITEM_IDS, PROTOCOL
from .core.seed import validate_manifest, sha

CAPABILITIES = ["atomic_delivery_v1", "persistent_checks_v1", "reward_suppression_v1", "victory_v1",
                "indexed_rewards_v1", "progressive_rewards_v1", "dungeon_rewards_v1"]


class MockSave:
    def __init__(self, path, identity):
        self.db = sqlite3.connect(path)
        try:
            with self.db:
                self.db.execute("CREATE TABLE IF NOT EXISTS game (id INTEGER PRIMARY KEY CHECK(id=1), identity TEXT, data TEXT)")
                row = self.db.execute("SELECT identity FROM game WHERE id=1").fetchone()
                if row and row[0] != sha(identity):
                    raise ValueError("Mock save belongs to another identity")
                if not row:
                    initial = {"t": "state", "cursor": 0, "history_hash": sha([]), "inventory": {},
                               "checks": [], "ready": True, "victory": False,"alive":True,
                               "deathlink_ack":0,"deathlink_busy":False}
                    self.db.execute("INSERT INTO game VALUES (1,?,?)", (sha(identity), json.dumps(initial)))
        except Exception:
            self.db.close(); raise

    def close(self):
        self.db.close()

    def state(self):
        return json.loads(self.db.execute("SELECT data FROM game WHERE id=1").fetchone()[0])

    def collect(self, ids):
        with self.db:
            state = self.state()
            state["checks"] = sorted(set(state["checks"]) | set(ids))
            self.db.execute("UPDATE game SET data=? WHERE id=1", (json.dumps(state),))

    def victory(self):
        with self.db:
            state = self.state(); state["victory"] = True
            self.db.execute("UPDATE game SET data=? WHERE id=1", (json.dumps(state),))

    def set_alive(self,alive,nonce=None):
        with self.db:
            state=self.state();state.update(alive=bool(alive),ready=bool(alive))
            if nonce is not None:state['deathlink_ack']=nonce
            self.db.execute('UPDATE game SET data=? WHERE id=1',(json.dumps(state),))

    def deliver(self, packet, fail=False):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            state = self.state()
            cursor = packet.get("expected_cursor")
            if type(cursor) is not int or cursor < 0:
                raise ValueError("Invalid expected cursor")
            if cursor < state["cursor"]:
                return False
            if cursor != state["cursor"] or packet.get("expected_hash") != state["history_hash"]:
                raise ValueError("Out-of-order delivery")
            grant = packet.get("grant", {})
            if grant.get("receipt_index") != cursor or ITEM_IDS.get(grant.get("item_name")) != grant.get("item_id"):
                raise ValueError("Malformed grant")
            if not state["ready"]:
                return False
            name = grant["item_name"]
            state["inventory"][name] = state["inventory"].get(name, 0) + 1
            state["cursor"] += 1
            state["history_hash"] = packet["next_hash"]
            self.db.execute("UPDATE game SET data=? WHERE id=1", (json.dumps(state),))
            if fail:
                raise RuntimeError("Mock crash before save commit")
        return True


async def run_game(manifest, save, *, port=17778, save_id="mock-save", team=0, stop=None):
    validate_manifest(manifest)
    backoff = 0.2
    while stop is None or not stop.is_set():
        writer = None
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            hello = {"t": "hello", "protocol": PROTOCOL, "implementation": "mock",
                     "identity": manifest["identity"], "manifest_digest": manifest["manifest_digest"],
                     "build_id": "MOCK", "save_id": save_id, "team": team, "capabilities": CAPABILITIES,
                     "supports_deathlink":manifest.get('player_settings',{}).get('death_link',False)}

            async def send(packet):
                writer.write((json.dumps(packet) + "\n").encode()); await writer.drain()

            await send(hello)
            ack = json.loads(await asyncio.wait_for(reader.readline(), 5))
            if not ack.get("ok"):
                raise ValueError(f"Bridge refused mock: {ack}")
            await send(save.state())
            backoff = 0.2
            while stop is None or not stop.is_set():
                try:
                    raw = await asyncio.wait_for(reader.readline(), 0.25)
                except asyncio.TimeoutError:
                    await send(save.state()); continue
                if not raw:
                    break
                packet = json.loads(raw)
                if packet.get("t") == "deliver":
                    save.deliver(packet)
                    await send(save.state())
                elif packet.get('t')=='deathlink' and manifest.get('player_settings',{}).get('death_link'):
                    save.set_alive(False,packet['nonce'])
                    await send(save.state())
                elif packet.get("t") == "error":
                    raise ValueError(packet["message"])
        except (OSError, asyncio.TimeoutError):
            await asyncio.sleep(backoff); backoff = min(backoff * 2, 5)
        finally:
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass


def launch(argv=None):
    parser = argparse.ArgumentParser(description="MOCK LAS GAME — never controls Ryujinx")
    parser.add_argument("manifest")
    parser.add_argument("--save", required=True)
    parser.add_argument("--save-id", default="mock-save")
    parser.add_argument("--team", type=int, default=0)
    parser.add_argument("--port", type=int, default=17778)
    parser.add_argument("--check", action="append", default=[])
    parser.add_argument("--victory", action="store_true")
    args = parser.parse_args(argv)
    with open(args.manifest, encoding="utf-8") as f:
        manifest = validate_manifest(json.load(f))
    locations = {p["location"]: p["location_id"] for p in manifest["placements"]}
    if any(name not in locations for name in args.check):
        parser.error("Unknown check")
    identity = {"manifest": manifest["manifest_digest"], "save_id": args.save_id, "team": args.team}
    with closing(MockSave(args.save, identity)) as save:
        save.collect([locations[name] for name in args.check])
        if args.victory:
            save.victory()
        print("MOCK GAME: TCP transport and transactional Python save; no LAS effects")
        asyncio.run(run_game(manifest, save, port=args.port, save_id=args.save_id, team=args.team))


if __name__ == "__main__":
    launch()
