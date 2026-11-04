"""Real AP CommonContext client. Game hooks remain external to this PC client."""
import argparse
import asyncio
import json
import logging
import time
import hashlib
from pathlib import Path

from CommonClient import CommonContext, get_base_parser, server_loop
from .bridge import Bridge
from .core.data import GAME
from .core.runtime import next_actions
from .core.seed import validate_manifest,default_save_id

log = logging.getLogger("Client")


class LASContext(CommonContext):
    game = GAME
    items_handling = 0b111
    want_slot_data = True

    def __init__(self, manifest, server_address=None, password=None, *, build_id, save_id, allow_mock=False):
        super().__init__(server_address, password)
        self.manifest = validate_manifest(manifest)
        self.auth = manifest["identity"]["slot_name"]
        self.ap_validated = False
        self.room_seed = None
        self.history_ready = False
        self.goal_sent = False
        self.last_send = None
        self.last_sent_at = 0.0
        self.last_check_sync = None
        self.last_check_sync_at = 0.0
        self.last_error = None
        self.death_link_enabled=manifest.get('player_settings',{}).get('death_link',False)
        self.last_alive=None
        self.remote_death=None
        self.remote_death_latched=False
        self.last_remote_death_at=0.0
        self.last_death_send_at=0.0
        self.sent_notifications=True
        self.outgoing_history=[]
        self.pending_hint=None
        self.pump_lock = asyncio.Lock()
        self.bridge = Bridge({"identity": manifest["identity"], "manifest_digest": manifest["manifest_digest"],
                              "build_id": build_id, "save_id": save_id}, self.game_state, allow_mock=allow_mock)

    async def server_auth(self, password_requested=False):
        self.auth = self.manifest["identity"]["slot_name"]
        if password_requested and not self.password:
            await super().server_auth(password_requested)
        await self.send_connect()

    async def send_msgs(self, msgs):
        # CommonContext replays checks during Connected before on_package runs.
        # Gate that replay until this exact seed/slot has been validated.
        if not self.ap_validated:
            msgs = [msg for msg in msgs if msg.get("cmd") not in {"LocationChecks", "StatusUpdate"}]
        if msgs:
            await super().send_msgs(msgs)

    def on_package(self, cmd, args):
        if cmd == "RoomInfo":
            # AP 0.6.7 and 0.6.8 store the server seed under different attributes.
            # Validate the protocol field directly for both supported cores.
            self.room_seed = args.get("seed_name")
        if cmd == "Connected":
            self.goal_sent = False
            data = args.get("slot_data", {})
            expected = self.manifest
            ids = {row["location"]: row["location_id"] for row in expected["placements"]}
            self.ap_validated = (self.room_seed == expected["identity"]["seed"] and
                                 self.slot == expected["identity"]["slot"] and
                                 data.get("identity") == expected["identity"] and
                                 data.get("source_digest") == expected["source_digest"] and
                                 data.get("profile") == expected["profile"] and
                                 data.get("location_ids") == ids)
            if expected['schema_version']==4:
                self.ap_validated=self.ap_validated and data.get('player_settings')==expected['player_settings'] and data.get('dungeon_entrances')==expected['dungeon_entrances']
            # AP 0.6.8 omits ReceivedItems entirely when history is empty,
            # including on Sync. A validated Connected establishes empty history;
            # a nonzero game cursor still blocks until canonical items arrive.
            self.history_ready = self.ap_validated
            if not self.ap_validated:
                log.error("Wrong AP seed, slot, or world data; game delivery disabled")
                asyncio.create_task(self.disconnect())
            else:
                asyncio.create_task(self.send_msgs([{"cmd": "Sync"}]))
        elif cmd == "ReceivedItems" and args.get("index") == 0:
            self.history_ready = True
        elif cmd == "ConnectionRefused":
            self.ap_validated = self.history_ready = False

    async def connection_closed(self):
        self.ap_validated = self.history_ready = False
        self.goal_sent = False
        self.tags.discard('DeathLink')
        self.remote_death=None
        self.remote_death_latched=False
        self.last_alive=None
        await super().connection_closed()

    async def game_state(self, state):
        if self.ap_validated and self.history_ready:
            actions=next_actions(self.manifest,state,self.items_received,self.checked_locations)
            if not actions['sync_required']:await self.deathlink_state(state)
        await self.pump()

    def make_gui(self):
        from .gui import LASManager
        return LASManager

    def on_print_json(self,args):
        super().on_print_json(args)
        item=args.get('item');recipient=args.get('receiving')
        if args.get('type')=='ItemSend' and item and item.player==self.slot and recipient!=self.slot:
            try:name=self.item_names.lookup_in_slot(item.item,recipient)
            except (KeyError,TypeError):name=str(item.item)
            player=self.player_names.get(recipient,'Player '+str(recipient))
            self.outgoing_history.append({'text':str(name)+' → '+player,'item_id':item.item,'recipient':recipient})
            self.outgoing_history=self.outgoing_history[-100:]

    def available_game_hints(self):
        if not self.ap_validated:return []
        routes={(r['finding_player'],r['location_id'],r['recipient_slot'],r['item_id']):r for r in self.manifest.get('hint_routes',[])}
        result=[];seen=set()
        for hint in self.stored_data.get(f'_read_hints_{self.team}_{self.slot}',[]):
            if not isinstance(hint,dict):continue
            values=[hint.get(k) for k in ('finding_player','location','receiving_player','item')]
            if any(type(v) is not int for v in values):continue
            route=routes.get(tuple(values))
            if route and route['index'] not in seen:
                seen.add(route['index'])
                result.append({'index':route['index'],'text':route['item_name']+' — '+route['location_name']+' ('+route['finding_name']+')'})
        return sorted(result,key=lambda r:r['index'])

    def request_game_hint(self,index):
        if index not in {r['index'] for r in self.available_game_hints()}:
            log.info('Choose a hint received from Archipelago first.');return False
        if not self.bridge.hello or self.bridge.hello.get('supports_hints') is not True:
            log.info('Connect a game build with in-game hints first.');return False
        nonce=int(hashlib.sha256(f'{index}:{time.time_ns()}'.encode()).hexdigest()[:8],16) or 1
        self.pending_hint={'index':index,'nonce':nonce,'at':time.monotonic(),'sent':0.0}
        log.info('Hint queued; it will appear when the game is ready.')
        return True

    async def pump_hint(self):
        pending=self.pending_hint;state=self.bridge.state
        if not pending or not state:return False
        if state.get('hint_ack')==pending['nonce']:
            self.pending_hint=None;return False
        now=time.monotonic()
        if now-pending['at']>60:
            self.pending_hint=None;log.info('Hint request expired while the game was unavailable.');return False
        if state.get('ready') and now-pending['sent']>2:
            if await self.bridge.send({'t':'hint','index':pending['index'],'nonce':pending['nonce']}):pending['sent']=now
        return True

    def on_deathlink(self,data):
        if not self.death_link_enabled or not self.ap_validated:return
        super().on_deathlink(data)
        state=self.bridge.state or {}
        if state.get('alive') is not True:return
        self.last_remote_death_at=time.monotonic()
        nonce=int(hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()[:8],16) or 1
        self.remote_death={'nonce':nonce,'at':self.last_remote_death_at,'sent':0.0}

    async def deathlink_state(self,state):
        if not self.death_link_enabled or not self.ap_validated:return
        alive=state.get('alive')
        if self.remote_death and state.get('deathlink_ack')==self.remote_death['nonce']:
            self.remote_death_latched=True
        if type(alive) is not bool:
            self.last_alive=None
            return
        if self.last_alive is True and alive is False:
            now=time.monotonic()
            if not self.remote_death_latched and now-self.last_remote_death_at>5 and now-self.last_death_send_at>5 and 'DeathLink' in self.tags:
                self.last_death_send_at=now
                await self.send_death(self.manifest['identity']['slot_name']+' fell in Koholint.')
            self.remote_death=None
            self.remote_death_latched=False
        elif alive is True and state.get('deathlink_busy') is False and not self.remote_death:
            self.remote_death_latched=False
        self.last_alive=alive

    async def pump_deathlink(self):
        supported=self.bridge.hello and self.bridge.hello.get('supports_deathlink') is True
        active=type((self.bridge.state or {}).get('alive')) is bool
        await self.update_death_link(bool(self.death_link_enabled and self.ap_validated and supported and active and not (self.bridge.state or {}).get('victory')))
        pending=self.remote_death;state=self.bridge.state
        if not pending or not state or not supported:return False
        if state.get('deathlink_ack')==pending['nonce']:
            self.remote_death=None
            return False
        now=time.monotonic()
        if now-pending['at']>20:
            self.remote_death=None
            log.info('DeathLink expired while the game was unavailable.')
            return False
        if state.get('ready') and now-pending['sent']>2:
            if await self.bridge.send({'t':'deathlink','nonce':pending['nonce']}):pending['sent']=now
        return True

    async def pump(self):
        async with self.pump_lock:
            if (not self.ap_validated or not self.history_ready or not self.server or
                    not self.server.socket.open or not self.bridge.state):
                return
            if self.bridge.hello.get("team") != self.team:
                raise ValueError("Game/AP team mismatch")
            actions = next_actions(self.manifest, self.bridge.state, self.items_received, self.checked_locations)
            if actions["sync_required"]:
                if time.monotonic() - self.last_sent_at > 2:
                    await self.send_msgs([{"cmd": "Sync"}]); self.last_sent_at = time.monotonic()
                return
            if actions["checks"]:
                self.locations_checked.update(actions["checks"])
                await self.send_msgs([{"cmd": "LocationChecks", "locations": actions["checks"]}])
            if actions["goal"] and not self.goal_sent:
                await self.send_msgs([{"cmd": "StatusUpdate", "status": 30}])
                self.finished_game = True
                self.goal_sent = True
            if await self.pump_deathlink():return
            if await self.pump_hint():return
            if self.bridge.hello.get('supports_check_sync') is True and self.bridge.state['ready']:
                valid={r['location_id'] for r in self.manifest['placements']}
                missing=sorted((set(self.checked_locations)&valid)-set(self.bridge.state['checks']))[:128]
                if missing:
                    marker=tuple(missing)
                    if marker!=self.last_check_sync or time.monotonic()-self.last_check_sync_at>2:
                        if await self.bridge.send({'t':'sync_checks','checks':missing}):
                            self.last_check_sync=marker;self.last_check_sync_at=time.monotonic()
                    return
            grant = actions["grant"]
            marker = json.dumps(grant, sort_keys=True)
            if grant and (marker != self.last_send or time.monotonic() - self.last_sent_at > 2):
                if await self.bridge.send(grant):
                    self.last_send = marker; self.last_sent_at = time.monotonic()

    async def watch_game(self):
        while not self.exit_event.is_set():
            try:
                await self.pump()
                self.last_error = None
            except (ValueError, OSError) as exc:
                if str(exc) != self.last_error:
                    log.error("Delivery blocked: %s", exc); self.last_error = str(exc)
            await asyncio.sleep(0.25)


async def run(args):
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    ctx = LASContext(manifest, args.connect, args.password, build_id=args.build_id,
                     save_id=args.save_id, allow_mock=args.allow_mock)
    await ctx.bridge.start(args.bridge_port)
    ctx.server_task = asyncio.create_task(server_loop(ctx), name="AP server")
    watcher = asyncio.create_task(ctx.watch_game())
    import Utils
    if Utils.gui_enabled and not getattr(args, "nogui", False):
        ctx.run_gui()
    ctx.run_cli()
    log.info("LAS bridge listening on 127.0.0.1:%s; native game hooks required", args.bridge_port)
    try:
        await ctx.exit_event.wait()
    finally:
        watcher.cancel()
        await asyncio.gather(watcher, return_exceptions=True)
        await ctx.bridge.close()
        await ctx.shutdown()


def launch(argv=None):
    parser = get_base_parser(description="LAS Switch Archipelago Client (beta)")
    parser.add_argument("manifest", nargs="?", help="Generated .lasap file")
    parser.add_argument("--build-id", help="Exact game executable build ID (mock only: MOCK)")
    parser.add_argument("--save-id", help="Expected persistent game save identifier")
    parser.add_argument("--bridge-port", type=int, default=17778)
    parser.add_argument("--allow-mock", action="store_true", help="Explicitly permit the test game")
    logging.basicConfig(level=logging.INFO)
    args = parser.parse_args(argv)
    if not args.manifest:
        from Utils import open_filename
        args.manifest = open_filename("Choose your LAS seed file", [("LAS seed", [".lasap"])])
        if not args.manifest:
            return
    config_path = Path(args.manifest).parent / "romfs/ap_config.json"
    if config_path.is_file():
        config = json.loads(config_path.read_text(encoding="utf-8"))
        args.build_id = args.build_id or config.get("build_id")
        args.save_id = args.save_id or config.get("save_id")
    manifest=validate_manifest(json.loads(Path(args.manifest).read_text(encoding='utf-8-sig')))
    if manifest['schema_version']==4 and not args.allow_mock:
        args.build_id=args.build_id or 'AE16F71E002AF8CB059A9A74C4D90F34BA984892'
        args.save_id=args.save_id or default_save_id(manifest)
    if not args.build_id or not args.save_id:
        import tkinter as tk
        from tkinter import simpledialog
        root = tk.Tk(); root.withdraw()
        try:
            args.build_id = args.build_id or simpledialog.askstring("LAS game version", "Enter the exact executable build ID:", parent=root)
            args.save_id = args.save_id or simpledialog.askstring("LAS save", "Enter the expected save identifier:", parent=root)
        finally:
            root.destroy()
        if not args.build_id or not args.save_id:
            return
    asyncio.run(run(args))


if __name__ == "__main__":
    launch()
