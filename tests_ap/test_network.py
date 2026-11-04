import asyncio
from contextlib import closing
from functools import partial
import json
import inspect
import copy
from pathlib import Path
import sys
import tempfile
import unittest
import time
from unittest.mock import AsyncMock,patch

import websockets
from CommonClient import server_loop
from MultiServer import Context, server
from Fill import distribute_items_restrictive
from test.general import setup_multiworld
from worlds.las_switch import LASWorld
from worlds.las_switch.client import LASContext
from worlds.las_switch.mock_game import MockSave, run_game, CAPABILITIES
from worlds.las_switch.bridge import Bridge
from worlds.las_switch.core.seed import validate_manifest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from generate_demo import multidata


async def until(predicate, seconds=8):
    async with asyncio.timeout(seconds):
        while not predicate():
            await asyncio.sleep(0.02)

def make_host():
    # AP 0.6.7's Context constructor removes group fields from the process-wide
    # data package. Give each server test its own package, as separate server
    # processes would have in normal use.
    import worlds
    package=copy.deepcopy(worlds.network_data_package)
    for game,world in worlds.AutoWorldRegister.world_types.items():
        if game in package['games']:
            package['games'][game]['item_name_groups']=copy.deepcopy(world.item_name_groups)
            package['games'][game]['location_name_groups']=copy.deepcopy(world.location_name_groups)
    with patch.object(worlds,'network_data_package',package):
        return Context('127.0.0.1',0,'','',1,10,True)


class NetworkTests(unittest.IsolatedAsyncioTestCase):
    async def test_starting_items_and_two_way_deathlink_use_real_ap_server(self):
        mw=setup_multiworld([LASWorld,LASWorld],options={'starting_items':{'sword':1},'death_link':True},seed=321)
        mw.seed_name='deathlink-starting-items';distribute_items_restrictive(mw)
        with tempfile.TemporaryDirectory() as temp:
            mw.worlds[1].generate_output(temp)
            manifest=validate_manifest(json.loads(next(Path(temp).glob('*.lasap')).read_text()))
            host=make_host()
            if 'game_data_packages' in inspect.signature(host._load).parameters:host._load(multidata(mw),{},False)
            else:host._load(multidata(mw),False)
            ws_server=await websockets.serve(partial(server,ctx=host),'127.0.0.1',0)
            address=f'127.0.0.1:{ws_server.sockets[0].getsockname()[1]}'
            ctx=LASContext(manifest,address,build_id='MOCK',save_id='deathlink-save',allow_mock=True)
            port=await ctx.bridge.start(0)
            ctx.server_task=asyncio.create_task(server_loop(ctx));watcher=asyncio.create_task(ctx.watch_game())
            game=MockSave(Path(temp)/'game.sqlite',{'manifest':manifest['manifest_digest']})
            game_task=asyncio.create_task(run_game(manifest,game,port=port,save_id='deathlink-save'))
            peer=None
            try:
                await until(lambda:ctx.ap_validated and game.state()['cursor']==1)
                self.assertEqual(game.state()['inventory'],{'sword':1})
                await until(lambda:any(client.slot==1 and 'DeathLink' in client.tags for client in host.endpoints))
                peer=await websockets.connect('ws://'+address)
                await peer.send(json.dumps([{'cmd':'Connect','password':None,'game':LASWorld.game,
                    'name':mw.player_name[2],'uuid':'deathlink-peer','version':{'major':0,'minor':6,'build':7,'class':'Version'},
                    'items_handling':7,'tags':['AP','DeathLink'],'slot_data':True}]))
                while True:
                    if any(p.get('cmd')=='Connected' for p in json.loads(await asyncio.wait_for(peer.recv(),5))):break
                ctx.send_death=AsyncMock(wraps=ctx.send_death)
                await peer.send(json.dumps([{'cmd':'Bounce','tags':['DeathLink'],'data':{'time':time.time(),'source':'TestFriend','cause':'TestFriend fell.'}}]))
                await until(lambda:game.state()['alive'] is False and ctx.last_alive is False)
                ctx.send_death.assert_not_awaited()
                self.assertEqual(game.state()['inventory'],{'sword':1})
                game.set_alive(True);await until(lambda:ctx.last_alive is True)
                ctx.last_remote_death_at=0  # Test a later independent death without a real-time cooldown delay.
                game.set_alive(False)
                try:
                    await until(lambda:ctx.send_death.await_count==1)
                except TimeoutError:
                    self.fail(str({'calls':ctx.send_death.await_count,'tags':ctx.tags,'alive':ctx.last_alive,
                                   'latched':ctx.remote_death_latched,'pending':ctx.remote_death,
                                   'state':ctx.bridge.state,'error':ctx.last_error,'validated':ctx.ap_validated}))
                bounced=False
                async with asyncio.timeout(5):
                    while not bounced:
                        packets=json.loads(await peer.recv())
                        bounced=any(p.get('cmd')=='Bounced' and 'DeathLink' in p.get('tags',[]) and p.get('data',{}).get('source')==mw.player_name[1] for p in packets)
                self.assertTrue(bounced)
                game.set_alive(True);await until(lambda:ctx.last_alive is True)
                old=ctx.bridge.writer;old.close();await old.wait_closed()
                await until(lambda:ctx.bridge.writer is not None and ctx.bridge.writer is not old)
                self.assertEqual(game.state()['cursor'],1)
                self.assertEqual(game.state()['inventory'],{'sword':1})
            finally:
                game_task.cancel();watcher.cancel();await asyncio.gather(game_task,watcher,return_exceptions=True)
                if peer:await peer.close()
                ctx.exit_event.set();await ctx.shutdown();await ctx.bridge.close()
                ws_server.close();await ws_server.wait_closed();game.close()

    async def test_real_ap_server_las_slots_round_trip_reconnect_and_goal(self):
        mw = setup_multiworld([LASWorld, LASWorld], seed=2026)
        mw.seed_name = "network-integration-seed"
        distribute_items_restrictive(mw)
        outgoing = next(loc for loc in mw.get_locations(1) if loc.item.player == 2)
        incoming = next(loc for loc in mw.get_locations(2) if loc.item.player == 1)
        with tempfile.TemporaryDirectory() as temp:
            mw.worlds[1].generate_output(temp)
            manifest = validate_manifest(json.loads(next(Path(temp).glob("*.lasap")).read_text()))
            data = multidata(mw)
            host = make_host()
            if "game_data_packages" in inspect.signature(host._load).parameters:
                host._load(data, {}, False)
            else:
                host._load(data, False)
            ws_server = await websockets.serve(partial(server, ctx=host), "127.0.0.1", 0)
            address = f"127.0.0.1:{ws_server.sockets[0].getsockname()[1]}"
            ctx = LASContext(manifest, address, build_id="MOCK", save_id="mock-save", allow_mock=True)
            bridge_port = await ctx.bridge.start(0)
            watcher = asyncio.create_task(ctx.watch_game())
            ctx.server_task = asyncio.create_task(server_loop(ctx))
            game = MockSave(Path(temp) / "mock.sqlite", {"manifest": manifest["manifest_digest"]})
            game_task = asyncio.create_task(run_game(manifest, game, port=bridge_port))
            peer = None
            try:
                await until(lambda: ctx.ap_validated and ctx.history_ready and ctx.bridge.state is not None)
                peer = await websockets.connect("ws://" + address)
                await peer.send(json.dumps([{"cmd": "Connect", "password": None,
                    "game": LASWorld.game, "name": mw.player_name[2], "uuid": "test-peer",
                    "version": {"major": 0, "minor": 6, "build": 8, "class": "Version"},
                    "items_handling": 7, "tags": ["AP"], "slot_data": True}]))
                connected = False
                while not connected:
                    packets = json.loads(await asyncio.wait_for(peer.recv(), 5))
                    connected = any(packet.get("cmd") == "Connected" for packet in packets)
                game.collect([outgoing.address])
                await until(lambda: outgoing.address in host.location_checks[0, 1])
                self.assertEqual(game.state()["inventory"], {})  # No original or remote reward grant.
                received_remote = False
                while not received_remote:
                    packets = json.loads(await asyncio.wait_for(peer.recv(), 5))
                    received_remote = any(p.get("cmd") == "ReceivedItems" and
                                           any((item["item"] if isinstance(item, dict) else item[0]) == outgoing.item.code
                                               for item in p.get("items", []))
                                           for p in packets)
                await peer.send(json.dumps([{"cmd": "LocationChecks", "locations": [incoming.address]}]))
                await until(lambda: game.state()["cursor"] == 1)
                self.assertEqual(game.state()["inventory"], {incoming.item.name: 1})
                await ctx.send_msgs([{"cmd": "Sync"}])
                await asyncio.sleep(0.2)
                self.assertEqual(game.state()["cursor"], 1)
                # Real TCP game reconnect: retained AP history and saved cursor must agree.
                old_writer = ctx.bridge.writer
                old_writer.close(); await old_writer.wait_closed()
                await until(lambda: ctx.bridge.writer is not None and ctx.bridge.writer is not old_writer)
                await asyncio.sleep(0.2)
                self.assertEqual(game.state()["inventory"], {incoming.item.name: 1})
                game.victory()
                await until(lambda: host.client_game_state[0, 1] == 30)
                # Real AP reconnect must revalidate and replay goal, not only TCP game reconnect.
                await ctx.disconnect()
                self.assertFalse(ctx.ap_validated)
                host.client_game_state[0, 1] = 0
                await ctx.connect(address)
                await until(lambda: ctx.ap_validated and host.client_game_state[0, 1] == 30)
                self.assertEqual(game.state()["inventory"], {incoming.item.name: 1})
            finally:
                game_task.cancel(); watcher.cancel()
                await asyncio.gather(game_task, watcher, return_exceptions=True)
                if peer:
                    await peer.close()
                ctx.exit_event.set()
                await ctx.shutdown()
                await ctx.bridge.close()
                ws_server.close(); await ws_server.wait_closed()
                game.close()

    async def test_bridge_rejects_mock_by_default_and_wrong_identity(self):
        expected = {"build_id": "build", "save_id": "save"}
        bridge = Bridge(expected, lambda state: None)
        hello = {"t": "hello", "protocol": 1, "implementation": "mock", "build_id": "build",
                 "save_id": "save", "capabilities": CAPABILITIES}
        with self.assertRaisesRegex(ValueError, "Mock game disabled"):
            bridge.validate_hello(hello)
        bridge.allow_mock = True
        bridge.validate_hello(hello)
        hello["build_id"] = "wrong"
        with self.assertRaisesRegex(ValueError, "build_id"):
            bridge.validate_hello(hello)
